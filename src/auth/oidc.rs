//! OIDC JWKS token validator: the production [`TokenValidator`] (plan §3.1,
//! WP A.1; provider profiles in WP C.1b, plan §3.9).
//!
//! Validates RS256 access tokens issued by an OIDC provider
//! against the keys it publishes at its JWKS endpoint, and turns the claims
//! into a [`Principal`]. There is **one** validator for every provider:
//! RS256 over a JWKS with `kid` rotation, background refresh, and a
//! validated-token cache are the same everywhere, and what differs per
//! provider is a handful of defaults and claim-shape corrections. Those are
//! a [`Profile`] — Okta, Entra, Keycloak, Auth0, or a spec-shaped generic —
//! chosen by `MCP_OIDC_PROFILE`; `MCP_AUTH_MODE=okta` with `MCP_OKTA_*` is
//! the Okta profile under its original name (see [`OidcKeys`]).
//!
//! ## What is checked, in order
//!
//! 1. The header parses and names `RS256` — `none`, HMAC, and every other
//!    family are rejected before a key is even looked up, so an HMAC token
//!    signed with the public key bytes cannot be confused for an RSA one.
//! 2. The header's `kid` names a cached key. If not, the JWKS is refetched
//!    (rotation), subject to a rate limit so a flood of unknown `kid`s cannot
//!    turn into a flood of requests to the identity provider (§8 "JWKS fetch rate limit").
//! 3. The signature verifies against that key.
//! 4. `iss` equals the configured issuer (with or without a trailing slash:
//!    Auth0 and Entra v1 issuers end in one, Okta's and Keycloak's do not,
//!    and the two spellings name one origin); `aud` contains the configured
//!    audience; `exp` is in the future and `nbf` (when present) in the
//!    past, both with the configured clock skew; the subject claim the
//!    profile names (`sub`, or `oid` for Entra) is present.
//! 5. If the groups claim is configured but absent and the token says the
//!    groups were *too many to include* (Entra's `_claim_names` /
//!    `_claim_sources` overage, or the older `hasgroups`), the token is
//!    refused as [`TokenRejection::GroupsOverage`] rather than read as "no
//!    groups": a policy that would deny an unknown group must not be
//!    consulted with an empty list for a user who has two hundred.
//!
//! ## Where the keys come from
//!
//! A profile names the JWKS directly (`{issuer}/v1/keys` for Okta,
//! `{issuer}/protocol/openid-connect/certs` for Keycloak,
//! `{issuer}/.well-known/jwks.json` for Auth0) or through the provider's
//! discovery document (`{issuer}/.well-known/openid-configuration` →
//! `jwks_uri`, for Entra and the generic profile). Discovery is resolved
//! on every fetch, the document's `issuer` must match the configured one,
//! and the `jwks_uri` it names is held to the same `https`-or-loopback rule
//! as a configured URL. `MCP_OIDC_JWKS_URL` overrides either.
//!
//! ## Caches
//!
//! - **Signing keys** are cached and refreshed in the background once older
//!   than [`OidcSettings::jwks_refresh`]; stale keys keep serving while a
//!   refresh is in flight or failing (the identity provider being briefly unreachable must
//!   not lock every user out). A validator that has *never* obtained keys
//!   fails closed with [`TokenRejection::KeysUnavailable`].
//! - **Validated tokens** are cached by SHA-256 of the token for
//!   `min(exp, 5 min)` (plan §3.6), so the steady state is one hash and one
//!   map lookup per request (§8: cache hit < 50 µs). The cache is bounded,
//!   and every entry remembers the `kid` that verified it: when a JWKS
//!   fetch no longer publishes that key, the entry is evicted, so a key the
//!   identity provider withdrew stops vouching for tokens at the next fetch
//!   rather than up to five minutes later. Revocation by subject or `jti`
//!   (deny-list, `revoke-all`) arrives in Phase B and operates on this table.
//!
//! ## What a JWKS entry must look like to be admitted
//!
//! Only an RSA public key with a `kid` is usable for RS256. An entry of any
//! other family (EC, OKP, symmetric) is skipped, and so is an RSA entry whose
//! `use` is not `sig` or whose `alg` names something other than `RS256`. Two
//! usable entries sharing a `kid` are ambiguous, and ambiguity is resolved
//! by admitting **neither**: a later key silently replacing an earlier one
//! would make which key verifies a token depend on document order. The
//! document is bounded (`JWKS_MAX_BYTES`) while it is being read, not after,
//! so a chunked response with no `Content-Length` cannot grow the process
//! before it is refused.
//!
//! ## Nothing about the token in logs
//!
//! The token is borrowed for the duration of `validate` and appears in no
//! log line, error, or cache key (only its digest). Rejections are
//! categories.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, errors::ErrorKind};
use serde::Deserialize;

use crate::config::{Config, OidcKeys};
use crate::policy::{Principal, PrincipalAuthority};
use crate::ports::token_validator::{
    AuthenticateFuture, Authenticated, TokenFacts, TokenRejection, TokenValidator, ValidateFuture,
    digest,
};

/// Config key: the provider profile, `MCP_AUTH_MODE=oidc` only. One of
/// `okta`, `entra`, `keycloak`, `auth0`, `generic`. Required: the profile
/// decides which claim carries the subject and where the keys live, and
/// enterprise mode does not guess either.
pub const PROFILE_KEY: &str = "MCP_OIDC_PROFILE";
/// Config key: the claim that identifies the subject, `MCP_AUTH_MODE=oidc`
/// only. Defaults per profile (`sub`, or `oid` for Entra).
pub const SUBJECT_CLAIM_KEY: &str = "MCP_OIDC_SUBJECT_CLAIM";
/// Config key: tenant label stamped on every principal. Defaults to the
/// issuer's host.
pub const TENANT_KEY: &str = "MCP_TENANT";

const DEFAULT_CLOCK_SKEW: Duration = Duration::from_mins(1);
const MAX_CLOCK_SKEW: Duration = Duration::from_mins(5);
/// How long validated tokens are cached at most (plan §3.6).
const VALIDATED_TTL: Duration = Duration::from_mins(5);
/// Bound on the validated-token cache. Past it, expired entries are swept;
/// if none are, the cache is cleared rather than grown.
const VALIDATED_CAPACITY: usize = 4096;
/// JWKS fetch timeout: a slow identity provider must not park every request.
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest JWKS document accepted.
const JWKS_MAX_BYTES: usize = 256 * 1024;
/// Largest discovery document accepted. Entra's runs to a few KB.
const DISCOVERY_MAX_BYTES: usize = 64 * 1024;

/// A provider profile: the defaults and claim-shape corrections that make
/// one provider's tokens readable by the one validator (plan §3.9, the
/// identity-provider row). Everything a profile decides can be overridden
/// by configuration; the profile is the starting point, not a cage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Okta authorization server: `{issuer}/v1/keys`, `scp` array, `sub`,
    /// `groups` (a custom claim on the authorization server).
    Okta,
    /// Microsoft Entra ID: keys through discovery, `scp` as a
    /// space-separated **string**, `oid` as the subject (`sub` is pairwise
    /// per application, so it cannot be the key policy and revocation bind
    /// to), `groups` (or `roles` for app roles). Groups **overage** fails
    /// closed.
    Entra,
    /// Keycloak realm: `{issuer}/protocol/openid-connect/certs`, `scope`
    /// string, `sub`, `groups` from a Group Membership mapper whose values
    /// are `/`-prefixed paths (normalised), or a nested claim such as
    /// `realm_access.roles`. `aud` is absent until an audience mapper is
    /// configured — still required here, so the runbook step is not
    /// optional.
    Keycloak,
    /// Auth0 tenant: `{issuer}/.well-known/jwks.json`, `scope` string,
    /// `sub`, an issuer that ends in `/`, and groups only through a
    /// namespaced custom claim an Action adds — so no default groups
    /// claim; configure `MCP_OIDC_GROUPS_CLAIM` to read one.
    Auth0,
    /// Any spec-shaped provider: keys through discovery, `sub`, `groups`,
    /// no value normalisation.
    Generic,
}

impl Profile {
    /// Parse the `MCP_OIDC_PROFILE` value (ASCII-case-insensitive).
    ///
    /// # Errors
    ///
    /// Names the accepted values when the input is not one of them.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let profile = if raw.eq_ignore_ascii_case("okta") {
            Self::Okta
        } else if raw.eq_ignore_ascii_case("entra") {
            Self::Entra
        } else if raw.eq_ignore_ascii_case("keycloak") {
            Self::Keycloak
        } else if raw.eq_ignore_ascii_case("auth0") {
            Self::Auth0
        } else if raw.eq_ignore_ascii_case("generic") {
            Self::Generic
        } else {
            return Err(format!(
                "{PROFILE_KEY} is {raw:?}; expected one of okta, entra, keycloak, auth0, generic"
            ));
        };
        Ok(profile)
    }

    /// The profile's name as configured.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Okta => "okta",
            Self::Entra => "entra",
            Self::Keycloak => "keycloak",
            Self::Auth0 => "auth0",
            Self::Generic => "generic",
        }
    }

    /// Where this provider publishes its signing keys, relative to a
    /// (slash-trimmed) issuer.
    #[must_use]
    pub fn default_jwks(self, issuer: &str) -> JwksLocation {
        match self {
            Self::Okta => JwksLocation::Direct(format!("{issuer}/v1/keys")),
            Self::Keycloak => {
                JwksLocation::Direct(format!("{issuer}/protocol/openid-connect/certs"))
            }
            Self::Auth0 => JwksLocation::Direct(format!("{issuer}/.well-known/jwks.json")),
            Self::Entra | Self::Generic => {
                JwksLocation::Discovery(format!("{issuer}/.well-known/openid-configuration"))
            }
        }
    }

    /// The claim that identifies the subject.
    #[must_use]
    pub const fn default_subject_claim(self) -> &'static str {
        match self {
            Self::Entra => "oid",
            Self::Okta | Self::Keycloak | Self::Auth0 | Self::Generic => "sub",
        }
    }

    /// The claim carrying group memberships, when the provider has a
    /// conventional one.
    #[must_use]
    pub const fn default_groups_claim(self) -> Option<&'static str> {
        match self {
            Self::Auth0 => None,
            Self::Okta | Self::Entra | Self::Keycloak | Self::Generic => Some("groups"),
        }
    }

    /// Normalise one group value the way the provider spells it: Keycloak's
    /// Group Membership mapper emits paths (`/engineering/platform`), and
    /// the leading `/` is the mapper's, not the group's.
    fn normalise_group(self, value: &str) -> &str {
        match self {
            Self::Keycloak => value.strip_prefix('/').unwrap_or(value),
            Self::Okta | Self::Entra | Self::Auth0 | Self::Generic => value,
        }
    }
}

/// Where signing keys are fetched from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwksLocation {
    /// A JWKS document at this URL.
    Direct(String),
    /// An OIDC discovery document at this URL, whose `jwks_uri` names the
    /// JWKS. Resolved on every fetch.
    Discovery(String),
}

impl JwksLocation {
    /// The URL the validator contacts first.
    #[must_use]
    pub fn url(&self) -> &str {
        match self {
            Self::Direct(url) | Self::Discovery(url) => url,
        }
    }
}

/// Everything the validator needs, read once from configuration.
#[derive(Debug, Clone)]
pub struct OidcSettings {
    pub profile: Profile,
    /// The issuer, without a trailing slash.
    pub issuer: String,
    pub audience: String,
    pub jwks: JwksLocation,
    /// The claim that becomes [`Principal::subject`].
    pub subject_claim: String,
    /// The claim (a name, or a dotted path into nested objects) that
    /// becomes [`Principal::groups`]; `None` reads no groups.
    pub groups_claim: Option<String>,
    pub clock_skew: Duration,
    pub tenant: String,
    /// Keys older than this are refreshed in the background.
    pub jwks_refresh: Duration,
    /// Minimum spacing between JWKS fetches triggered by unknown `kid`s.
    pub jwks_min_refetch_interval: Duration,
}

impl OidcSettings {
    /// Read the settings from configuration under the key family the auth
    /// mode selected, refusing anything incomplete.
    ///
    /// # Errors
    ///
    /// A human-readable reason when the issuer or audience is missing, the
    /// issuer is not an `https` URL, the profile is missing or unknown
    /// (`oidc` family), keys of the other family are also set, or the skew
    /// is out of range. Every error here is a startup failure: enterprise
    /// mode never guesses an issuer.
    pub fn from_config(config: &Config, keys: OidcKeys) -> Result<Self, String> {
        if let Some(stray) = keys
            .other()
            .all()
            .iter()
            .find(|key| optional(config, key).is_some())
        {
            return Err(format!(
                "{stray} is set but MCP_AUTH_MODE={} reads {}_* keys only; a deployment \
                 configures one key family so that which issuer is in force is never a \
                 question (unset it, or switch MCP_AUTH_MODE to {})",
                keys.mode(),
                keys.issuer().trim_end_matches("_ISSUER"),
                keys.other().mode()
            ));
        }
        let profile = match keys {
            OidcKeys::Okta => Profile::Okta,
            OidcKeys::Oidc => Profile::parse(&required(config, keys, PROFILE_KEY)?)?,
        };
        let issuer_key = keys.issuer();
        let issuer = required(config, keys, issuer_key)?;
        let issuer = issuer.trim_end_matches('/').to_owned();
        let parsed = url::Url::parse(&issuer)
            .map_err(|error| format!("{issuer_key} is not a URL: {error}"))?;
        require_https_unless_loopback(&parsed, issuer_key)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("{issuer_key} has no host"))?
            .to_owned();
        let audience = required(config, keys, keys.audience())?;
        let jwks = match optional(config, keys.jwks_url()) {
            Some(url) => JwksLocation::Direct(url.to_owned()),
            None => profile.default_jwks(&issuer),
        };
        let parsed_jwks = url::Url::parse(jwks.url())
            .map_err(|error| format!("{} is not a URL: {error}", keys.jwks_url()))?;
        require_https_unless_loopback(&parsed_jwks, keys.jwks_url())?;
        let subject_claim = match keys {
            OidcKeys::Okta => None,
            OidcKeys::Oidc => optional(config, SUBJECT_CLAIM_KEY),
        }
        .map_or_else(|| profile.default_subject_claim().to_owned(), str::to_owned);
        let groups_claim = match optional(config, keys.groups_claim()) {
            Some(claim) => Some(claim.to_owned()),
            None => profile.default_groups_claim().map(str::to_owned),
        };
        let clock_skew_key = keys.clock_skew_seconds();
        let clock_skew = match optional(config, clock_skew_key) {
            None => DEFAULT_CLOCK_SKEW,
            Some(raw) => {
                let seconds: u64 = raw.parse().map_err(|_| {
                    format!("{clock_skew_key} must be a whole number of seconds, got {raw:?}")
                })?;
                let skew = Duration::from_secs(seconds);
                if skew > MAX_CLOCK_SKEW {
                    return Err(format!(
                        "{clock_skew_key} is {seconds}s; more than {}s of skew is a clock \
                         problem to fix, not a tolerance to configure",
                        MAX_CLOCK_SKEW.as_secs()
                    ));
                }
                skew
            }
        };
        let tenant = optional(config, TENANT_KEY).map_or(host, str::to_owned);
        Ok(Self {
            profile,
            issuer,
            audience,
            jwks,
            subject_claim,
            groups_claim,
            clock_skew,
            tenant,
            jwks_refresh: Duration::from_mins(10),
            jwks_min_refetch_interval: Duration::from_secs(30),
        })
    }

    /// Replace the tenant label.
    #[must_use]
    pub fn with_tenant(mut self, tenant: &str) -> Self {
        tenant.clone_into(&mut self.tenant);
        self
    }

    /// Settings for tests and embedders that hold the values already: the
    /// profile's defaults for everything not given.
    #[must_use]
    pub fn new(profile: Profile, issuer: &str, audience: &str, jwks: JwksLocation) -> Self {
        let issuer = issuer.trim_end_matches('/');
        let tenant = url::Url::parse(issuer)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_else(|| "tenant".to_owned());
        Self {
            profile,
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            jwks,
            subject_claim: profile.default_subject_claim().to_owned(),
            groups_claim: profile.default_groups_claim().map(str::to_owned),
            clock_skew: DEFAULT_CLOCK_SKEW,
            tenant,
            jwks_refresh: Duration::from_mins(10),
            jwks_min_refetch_interval: Duration::from_secs(30),
        }
    }
}

/// Keys are only as trustworthy as the channel they arrive over, so the
/// issuer and JWKS URLs must be `https` — except on loopback, where a local
/// JWKS mirror (air-gapped deployments, tests) is the same trust boundary
/// as the process itself.
fn require_https_unless_loopback(url: &url::Url, key: &str) -> Result<(), String> {
    if url.scheme() == "https" {
        return Ok(());
    }
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if url.scheme() == "http" && loopback {
        return Ok(());
    }
    Err(format!(
        "{key} must be an https URL (or http on loopback): tokens are only as \
         trustworthy as the channel their keys arrive over"
    ))
}

fn required(config: &Config, keys: OidcKeys, key: &str) -> Result<String, String> {
    optional(config, key)
        .map(str::to_owned)
        .ok_or_else(|| format!("{key} is required when MCP_AUTH_MODE={}", keys.mode()))
}

fn optional<'a>(config: &'a Config, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The claims this validator reads. Everything else in the token is
/// ignored; the subject and groups claims have configurable names, so they
/// are read from the flattened remainder.
///
/// Scopes come in two spellings and two shapes: Okta's `scp` is an array,
/// Entra's `scp` is one space-separated string, Keycloak's and Auth0's
/// `scope` is a string. Both claims accept both shapes, and the union is
/// the token's scope set.
#[derive(Deserialize)]
struct Claims {
    exp: Option<u64>,
    iat: Option<u64>,
    jti: Option<String>,
    #[serde(default, deserialize_with = "string_or_array")]
    scp: Vec<String>,
    #[serde(default, deserialize_with = "string_or_array")]
    scope: Vec<String>,
    #[serde(flatten)]
    rest: serde_json::Map<String, serde_json::Value>,
}

/// A claim that is either a space-separated string or an array of strings.
/// Anything else (a number, an object, a non-string member) is dropped
/// rather than refused: an unreadable scope is a scope the token does not
/// grant.
fn string_or_array<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(match value {
        serde_json::Value::String(joined) => joined.split_whitespace().map(str::to_owned).collect(),
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|item| match item {
                serde_json::Value::String(scope) => Some(scope),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    })
}

/// The part of a discovery document the validator uses.
#[derive(Deserialize)]
struct Discovery {
    issuer: Option<String>,
    jwks_uri: Option<String>,
}

/// Entra's signal that the groups did not fit in the token: `_claim_names`
/// maps the claim to a source in `_claim_sources` (a Graph URL the gateway
/// will not follow); older v1 tokens say `hasgroups: true` instead.
fn groups_are_overaged(rest: &serde_json::Map<String, serde_json::Value>, claim: &str) -> bool {
    let named_elsewhere = rest
        .get("_claim_names")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|names| names.contains_key(claim));
    let has_groups_flag = rest
        .get("hasgroups")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    named_elsewhere || rest.contains_key("_claim_sources") || has_groups_flag
}

/// Read a claim by name, or by dotted path when no claim has the literal
/// name — so `https://example.com/groups` (Auth0's namespaced claim, dots
/// and all) and `realm_access.roles` (Keycloak's nested realm roles) both
/// resolve. Literal first: a token cannot redirect a configured name by
/// planting a nested object, because the literal key wins when present.
fn lookup_claim<'a>(
    rest: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<&'a serde_json::Value> {
    if let Some(value) = rest.get(name) {
        return Some(value);
    }
    let mut segments = name.split('.');
    let mut current = rest.get(segments.next()?)?;
    for segment in segments {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

/// The `&'static str` a [`TokenRejection::MissingClaim`] can carry for a
/// configured subject claim: the well-known names by name, anything else
/// as `subject`.
fn static_claim_name(name: &str) -> &'static str {
    match name {
        "sub" => "sub",
        "oid" => "oid",
        "email" => "email",
        "upn" => "upn",
        "preferred_username" => "preferred_username",
        _ => "subject",
    }
}

/// An admitted RSA signing key and a fingerprint of its material, so a
/// rotation that reuses a `kid` for new material is still a change.
struct AdmittedKey {
    key: DecodingKey,
    /// SHA-256 over the JWK's `n` and `e`.
    fingerprint: [u8; 32],
}

struct KeyCache {
    /// `kid` → key. Keys without a `kid` are unusable: rotation is keyed on it.
    keys: Arc<HashMap<String, AdmittedKey>>,
    fetched_at: Option<Instant>,
    /// Bumped on every key installation. A validation remembers the
    /// generation of the keys it verified against and is cached only if
    /// that generation is still current — see [`OidcJwksValidator::remember`].
    generation: u64,
}

/// What a validation reads: the keys, their age, and their generation.
struct KeySnapshot {
    keys: Arc<HashMap<String, AdmittedKey>>,
    fetched_at: Option<Instant>,
    generation: u64,
}

struct Validated {
    authenticated: Authenticated,
    expires_at: Instant,
    /// The `kid` whose key verified this token, and that key's material. A
    /// fetch that no longer publishes the kid — or publishes it with other
    /// material — evicts the entry.
    kid: String,
    fingerprint: [u8; 32],
}

/// What a full validation established, for the caller and for the cache.
struct Verified {
    authenticated: Authenticated,
    exp: u64,
    kid: String,
    fingerprint: [u8; 32],
    generation: u64,
}

/// RS256 JWT validation against an OIDC provider's JWKS.
pub struct OidcJwksValidator {
    settings: OidcSettings,
    /// Built once: every principal this validator produces shares it.
    authority: PrincipalAuthority,
    client: reqwest::Client,
    validation: Validation,
    keys: RwLock<KeyCache>,
    /// Serialises fetches: one in flight at a time, and the rate limit for
    /// unknown-`kid` refetches.
    fetch_gate: tokio::sync::Mutex<Option<Instant>>,
    refreshing: AtomicBool,
    validated: Mutex<HashMap<[u8; 32], Validated>>,
}

impl OidcJwksValidator {
    /// Build the validator. No network I/O happens here: the first
    /// validation fetches keys, so a misconfigured identity provider surfaces as a 503 on
    /// the first request rather than as a startup hang.
    #[must_use]
    pub fn new(settings: OidcSettings, client: reqwest::Client) -> Self {
        let mut validation = Validation::new(Algorithm::RS256);
        // One origin, two spellings: the configured issuer is trimmed, and
        // the token may carry the slash (Auth0 always does; Entra v1 does).
        let with_slash = format!("{}/", settings.issuer);
        validation.set_issuer(&[settings.issuer.as_str(), with_slash.as_str()]);
        validation.set_audience(&[settings.audience.as_str()]);
        // `sub` is not in this list: the subject claim is the profile's to
        // name, and its absence is reported by `principal_from`.
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.validate_nbf = true;
        validation.leeway = settings.clock_skew.as_secs();
        Self {
            authority: PrincipalAuthority::oidc(&settings.issuer),
            settings,
            client,
            validation,
            keys: RwLock::new(KeyCache {
                keys: Arc::new(HashMap::new()),
                fetched_at: None,
                generation: 0,
            }),
            fetch_gate: tokio::sync::Mutex::new(None),
            refreshing: AtomicBool::new(false),
            validated: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn settings(&self) -> &OidcSettings {
        &self.settings
    }

    /// Fetch the JWKS now (startup warm-up, tests). Failure leaves any
    /// previously cached keys in place.
    ///
    /// # Errors
    ///
    /// When the JWKS cannot be fetched or parsed. The message never
    /// contains a token; it may name the JWKS URL.
    pub async fn refresh_keys(&self) -> Result<usize, String> {
        let _fetching = self.fetch_gate.lock().await;
        self.fetch_and_store().await
    }

    async fn fetch_and_store(&self) -> Result<usize, String> {
        let jwks_url = match &self.settings.jwks {
            JwksLocation::Direct(url) => std::borrow::Cow::Borrowed(url.as_str()),
            JwksLocation::Discovery(url) => std::borrow::Cow::Owned(self.discover(url).await?),
        };
        let body = self
            .fetch_bounded(&jwks_url, JWKS_MAX_BYTES, "JWKS")
            .await?;
        let set: JwkSet =
            serde_json::from_slice(&body).map_err(|_| "JWKS document is not valid".to_owned())?;
        Ok(self.install_keys(admit_keys(&set)))
    }

    /// Resolve the JWKS URL through the provider's discovery document. The
    /// document must name the configured issuer (a discovery endpoint that
    /// answers for a different issuer is the wrong endpoint, or a
    /// multi-tenant one that would vouch for every tenant), and the
    /// `jwks_uri` it names is held to the same channel rule as a configured
    /// URL: `https`, or `http` on loopback.
    async fn discover(&self, discovery_url: &str) -> Result<String, String> {
        let body = self
            .fetch_bounded(discovery_url, DISCOVERY_MAX_BYTES, "discovery")
            .await?;
        let document: Discovery = serde_json::from_slice(&body)
            .map_err(|_| "discovery document is not valid".to_owned())?;
        let issuer = document
            .issuer
            .ok_or_else(|| "discovery document names no issuer".to_owned())?;
        if issuer.trim_end_matches('/') != self.settings.issuer {
            return Err(
                "discovery document names a different issuer than the one configured".to_owned(),
            );
        }
        let jwks_uri = document
            .jwks_uri
            .ok_or_else(|| "discovery document names no jwks_uri".to_owned())?;
        let parsed = url::Url::parse(&jwks_uri)
            .map_err(|_| "discovery document's jwks_uri is not a URL".to_owned())?;
        require_https_unless_loopback(&parsed, "the discovery document's jwks_uri")?;
        Ok(jwks_uri)
    }

    /// GET a JSON document with the fetch timeout and a byte bound enforced
    /// on the declared length *and* while the body streams.
    async fn fetch_bounded(
        &self,
        url: &str,
        max_bytes: usize,
        what: &str,
    ) -> Result<Vec<u8>, String> {
        let mut response = self
            .client
            .get(url)
            // Covers the body read too, so a slow chunked stream is bounded
            // in time as well as in bytes.
            .timeout(JWKS_FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|error| format!("{what} fetch failed: {}", redacted_reqwest_error(&error)))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("{what} fetch returned HTTP {}", status.as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes as u64)
        {
            return Err(format!("{what} document too large"));
        }
        // Read chunk by chunk and stop at the bound: `Content-Length` is
        // optional, and a chunked response must not be buffered whole before
        // it is measured.
        let mut body: Vec<u8> = Vec::with_capacity(
            response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or(4096)
                .min(max_bytes),
        );
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| format!("{what} body could not be read"))?
        {
            if body.len() + chunk.len() > max_bytes {
                return Err(format!("{what} document too large"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Make `keys` the current set and evict every cached validation whose
    /// key is no longer in it, as **one** critical section on the validated
    /// cache. Lock order is validated → keys, the same order [`Self::remember`]
    /// takes, so no lookup can observe the new keys with the old cache and
    /// no validation that read the old keys can be inserted after the prune
    /// (its generation is stale by then). Returns the number of usable keys.
    fn install_keys(&self, keys: HashMap<String, AdmittedKey>) -> usize {
        let count = keys.len();
        let keys = Arc::new(keys);
        let mut validated = self
            .validated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        {
            let mut cache = self
                .keys
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cache.keys = Arc::clone(&keys);
            cache.fetched_at = Some(Instant::now());
            cache.generation += 1;
        }
        // A token verified by a key the identity provider no longer
        // publishes — or publishes under the same kid with new material —
        // must not keep being served from the validated cache.
        validated.retain(|_, entry| {
            keys.get(&entry.kid)
                .is_some_and(|admitted| admitted.fingerprint == entry.fingerprint)
        });
        count
    }

    /// Current key snapshot, its age, and its generation.
    fn snapshot(&self) -> KeySnapshot {
        let cache = self
            .keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        KeySnapshot {
            keys: Arc::clone(&cache.keys),
            fetched_at: cache.fetched_at,
            generation: cache.generation,
        }
    }

    /// Refetch because a `kid` was not found, unless a fetch happened too
    /// recently. Returns the fresh snapshot either way.
    async fn refetch_for_unknown_kid(&self) -> KeySnapshot {
        let mut last = self.fetch_gate.lock().await;
        let recently =
            last.is_some_and(|at| at.elapsed() < self.settings.jwks_min_refetch_interval);
        if !recently {
            *last = Some(Instant::now());
            if let Err(error) = self.fetch_and_store().await {
                tracing::warn!(%error, "JWKS refetch after unknown kid failed");
            }
        }
        drop(last);
        self.snapshot()
    }

    /// Kick off a background refresh when the keys are older than the
    /// refresh interval. Never blocks the request.
    fn maybe_refresh_in_background(self: &Arc<Self>, fetched_at: Instant) {
        if fetched_at.elapsed() < self.settings.jwks_refresh {
            return;
        }
        if self
            .refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let this = Arc::clone(self);
        if tokio::runtime::Handle::try_current().is_err() {
            this.refreshing.store(false, Ordering::Release);
            return;
        }
        tokio::spawn(async move {
            if let Err(error) = this.refresh_keys().await {
                tracing::warn!(%error, "background JWKS refresh failed; serving cached keys");
            }
            this.refreshing.store(false, Ordering::Release);
        });
    }

    fn cached(&self, key: &[u8; 32]) -> Option<Authenticated> {
        let cache = self
            .validated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache
            .get(key)
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.authenticated.clone())
    }

    /// Cache a validation — unless the keys it was verified against have
    /// been replaced since (`generation` is no longer current), in which
    /// case the result is still returned to the caller but not remembered:
    /// the next request revalidates against the keys now in force. Checked
    /// under the same lock [`Self::install_keys`] prunes under, so the
    /// interleaving "snapshot old keys → install and prune → insert" cannot
    /// leave an entry behind.
    fn remember(&self, key: [u8; 32], verified: &Verified) {
        let now_unix = jsonwebtoken::get_current_timestamp();
        let until_exp = Duration::from_secs(verified.exp.saturating_sub(now_unix));
        let ttl = until_exp.min(VALIDATED_TTL);
        if ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        let mut cache = self
            .validated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = self
            .keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generation;
        if verified.generation != current {
            return;
        }
        if cache.len() >= VALIDATED_CAPACITY {
            cache.retain(|_, entry| entry.expires_at > now);
            if cache.len() >= VALIDATED_CAPACITY {
                cache.clear();
            }
        }
        cache.insert(
            key,
            Validated {
                authenticated: verified.authenticated.clone(),
                expires_at: now + ttl,
                kid: verified.kid.clone(),
                fingerprint: verified.fingerprint,
            },
        );
    }

    /// Drop every cached validation. The revocation-list watcher calls this
    /// on every change (WP B.4), through [`TokenValidator::forget_validated`].
    pub fn clear_validated(&self) {
        self.validated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    fn principal_from(&self, claims: Claims) -> Result<(Authenticated, u64), TokenRejection> {
        let subject_claim = self.settings.subject_claim.as_str();
        let subject = claims
            .rest
            .get(subject_claim)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|subject| !subject.is_empty())
            .ok_or(TokenRejection::MissingClaim(static_claim_name(
                subject_claim,
            )))?
            .to_owned();
        let exp = claims.exp.ok_or(TokenRejection::MissingClaim("exp"))?;
        // An issue time in the future (beyond the skew) is not a token this
        // gateway can date: it would outrun every `revoke all` cut-off and
        // count as freshly minted for writes forever. `jsonwebtoken` checks
        // `exp` and `nbf` only, so `iat` is bounded here, before anything is
        // cached. Rejected under the same category as a premature `nbf`.
        let now = jsonwebtoken::get_current_timestamp();
        if claims
            .iat
            .is_some_and(|iat| iat > now.saturating_add(self.settings.clock_skew.as_secs()))
        {
            return Err(TokenRejection::NotYetValid);
        }
        let token = TokenFacts {
            issued_at: claims.iat,
            token_id: claims.jti.filter(|jti| !jti.trim().is_empty()),
            actors: crate::auth::ema::actors(claims.rest.get("act"))?,
        };
        let mut scopes = claims.scp;
        scopes.extend(claims.scope);
        scopes.sort_unstable();
        scopes.dedup();
        let mut groups: Vec<String> = match &self.settings.groups_claim {
            None => Vec::new(),
            Some(claim) => match lookup_claim(&claims.rest, claim) {
                Some(values) => values
                    .as_array()
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .map(|value| self.settings.profile.normalise_group(value).to_owned())
                            .collect()
                    })
                    .unwrap_or_default(),
                None if groups_are_overaged(&claims.rest, claim) => {
                    return Err(TokenRejection::GroupsOverage);
                }
                None => Vec::new(),
            },
        };
        groups.sort_unstable();
        groups.dedup();
        Ok((
            Authenticated {
                principal: Principal {
                    tenant: self.settings.tenant.clone(),
                    subject,
                    groups,
                    scopes,
                    authority: self.authority.clone(),
                },
                token,
            },
            exp,
        ))
    }

    /// Full validation: the principal, its `exp`, the key that verified it
    /// (`kid` and material fingerprint, for eviction), and the key
    /// generation used (for the insertion gate).
    async fn validate_uncached(self: &Arc<Self>, token: &str) -> Result<Verified, TokenRejection> {
        let header = decode_header(token).map_err(|_| TokenRejection::Malformed)?;
        if header.alg != Algorithm::RS256 {
            return Err(TokenRejection::UnsupportedAlgorithm);
        }
        if header.typ.as_deref() == Some("oauth-id-jag+jwt") {
            return Err(TokenRejection::Malformed);
        }
        let kid = header.kid.ok_or(TokenRejection::UnknownKey)?;

        let mut snapshot = self.snapshot();
        if let Some(at) = snapshot.fetched_at {
            self.maybe_refresh_in_background(at);
        } else {
            // Never fetched: this request pays for the first fetch.
            // Failure means we can say nothing about any token.
            let _fetching = self.fetch_gate.lock().await;
            if self.snapshot().fetched_at.is_none() {
                self.fetch_and_store().await.map_err(|error| {
                    tracing::error!(%error, "cannot obtain signing keys; refusing token");
                    TokenRejection::KeysUnavailable
                })?;
            }
            snapshot = self.snapshot();
        }
        if !snapshot.keys.contains_key(&kid) {
            snapshot = self.refetch_for_unknown_kid().await;
        }
        let admitted = snapshot.keys.get(&kid).ok_or(TokenRejection::UnknownKey)?;

        let data = decode::<Claims>(token, &admitted.key, &self.validation).map_err(|error| {
            let rejection = match error.kind() {
                ErrorKind::ExpiredSignature => TokenRejection::Expired,
                ErrorKind::ImmatureSignature => TokenRejection::NotYetValid,
                ErrorKind::InvalidIssuer => TokenRejection::WrongIssuer,
                ErrorKind::InvalidAudience => TokenRejection::WrongAudience,
                ErrorKind::InvalidSignature => TokenRejection::InvalidSignature,
                ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
                    TokenRejection::UnsupportedAlgorithm
                }
                ErrorKind::MissingRequiredClaim(claim) => {
                    TokenRejection::MissingClaim(match claim.as_str() {
                        "iss" => "iss",
                        "aud" => "aud",
                        "sub" => "sub",
                        "exp" => "exp",
                        _ => "claim",
                    })
                }
                _ => TokenRejection::Malformed,
            };
            if self.settings.profile == Profile::Keycloak
                && matches!(
                    rejection,
                    TokenRejection::WrongAudience | TokenRejection::MissingClaim("aud")
                )
            {
                tracing::debug!(
                    "audience rejected: a Keycloak token carries no `aud` of ours until the \
                     client has an audience mapper (see docs/identity-provider-runbook.md)"
                );
            }
            rejection
        })?;
        let (authenticated, exp) = self.principal_from(data.claims)?;
        Ok(Verified {
            authenticated,
            exp,
            kid,
            fingerprint: admitted.fingerprint,
            generation: snapshot.generation,
        })
    }
}

impl TokenValidator for Arc<OidcJwksValidator> {
    fn validate<'a>(&'a self, token: &'a str) -> ValidateFuture<'a> {
        Box::pin(async move { Ok(self.authenticate(token).await?.principal) })
    }

    fn authenticate<'a>(&'a self, token: &'a str) -> AuthenticateFuture<'a> {
        Box::pin(async move {
            let key = digest(token);
            if let Some(authenticated) = self.cached(&key) {
                return Ok(authenticated);
            }
            let verified = self.validate_uncached(token).await?;
            self.remember(key, &verified);
            Ok(verified.authenticated)
        })
    }

    fn forget_validated(&self) {
        self.clear_validated();
    }
}

/// The keys a JWKS document actually offers for RS256, by `kid`.
///
/// Admission rules (module docs): RSA only; `use`, when present, must be
/// `sig`; `alg`, when present, must be `RS256`; an entry without a `kid` or
/// whose parameters do not parse is skipped; and a `kid` shared by two
/// admissible entries is dropped altogether rather than resolved by
/// document order.
fn admit_keys(set: &JwkSet) -> HashMap<String, AdmittedKey> {
    let mut keys: HashMap<String, AdmittedKey> = HashMap::with_capacity(set.keys.len());
    // Duplicate kids are the exception; do not allocate for them up front.
    let mut ambiguous: Vec<&str> = Vec::new();
    for jwk in &set.keys {
        let Some(kid) = jwk.common.key_id.as_deref() else {
            continue;
        };
        if !is_rs256_signing_key(jwk) {
            continue;
        }
        let (Ok(key), Some(fingerprint)) = (DecodingKey::from_jwk(jwk), fingerprint_of(jwk)) else {
            continue;
        };
        let admitted = AdmittedKey { key, fingerprint };
        if keys.insert(kid.to_owned(), admitted).is_some() {
            ambiguous.push(kid);
        }
    }
    for kid in ambiguous {
        tracing::warn!(
            kid,
            "JWKS publishes more than one RSA signing key under this kid; admitting neither"
        );
        keys.remove(kid);
    }
    keys
}

/// SHA-256 over the RSA public components, so two keys are "the same" only
/// when their material is.
fn fingerprint_of(jwk: &Jwk) -> Option<[u8; 32]> {
    use sha2::{Digest as _, Sha256};
    let AlgorithmParameters::RSA(params) = &jwk.algorithm else {
        return None;
    };
    let mut hasher = Sha256::new();
    hasher.update(params.n.as_bytes());
    hasher.update([0]);
    hasher.update(params.e.as_bytes());
    Some(hasher.finalize().into())
}

fn is_rs256_signing_key(jwk: &Jwk) -> bool {
    matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
        && jwk
            .common
            .public_key_use
            .as_ref()
            .is_none_or(|purpose| *purpose == PublicKeyUse::Signature)
        && jwk
            .common
            .key_algorithm
            .is_none_or(|algorithm| algorithm == KeyAlgorithm::RS256)
}

/// A reqwest error can quote the URL it was sent to (which is the JWKS
/// URL, not secret) but never a token; still, keep to the error kind so a
/// future header-quoting variant cannot leak.
fn redacted_reqwest_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_status() {
        "http error status"
    } else if error.is_body() || error.is_decode() {
        "body error"
    } else {
        "request error"
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use pretty_assertions::assert_eq;

    use super::*;

    fn config(pairs: &[(&str, &str)]) -> Config {
        Config::from_map(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<HashMap<_, _>>(),
        )
    }

    #[test]
    fn okta_family_requires_issuer_and_audience_and_defaults_the_rest() {
        let settings = OidcSettings::from_config(
            &config(&[
                ("MCP_OKTA_ISSUER", "https://acme.okta.com/oauth2/default/"),
                ("MCP_OKTA_AUDIENCE", "api://mcp-devtools"),
            ]),
            OidcKeys::Okta,
        )
        .unwrap();
        assert_eq!(settings.profile, Profile::Okta);
        assert_eq!(settings.issuer, "https://acme.okta.com/oauth2/default");
        assert_eq!(
            settings.jwks,
            JwksLocation::Direct("https://acme.okta.com/oauth2/default/v1/keys".to_owned())
        );
        assert_eq!(settings.subject_claim, "sub");
        assert_eq!(settings.groups_claim.as_deref(), Some("groups"));
        assert_eq!(settings.clock_skew, DEFAULT_CLOCK_SKEW);
        assert_eq!(settings.tenant, "acme.okta.com");

        for missing in [
            &[("MCP_OKTA_AUDIENCE", "x")][..],
            &[("MCP_OKTA_ISSUER", "https://a.okta.com")][..],
        ] {
            let error = OidcSettings::from_config(&config(missing), OidcKeys::Okta).unwrap_err();
            assert!(error.contains("MCP_AUTH_MODE=okta"), "{error}");
        }
    }

    /// The `oidc` family names its profile explicitly, and each profile's
    /// defaults are the ones the §3.9 table records.
    #[test]
    fn oidc_family_requires_a_profile_and_each_profile_has_its_defaults() {
        let base = |profile: &str| {
            config(&[
                ("MCP_OIDC_PROFILE", profile),
                ("MCP_OIDC_ISSUER", "https://login.example/realms/acme/"),
                ("MCP_OIDC_AUDIENCE", "api://mcp-devtools"),
            ])
        };
        let no_profile = OidcSettings::from_config(
            &config(&[
                ("MCP_OIDC_ISSUER", "https://login.example/realms/acme"),
                ("MCP_OIDC_AUDIENCE", "api://mcp-devtools"),
            ]),
            OidcKeys::Oidc,
        )
        .unwrap_err();
        assert!(no_profile.contains("MCP_OIDC_PROFILE"), "{no_profile}");
        assert!(no_profile.contains("MCP_AUTH_MODE=oidc"), "{no_profile}");
        let unknown = OidcSettings::from_config(&base("ping"), OidcKeys::Oidc).unwrap_err();
        assert!(unknown.contains("keycloak"), "{unknown}");

        let issuer = "https://login.example/realms/acme";
        let rows: &[(&str, Profile, JwksLocation, &str, Option<&str>)] = &[
            (
                "okta",
                Profile::Okta,
                JwksLocation::Direct(format!("{issuer}/v1/keys")),
                "sub",
                Some("groups"),
            ),
            (
                "Entra",
                Profile::Entra,
                JwksLocation::Discovery(format!("{issuer}/.well-known/openid-configuration")),
                "oid",
                Some("groups"),
            ),
            (
                "keycloak",
                Profile::Keycloak,
                JwksLocation::Direct(format!("{issuer}/protocol/openid-connect/certs")),
                "sub",
                Some("groups"),
            ),
            (
                "auth0",
                Profile::Auth0,
                JwksLocation::Direct(format!("{issuer}/.well-known/jwks.json")),
                "sub",
                None,
            ),
            (
                "generic",
                Profile::Generic,
                JwksLocation::Discovery(format!("{issuer}/.well-known/openid-configuration")),
                "sub",
                Some("groups"),
            ),
        ];
        for (name, profile, jwks, subject, groups) in rows {
            let settings = OidcSettings::from_config(&base(name), OidcKeys::Oidc).unwrap();
            assert_eq!(settings.profile, *profile, "{name}");
            assert_eq!(settings.jwks, *jwks, "{name}");
            assert_eq!(settings.subject_claim, *subject, "{name}");
            assert_eq!(settings.groups_claim.as_deref(), *groups, "{name}");
            assert_eq!(settings.issuer, issuer, "{name}: trailing slash trimmed");
        }

        // Overrides win over the profile.
        let overridden = OidcSettings::from_config(
            &config(&[
                ("MCP_OIDC_PROFILE", "entra"),
                ("MCP_OIDC_ISSUER", issuer),
                ("MCP_OIDC_AUDIENCE", "api://mcp-devtools"),
                ("MCP_OIDC_JWKS_URL", "https://keys.example/jwks"),
                ("MCP_OIDC_SUBJECT_CLAIM", "upn"),
                ("MCP_OIDC_GROUPS_CLAIM", "roles"),
            ]),
            OidcKeys::Oidc,
        )
        .unwrap();
        assert_eq!(
            overridden.jwks,
            JwksLocation::Direct("https://keys.example/jwks".to_owned())
        );
        assert_eq!(overridden.subject_claim, "upn");
        assert_eq!(overridden.groups_claim.as_deref(), Some("roles"));
    }

    /// One key family per deployment: a stray key from the other family is
    /// refused rather than ignored, so a half-migrated configuration
    /// cannot leave the wrong issuer silently in force.
    #[test]
    fn mixing_the_two_key_families_is_refused() {
        let mixed = OidcSettings::from_config(
            &config(&[
                ("MCP_OKTA_ISSUER", "https://acme.okta.com/oauth2/default"),
                ("MCP_OKTA_AUDIENCE", "api://mcp-devtools"),
                ("MCP_OIDC_PROFILE", "entra"),
            ]),
            OidcKeys::Okta,
        )
        .unwrap_err();
        assert!(mixed.contains("MCP_OIDC_PROFILE"), "{mixed}");
        assert!(mixed.contains("MCP_AUTH_MODE=okta"), "{mixed}");
        let mixed = OidcSettings::from_config(
            &config(&[
                ("MCP_OIDC_PROFILE", "okta"),
                ("MCP_OIDC_ISSUER", "https://acme.okta.com/oauth2/default"),
                ("MCP_OIDC_AUDIENCE", "api://mcp-devtools"),
                ("MCP_OKTA_GROUPS_CLAIM", "roles"),
            ]),
            OidcKeys::Oidc,
        )
        .unwrap_err();
        assert!(mixed.contains("MCP_OKTA_GROUPS_CLAIM"), "{mixed}");
    }

    #[test]
    fn scope_claims_accept_a_string_or_an_array_and_claims_resolve_by_name_or_path() {
        let parse = |json: &str| serde_json::from_str::<Claims>(json).unwrap();
        assert_eq!(parse(r#"{"scp":["a","b"]}"#).scp, vec!["a", "b"]);
        assert_eq!(parse(r#"{"scp":"a b  c"}"#).scp, vec!["a", "b", "c"]);
        assert_eq!(parse(r#"{"scope":["a",1,null]}"#).scope, vec!["a"]);
        assert_eq!(parse(r#"{"scope":42}"#).scope, Vec::<String>::new());
        assert!(parse("{}").scp.is_empty());

        let rest = parse(
            r#"{"https://example.com/groups":["g"],"realm_access":{"roles":["r"]},
                "realm_access.roles":["literal"],"groups":["x"]}"#,
        )
        .rest;
        assert_eq!(
            lookup_claim(&rest, "https://example.com/groups").unwrap(),
            &serde_json::json!(["g"])
        );
        assert_eq!(
            lookup_claim(&rest, "realm_access.roles").unwrap(),
            &serde_json::json!(["literal"]),
            "the literal key wins over the path"
        );
        let rest = parse(r#"{"realm_access":{"roles":["r"]}}"#).rest;
        assert_eq!(
            lookup_claim(&rest, "realm_access.roles").unwrap(),
            &serde_json::json!(["r"])
        );
        assert!(lookup_claim(&rest, "realm_access.roles.deeper").is_none());
        assert!(lookup_claim(&rest, "missing").is_none());
    }

    #[test]
    fn group_normalisation_is_keycloaks_alone() {
        assert_eq!(
            Profile::Keycloak.normalise_group("/engineering"),
            "engineering"
        );
        assert_eq!(
            Profile::Keycloak.normalise_group("/engineering/platform"),
            "engineering/platform"
        );
        assert_eq!(
            Profile::Keycloak.normalise_group("engineering"),
            "engineering"
        );
        assert_eq!(
            Profile::Okta.normalise_group("/engineering"),
            "/engineering"
        );
        assert_eq!(
            Profile::Entra.normalise_group("/engineering"),
            "/engineering"
        );
    }

    /// The interleaving the generation exists for: a validation snapshots
    /// the keys, a refresh installs a set without that key and prunes the
    /// cache, and only then does the validation try to cache its result.
    /// Not reachable deterministically through `validate` (there is no
    /// await between snapshot and insert on the common path; the race is
    /// between worker threads), so the mechanism is exercised directly.
    #[test]
    fn a_validation_against_replaced_keys_is_not_cached() {
        let validator = OidcJwksValidator::new(
            OidcSettings::from_config(
                &config(&[
                    ("MCP_OKTA_ISSUER", "https://acme.okta.com/oauth2/default"),
                    ("MCP_OKTA_AUDIENCE", "api://mcp-devtools"),
                ]),
                OidcKeys::Okta,
            )
            .unwrap(),
            reqwest::Client::new(),
        );
        let key_named = |kid: &str, material: u8| {
            HashMap::from([(
                kid.to_owned(),
                AdmittedKey {
                    key: DecodingKey::from_secret(b"not-a-real-key"),
                    fingerprint: [material; 32],
                },
            )])
        };
        let verified = |kid: &str, material: u8, generation: u64| Verified {
            authenticated: Authenticated {
                principal: Principal {
                    tenant: "acme".to_owned(),
                    subject: "alice@acme.example".to_owned(),
                    groups: Vec::new(),
                    scopes: Vec::new(),
                    authority: PrincipalAuthority::oidc("https://acme.okta.com/oauth2/default"),
                },
                token: TokenFacts::default(),
            },
            exp: jsonwebtoken::get_current_timestamp() + 300,
            kid: kid.to_owned(),
            fingerprint: [material; 32],
            generation,
        };
        let token = digest("token-under-old");

        validator.install_keys(key_named("old", 1));
        // Request A reads the keys (generation 1) …
        let seen_by_a = validator.snapshot();
        assert!(seen_by_a.keys.contains_key("old"));
        // … refresh B withdraws `old` and prunes (generation 2) …
        validator.install_keys(key_named("new", 2));
        // … and A, having verified against `old`, tries to cache.
        validator.remember(token, &verified("old", 1, seen_by_a.generation));
        assert!(
            validator.cached(&token).is_none(),
            "a result verified against replaced keys must not be cached"
        );

        // The same insert with the current generation is cached — the
        // gate is on staleness, not on the kid alone.
        let current = validator.snapshot();
        validator.remember(token, &verified("new", 2, current.generation));
        assert!(validator.cached(&token).is_some());
        // The same kid republished with other material evicts it: the kid
        // is a label, the material is the key.
        validator.install_keys(key_named("new", 3));
        assert!(
            validator.cached(&token).is_none(),
            "same kid, new material: the cached verification is void"
        );
        let current = validator.snapshot();
        validator.remember(token, &verified("new", 3, current.generation));
        assert!(validator.cached(&token).is_some());
        // And a withdrawal of `new` evicts it too.
        validator.install_keys(HashMap::new());
        assert!(validator.cached(&token).is_none());
    }

    #[test]
    fn settings_refuse_plain_http_and_absurd_skew() {
        let http = OidcSettings::from_config(
            &config(&[
                ("MCP_OKTA_ISSUER", "http://acme.okta.com/oauth2/default"),
                ("MCP_OKTA_AUDIENCE", "x"),
            ]),
            OidcKeys::Okta,
        );
        assert!(http.unwrap_err().contains("https"));
        // Loopback is the one place plain http is the same trust boundary
        // as the process: a local JWKS mirror, or a test.
        let loopback = OidcSettings::from_config(
            &config(&[
                ("MCP_OKTA_ISSUER", "http://127.0.0.1:8080/oauth2/default"),
                ("MCP_OKTA_AUDIENCE", "x"),
            ]),
            OidcKeys::Okta,
        )
        .unwrap();
        assert_eq!(
            loopback.jwks.url(),
            "http://127.0.0.1:8080/oauth2/default/v1/keys"
        );
        let remote_jwks = OidcSettings::from_config(
            &config(&[
                ("MCP_OKTA_ISSUER", "https://acme.okta.com/oauth2/default"),
                ("MCP_OKTA_AUDIENCE", "x"),
                ("MCP_OKTA_JWKS_URL", "http://keys.example/jwks"),
            ]),
            OidcKeys::Okta,
        );
        assert!(remote_jwks.unwrap_err().contains("https"));

        let skew = OidcSettings::from_config(
            &config(&[
                ("MCP_OKTA_ISSUER", "https://acme.okta.com/oauth2/default"),
                ("MCP_OKTA_AUDIENCE", "x"),
                ("MCP_OKTA_CLOCK_SKEW_SECONDS", "3600"),
            ]),
            OidcKeys::Okta,
        );
        assert!(skew.unwrap_err().contains("skew"));

        let overrides = OidcSettings::from_config(
            &config(&[
                ("MCP_OKTA_ISSUER", "https://acme.okta.com/oauth2/default"),
                ("MCP_OKTA_AUDIENCE", "x"),
                ("MCP_OKTA_JWKS_URL", "https://keys.example/jwks"),
                ("MCP_OKTA_GROUPS_CLAIM", "roles"),
                ("MCP_OKTA_CLOCK_SKEW_SECONDS", "10"),
                ("MCP_TENANT", "acme"),
            ]),
            OidcKeys::Okta,
        )
        .unwrap();
        assert_eq!(overrides.jwks.url(), "https://keys.example/jwks");
        assert_eq!(overrides.groups_claim.as_deref(), Some("roles"));
        assert_eq!(overrides.clock_skew, Duration::from_secs(10));
        assert_eq!(overrides.tenant, "acme");
    }
}

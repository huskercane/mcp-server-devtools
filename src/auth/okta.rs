//! Okta JWKS token validator: the production [`TokenValidator`] (plan §3.1,
//! WP A.1).
//!
//! Validates RS256 access tokens issued by an Okta authorization server
//! against the keys it publishes at its JWKS endpoint, and turns the claims
//! into a [`Principal`]. Nothing Okta-specific is hard-coded beyond the
//! JWKS URL default (`{issuer}/v1/keys`); an Entra adapter would differ in
//! claim names, which are configurable here already.
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
//! 4. `iss` equals the configured issuer; `aud` contains the configured
//!    audience; `exp` is in the future and `nbf` (when present) in the past,
//!    both with the configured clock skew; `sub` is present.
//!
//! ## Caches
//!
//! - **Signing keys** are cached and refreshed in the background once older
//!   than [`OktaSettings::jwks_refresh`]; stale keys keep serving while a
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

use crate::config::Config;
use crate::policy::{Principal, PrincipalAuthority};
use crate::ports::token_validator::{TokenRejection, TokenValidator, ValidateFuture, digest};

/// Config key: the Okta authorization server issuer URL
/// (`https://<org>.okta.com/oauth2/<server id>`). Required.
pub const ISSUER_KEY: &str = "MCP_OKTA_ISSUER";
/// Config key: the audience the tokens must carry. Required.
pub const AUDIENCE_KEY: &str = "MCP_OKTA_AUDIENCE";
/// Config key: JWKS URL override. Defaults to `{issuer}/v1/keys`.
pub const JWKS_URL_KEY: &str = "MCP_OKTA_JWKS_URL";
/// Config key: the claim carrying group memberships. Defaults to `groups`.
pub const GROUPS_CLAIM_KEY: &str = "MCP_OKTA_GROUPS_CLAIM";
/// Config key: clock skew tolerance in seconds. Defaults to 60, at most 300.
pub const CLOCK_SKEW_KEY: &str = "MCP_OKTA_CLOCK_SKEW_SECONDS";
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

/// Everything the validator needs, read once from configuration.
#[derive(Debug, Clone)]
pub struct OktaSettings {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
    pub groups_claim: String,
    pub clock_skew: Duration,
    pub tenant: String,
    /// Keys older than this are refreshed in the background.
    pub jwks_refresh: Duration,
    /// Minimum spacing between JWKS fetches triggered by unknown `kid`s.
    pub jwks_min_refetch_interval: Duration,
}

impl OktaSettings {
    /// Read the settings from configuration, refusing anything incomplete.
    ///
    /// # Errors
    ///
    /// A human-readable reason when the issuer or audience is missing, the
    /// issuer is not an `https` URL, or the skew is out of range. Every
    /// error here is a startup failure: enterprise mode never guesses an
    /// issuer.
    pub fn from_config(config: &Config) -> Result<Self, String> {
        let issuer = required(config, ISSUER_KEY)?;
        let issuer = issuer.trim_end_matches('/').to_owned();
        let parsed = url::Url::parse(&issuer)
            .map_err(|error| format!("{ISSUER_KEY} is not a URL: {error}"))?;
        require_https_unless_loopback(&parsed, ISSUER_KEY)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("{ISSUER_KEY} has no host"))?
            .to_owned();
        let audience = required(config, AUDIENCE_KEY)?;
        let jwks_url = optional(config, JWKS_URL_KEY)
            .map_or_else(|| format!("{issuer}/v1/keys"), str::to_owned);
        let parsed_jwks = url::Url::parse(&jwks_url)
            .map_err(|error| format!("{JWKS_URL_KEY} is not a URL: {error}"))?;
        require_https_unless_loopback(&parsed_jwks, JWKS_URL_KEY)?;
        let groups_claim =
            optional(config, GROUPS_CLAIM_KEY).map_or_else(|| "groups".to_owned(), str::to_owned);
        let clock_skew = match optional(config, CLOCK_SKEW_KEY) {
            None => DEFAULT_CLOCK_SKEW,
            Some(raw) => {
                let seconds: u64 = raw.parse().map_err(|_| {
                    format!("{CLOCK_SKEW_KEY} must be a whole number of seconds, got {raw:?}")
                })?;
                let skew = Duration::from_secs(seconds);
                if skew > MAX_CLOCK_SKEW {
                    return Err(format!(
                        "{CLOCK_SKEW_KEY} is {seconds}s; more than {}s of skew is a clock \
                         problem to fix, not a tolerance to configure",
                        MAX_CLOCK_SKEW.as_secs()
                    ));
                }
                skew
            }
        };
        let tenant = optional(config, TENANT_KEY).map_or(host, str::to_owned);
        Ok(Self {
            issuer,
            audience,
            jwks_url,
            groups_claim,
            clock_skew,
            tenant,
            jwks_refresh: Duration::from_mins(10),
            jwks_min_refetch_interval: Duration::from_secs(30),
        })
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

fn required(config: &Config, key: &str) -> Result<String, String> {
    optional(config, key)
        .map(str::to_owned)
        .ok_or_else(|| format!("{key} is required when MCP_AUTH_MODE=okta"))
}

fn optional<'a>(config: &'a Config, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The claims this validator reads. Everything else in the token is
/// ignored; the groups claim has a configurable name, so it is read from
/// the flattened remainder.
#[derive(Deserialize)]
struct Claims {
    sub: Option<String>,
    exp: Option<u64>,
    #[serde(default)]
    scp: Option<Vec<String>>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(flatten)]
    rest: serde_json::Map<String, serde_json::Value>,
}

struct KeyCache {
    /// `kid` → key. Keys without a `kid` are unusable: rotation is keyed on it.
    keys: Arc<HashMap<String, DecodingKey>>,
    fetched_at: Option<Instant>,
}

struct Validated {
    principal: Principal,
    expires_at: Instant,
    /// The `kid` whose key verified this token. A fetch that no longer
    /// publishes it evicts the entry.
    kid: String,
}

/// RS256 JWT validation against an Okta JWKS.
pub struct OktaJwksValidator {
    settings: OktaSettings,
    client: reqwest::Client,
    validation: Validation,
    keys: RwLock<KeyCache>,
    /// Serialises fetches: one in flight at a time, and the rate limit for
    /// unknown-`kid` refetches.
    fetch_gate: tokio::sync::Mutex<Option<Instant>>,
    refreshing: AtomicBool,
    validated: Mutex<HashMap<[u8; 32], Validated>>,
}

impl OktaJwksValidator {
    /// Build the validator. No network I/O happens here: the first
    /// validation fetches keys, so a misconfigured identity provider surfaces as a 503 on
    /// the first request rather than as a startup hang.
    #[must_use]
    pub fn new(settings: OktaSettings, client: reqwest::Client) -> Self {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[settings.issuer.as_str()]);
        validation.set_audience(&[settings.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = settings.clock_skew.as_secs();
        Self {
            settings,
            client,
            validation,
            keys: RwLock::new(KeyCache {
                keys: Arc::new(HashMap::new()),
                fetched_at: None,
            }),
            fetch_gate: tokio::sync::Mutex::new(None),
            refreshing: AtomicBool::new(false),
            validated: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn settings(&self) -> &OktaSettings {
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
        let mut response = self
            .client
            .get(&self.settings.jwks_url)
            // Covers the body read too, so a slow chunked stream is bounded
            // in time as well as in bytes.
            .timeout(JWKS_FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|error| format!("JWKS fetch failed: {}", redacted_reqwest_error(&error)))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("JWKS fetch returned HTTP {}", status.as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > JWKS_MAX_BYTES as u64)
        {
            return Err("JWKS document too large".to_owned());
        }
        // Read chunk by chunk and stop at the bound: `Content-Length` is
        // optional, and a chunked response must not be buffered whole before
        // it is measured.
        let mut body: Vec<u8> = Vec::with_capacity(
            response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or(4096)
                .min(JWKS_MAX_BYTES),
        );
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "JWKS body could not be read".to_owned())?
        {
            if body.len() + chunk.len() > JWKS_MAX_BYTES {
                return Err("JWKS document too large".to_owned());
            }
            body.extend_from_slice(&chunk);
        }
        let set: JwkSet =
            serde_json::from_slice(&body).map_err(|_| "JWKS document is not valid".to_owned())?;
        let keys = admit_keys(&set);
        let count = keys.len();
        let keys = Arc::new(keys);
        {
            let mut cache = self
                .keys
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cache.keys = Arc::clone(&keys);
            cache.fetched_at = Some(Instant::now());
        }
        // A token verified by a key the identity provider no longer
        // publishes must not keep being served from the validated cache.
        self.validated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|_, entry| keys.contains_key(&entry.kid));
        Ok(count)
    }

    /// Current key snapshot and its age.
    fn snapshot(&self) -> (Arc<HashMap<String, DecodingKey>>, Option<Instant>) {
        let cache = self
            .keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (Arc::clone(&cache.keys), cache.fetched_at)
    }

    /// Refetch because a `kid` was not found, unless a fetch happened too
    /// recently. Returns the fresh snapshot either way.
    async fn refetch_for_unknown_kid(&self) -> Arc<HashMap<String, DecodingKey>> {
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
        self.snapshot().0
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

    fn cached_principal(&self, key: &[u8; 32]) -> Option<Principal> {
        let cache = self
            .validated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache
            .get(key)
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.principal.clone())
    }

    fn remember(&self, key: [u8; 32], principal: &Principal, exp: u64, kid: String) {
        let now_unix = jsonwebtoken::get_current_timestamp();
        let until_exp = Duration::from_secs(exp.saturating_sub(now_unix));
        let ttl = until_exp.min(VALIDATED_TTL);
        if ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        let mut cache = self
            .validated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.len() >= VALIDATED_CAPACITY {
            cache.retain(|_, entry| entry.expires_at > now);
            if cache.len() >= VALIDATED_CAPACITY {
                cache.clear();
            }
        }
        cache.insert(
            key,
            Validated {
                principal: principal.clone(),
                expires_at: now + ttl,
                kid,
            },
        );
    }

    /// Drop every cached validation. Phase B's `revoke-all` calls this.
    pub fn clear_validated(&self) {
        self.validated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    fn principal_from(&self, claims: Claims) -> Result<(Principal, u64), TokenRejection> {
        let subject = claims
            .sub
            .filter(|sub| !sub.trim().is_empty())
            .ok_or(TokenRejection::MissingClaim("sub"))?;
        let exp = claims.exp.ok_or(TokenRejection::MissingClaim("exp"))?;
        let mut scopes = claims.scp.unwrap_or_default();
        if let Some(scope) = claims.scope {
            scopes.extend(scope.split_whitespace().map(str::to_owned));
        }
        scopes.sort_unstable();
        scopes.dedup();
        let mut groups: Vec<String> = claims
            .rest
            .get(&self.settings.groups_claim)
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        groups.sort_unstable();
        groups.dedup();
        Ok((
            Principal {
                tenant: self.settings.tenant.clone(),
                subject,
                groups,
                scopes,
                authority: PrincipalAuthority::Okta,
            },
            exp,
        ))
    }

    /// Full validation: returns the principal, its `exp`, and the `kid` that
    /// verified it (the cache entry is keyed on that for eviction).
    async fn validate_uncached(
        self: &Arc<Self>,
        token: &str,
    ) -> Result<(Principal, u64, String), TokenRejection> {
        let header = decode_header(token).map_err(|_| TokenRejection::Malformed)?;
        if header.alg != Algorithm::RS256 {
            return Err(TokenRejection::UnsupportedAlgorithm);
        }
        let kid = header.kid.ok_or(TokenRejection::UnknownKey)?;

        let (mut keys, fetched_at) = self.snapshot();
        if let Some(at) = fetched_at {
            self.maybe_refresh_in_background(at);
        } else {
            // Never fetched: this request pays for the first fetch.
            // Failure means we can say nothing about any token.
            let _fetching = self.fetch_gate.lock().await;
            if self.snapshot().1.is_none() {
                self.fetch_and_store().await.map_err(|error| {
                    tracing::error!(%error, "cannot obtain signing keys; refusing token");
                    TokenRejection::KeysUnavailable
                })?;
            }
            keys = self.snapshot().0;
        }
        if !keys.contains_key(&kid) {
            keys = self.refetch_for_unknown_kid().await;
        }
        let key = keys.get(&kid).ok_or(TokenRejection::UnknownKey)?;

        let data =
            decode::<Claims>(token, key, &self.validation).map_err(|error| match error.kind() {
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
            })?;
        let (principal, exp) = self.principal_from(data.claims)?;
        Ok((principal, exp, kid))
    }
}

impl TokenValidator for Arc<OktaJwksValidator> {
    fn validate<'a>(&'a self, token: &'a str) -> ValidateFuture<'a> {
        Box::pin(async move {
            let key = digest(token);
            if let Some(principal) = self.cached_principal(&key) {
                return Ok(principal);
            }
            let (principal, exp, kid) = self.validate_uncached(token).await?;
            self.remember(key, &principal, exp, kid);
            Ok(principal)
        })
    }
}

/// The keys a JWKS document actually offers for RS256, by `kid`.
///
/// Admission rules (module docs): RSA only; `use`, when present, must be
/// `sig`; `alg`, when present, must be `RS256`; an entry without a `kid` or
/// whose parameters do not parse is skipped; and a `kid` shared by two
/// admissible entries is dropped altogether rather than resolved by
/// document order.
fn admit_keys(set: &JwkSet) -> HashMap<String, DecodingKey> {
    let mut keys: HashMap<String, DecodingKey> = HashMap::with_capacity(set.keys.len());
    let mut ambiguous: Vec<String> = Vec::new();
    for jwk in &set.keys {
        let Some(kid) = jwk.common.key_id.as_deref() else {
            continue;
        };
        if !is_rs256_signing_key(jwk) {
            continue;
        }
        let Ok(key) = DecodingKey::from_jwk(jwk) else {
            continue;
        };
        if keys.insert(kid.to_owned(), key).is_some() {
            ambiguous.push(kid.to_owned());
        }
    }
    for kid in ambiguous {
        tracing::warn!(
            kid,
            "JWKS publishes more than one RSA signing key under this kid; admitting neither"
        );
        keys.remove(&kid);
    }
    keys
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
    fn settings_require_issuer_and_audience_and_default_the_rest() {
        let settings = OktaSettings::from_config(&config(&[
            ("MCP_OKTA_ISSUER", "https://acme.okta.com/oauth2/default/"),
            ("MCP_OKTA_AUDIENCE", "api://mcp-devtools"),
        ]))
        .unwrap();
        assert_eq!(settings.issuer, "https://acme.okta.com/oauth2/default");
        assert_eq!(
            settings.jwks_url,
            "https://acme.okta.com/oauth2/default/v1/keys"
        );
        assert_eq!(settings.groups_claim, "groups");
        assert_eq!(settings.clock_skew, DEFAULT_CLOCK_SKEW);
        assert_eq!(settings.tenant, "acme.okta.com");

        for missing in [
            &[("MCP_OKTA_AUDIENCE", "x")][..],
            &[("MCP_OKTA_ISSUER", "https://a.okta.com")][..],
        ] {
            assert!(OktaSettings::from_config(&config(missing)).is_err());
        }
    }

    #[test]
    fn settings_refuse_plain_http_and_absurd_skew() {
        let http = OktaSettings::from_config(&config(&[
            ("MCP_OKTA_ISSUER", "http://acme.okta.com/oauth2/default"),
            ("MCP_OKTA_AUDIENCE", "x"),
        ]));
        assert!(http.unwrap_err().contains("https"));
        // Loopback is the one place plain http is the same trust boundary
        // as the process: a local JWKS mirror, or a test.
        let loopback = OktaSettings::from_config(&config(&[
            ("MCP_OKTA_ISSUER", "http://127.0.0.1:8080/oauth2/default"),
            ("MCP_OKTA_AUDIENCE", "x"),
        ]))
        .unwrap();
        assert_eq!(
            loopback.jwks_url,
            "http://127.0.0.1:8080/oauth2/default/v1/keys"
        );
        let remote_jwks = OktaSettings::from_config(&config(&[
            ("MCP_OKTA_ISSUER", "https://acme.okta.com/oauth2/default"),
            ("MCP_OKTA_AUDIENCE", "x"),
            ("MCP_OKTA_JWKS_URL", "http://keys.example/jwks"),
        ]));
        assert!(remote_jwks.unwrap_err().contains("https"));

        let skew = OktaSettings::from_config(&config(&[
            ("MCP_OKTA_ISSUER", "https://acme.okta.com/oauth2/default"),
            ("MCP_OKTA_AUDIENCE", "x"),
            ("MCP_OKTA_CLOCK_SKEW_SECONDS", "3600"),
        ]));
        assert!(skew.unwrap_err().contains("skew"));

        let overrides = OktaSettings::from_config(&config(&[
            ("MCP_OKTA_ISSUER", "https://acme.okta.com/oauth2/default"),
            ("MCP_OKTA_AUDIENCE", "x"),
            ("MCP_OKTA_JWKS_URL", "https://keys.example/jwks"),
            ("MCP_OKTA_GROUPS_CLAIM", "roles"),
            ("MCP_OKTA_CLOCK_SKEW_SECONDS", "10"),
            ("MCP_TENANT", "acme"),
        ]))
        .unwrap();
        assert_eq!(overrides.jwks_url, "https://keys.example/jwks");
        assert_eq!(overrides.groups_claim, "roles");
        assert_eq!(overrides.clock_skew, Duration::from_secs(10));
        assert_eq!(overrides.tenant, "acme");
    }
}

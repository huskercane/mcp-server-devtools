//! `TokenValidator` port: an inbound bearer token becomes a validated
//! [`Principal`], or a categorized rejection (plan §3.1, WP A.1).
//!
//! The port is the inbound trust boundary of enterprise mode. Everything on
//! the other side of it — the HTTP middleware, `call_tool`, policy, audit —
//! sees a `Principal` carrying validated claims and never the raw token
//! (guiding constraint 4: no token passthrough). That is enforced by shape:
//! nothing here can return, store, or format the token.
//!
//! ## Two implementations from day one
//!
//! - `crate::auth::okta::OktaJwksValidator` — RS256 JWTs against the identity provider's
//!   JWKS, with key caching, rotation, and clock-skew tolerance.
//! - [`StaticValidator`] — a fixed token → principal table for tests and
//!   local development. It is deliberately **not** reachable from
//!   `MCP_AUTH_MODE`: a shared static bearer read from the environment is
//!   exactly the credential model the product exists to replace, so it can
//!   only be wired programmatically (`ServerBuilder`, test harnesses).
//!
//! ## Nothing about the token in logs
//!
//! [`TokenRejection`] is a closed set of categories with no payload that
//! could carry token material. Its `Display` is the category name, which is
//! what the middleware logs and what the `WWW-Authenticate` challenge
//! describes. A validator that wants to explain more does so in its own
//! tracing at `debug`, without the token.
//!
//! Consumed as `Arc<dyn TokenValidator>`: one call per HTTP request, on a
//! path that already parses headers and may do a JWKS fetch; vtable
//! dispatch is noise there, and a generic parameter would ripple through the
//! axum router types (the documented deviation from ports-prefer-generics).

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use sha2::{Digest as _, Sha256};

use crate::policy::Principal;

/// Why a token was not accepted. Categories only — never the token, never
/// a claim value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenRejection {
    /// Not a JWT, or not one this validator can parse.
    Malformed,
    /// The signature did not verify against the key it names.
    InvalidSignature,
    /// `exp` is in the past (beyond the configured skew).
    Expired,
    /// `nbf` is in the future (beyond the configured skew).
    NotYetValid,
    /// `iss` is not the configured issuer.
    WrongIssuer,
    /// `aud` does not contain the configured audience.
    WrongAudience,
    /// The `kid` names no key the identity provider currently publishes.
    UnknownKey,
    /// `alg` is not one this validator accepts (`none`, HMAC, …).
    UnsupportedAlgorithm,
    /// A claim the principal model needs is absent.
    MissingClaim(&'static str),
    /// The validator could not obtain signing keys at all and holds none;
    /// the token may be fine, but nothing can be said about it. Fail closed.
    KeysUnavailable,
    /// The validator does not recognise the token at all (static tables).
    Unknown,
    /// The token validated, but the revocation list names its subject,
    /// its id, or its issue time (WP B.4).
    Revoked,
}

impl TokenRejection {
    /// Stable, secret-free label for logs, metrics, and the
    /// `WWW-Authenticate` challenge.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::InvalidSignature => "invalid_signature",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::WrongIssuer => "wrong_issuer",
            Self::WrongAudience => "wrong_audience",
            Self::UnknownKey => "unknown_key",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::MissingClaim(_) => "missing_claim",
            Self::KeysUnavailable => "keys_unavailable",
            Self::Unknown => "unknown_token",
            Self::Revoked => "revoked",
        }
    }

    /// Whether the failure is on the server's side (no keys) rather than
    /// the token's. The middleware answers 503 rather than 401 for these:
    /// telling a client its valid token is invalid would be false, and would
    /// send it off to re-authenticate for nothing.
    #[must_use]
    pub const fn is_server_side(&self) -> bool {
        matches!(self, Self::KeysUnavailable)
    }
}

impl fmt::Display for TokenRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

/// The future [`TokenValidator::validate`] returns.
pub type ValidateFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Principal, TokenRejection>> + Send + 'a>>;

/// The future [`TokenValidator::authenticate`] returns.
pub type AuthenticateFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Authenticated, TokenRejection>> + Send + 'a>>;

/// Facts about the token itself that revocation needs (plan §3.6, WP B.4)
/// and that are **not** part of the principal: they describe one credential,
/// not the person. Never the token, never a signature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenFacts {
    /// `iat`, seconds since the Unix epoch, when the token carries it. A
    /// `revoke all` cut-off and the fresh-token rule for writes compare
    /// against this; a token without it fails both, closed.
    pub issued_at: Option<u64>,
    /// `jti`, when the token carries it. What a per-token revocation names.
    pub token_id: Option<String>,
}

/// A validated token: who it proves, and the facts about the token that
/// revocation checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    pub principal: Principal,
    pub token: TokenFacts,
}

/// Turns a bearer token into a validated principal.
pub trait TokenValidator: Send + Sync {
    /// Validate `token` and return the principal it proves.
    ///
    /// Implementations must never log, store, or return the token. Async
    /// because a first validation may need to fetch signing keys.
    fn validate<'a>(&'a self, token: &'a str) -> ValidateFuture<'a>;

    /// Validate `token` and return the principal together with the
    /// [`TokenFacts`] revocation needs. The default wraps
    /// [`Self::validate`] with empty facts, which a revocation list
    /// treats as "undatable": fine for a validator with no notion of
    /// issue time, wrong for one that has it — so a real validator
    /// overrides this.
    fn authenticate<'a>(&'a self, token: &'a str) -> AuthenticateFuture<'a> {
        Box::pin(async move {
            Ok(Authenticated {
                principal: self.validate(token).await?,
                token: TokenFacts::default(),
            })
        })
    }

    /// Drop every cached validation, so the next request revalidates from
    /// scratch. Called when the revocation list changes; a validator with
    /// no cache has nothing to do.
    fn forget_validated(&self) {}
}

/// Fixed token → principal table for tests and local development.
///
/// Tokens are held only as SHA-256 digests, so the table itself never
/// contains a bearer value, and the lookup compares digests rather than the
/// secret bytes. This is a test seam with a documented shape, not a
/// production validator: it has no expiry, no issuer, and no rotation.
#[derive(Debug, Default)]
pub struct StaticValidator {
    by_digest: HashMap<[u8; 32], Authenticated>,
}

impl StaticValidator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept `token` as `principal`, with no token facts.
    #[must_use]
    pub fn with(self, token: &str, principal: Principal) -> Self {
        self.with_facts(token, principal, TokenFacts::default())
    }

    /// Accept `token` as `principal`, carrying `facts` (an issue time, a
    /// token id) for revocation tests.
    #[must_use]
    pub fn with_facts(mut self, token: &str, principal: Principal, facts: TokenFacts) -> Self {
        self.by_digest.insert(
            digest(token),
            Authenticated {
                principal,
                token: facts,
            },
        );
        self
    }

    fn lookup(&self, token: &str) -> Result<Authenticated, TokenRejection> {
        self.by_digest
            .get(&digest(token))
            .cloned()
            .ok_or(TokenRejection::Unknown)
    }
}

impl TokenValidator for StaticValidator {
    fn validate<'a>(&'a self, token: &'a str) -> ValidateFuture<'a> {
        Box::pin(std::future::ready(
            self.lookup(token)
                .map(|authenticated| authenticated.principal),
        ))
    }

    fn authenticate<'a>(&'a self, token: &'a str) -> AuthenticateFuture<'a> {
        Box::pin(std::future::ready(self.lookup(token)))
    }
}

/// SHA-256 of a token: the only form in which a validator may key on it.
#[must_use]
pub fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PrincipalAuthority;

    fn principal(subject: &str) -> Principal {
        Principal {
            tenant: "acme".to_owned(),
            subject: subject.to_owned(),
            groups: vec!["SRE".to_owned()],
            scopes: vec!["mcp:tools".to_owned()],
            authority: PrincipalAuthority::Okta,
        }
    }

    #[tokio::test]
    async fn static_validator_maps_known_tokens_and_rejects_the_rest() {
        let validator = StaticValidator::new().with("tok-alice", principal("alice"));
        assert_eq!(
            validator.validate("tok-alice").await.unwrap().subject,
            "alice"
        );
        assert_eq!(
            validator.validate("tok-bob").await.unwrap_err(),
            TokenRejection::Unknown
        );
        // The table holds digests, not tokens.
        assert!(!format!("{validator:?}").contains("tok-alice"));
    }

    #[test]
    fn rejections_display_only_a_category() {
        for rejection in [
            TokenRejection::Malformed,
            TokenRejection::InvalidSignature,
            TokenRejection::Expired,
            TokenRejection::NotYetValid,
            TokenRejection::WrongIssuer,
            TokenRejection::WrongAudience,
            TokenRejection::UnknownKey,
            TokenRejection::UnsupportedAlgorithm,
            TokenRejection::MissingClaim("sub"),
            TokenRejection::KeysUnavailable,
            TokenRejection::Unknown,
        ] {
            let text = rejection.to_string();
            assert!(!text.is_empty());
            assert!(
                text.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "{text}"
            );
        }
        assert!(TokenRejection::KeysUnavailable.is_server_side());
        assert!(!TokenRejection::Expired.is_server_side());
    }
}

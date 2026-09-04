//! Inbound bearer authentication for the HTTP transport (plan §3.7, WPs A.2
//! and A.3).
//!
//! An axum middleware that turns `Authorization: Bearer …` into a validated
//! [`Principal`](crate::policy::Principal) in the request extensions — which rmcp carries into
//! `call_tool` (`docs/spikes/rmcp-extensions.md`) — and the RFC 9728
//! protected-resource metadata document that tells a client *where* to get
//! such a token.
//!
//! ## Responses
//!
//! | Situation | Status | `WWW-Authenticate` |
//! |---|---|---|
//! | No bearer, or not a bearer scheme | 401 | `Bearer realm=…, resource_metadata=…` |
//! | Token rejected by the validator | 401 | `… error="invalid_token", error_description="<category>"` |
//! | Validator has no signing keys | 503 | — (the token may be fine) |
//! | Token valid but lacks the required scope | 403 | `… error="insufficient_scope", scope="<required>"` |
//! | Token valid but revoked (WP B.4) | 401 | `… error="invalid_token", error_description="revoked"` |
//!
//! The revocation check runs **after** validation and regardless of the
//! validated-token cache, so a revocation takes effect at the next request
//! once the list has been reloaded; each refusal is a `revoked_token_rejected`
//! control record in the audit journal (bounded append, category-only
//! logging). The [`Principal`](crate::policy::Principal) and the
//! [`TokenFacts`] go into the request extensions together, so `call_tool`
//! can apply the fresh-token rule for writes (§3.6).
//!
//! `resource_metadata` points at `/.well-known/oauth-protected-resource` on
//! the configured public URL, as RFC 9728 §5.1 specifies, so an MCP client
//! that receives the 401 can discover the authorization server.
//!
//! ## Nothing about the token in logs
//!
//! The token is read from the header, handed to the validator, and dropped.
//! Rejections are logged as their category only. Error bodies carry the
//! category, never the token or any claim value.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tracing::warn;

use crate::auth::revocation::{RevocationList, RevocationReason};
use crate::policy::BundleAudit;
use crate::policy::bundle::BundleDocument as _;
use crate::ports::audit_sink::{AuditFailure, ControlEvent, ControlEventKind};
use crate::ports::{Authenticated, TokenRejection, TokenValidator};

/// RFC 9728 well-known path.
pub const PROTECTED_RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

/// Config key: the URL clients reach this server at, through the ingress.
/// It is the RFC 9728 `resource` identifier and the base of the
/// `resource_metadata` URL in every challenge. Required in enterprise mode.
pub const PUBLIC_URL_KEY: &str = "MCP_PUBLIC_URL";

/// Config key: the scope a token must carry to call tools. Defaults to
/// [`DEFAULT_REQUIRED_SCOPE`].
pub const REQUIRED_SCOPE_KEY: &str = "MCP_REQUIRED_SCOPE";

/// The scope required for `/mcp` unless configured otherwise.
pub const DEFAULT_REQUIRED_SCOPE: &str = "mcp:tools";

/// The realm named in every challenge.
const REALM: &str = "mcp-devtools";

/// Everything the middleware and the metadata document need.
#[derive(Debug, Clone)]
pub struct InboundAuthSettings {
    /// The resource identifier (RFC 9728 `resource`), no trailing slash.
    pub public_url: String,
    /// Issuer URLs of the authorization servers that mint accepted tokens.
    pub authorization_servers: Vec<String>,
    /// The scope every tool call needs.
    pub required_scope: String,
}

impl InboundAuthSettings {
    /// Read the public URL and required scope from configuration.
    ///
    /// # Errors
    ///
    /// When `MCP_PUBLIC_URL` is absent or not an `https` (or loopback
    /// `http`) URL. A challenge that points clients at an unreachable or
    /// plaintext metadata URL is worse than no challenge.
    pub fn from_config(
        config: &crate::config::Config,
        auth_mode: &str,
        authorization_servers: Vec<String>,
    ) -> Result<Self, String> {
        let public_url = config
            .get(PUBLIC_URL_KEY)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!(
                    "{PUBLIC_URL_KEY} is required when MCP_AUTH_MODE={auth_mode}: it is the \
                     RFC 9728 resource identifier clients are told to obtain a token for"
                )
            })?
            .trim_end_matches('/')
            .to_owned();
        let parsed = url::Url::parse(&public_url)
            .map_err(|error| format!("{PUBLIC_URL_KEY} is not a URL: {error}"))?;
        let loopback = match parsed.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            None => false,
        };
        if !(parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback)) {
            return Err(format!(
                "{PUBLIC_URL_KEY} must be an https URL (or http on loopback)"
            ));
        }
        let required_scope = config
            .get(REQUIRED_SCOPE_KEY)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_REQUIRED_SCOPE)
            .to_owned();
        Ok(Self {
            public_url,
            authorization_servers,
            required_scope,
        })
    }

    fn metadata_url(&self) -> String {
        format!("{}{PROTECTED_RESOURCE_METADATA_PATH}", self.public_url)
    }
}

/// The middleware's state: a validator, the settings, and — in enterprise
/// mode — the revocation list and where to journal refusals.
pub struct InboundAuth {
    validator: Arc<dyn TokenValidator>,
    settings: InboundAuthSettings,
    revocations: Option<Arc<RevocationList>>,
    audit: Option<BundleAudit>,
    /// Per-principal rate limit (C.6), applied after validation and the
    /// scope check.
    rate_limit: Option<Arc<super::rate_limit::RateLimiter>>,
}

impl InboundAuth {
    #[must_use]
    pub fn new(validator: Arc<dyn TokenValidator>, settings: InboundAuthSettings) -> Self {
        Self {
            validator,
            settings,
            revocations: None,
            audit: None,
            rate_limit: None,
        }
    }

    /// Enforce a per-principal rate limit (C.6).
    #[must_use]
    pub fn with_rate_limit(mut self, limiter: Arc<super::rate_limit::RateLimiter>) -> Self {
        self.rate_limit = Some(limiter);
        self
    }

    /// The limiter, if one is enforced.
    #[must_use]
    pub fn rate_limiter(&self) -> Option<&Arc<super::rate_limit::RateLimiter>> {
        self.rate_limit.as_ref()
    }

    /// Enforce `list` after validation (WP B.4).
    #[must_use]
    pub fn with_revocations(mut self, list: Arc<RevocationList>) -> Self {
        self.revocations = Some(list);
        self
    }

    /// Journal revoked-token refusals (and, through the list's watcher,
    /// revocation-list changes) to `audit`.
    #[must_use]
    pub fn with_audit(mut self, audit: BundleAudit) -> Self {
        self.audit = Some(audit);
        self
    }

    #[must_use]
    pub fn settings(&self) -> &InboundAuthSettings {
        &self.settings
    }

    #[must_use]
    pub fn validator(&self) -> &Arc<dyn TokenValidator> {
        &self.validator
    }

    #[must_use]
    pub fn revocations(&self) -> Option<&Arc<RevocationList>> {
        self.revocations.as_ref()
    }

    #[must_use]
    pub fn audit(&self) -> Option<&BundleAudit> {
        self.audit.as_ref()
    }

    /// Append the `revocation_loaded` record for the list in force (WP
    /// B.4), before the port is bound. A no-op without a list or a journal.
    ///
    /// # Errors
    ///
    /// When the record could not be made durable: the server must not
    /// start, for the same reason as [`crate::tools::DevtoolsServer::journal_startup`].
    pub async fn journal_startup(&self) -> std::io::Result<()> {
        let (Some(list), Some(audit)) = (&self.revocations, &self.audit) else {
            return Ok(());
        };
        list.journal_in_force(audit).await.map(drop)
    }

    /// Whether the revocation list refuses `authenticated`, and why.
    fn revocation(&self, authenticated: &Authenticated) -> Option<(RevocationReason, String)> {
        let list = self.revocations.as_ref()?;
        let snapshot = list.snapshot();
        snapshot
            .document
            .check(authenticated)
            .map(|reason| (reason, snapshot.document.version().to_owned()))
    }

    /// Journal a refused revoked token. The refusal happens either way;
    /// the record not being durable is loud but changes nothing.
    async fn journal_revoked(
        &self,
        authenticated: &Authenticated,
        reason: RevocationReason,
        list_version: String,
    ) {
        let Some(audit) = &self.audit else {
            return;
        };
        let mut event =
            ControlEvent::now(ControlEventKind::RevokedTokenRejected).with_reason(reason.as_str());
        event.principal = Some(authenticated.principal.clone());
        event.version = Some(list_version);
        if let Err(error) = crate::policy::egress::append_control_bounded(
            audit.sink.as_ref(),
            &event,
            audit.append_timeout,
        )
        .await
        {
            tracing::error!(
                failure = %AuditFailure::classify(&error),
                "failed to journal a revoked-token refusal"
            );
        }
    }

    /// The RFC 9728 document, as JSON.
    #[must_use]
    pub fn protected_resource_metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "resource": self.settings.public_url,
            "authorization_servers": self.settings.authorization_servers,
            "scopes_supported": [self.settings.required_scope],
            "bearer_methods_supported": ["header"],
            "resource_name": REALM,
        })
    }
}

/// Serve the RFC 9728 metadata. Unauthenticated by design: it is how a
/// client without a token learns where to get one.
pub async fn protected_resource_metadata(State(auth): State<Arc<InboundAuth>>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=300"),
            ),
        ],
        auth.protected_resource_metadata().to_string(),
    )
        .into_response()
}

/// Require a valid bearer token with the configured scope; on success the
/// [`Principal`](crate::policy::Principal) is in the request extensions for
/// everything downstream.
pub async fn require_bearer(
    State(auth): State<Arc<InboundAuth>>,
    mut request: Request,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token);
    let Some(token) = token else {
        return auth.challenge(
            StatusCode::UNAUTHORIZED,
            None,
            "unauthorized",
            "a bearer token is required",
        );
    };

    let authenticated = match auth.validator.authenticate(token).await {
        Ok(authenticated) => authenticated,
        Err(rejection) if rejection.is_server_side() => {
            warn!(rejection = %rejection, "cannot validate bearer tokens; refusing (503)");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )],
                r#"{"error":"authentication_unavailable","error_description":"signing keys unavailable"}"#,
            )
                .into_response();
        }
        Err(rejection) => {
            warn!(rejection = %rejection, "rejected bearer token");
            let description = rejection_description(&rejection);
            return auth.challenge(
                StatusCode::UNAUTHORIZED,
                Some(("invalid_token", rejection)),
                "invalid_token",
                description,
            );
        }
    };

    // WP B.4: the list is consulted on every request, cached validation or
    // not, so revocation does not wait for a cache miss.
    if let Some((reason, list_version)) = auth.revocation(&authenticated) {
        warn!(
            rejection = "revoked",
            revoked_by = reason.as_str(),
            "rejected a revoked bearer token"
        );
        auth.journal_revoked(&authenticated, reason, list_version)
            .await;
        return auth.challenge(
            StatusCode::UNAUTHORIZED,
            Some(("invalid_token", TokenRejection::Revoked)),
            "invalid_token",
            "the token has been revoked",
        );
    }

    let Authenticated {
        principal,
        token: facts,
    } = authenticated;
    if !principal
        .scopes
        .iter()
        .any(|scope| scope == &auth.settings.required_scope)
    {
        // Category only. The subject is a validated claim and belongs in the
        // audit journal, which is the evidence pipeline; the operator log is
        // not, so no token-derived value goes here.
        warn!(
            rejection = "insufficient_scope",
            "bearer token lacks the required scope (403)"
        );
        return auth.insufficient_scope();
    }

    // C.6: a validated, in-scope principal past its budget is refused
    // with a retry hint. Category only in the log, as above.
    if let Some(limiter) = &auth.rate_limit
        && let super::rate_limit::Verdict::Refuse { retry_after_secs } =
            limiter.check(&principal.subject)
    {
        warn!(
            rejection = "rate_limited",
            "principal over its rate limit (429)"
        );
        return rate_limited(retry_after_secs);
    }

    request.extensions_mut().insert(principal);
    request.extensions_mut().insert(facts);
    next.run(request).await
}

impl InboundAuth {
    fn base_challenge(&self) -> String {
        format!(
            "Bearer realm=\"{REALM}\", resource_metadata=\"{}\"",
            self.settings.metadata_url()
        )
    }

    fn challenge(
        &self,
        status: StatusCode,
        error: Option<(&str, TokenRejection)>,
        body_error: &str,
        body_description: &str,
    ) -> Response {
        let mut challenge = self.base_challenge();
        if let Some((code, rejection)) = error {
            use std::fmt::Write as _;
            let _ = write!(
                challenge,
                ", error=\"{code}\", error_description=\"{}\"",
                rejection.category()
            );
        }
        error_response(status, &challenge, body_error, body_description)
    }

    fn insufficient_scope(&self) -> Response {
        let challenge = format!(
            "{}, error=\"insufficient_scope\", scope=\"{}\"",
            self.base_challenge(),
            self.settings.required_scope
        );
        error_response(
            StatusCode::FORBIDDEN,
            &challenge,
            "insufficient_scope",
            "the token does not carry the scope required for this resource",
        )
    }
}

/// `429 Too Many Requests` with `Retry-After`, in the JSON envelope the
/// other refusals use.
fn rate_limited(retry_after_secs: u64) -> Response {
    let body = serde_json::json!({
        "error": "rate_limited",
        "error_description": "the principal has exceeded its request rate; retry after the indicated delay",
    })
    .to_string();
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                header::RETRY_AFTER,
                HeaderValue::from_str(&retry_after_secs.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("1")),
            ),
        ],
        body,
    )
        .into_response()
}

fn error_response(status: StatusCode, challenge: &str, error: &str, description: &str) -> Response {
    let body = serde_json::json!({
        "error": error,
        "error_description": description,
    })
    .to_string();
    let challenge = HeaderValue::from_str(challenge)
        .unwrap_or_else(|_| HeaderValue::from_static("Bearer realm=\"mcp-devtools\""));
    (
        status,
        [
            (header::WWW_AUTHENTICATE, challenge),
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
        ],
        body,
    )
        .into_response()
}

/// A human-readable description that names the category, and nothing else.
fn rejection_description(rejection: &TokenRejection) -> &'static str {
    match rejection {
        TokenRejection::Expired => "the token has expired",
        TokenRejection::NotYetValid => "the token is not yet valid",
        TokenRejection::WrongIssuer => "the token was not issued by the configured issuer",
        TokenRejection::WrongAudience => "the token is not intended for this resource",
        TokenRejection::UnknownKey => "the token is signed with a key this server does not know",
        TokenRejection::UnsupportedAlgorithm => "the token uses an unsupported algorithm",
        TokenRejection::InvalidSignature => "the token signature did not verify",
        TokenRejection::MissingClaim(_) => "the token is missing a required claim",
        TokenRejection::Revoked => "the token has been revoked",
        _ => "the token was not accepted",
    }
}

/// `Bearer <token>` → `<token>`. Scheme matching is case-insensitive per RFC
/// 6750; an empty token is treated as absent.
fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, rest) = value.trim().split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
    (!token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_scheme_is_case_insensitive_and_empty_tokens_are_absent() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("bearer   abc  "), Some("abc"));
        assert_eq!(bearer_token("BEARER abc"), Some("abc"));
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("Bearer"), None);
        assert_eq!(bearer_token("Bearer "), None);
        assert_eq!(bearer_token(""), None);
    }

    #[test]
    fn settings_require_a_public_https_url_and_default_the_scope() {
        let config = |pairs: &[(&str, &str)]| {
            crate::config::Config::from_map(
                pairs
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect(),
            )
        };
        let settings = InboundAuthSettings::from_config(
            &config(&[("MCP_PUBLIC_URL", "https://mcp.acme.example/")]),
            "okta",
            vec!["https://acme.okta.com/oauth2/default".to_owned()],
        )
        .unwrap();
        assert_eq!(settings.public_url, "https://mcp.acme.example");
        assert_eq!(settings.required_scope, DEFAULT_REQUIRED_SCOPE);
        assert_eq!(
            settings.metadata_url(),
            "https://mcp.acme.example/.well-known/oauth-protected-resource"
        );

        let missing =
            InboundAuthSettings::from_config(&config(&[]), "oidc", Vec::new()).unwrap_err();
        assert!(missing.contains("MCP_AUTH_MODE=oidc"), "{missing}");
        assert!(
            InboundAuthSettings::from_config(
                &config(&[("MCP_PUBLIC_URL", "http://mcp.acme.example")]),
                "okta",
                Vec::new()
            )
            .is_err()
        );
        let loopback = InboundAuthSettings::from_config(
            &config(&[
                ("MCP_PUBLIC_URL", "http://127.0.0.1:3000"),
                ("MCP_REQUIRED_SCOPE", "mcp:read"),
            ]),
            "okta",
            Vec::new(),
        )
        .unwrap();
        assert_eq!(loopback.required_scope, "mcp:read");
    }
}

//! Mend Platform API 3.0 credential bootstrap and token cache.
//!
//! Login returns a refresh token; `/api/v3.0/login/accessToken` exchanges it
//! with `wss-refresh-token` and the configured organization for an access JWT.
//! Access expiry uses `tokenTTL` milliseconds (ten-minute fallback); the refresh
//! token is renewed conservatively after 25 minutes. Direct-JWT login responses
//! are accepted for compatibility. Tokens are scoped by base URL, email,
//! organization and credential fingerprint. The async write lock deliberately
//! spans bounded credential bootstrap to collapse concurrent refreshes.
//!
//! Bootstrap bypasses response caching and artifact persistence. Bodies are
//! capped at 64 KiB and errors never echo credentials or upstream auth bodies.

use std::time::{Duration, Instant};

use http::StatusCode;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::RwLock;

use crate::error::{McpError, api_error, auth_invalid, unexpected};
use crate::transport::HttpClient;

/// Renew this far ahead of Mend's reported expiry.
const EXPIRY_SKEW: Duration = Duration::from_mins(1);

/// Conservative refresh-token lifetime; renew before the documented 30 minutes.
const DEFAULT_TTL: Duration = Duration::from_mins(25);

/// Identity a cached JWT is valid for. A change in any field invalidates the
/// cache — defends a long-lived vendor instance against config reloads and
/// keeps test login-servers from bleeding state into one another.
///
/// The user key is represented as a non-reversible fingerprint, not the raw
/// value: rotating the key must invalidate the cached JWT, but the plaintext
/// key should never live in this struct — that keeps it out of the derived
/// `Debug` and out of memory beyond the login call.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TokenKey {
    base: String,
    email: String,
    org_uuid: String,
    user_key_fp: [u8; 32],
}

/// Credential fingerprint for cache isolation without retaining the user key.
fn secret_fingerprint(secret: &str) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(secret.as_bytes()).into()
}

struct Cached {
    key: TokenKey,
    token: String,
    /// Monotonic deadline (`Instant`, not wall-clock) so the TTL is immune to
    /// system-clock adjustments.
    expires_at: Instant,
    refresh_token: Option<String>,
    refresh_expires_at: Instant,
}

impl std::fmt::Debug for Cached {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Cached")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Per-vendor-instance JWT cache.
#[derive(Debug, Default)]
pub struct TokenCache {
    inner: RwLock<Option<Cached>>,
}

/// Wire shape of the login request. Field names are Mend's.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginRequest<'a> {
    email: &'a str,
    user_key: &'a str,
    org_uuid: &'a str,
}

impl TokenCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a valid JWT for the given identity, logging in only when the
    /// cache is empty, scoped to a different identity, or within
    /// [`EXPIRY_SKEW`] of expiry.
    pub async fn bearer(
        &self,
        client: &HttpClient,
        base: &str,
        email: &str,
        org_uuid: &str,
        user_key: &str,
    ) -> Result<String, McpError> {
        let key = TokenKey {
            base: base.to_owned(),
            email: email.to_owned(),
            org_uuid: org_uuid.to_owned(),
            user_key_fp: secret_fingerprint(user_key),
        };

        // Fast path: shared read lock, no login.
        {
            let guard = self.inner.read().await;
            if let Some(c) = guard.as_ref()
                && c.key == key
                && Instant::now() < c.expires_at
            {
                return Ok(c.token.clone());
            }
        }

        // Slow path: exclusive write lock. Re-check first — a concurrent
        // caller may have logged in while we waited for the lock, so only one
        // login happens per expiry window (no stampede).
        let mut guard = self.inner.write().await;
        if let Some(c) = guard.as_ref()
            && c.key == key
            && Instant::now() < c.expires_at
        {
            return Ok(c.token.clone());
        }

        let fresh = if let Some(cached) = guard.as_ref()
            && cached.key == key
            && Instant::now() < cached.refresh_expires_at
            && let Some(refresh_token) = cached.refresh_token.as_deref()
        {
            Some(refresh(client, &key, refresh_token).await)
        } else {
            None
        };
        let (token, ttl, refresh_token, refresh_expires_at) = match fresh {
            Some(Ok((token, ttl, rotated))) => {
                let cached = guard.as_ref().expect("refresh requires cached identity");
                (
                    token,
                    ttl,
                    rotated.or_else(|| cached.refresh_token.clone()),
                    cached.refresh_expires_at,
                )
            }
            Some(Err(error)) if !matches!(error.status_code, Some(401 | 403)) => return Err(error),
            _ => login(client, &key, user_key).await?,
        };
        // Subtract the skew; never let the effective lifetime hit zero even if
        // Mend returns an implausibly short TTL.
        let effective = ttl.saturating_sub(EXPIRY_SKEW).max(Duration::from_secs(1));
        *guard = Some(Cached {
            key,
            token: token.clone(),
            expires_at: Instant::now() + effective,
            refresh_token,
            refresh_expires_at,
        });
        Ok(token)
    }
}

/// Perform the login exchange. Returns the JWT and Mend's reported lifetime
/// (skew is applied by the caller).
async fn login(
    client: &HttpClient,
    key: &TokenKey,
    user_key: &str,
) -> Result<(String, Duration, Option<String>, Instant), McpError> {
    let url = format!("{}{}", key.base, super::LOGIN_PATH);
    let body = LoginRequest {
        email: &key.email,
        user_key,
        org_uuid: &key.org_uuid,
    };
    let call = crate::transport::HttpCallLog::new("mend-login", "POST", &url);
    let response = client
        .post(&url)
        .timeout(Duration::from_secs(30))
        .header(http::header::ACCEPT, "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            crate::transport::log_http_transport_failure(call, &e, false);
            api_error(format!("Mend login request failed: {e}"), None, None)
        })?;

    let status = response.status();
    let policy = crate::transport::StreamingPolicy::new(64 * 1024, 64 * 1024);
    let body = crate::transport::bounded_body(
        response,
        &policy,
        tokio::time::Instant::now() + Duration::from_secs(30),
    )
    .await?;
    if !status.is_success() {
        crate::transport::log_http_status_failure(call, status, false);
        return Err(classify_login_error(status, &body));
    }

    // The successful body carries the JWT, so it is deliberately never
    // attached to an error's `original` or logged.
    let parsed: Value = serde_json::from_str(&body)
        .map_err(|e| unexpected(format!("Mend login response was not valid JSON: {e}"), None))?;
    if let Some(refresh_token) = login_field(&parsed, "refreshToken")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
    {
        let (token, ttl, rotated) = refresh(client, key, refresh_token).await?;
        return Ok((
            token,
            ttl,
            Some(rotated.unwrap_or_else(|| refresh_token.to_owned())),
            Instant::now() + DEFAULT_TTL,
        ));
    }
    let token = login_field(&parsed, "jwtToken")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            unexpected(
                "Mend login response did not carry a JWT at retVal.jwtToken, \
                 response.jwtToken or jwtToken.",
                None,
            )
        })?
        .to_owned();
    let ttl = login_field(&parsed, "jwtTTL")
        .and_then(Value::as_u64)
        .map_or(Duration::from_mins(10), Duration::from_millis);
    Ok((token, ttl, None, Instant::now()))
}

/// Refresh is credential bootstrap, never response-cached or artifact-persisted.
async fn refresh(
    client: &HttpClient,
    key: &TokenKey,
    refresh_token: &str,
) -> Result<(String, Duration, Option<String>), McpError> {
    let mut url = url::Url::parse(&format!("{}{}", key.base, super::LOGIN_REFRESH_PATH))
        .map_err(|_| api_error("Invalid Mend API base", Some(400), None))?;
    url.query_pairs_mut().append_pair("orgUuid", &key.org_uuid);
    let response = client
        .post(url.as_str())
        .header("wss-refresh-token", refresh_token)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|_| api_error("Mend refresh request failed", Some(502), None))?;
    let status = response.status();
    let policy = crate::transport::StreamingPolicy::new(64 * 1024, 64 * 1024);
    let body = crate::transport::bounded_body(
        response,
        &policy,
        tokio::time::Instant::now() + Duration::from_secs(30),
    )
    .await?;
    if !status.is_success() {
        return Err(classify_login_error(status, &body));
    }
    let parsed: Value = serde_json::from_str(&body)
        .map_err(|_| unexpected("Invalid Mend refresh response", None))?;
    let token = login_field(&parsed, "jwtToken")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| unexpected("Mend refresh response has no jwtToken", None))?
        .to_owned();
    let ttl = login_field(&parsed, "tokenTTL")
        .or_else(|| login_field(&parsed, "jwtTTL"))
        .and_then(Value::as_u64)
        .map_or(Duration::from_secs(600), Duration::from_millis);
    let rotated = login_field(&parsed, "refreshToken")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_owned);
    Ok((token, ttl, rotated))
}

/// Locate `field` in the login response, tolerating the wrapper variants the
/// public docs leave open: `retVal.<field>`, `response.<field>` or a
/// top-level `<field>`.
fn login_field<'a>(value: &'a Value, field: &str) -> Option<&'a Value> {
    value
        .get("retVal")
        .and_then(|v| v.get(field))
        .or_else(|| value.get("response").and_then(|v| v.get(field)))
        .or_else(|| value.get(field))
}

/// Map a failed login to a typed error. The envelope is the same as the API's
/// (`errorMessage` / `message` / `error`, plus a `supportToken`), so the
/// vendor's parser is reused; only the wording and the status mapping differ
/// (a rejected login is an `auth_invalid` naming the three inputs).
fn classify_login_error(status: StatusCode, _body: &str) -> McpError {
    let mut error = if matches!(status.as_u16(), 401 | 403) {
        auth_invalid(
            "Mend login rejected the credentials; check MEND_EMAIL, MEND_USER_KEY, MEND_ORG_UUID and MEND_API_BASE",
        )
    } else {
        api_error(
            "Mend authentication exchange failed",
            Some(status.as_u16()),
            None,
        )
    };
    error.status_code = Some(status.as_u16());
    error
}

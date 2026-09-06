//! The authorization-code + PKCE flow (ADR-013): where the browser is sent,
//! and how the code that comes back is turned into the bearer the admin
//! API will see. The console never mints a token and never sees a client
//! secret: it is a public client, and the proof is the PKCE verifier.
//!
//! Nothing in this module logs or returns a token: errors are categories.

use std::time::Duration;

use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::ConsoleSettings;
use crate::auth::oidc::{AuthorizationEndpoints, Profile};

/// Token endpoint timeout: covers connect, send, and the body.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest token response accepted.
const EXCHANGE_MAX_BYTES: usize = 64 * 1024;
/// Session lifetime bounds around the provider's `expires_in`.
const MIN_SESSION_TTL: Duration = Duration::from_mins(1);
const MAX_SESSION_TTL: Duration = Duration::from_hours(12);
const DEFAULT_SESSION_TTL: Duration = Duration::from_hours(1);

/// A PKCE pair (RFC 7636, `S256`).
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// A fresh verifier (43 url-safe characters from 32 random bytes) and its
/// challenge.
#[must_use]
pub fn pkce() -> Pkce {
    let verifier = super::session::random_id();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    Pkce {
        verifier,
        challenge,
    }
}

/// The authorization request the browser is redirected to.
///
/// No `nonce` is sent: a nonce is only meaningful bound to an ID token, and
/// the console requests none — the administrator's identity comes from the
/// access token, which the admin API validates at its own boundary. A
/// parameter that looks like a check but is never verified is worse than its
/// absence. `openid` stays in the default scopes because providers expect it
/// on an OIDC authorization request.
///
/// The audience the bearer boundary validates is asked for the way each
/// profile expects it: Auth0 as `audience`, Keycloak and spec-shaped
/// providers as RFC 8707 `resource`, Entra through the resource-prefixed
/// scope the operator configures (`MCP_CONSOLE_SCOPES`), Okta through
/// its authorization server's own audience setting.
///
/// # Errors
///
/// When the endpoint the provider advertised is not a URL.
pub fn authorize_url(
    endpoints: &AuthorizationEndpoints,
    settings: &ConsoleSettings,
    state: &str,
    challenge: &str,
) -> Result<String, String> {
    let mut url = url::Url::parse(&endpoints.authorization_endpoint)
        .map_err(|_| "authorization endpoint is not a URL".to_owned())?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &settings.client_id)
            .append_pair("redirect_uri", &settings.redirect_uri())
            .append_pair("scope", &settings.scopes)
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        match settings.profile {
            Profile::Auth0 => {
                query.append_pair("audience", &settings.audience);
            }
            Profile::Keycloak | Profile::Generic => {
                query.append_pair("resource", &settings.audience);
            }
            Profile::Okta | Profile::Entra => {}
        }
    }
    Ok(url.into())
}

/// What a successful exchange yields: the bearer and how long the console
/// may hold it.
pub struct Exchanged {
    pub access_token: String,
    pub ttl: Duration,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<u64>,
}

/// Redeem `code` at the token endpoint with the PKCE verifier.
///
/// # Errors
///
/// A category: the endpoint unreachable or answering non-2xx, a response
/// that is not a bearer token, or a body over the bound.
pub async fn exchange(
    http: &reqwest::Client,
    endpoints: &AuthorizationEndpoints,
    settings: &ConsoleSettings,
    code: &str,
    verifier: &str,
) -> Result<Exchanged, &'static str> {
    let redirect_uri = settings.redirect_uri();
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &redirect_uri),
        ("client_id", &settings.client_id),
        ("code_verifier", verifier),
    ];
    if matches!(settings.profile, Profile::Keycloak | Profile::Generic) {
        form.push(("resource", &settings.audience));
    }
    let mut response = http
        .post(&endpoints.token_endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&form)
        .timeout(EXCHANGE_TIMEOUT)
        .send()
        .await
        .map_err(|_| "token endpoint unreachable")?;
    if !response.status().is_success() {
        return Err("token endpoint refused the code");
    }
    if response
        .content_length()
        .is_some_and(|length| length > EXCHANGE_MAX_BYTES as u64)
    {
        return Err("token response too large");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "token response could not be read")?
    {
        if chunk.len() > EXCHANGE_MAX_BYTES - body.len() {
            return Err("token response too large");
        }
        body.extend_from_slice(&chunk);
    }
    let parsed: TokenResponse =
        serde_json::from_slice(&body).map_err(|_| "token response is not JSON")?;
    if parsed
        .token_type
        .as_deref()
        .is_some_and(|kind| !kind.eq_ignore_ascii_case("bearer"))
    {
        return Err("token response is not a bearer token");
    }
    let access_token = parsed
        .access_token
        .filter(|token| !token.is_empty() && token.len() <= 16 * 1024)
        .ok_or("token response carries no access token")?;
    let ttl = parsed
        .expires_in
        .map_or(DEFAULT_SESSION_TTL, Duration::from_secs)
        .clamp(MIN_SESSION_TTL, MAX_SESSION_TTL);
    Ok(Exchanged { access_token, ttl })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[tokio::test]
    async fn chunked_token_response_is_bounded_before_eof() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10001\r\n")
                .await
                .unwrap();
            stream
                .write_all(&vec![b' '; EXCHANGE_MAX_BYTES + 1])
                .await
                .unwrap();
            stream.write_all(b"\r\n").await.unwrap();
            std::future::pending::<()>().await;
        });
        let settings = ConsoleSettings {
            client_id: "console".into(),
            redirect_path: "/console/callback".into(),
            scopes: "openid mcp:admin".into(),
            issuer: endpoint.clone(),
            audience: endpoint.clone(),
            profile: Profile::Generic,
            public_url: endpoint.clone(),
        };
        let endpoints = AuthorizationEndpoints {
            authorization_endpoint: endpoint.clone(),
            token_endpoint: endpoint,
        };
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            exchange(
                &reqwest::Client::new(),
                &endpoints,
                &settings,
                "code",
                "verifier",
            ),
        )
        .await;
        server.abort();
        assert!(matches!(result, Ok(Err("token response too large"))));
    }
}

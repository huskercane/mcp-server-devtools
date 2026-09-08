//! EMA client-side exchange over trusted issuer metadata. The external
//! authorization server validates the ID-JAG and issues access tokens;
//! this adapter never turns an assertion into a domain principal.
use serde::Deserialize;

pub const EXTENSION: &str = "io.modelcontextprotocol/enterprise-managed-authorization";
pub const GRANT_PROFILE: &str = "urn:ietf:params:oauth:grant-profile:id-jag";
pub const ID_JAG: &str = "urn:ietf:params:oauth:token-type:id-jag";
pub const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
pub const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const LIMIT: usize = 64 * 1024;

/// Explicit operator opt-in; advertising EMA does not make an issuer support it.
/// # Errors
/// Rejects misspelled values instead of silently disabling security configuration.
pub fn enabled(config: &crate::config::Config) -> Result<bool, &'static str> {
    match config.get("MCP_EMA_ENABLED") {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        _ => Err("MCP_EMA_ENABLED must be true or false"),
    }
}

/// HTTPS, or loopback HTTP for local integration tests. No embedded credentials.
/// # Errors
/// Returns a secret-free category on invalid input.
pub fn trusted_url(value: &str) -> Result<url::Url, &'static str> {
    let url = url::Url::parse(value).map_err(|_| "invalid_url")?;
    let local = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && local))
    {
        return Err("invalid_url");
    }
    Ok(url)
}

/// A freshly supplied private-key JWT, or a pre-registered public client.
/// Credentials intentionally have no Debug implementation.
pub struct ClientCredentials<'a> {
    pub client_id: &'a str,
    pub assertion: Option<&'a str>,
}
impl<'a> ClientCredentials<'a> {
    fn apply(&self, form: &mut Vec<(&'static str, &'a str)>) {
        form.push(("client_id", self.client_id));
        if let Some(assertion) = self.assertion {
            form.push((
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ));
            form.push(("client_assertion", assertion));
        }
    }
}

#[derive(Deserialize)]
struct Metadata {
    issuer: String,
    token_endpoint: String,
    #[serde(default)]
    authorization_grant_profiles_supported: Vec<String>,
    #[serde(default)]
    grant_types_supported: Vec<String>,
}

/// No Debug/Serialize: token bytes leave only through the explicit accessor.
pub struct AccessToken(String);
impl AccessToken {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    issued_token_type: Option<String>,
    expires_in: Option<u64>,
}

/// One reusable HTTP adapter for the RFC 8693 and RFC 7523 legs.
/// Redirects and automatic retries are disabled: assertions must never be
/// sent to a redirected endpoint or replayed after an ambiguous response.
pub struct OidcExchange {
    client: reqwest::Client,
}
impl OidcExchange {
    /// # Errors
    /// Returns a category if TLS/client initialization fails.
    pub fn new() -> Result<Self, &'static str> {
        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|_| "http_client_unavailable")?,
        })
    }

    async fn json<T: serde::de::DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, &'static str> {
        let mut response = request.send().await.map_err(|_| "issuer_unavailable")?;
        if !response.status().is_success() {
            return Err("issuer_rejected_request");
        }
        if response
            .content_length()
            .is_some_and(|size| size > LIMIT as u64)
        {
            return Err("issuer_response_too_large");
        }
        let mut bytes = Vec::with_capacity(4096);
        while let Some(chunk) = response.chunk().await.map_err(|_| "issuer_unavailable")? {
            if bytes.len().saturating_add(chunk.len()) > LIMIT {
                return Err("issuer_response_too_large");
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| "invalid_issuer_response")
    }

    /// RFC 8414 path insertion, including issuers with path components.
    async fn metadata(&self, issuer: &str) -> Result<Metadata, &'static str> {
        let mut url = trusted_url(issuer)?;
        let path = format!(
            "/.well-known/oauth-authorization-server{}",
            url.path().trim_end_matches('/')
        );
        url.set_path(&path);
        let metadata: Metadata = self.json(self.client.get(url)).await?;
        if metadata.issuer != issuer {
            return Err("metadata_issuer_mismatch");
        }
        trusted_url(&metadata.token_endpoint)?;
        Ok(metadata)
    }

    /// Confirm the resource AS's normative EMA discovery marker before use.
    /// # Errors
    /// Refuses inaccessible metadata, a different issuer, or unsupported profile.
    pub async fn verify_resource_issuer(&self, issuer: &str) -> Result<(), &'static str> {
        let metadata = self.metadata(issuer).await?;
        Self::require_profile(&metadata)
    }
    fn require_profile(metadata: &Metadata) -> Result<(), &'static str> {
        if !metadata
            .authorization_grant_profiles_supported
            .iter()
            .any(|v| v == GRANT_PROFILE)
            || !metadata
                .grant_types_supported
                .iter()
                .any(|v| v == JWT_BEARER)
        {
            return Err("id_jag_profile_unavailable");
        }
        Ok(())
    }

    /// Run both grants. The final resource server still validates the resulting
    /// access token through `TokenValidator`; this client does not mint tokens.
    /// # Errors
    /// Secret-free errors; issuer response bodies are never propagated.
    pub async fn exchange(
        &self,
        request: &ExchangeRequest<'_>,
    ) -> Result<AccessToken, &'static str> {
        trusted_url(request.resource)?;
        if request.identity_assertion.is_empty()
            || request.identity_assertion.len() > LIMIT
            || request.idp_client.client_id.is_empty()
            || request.resource_client.client_id.is_empty()
        {
            return Err("invalid_exchange_request");
        }
        let idp = self.metadata(request.idp_issuer).await?;
        let resource_as = self.metadata(request.resource_issuer).await?;
        Self::require_profile(&resource_as)?;
        let mut form = Vec::with_capacity(10);
        form.extend([
            ("grant_type", TOKEN_EXCHANGE),
            ("requested_token_type", ID_JAG),
            ("audience", request.resource_issuer),
            ("resource", request.resource),
            ("scope", request.scope),
            ("subject_token", request.identity_assertion),
            ("subject_token_type", request.subject_type.as_str()),
        ]);
        request.idp_client.apply(&mut form);
        let jag: TokenResponse = self
            .json(self.client.post(&idp.token_endpoint).form(&form))
            .await?;
        if jag.issued_token_type.as_deref() != Some(ID_JAG)
            || jag.access_token.is_empty()
            || jag.expires_in == Some(0)
            || !matches!(jag.token_type.as_str(), "N_A" | "Bearer")
        {
            return Err("invalid_id_jag_response");
        }
        // A JWT grant, not a bearer credential for the resource. The resource AS
        // owns signature, audience, client binding and replay checks.
        if jsonwebtoken::decode_header(&jag.access_token)
            .ok()
            .and_then(|h| h.typ)
            .as_deref()
            != Some("oauth-id-jag+jwt")
        {
            return Err("invalid_id_jag_response");
        }
        let mut form = Vec::with_capacity(6);
        form.extend([
            ("grant_type", JWT_BEARER),
            ("assertion", jag.access_token.as_str()),
            ("scope", request.scope),
        ]);
        request.resource_client.apply(&mut form);
        let access: TokenResponse = self
            .json(self.client.post(&resource_as.token_endpoint).form(&form))
            .await?;
        if !access.token_type.eq_ignore_ascii_case("Bearer")
            || access.access_token.is_empty()
            || access.expires_in == Some(0)
            || access
                .issued_token_type
                .as_deref()
                .is_some_and(|t| t != "urn:ietf:params:oauth:token-type:access_token")
            || jsonwebtoken::decode_header(&access.access_token)
                .ok()
                .and_then(|h| h.typ)
                .as_deref()
                == Some("oauth-id-jag+jwt")
        {
            return Err("invalid_access_token_response");
        }
        Ok(AccessToken(access.access_token))
    }
}

/// Identity assertions obtained by the client's SSO flow. SAML callers first
/// obtain a refresh token at their `IdP`; this adapter does not implement SSO.
#[derive(Clone, Copy)]
pub enum SubjectType {
    IdToken,
    RefreshToken,
}
impl SubjectType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::IdToken => "urn:ietf:params:oauth:token-type:id_token",
            Self::RefreshToken => "urn:ietf:params:oauth:token-type:refresh_token",
        }
    }
}
pub struct ExchangeRequest<'a> {
    pub idp_issuer: &'a str,
    pub resource_issuer: &'a str,
    pub resource: &'a str,
    pub scope: &'a str,
    pub identity_assertion: &'a str,
    pub subject_type: SubjectType,
    pub idp_client: ClientCredentials<'a>,
    pub resource_client: ClientCredentials<'a>,
}

/// Parse only signed claims after JWT verification. Bound the history depth;
/// ignore non-identity actor claims, which cannot grant privileges (RFC 8693).
pub(crate) fn actors(
    mut value: Option<&serde_json::Value>,
) -> Result<
    Option<std::sync::Arc<[crate::ports::token_validator::Actor]>>,
    crate::ports::TokenRejection,
> {
    use crate::ports::{TokenRejection, token_validator::Actor};
    if value.is_none() {
        return Ok(None);
    }
    let mut actors = Vec::with_capacity(4);
    while let Some(current) = value {
        if actors.len() == 8 {
            return Err(TokenRejection::Malformed);
        }
        let object = current.as_object().ok_or(TokenRejection::Malformed)?;
        let subject = object
            .get("sub")
            .and_then(serde_json::Value::as_str)
            .filter(|v| !v.trim().is_empty())
            .ok_or(TokenRejection::Malformed)?;
        let issuer = object
            .get("iss")
            .map(|v| {
                v.as_str()
                    .filter(|v| !v.is_empty())
                    .ok_or(TokenRejection::Malformed)
            })
            .transpose()?;
        actors.push(Actor {
            subject: subject.to_owned(),
            issuer: issuer.map(str::to_owned),
        });
        value = object.get("act");
    }
    Ok(Some(actors.into()))
}

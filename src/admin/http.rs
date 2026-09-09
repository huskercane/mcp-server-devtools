//! The remote adapter: one HTTP client per `HttpAdminClient`.
use crate::ports::{
    AdminCallFuture, AdminClient, AdminClientError, AdminMethod, AdminRequest, AdminResponse,
    MAX_RESPONSE_BYTES,
};
use std::time::Duration;

/// A client of a remote admin boundary at a validated base URL.
pub struct HttpAdminClient {
    base: url::Url,
    client: crate::transport::HttpClient,
}

impl HttpAdminClient {
    /// Accept a base origin: `https://host[:port]/`, or `http://` on
    /// loopback only; no credentials, query, fragment, or path. Redirects
    /// are never followed — a bearer must not travel to a second host.
    ///
    /// # Errors
    ///
    /// [`AdminClientError::InvalidUrl`] for any other URL,
    /// [`AdminClientError::Unavailable`] if the HTTP client cannot be built.
    pub fn new(base: &str) -> Result<Self, AdminClientError> {
        let base = url::Url::parse(base).map_err(|_| AdminClientError::InvalidUrl)?;
        let local = match base.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain("localhost")) => true,
            _ => false,
        };
        if !(base.scheme() == "https" || (base.scheme() == "http" && local))
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            return Err(AdminClientError::InvalidUrl);
        }
        let client = crate::transport::HttpClient::builder()
            .no_redirects()
            .timeout(Duration::from_mins(1))
            .build()
            .map_err(|_| AdminClientError::Unavailable)?;
        Ok(Self { base, client })
    }

    async fn perform(
        &self,
        bearer: &str,
        request: AdminRequest<'_>,
    ) -> Result<AdminResponse, AdminClientError> {
        let method = match request.method {
            AdminMethod::Get => http::Method::GET,
            AdminMethod::Post => http::Method::POST,
            AdminMethod::Put => http::Method::PUT,
        };
        let url = self
            .base
            .join(&format!("admin/{}", request.operation))
            .map_err(|_| AdminClientError::InvalidUrl)?;
        let mut builder = self.client.request(method, url).bearer_auth(bearer);
        if let Some(body) = request.body {
            builder = builder.json(body);
        }
        let mut response = builder
            .send()
            .await
            .map_err(|_| AdminClientError::Unreachable)?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AdminClientError::InvalidResponse)?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(AdminClientError::ResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = serde_json::from_slice(&bytes).map_err(|_| AdminClientError::InvalidResponse)?;
        Ok(AdminResponse { status, body })
    }
}

impl AdminClient for HttpAdminClient {
    fn call<'a>(&'a self, bearer: &'a str, request: AdminRequest<'a>) -> AdminCallFuture<'a> {
        Box::pin(self.perform(bearer, request))
    }
}

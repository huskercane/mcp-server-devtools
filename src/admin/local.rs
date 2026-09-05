//! The in-process adapter: the admin `Router` driven as a `tower::Service`.
use crate::ports::{
    AdminCallFuture, AdminClient, AdminClientError, AdminMethod, AdminRequest, AdminResponse,
    MAX_RESPONSE_BYTES,
};
use axum::{
    Router,
    body::Body,
    http::{Method, Request, header},
};
use tower::ServiceExt as _;

/// A client of the admin boundary composed into this process.
///
/// Holds the router the HTTP transport serves (or any router that mounts
/// `/admin/*`); `Router` is cheap to clone and each call is a `oneshot`
/// through the full middleware stack, so the bearer check, the admin
/// limiter, and the audit see exactly what a remote caller would send.
#[derive(Clone)]
pub struct LocalAdminClient {
    router: Router,
}

impl LocalAdminClient {
    #[must_use]
    pub fn new(router: Router) -> Self {
        Self { router }
    }

    async fn perform(
        &self,
        bearer: &str,
        request: AdminRequest<'_>,
    ) -> Result<AdminResponse, AdminClientError> {
        let method = match request.method {
            AdminMethod::Get => Method::GET,
            AdminMethod::Post => Method::POST,
            AdminMethod::Put => Method::PUT,
        };
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("/admin/{}", request.operation))
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        let body = match request.body {
            Some(body) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(serde_json::to_vec(body).map_err(|_| AdminClientError::InvalidUrl)?)
            }
            None => Body::empty(),
        };
        let request = builder
            .body(body)
            .map_err(|_| AdminClientError::InvalidUrl)?;
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .map_err(|_| AdminClientError::Unreachable)?;
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
            .await
            .map_err(|_| AdminClientError::ResponseTooLarge)?;
        let body = serde_json::from_slice(&bytes).map_err(|_| AdminClientError::InvalidResponse)?;
        Ok(AdminResponse { status, body })
    }
}

impl AdminClient for LocalAdminClient {
    fn call<'a>(&'a self, bearer: &'a str, request: AdminRequest<'a>) -> AdminCallFuture<'a> {
        Box::pin(self.perform(bearer, request))
    }
}

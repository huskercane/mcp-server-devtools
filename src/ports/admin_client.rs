//! A client of the admin HTTP boundary (plan §3.10.1, WP D.0).
//!
//! The admin API is the single enforcement surface (ADR-009); everything
//! that operates on it — the `mcp-devtools admin` CLI today, the console
//! (WP D.1) next — is a client of it. This port is what such a client
//! depends on. Two adapters exist: [`crate::admin::HttpAdminClient`] speaks
//! to a remote process over HTTPS, and [`crate::admin::LocalAdminClient`]
//! drives the same router in process, so the console can render a page
//! without opening a loopback socket while still passing every request
//! through the bearer check, the admin limiter, and the audit.
//!
//! The port carries no framework type: the method is a small enum, the
//! operation is the path under `/admin/`, the body is JSON. A response is
//! whatever the boundary answered, status included — the client decides
//! what a non-success means, the port does not.
use serde_json::Value;
use std::{future::Future, pin::Pin};

/// The HTTP methods the admin API dispatches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminMethod {
    Get,
    Post,
    Put,
}

impl AdminMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

/// One call: `method /admin/{operation}` with an optional JSON body.
#[derive(Debug, Clone, Copy)]
pub struct AdminRequest<'a> {
    pub method: AdminMethod,
    /// The path under `/admin/`, e.g. `policy/reload`.
    pub operation: &'a str,
    pub body: Option<&'a Value>,
}

/// What the boundary answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminResponse {
    pub status: u16,
    pub body: Value,
}

impl AdminResponse {
    /// A 2xx answer.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

/// Why a call produced no [`AdminResponse`]. These are transport
/// failures; an API error is a response with a non-success status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminClientError {
    /// The base URL is not one this client will talk to.
    InvalidUrl,
    /// The HTTP client could not be built.
    Unavailable,
    /// The boundary could not be reached.
    Unreachable,
    /// The answer was not JSON, or the stream failed mid-body.
    InvalidResponse,
    /// The body exceeded the client's bound.
    ResponseTooLarge,
}

impl AdminClientError {
    /// The stable error code the CLI prints.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidUrl => "invalid_url",
            Self::Unavailable => "http_unavailable",
            Self::Unreachable => "admin_unreachable",
            Self::InvalidResponse => "invalid_response",
            Self::ResponseTooLarge => "response_too_large",
        }
    }
}

pub type AdminCallFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AdminResponse, AdminClientError>> + Send + 'a>>;

/// The port. Boxed futures: a control-plane client, never on the MCP
/// request path, and the console holds it as `Arc<dyn AdminClient>`.
pub trait AdminClient: Send + Sync {
    /// Perform one call as the holder of `bearer`.
    fn call<'a>(&'a self, bearer: &'a str, request: AdminRequest<'a>) -> AdminCallFuture<'a>;
}

/// The largest response body either adapter will accept.
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

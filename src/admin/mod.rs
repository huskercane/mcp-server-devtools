//! Adapters for the [`AdminClient`](crate::ports::AdminClient) port (plan
//! §3.10.1, WP D.0): the clients of the admin HTTP boundary.
//!
//! - [`HttpAdminClient`] — a remote process over HTTPS (loopback HTTP
//!   allowed), redirects disabled, bounded response. What `mcp-devtools
//!   admin` uses.
//! - [`LocalAdminClient`] — the same router driven in process through
//!   `tower::ServiceExt::oneshot`. What the console (WP D.1) uses to render
//!   a page: every request still passes the bearer check, the admin limiter,
//!   the task budget, and the audit, with no loopback socket.
//!
//! Both answer with the boundary's own status and JSON, so a caller sees the
//! same bytes whichever adapter it holds; `tests/admin_client_tests.rs` runs
//! one conformance suite across both.

mod http;
mod local;

pub use http::HttpAdminClient;
pub use local::LocalAdminClient;

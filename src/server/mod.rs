//! MCP server transports.
//!
//! - [`run_stdio`] — stdio JSON-RPC transport (default).
//! - [`run_http`]  — streamable-HTTP transport, behind `TRANSPORT_MODE=http`.

pub mod auth;
pub mod http;
pub mod rate_limit;
pub mod session;
pub mod shutdown;
pub mod stdio;

pub use http::{Role, run_http, run_http_as};
pub use stdio::run_stdio;

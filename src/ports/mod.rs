//! Application-owned outbound ports.
//!
//! A port is an interface the application layer *owns* and the infrastructure
//! layer *implements* — the dependency-inversion direction the hexagonal
//! arrangement is actually for. Controllers depend on the trait declared here;
//! `shell`, `reqwest`, and friends depend on nothing in the other direction.
//!
//! ## What earns a port
//!
//! Only a boundary with a real second implementation. A trait with exactly one
//! impl that no test or alternate caller substitutes is an invented seam: it
//! costs indirection and buys nothing. The bar each port here clears is a
//! concrete, demonstrated one — see [`command_runner`] for the worked example.
//!
//! ## Dispatch
//!
//! Ports use return-position `impl Future` rather than boxed futures, and are
//! consumed through generic parameters rather than `&dyn`. That keeps
//! dispatch static and adds no allocation on any call path. The cost of a port
//! is therefore a type parameter on the one function that needs it — not a
//! heap allocation on every request.

pub mod audit_sink;
pub mod command_runner;
pub mod credential_broker;
pub mod usage_sink;

pub use audit_sink::{AuditEvent, AuditEventKind, AuditSink, InMemoryAuditSink};
pub use command_runner::{CommandOutput, CommandRunner};
pub use credential_broker::{ConfigCredentialBroker, CredentialBroker, StaticCredentialBroker};
pub use usage_sink::{BoundedUsageChannel, NoopUsageSink, UsageEvent, UsageSink};

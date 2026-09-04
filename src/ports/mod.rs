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
pub mod checkpoint_sink;
pub mod command_runner;
pub mod credential_broker;
pub mod policy_decision_point;
pub mod secret_source;
pub mod token_validator;
pub mod usage_sink;

pub use audit_sink::{
    AuditEvent, AuditEventKind, AuditFailure, AuditSink, ControlEvent, ControlEventKind,
    InMemoryAuditSink, SignatureStatus,
};
pub use checkpoint_sink::{CheckpointSink, DirectoryCheckpointSink, InMemoryCheckpointSink};
pub use command_runner::{CommandOutput, CommandRunner};
pub use credential_broker::{ConfigCredentialBroker, CredentialBroker, StaticCredentialBroker};
pub use policy_decision_point::{AllowAll, PolicyDecisionPoint};
pub use secret_source::{
    FetchedSecret, InMemorySecretSource, Scheme, SecretFetchFuture, SecretLocator, SecretSource,
    SecretSourceError,
};
pub use token_validator::{
    Authenticated, StaticValidator, TokenFacts, TokenRejection, TokenValidator,
};
pub use usage_sink::{BoundedUsageChannel, NoopUsageSink, UsageEvent, UsageSink};

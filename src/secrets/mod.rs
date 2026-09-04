//! Secret references: configuration values that *point at* a secret rather
//! than holding it (plan §3.8, C.2a).
//!
//! ```text
//! GRAFANA_TOKEN = "file:///run/secrets/grafana#token"
//!                  ^^^^   ^^^^^^^^^^^^^^^^^^^ ^^^^^
//!                  scheme locator target      fragment (a JSON key)
//! ```
//!
//! The pieces:
//!
//! - [`reference`] parses a value into a [`SecretReference`] — or decides it
//!   is a literal. Only the schemes in [`crate::ports::Scheme`] are
//!   references; everything else is left exactly as it was, so a deployment
//!   with no references behaves byte-for-byte as before (constraint 1).
//! - [`snapshot`] is what the request path reads: every reference in the
//!   configuration, resolved, with the provider's version alongside for the
//!   audit record. It hangs off [`crate::config::Config`], so a tool call's
//!   config snapshot *is* its secret snapshot and neither can tear against
//!   the other.
//! - [`resolver`] turns references into a snapshot through the
//!   [`crate::ports::SecretSource`] port: one fetch per document, every
//!   `#key` taken from that same fetch.
//! - [`file`] is the first adapter: a file on a mounted volume, which is
//!   what a Kubernetes Secret or a CSI Secrets Store volume presents.
//!
//! The background refresh and the health signal live in
//! [`crate::bootstrap::secrets`], because when to refresh is a composition
//! decision, not a property of a reference.

pub mod file;
pub mod reference;
pub mod resolver;
pub mod snapshot;

pub use file::FileSecretSource;
pub use reference::{ReferenceError, SecretReference, is_keychain_sentinel, is_reference};
pub use resolver::{ResolveCause, SecretResolveError, SecretResolver};
pub use snapshot::{ResolvedSecret, SecretProvenance, SecretSnapshot};

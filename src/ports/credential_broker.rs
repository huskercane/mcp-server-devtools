//! `CredentialBroker` port: who acts upstream, as an identity — never a
//! secret (WP 0.6).
//!
//! ## The boundary
//!
//! Credential *values* are resolved where they always were
//! ([`crate::auth::Credentials`] over the [`crate::auth::secrets`] registry).
//! This port answers a different question the enterprise control plane and
//! every audit event need answered: **which** credential slot would act for a
//! vendor, as a stable, non-secret [`UpstreamIdentity`] label with vendor,
//! environment classification, and `Shared`/`Delegated` authority.
//!
//! Splitting identification from resolution keeps the secret material out of
//! the audit path entirely: nothing implementing this trait ever receives a
//! token, so no future refactor can accidentally log one from here.
//!
//! ## Predicting the same slot the resolver will pick
//!
//! Write-before-dispatch means the identity is recorded *before* the
//! credential is resolved, so the broker predicts rather than observes. A
//! prediction that uses different rules than the resolver is worse than no
//! prediction: it signs the audit trail with the wrong account.
//!
//! [`ConfigCredentialBroker`] therefore walks the registry with the same
//! rules [`crate::auth::Credentials`] uses, **including the implicit
//! keychain fallback** — an earlier revision only looked for a value in
//! config, so a vendor whose token lived solely in the OS keychain
//! dispatched happily while every audit record said `vendor/unconfigured`.
//! Presence is probed through [`crate::auth::keychain::KeychainBackend::contains`],
//! which answers a yes/no question and never hands the secret to this
//! module. The probe only runs when config is silent about every slot, and
//! it runs on the blocking pool — the OS keychain backends are synchronous
//! and can block on a D-Bus round trip or an ACL prompt.
//!
//! What remains is a narrow time-of-check gap: config or the keychain could
//! change between the prediction and the resolution microseconds later. That
//! is a rotation-during-a-call race, not a rules mismatch, and it closes
//! properly when delegated credentials (ADR-006) let one resolution produce
//! both the value and the identity.
//!
//! ## Why this is a port
//!
//! Two real implementations exist from day one (the bar `ports::mod`
//! documents): [`ConfigCredentialBroker`] wraps the existing registry-driven
//! resolution order, and [`StaticCredentialBroker`] lets tests pin an
//! identity without constructing vendor config. Later phases add secret
//! providers (Vault, AWS SM) and delegated OAuth behind the same trait.
//!
//! Dispatch is `dyn`-friendly on purpose, unlike [`super::command_runner`]:
//! the broker is consulted once per tool call on a path that already does
//! file I/O (the audit journal), so vtable dispatch is noise, and a generic
//! parameter would ripple through `DevtoolsServer` and every
//! `#[tool_router]` block. That tradeoff is documented here per the
//! architecture conventions.

use std::future::Future;
use std::pin::Pin;

use crate::config::Config;
use crate::policy::UpstreamIdentity;

// Compatibility exports retain downstream enterprise library imports, avoiding
// a breaking API change during adapter relocation. No implementation lives here.
pub use crate::auth::credential_broker::{ConfigCredentialBroker, StaticCredentialBroker};

/// Config key holding the environment classification of a vendor account
/// (`prod` / `staging` / `qa` / `dev`). Vendor-scoped: a `jira` section may
/// classify Jira as `prod` while `grafana` says `qa`; the shared overlay
/// classifies the whole deployment. Absent or unrecognised values are
/// [`crate::policy::EnvironmentClass::Unclassified`], which environment-scoped allow rules
/// never match — the conservative direction.
pub const ENVIRONMENT_KEY: &str = "MCP_VENDOR_ENVIRONMENT";

/// The future [`CredentialBroker::upstream_identity`] returns.
pub type UpstreamIdentityFuture<'a> = Pin<Box<dyn Future<Output = UpstreamIdentity> + Send + 'a>>;

/// Identifies the upstream identity that acts for a vendor.
///
/// Implementations must never return or log secret material — the returned
/// label appears in every audit event.
pub trait CredentialBroker: Send + Sync {
    /// The identity that would act upstream for `vendor` under `config`.
    ///
    /// Total by design: even an unconfigured vendor gets a stable
    /// `"{vendor}/unconfigured"` label, so an audit record can always name
    /// the upstream identity (the subsequent dispatch fails with the usual
    /// auth-missing error; the audit trail still shows what was attempted).
    ///
    /// Async because answering correctly can require asking the OS keychain
    /// whether a slot exists (see the module docs), which blocks. The
    /// question is only asked when config leaves it open.
    fn upstream_identity<'a>(
        &'a self,
        config: &'a Config,
        vendor: &'a str,
    ) -> UpstreamIdentityFuture<'a>;
}

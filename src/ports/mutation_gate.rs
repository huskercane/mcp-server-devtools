//! Admission of an administrative mutation (plan §3.10.1, WP D.0).
//!
//! Every mutation the admin HTTP boundary performs — reloading the policy,
//! replacing the deny-list, revoking a session, purging an artifact — asks
//! this port whether it may proceed **before** it appends its durable
//! `admin_mutation` intent. The community adapter, [`DirectGate`], always
//! admits: that is the behaviour the boundary had before the port existed,
//! byte for byte. The two-person approval adapter (WP D.2) defers a
//! mutation into a proposal a second administrator must approve, and is
//! selected by `MCP_ADMIN_APPROVALS=required` (`bootstrap::approvals`).
//!
//! The intent is borrowed: under [`DirectGate`] admission allocates nothing.
use crate::policy::Principal;
use std::{future::Future, pin::Pin};

/// Which mutation is asking. Named after the admin API operation so that
/// a proposal's record and the API's error text agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationKind {
    /// `POST /admin/policy/reload`.
    PolicyReload,
    /// `PUT /admin/deny-list`.
    DenyListReplace,
    /// `POST /admin/sessions/revoke`.
    SessionRevoke,
    /// `POST /admin/artifacts/purge`.
    ArtifactPurge,
}

impl MutationKind {
    /// The admin API operation this kind names.
    #[must_use]
    pub const fn operation(self) -> &'static str {
        match self {
            Self::PolicyReload => "policy/reload",
            Self::DenyListReplace => "deny-list/replace",
            Self::SessionRevoke => "sessions/revoke",
            Self::ArtifactPurge => "artifacts/purge",
        }
    }
}

/// What an administrator asked for, as the gate sees it.
#[derive(Debug, Clone, Copy)]
pub struct MutationIntent<'a> {
    pub kind: MutationKind,
    /// The validated administrator.
    pub principal: &'a Principal,
    /// The mutation's target: a session or artifact id, or the version of
    /// the document about to be installed.
    pub target: Option<&'a str>,
    /// The exact candidate bytes, when the mutation installs a document.
    /// An approval adapter binds its proposal to a digest of these so that
    /// what is applied later is what was proposed, not what is on disk then.
    pub candidate: Option<&'a [u8]>,
}

/// The gate's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Proceed: append the intent, then take effect.
    Apply,
    /// Not now: the mutation was recorded as a proposal with this id and
    /// takes effect only when approved. The boundary answers `202` and
    /// appends **no** `admin_mutation` record — the adapter journaled the
    /// proposal itself.
    Deferred { proposal: String },
    /// Never: a bounded, static cause (`approval_self`, `approval_expired`).
    /// The boundary answers `409` with it.
    Refused(&'static str),
}

pub type AdmissionFuture<'a> = Pin<Box<dyn Future<Output = Admission> + Send + 'a>>;

/// The port. Boxed futures, like [`super::policy_admin::PolicyAdmin`]:
/// these are infrequent control calls outside the MCP request path, and an
/// injected adapter must not make the HTTP router generic.
pub trait MutationGate: Send + Sync {
    fn admit<'a>(&'a self, intent: &'a MutationIntent<'a>) -> AdmissionFuture<'a>;
    /// The adapter's name for the health banner and startup log.
    fn name(&self) -> &'static str;
}

/// Admit everything: the boundary's behaviour before the port existed.
#[derive(Debug, Default, Clone, Copy)]
pub struct DirectGate;

impl MutationGate for DirectGate {
    fn admit<'a>(&'a self, _intent: &'a MutationIntent<'a>) -> AdmissionFuture<'a> {
        Box::pin(std::future::ready(Admission::Apply))
    }
    fn name(&self) -> &'static str {
        "direct"
    }
}

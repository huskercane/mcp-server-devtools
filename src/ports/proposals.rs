//! Two-person approval of administrative mutations (plan §3.10.3, WP D.2).
//!
//! When `MCP_ADMIN_APPROVALS=required`, a gated mutation does not apply:
//! the [`super::MutationGate`] adapter records it as a *proposal* and a
//! **different** administrator in the same tenant approves or rejects it
//! through this port. The journal is the source of truth — every
//! transition is a control record before it is a state — and the pending
//! set is a projection rebuilt from it at startup.
use crate::policy::Principal;
use crate::ports::MutationKind;
use serde::Serialize;
use std::{future::Future, pin::Pin};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalState {
    Pending,
    Approved,
    Rejected,
    Expired,
}

/// Who proposed or decided: the identity, not the whole principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Party {
    pub tenant: String,
    pub subject: String,
}

impl From<&Principal> for Party {
    fn from(principal: &Principal) -> Self {
        Self {
            tenant: principal.tenant.clone(),
            subject: principal.subject.clone(),
        }
    }
}

/// A proposal as the API reports it. The locked JSON shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Proposal {
    pub id: String,
    /// The admin operation it would perform (`policy/install`,
    /// `deny-list/replace`).
    pub operation: &'static str,
    /// The version label the candidate would install as.
    pub target: String,
    /// `sha256:<hex>` over the exact document bytes and the signature as
    /// submitted; re-checked before the candidate is applied.
    pub candidate_digest: String,
    pub proposer: Party,
    pub created: String,
    pub expires: String,
    pub state: ProposalState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<Party>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The `admin_mutation` sequence under which an approved candidate was
    /// applied; absent until it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_seq: Option<u64>,
}

impl Proposal {
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.state == ProposalState::Pending
    }
}

/// The exact bytes an approved proposal applies: what was proposed, not
/// what is on disk now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub kind: MutationKind,
    pub document: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalError {
    NotFound,
    /// The approver is the proposer.
    SelfApproval,
    Expired,
    /// Already rejected, or approved when a rejection was asked for.
    Decided,
    /// The stored candidate no longer matches the digest it was proposed
    /// under: the journal it was projected from has been altered.
    DigestMismatch,
    AuditUnavailable,
}

impl ProposalError {
    /// The admin API's error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::SelfApproval => "approval_self",
            Self::Expired => "approval_expired",
            Self::Decided => "proposal_decided",
            Self::DigestMismatch => "proposal_digest_mismatch",
            Self::AuditUnavailable => "audit_unavailable",
        }
    }
}

/// An approval that was made durable. `apply` is `Some` when the caller
/// must now apply the candidate through the ordinary mutation path, and
/// `None` when a previous approval already did (a repeat is idempotent).
#[derive(Debug, Clone)]
pub struct Approval {
    pub proposal: Proposal,
    pub apply: Option<Candidate>,
}

pub type ProposalFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProposalError>> + Send + 'a>>;

/// The port. Tenant-scoped throughout: a proposal from another tenant does
/// not exist for the caller.
pub trait ProposalRegistry: Send + Sync {
    /// Every proposal of `tenant`, oldest first, with expiry applied.
    fn list(&self, tenant: &str) -> Vec<Proposal>;
    fn get(&self, tenant: &str, id: &str) -> Option<Proposal>;
    /// Journal an `admin_approval` by `approver` (who must not be the
    /// proposer) and hand back what to apply.
    fn approve<'a>(&'a self, id: &'a str, approver: &'a Principal) -> ProposalFuture<'a, Approval>;
    /// Record that the approved candidate was applied under `audit_seq`.
    fn applied(&self, id: &str, audit_seq: u64);
    /// Journal an `admin_rejection` by `principal`, with a bounded reason.
    fn reject<'a>(
        &'a self,
        id: &'a str,
        principal: &'a Principal,
        reason: Option<&'a str>,
    ) -> ProposalFuture<'a, Proposal>;
}

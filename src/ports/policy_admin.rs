//! Policy administration boundary. HTTP supplies documents and principals;
//! adapters own persistence, verification, synchronization, and durable intent.
//! Boxed futures permit an injected backend without making the HTTP router
//! generic. These infrequent control calls are outside the MCP request path.
use crate::{
    policy::{ActionContext, Explanation, Principal, RuleDescription},
    ports::{SignatureStatus, activity_reports::AccessRow},
};
use serde::Serialize;
use std::{collections::BTreeMap, future::Future, pin::Pin};

pub type AdminFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, PolicyAdminError>> + Send + 'a>>;
#[derive(Debug, Clone, Copy)]
pub enum PolicyAdminError {
    Invalid,
    Unavailable,
    AuditUnavailable,
}
#[derive(Serialize)]
pub struct PolicyDocument {
    pub version: String,
    pub document: String,
    pub signature: Option<SignatureStatus>,
}
#[derive(Serialize)]
pub struct PolicyValidation {
    pub valid: bool,
    pub version: String,
    pub rules: usize,
    pub signature_verified: bool,
}
#[derive(Serialize)]
pub struct PolicyDiff {
    pub current_version: String,
    pub candidate_version: String,
    pub current_rules: Vec<RuleDescription>,
    pub candidate_rules: Vec<RuleDescription>,
}
/// What [`PolicyAdmin::install`] reports: the durable intent's sequence and
/// the version now in force.
#[derive(Serialize)]
pub struct PolicyInstall {
    pub audit_seq: u64,
    pub version: String,
}
/// What [`PolicyAdmin::explain`] reports: the decision the policy in force
/// makes for one action, and every rule's reason (WP B.2's logic, reached
/// through the admin boundary for the console and the CLI — plan §3.10.2).
#[derive(Serialize)]
pub struct PolicyExplanation {
    pub policy_version: Option<String>,
    pub explanation: Explanation,
}
#[derive(Serialize)]
pub struct PolicyReload {
    pub audit_seq: u64,
    pub changed: bool,
    pub version: String,
}

pub trait PolicyAdmin: Send + Sync {
    fn read(&self) -> AdminFuture<'_, PolicyDocument>;
    // Ownership moves into blocking workers; borrowed documents would require
    // the adapter to make another allocation before spawning them.
    fn validate(&self, document: String) -> AdminFuture<'_, PolicyValidation>;
    fn diff(&self, document: String) -> AdminFuture<'_, PolicyDiff>;
    /// Serialize reloads with the watcher; durably audit before changing state.
    /// Callers must let the future finish once started, even on disconnect.
    fn reload<'a>(&'a self, principal: &'a Principal) -> AdminFuture<'a, PolicyReload>;
    /// Verify a signed candidate against the same trust anchor as file
    /// reloads and compile it, without changing state: what [`Self::install`]
    /// would put in force. `signature_verified` is `true` on success.
    /// Borrowed so the caller keeps the bytes for its admission intent.
    fn verify<'a>(
        &'a self,
        document: &'a str,
        signature: &'a str,
    ) -> AdminFuture<'a, PolicyValidation>;
    /// Install exact candidate bytes and their detached signature as the
    /// policy: verified again under the reload lock, journaled as a durable
    /// `policy/install` intent, written beside the file the watcher reads,
    /// then committed. Callers must let the future finish once started.
    fn install<'a>(
        &'a self,
        principal: &'a Principal,
        document: String,
        signature: String,
    ) -> AdminFuture<'a, PolicyInstall>;
    fn access_review(
        &self,
        groups: BTreeMap<String, Vec<String>>,
        tenant: String,
    ) -> AdminFuture<'_, Vec<AccessRow>>;
    /// Evaluate `context` against the policy in force and say why: the
    /// decision, and for every rule whether it matched or the first key it
    /// failed on. Read-only; nothing is journaled.
    fn explain(&self, context: ActionContext) -> AdminFuture<'_, PolicyExplanation>;
}

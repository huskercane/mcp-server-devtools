//! Policy administration boundary. HTTP supplies documents and principals;
//! adapters own persistence, verification, synchronization, and durable intent.
//! Boxed futures permit an injected backend without making the HTTP router
//! generic. These infrequent control calls are outside the MCP request path.
use crate::{
    policy::{Principal, RuleDescription},
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
    fn access_review(
        &self,
        groups: BTreeMap<String, Vec<String>>,
        tenant: String,
    ) -> AdminFuture<'_, Vec<AccessRow>>;
}

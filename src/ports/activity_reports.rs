//! Named activity-report boundary. Storage locations never cross this port.
use serde::Serialize;
use std::collections::BTreeMap;
use std::{future::Future, pin::Pin};
pub type ActivityFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ActivityExport, ActivityUnavailable>> + Send + 'a>>;
#[derive(Debug)]
pub struct ActivityUnavailable;
pub trait ActivityReports: Send + Sync {
    fn activity<'a>(&'a self, filter: &'a ActivityFilter) -> ActivityFuture<'a>;
}

/// Which records to export.
#[derive(Debug, Clone, Default)]
pub struct ActivityFilter {
    /// RFC 3339 lower bound (inclusive) on `timestamp`.
    pub since: Option<String>,
    /// RFC 3339 upper bound (exclusive).
    pub until: Option<String>,
    pub subject: Option<String>,
    pub vendor: Option<String>,
    /// Record kinds to keep; empty keeps every kind except checkpoints.
    pub kinds: Vec<String>,
}

/// One journal record, flattened.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct ActivityRow {
    pub seq: u64,
    pub timestamp: String,
    pub kind: String,
    pub request_id: Option<String>,
    pub subject: Option<String>,
    pub tenant: Option<String>,
    pub groups: Option<String>,
    pub tool: Option<String>,
    pub vendor: Option<String>,
    pub environment: Option<String>,
    pub normalized_action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_scope: Option<String>,
    pub request_risk: Option<String>,
    pub effect: Option<String>,
    pub rule_id: Option<String>,
    pub policy_version: Option<String>,
    pub reason: Option<String>,
    pub upstream_label: Option<String>,
    pub upstream_authority: Option<String>,
    pub outcome: Option<String>,
    pub duration_ms: Option<u64>,
    pub egress_allowed: Option<u64>,
    pub egress_denied: Option<u64>,
    pub egress_attempted: Option<u64>,
    /// Control records: the document version the record is about.
    pub version: Option<String>,
}

/// The rows, plus why the read stopped early if it did.
#[derive(Debug, Default, Serialize)]
pub struct ActivityExport {
    pub rows: Vec<ActivityRow>,
    /// Records read, including the ones the filter dropped.
    pub records_read: u64,
    /// Set when the journal could not be read to the end.
    pub stopped: Option<String>,
}

/// One (subject, rule) pair the policy would consider.
#[derive(Debug, Clone, Serialize)]
pub struct AccessRow {
    pub subject: String,
    pub groups: Vec<String>,
    pub rule_id: String,
    pub effect: String,
    /// The rule's match keys (`vendor`, `environment`, `resource_id`, …).
    pub matches: BTreeMap<&'static str, Vec<String>>,
}

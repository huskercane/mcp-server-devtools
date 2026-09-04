//! `RollupStore` port: usage rows in, the fixed set of named reports out
//! (plan §3.9 "Usage rollups and reports", WP C.6).
//!
//! The **usage** pipeline's durable end. Usage events arrive lossy
//! ([`super::usage_sink`]: bounded channel, drop with a counter) and are
//! appended here in batches by a consumer on the control plane; the admin
//! API (C.4), the CLI (C.5), and the §7 trial metrics read them back
//! through the named queries below. Nothing about the backend crosses the
//! port: no SQL, no dialect type, no connection handle. A report is a
//! *named operation* with typed parameters and a typed, serialisable
//! result — a partner on `PostgreSQL` implements the same names.
//!
//! Two implementations from day one: `SQLite` (`crate::rollups::sqlite`,
//! embedded, exact-pinned) and [`InMemoryRollupStore`] for tests, whose
//! reports are computed in Rust over a `Vec` — the conformance suite runs
//! the same queries against both and expects the same answers, which is
//! what keeps a SQL rewrite honest.
//!
//! Rows are metadata (§3.3): a subject, a vendor, an environment, a tool,
//! the decision, the outcome, a duration. Never arguments, never content,
//! never a token. The subject is here because per-principal usage is the
//! point of a rollup (who is using what, how much, how often denied), and
//! it is already on every audit record; retention (`prune`) bounds how
//! long it stays.
//!
//! Consumed as `Arc<dyn RollupStore>` (boxed future per batch or report,
//! never per request): appends run on a background consumer, reports on
//! the admin path — the documented ports-prefer-generics deviation, for
//! the same reason as `SecretSource` and `AuditForwarder`.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// One usage row. Built from a [`super::UsageEvent`]; the consumer owns
/// the conversion so the sink stays cheap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageRow {
    /// RFC 3339 UTC, the journal's `timestamp` form.
    pub timestamp: String,
    pub tenant: String,
    pub subject: String,
    pub vendor: String,
    /// `prod` … `unclassified`.
    pub environment: String,
    pub tool_name: String,
    /// `allow` or `deny` (the tool-level decision).
    pub decision: String,
    /// `read`, `write`, `destructive`, or `unknown`.
    pub risk: String,
    /// `success`, `error`, `policy_denied`, … — the legacy audit outcome
    /// label.
    pub outcome: String,
    pub duration_ms: u64,
}

/// A time window, inclusive `since`, exclusive `until`; each optional.
/// RFC 3339 strings compare lexically when they share the journal's form,
/// which every row does.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

impl Window {
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    /// Whether `timestamp` falls inside.
    #[must_use]
    pub fn contains(&self, timestamp: &str) -> bool {
        self.since.as_deref().is_none_or(|since| timestamp >= since)
            && self.until.as_deref().is_none_or(|until| timestamp < until)
    }
}

/// Timeline granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bucket {
    Hour,
    Day,
}

impl Bucket {
    /// The bucket label a timestamp falls in: `2026-09-04T12` or
    /// `2026-09-04`.
    #[must_use]
    pub fn label(self, timestamp: &str) -> &str {
        let cut = match self {
            Self::Hour => 13,
            Self::Day => 10,
        };
        timestamp.get(..cut).unwrap_or(timestamp)
    }
}

/// The fixed set of reports. Adding one is a port change, implemented by
/// every adapter and checked by the conformance suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "report", rename_all = "snake_case")]
pub enum ReportQuery {
    /// Totals over the window, and the §7 proxies computable from usage.
    Totals { window: Window },
    /// One row per subject.
    ByPrincipal { window: Window },
    /// One row per vendor.
    ByVendor { window: Window },
    /// One row per tool.
    ByTool { window: Window },
    /// Denied calls per environment.
    DenialsByEnvironment { window: Window },
    /// Calls per bucket.
    Timeline { window: Window, bucket: Bucket },
}

/// `Totals` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Totals {
    pub rows: u64,
    pub allowed: u64,
    pub denied: u64,
    /// Allowed calls whose outcome was not `success`.
    pub failed: u64,
    pub subjects: u64,
    pub vendors: u64,
    /// `allowed / rows`, `null` with no rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_share: Option<f64>,
    /// Mean duration of allowed calls, `null` with none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_duration_ms: Option<f64>,
    /// Denied calls by a subject who has an allowed call for the same
    /// vendor in another environment (the §7 cross-environment proxy).
    pub cross_environment_attempts: u64,
    pub first_timestamp: Option<String>,
    pub last_timestamp: Option<String>,
}

/// A grouped row (`ByPrincipal`, `ByVendor`, `ByTool`,
/// `DenialsByEnvironment`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GroupRow {
    pub key: String,
    pub rows: u64,
    pub allowed: u64,
    pub denied: u64,
    pub failed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_duration_ms: Option<f64>,
    pub first_timestamp: Option<String>,
    pub last_timestamp: Option<String>,
}

/// A timeline row.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineRow {
    pub bucket: String,
    pub rows: u64,
    pub allowed: u64,
    pub denied: u64,
}

/// A report's result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "shape", rename_all = "snake_case")]
pub enum Report {
    Totals(Totals),
    Groups { rows: Vec<GroupRow> },
    Timeline { rows: Vec<TimelineRow> },
}

/// Why a store operation failed. `category` is fixed vocabulary; `detail`
/// is bounded operator text and never a row's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollupError {
    pub category: &'static str,
    pub detail: String,
}

impl RollupError {
    pub const UNAVAILABLE: &'static str = "rollup_store_unavailable";
    pub const CORRUPT: &'static str = "rollup_store_corrupt";
    pub const INVALID: &'static str = "rollup_query_invalid";

    #[must_use]
    pub fn new(category: &'static str, detail: impl Into<String>) -> Self {
        const MAX_DETAIL: usize = 256;
        let mut detail: String = detail.into();
        if detail.len() > MAX_DETAIL {
            let mut cut = MAX_DETAIL;
            while !detail.is_char_boundary(cut) {
                cut -= 1;
            }
            detail.truncate(cut);
            detail.push('…');
        }
        Self { category, detail }
    }
}

impl std::fmt::Display for RollupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.detail.is_empty() {
            formatter.write_str(self.category)
        } else {
            write!(formatter, "{}: {}", self.category, self.detail)
        }
    }
}

impl std::error::Error for RollupError {}

/// The future a store operation returns.
pub type RollupFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, RollupError>> + Send + 'a>>;

/// Usage rows in, named reports out.
pub trait RollupStore: Send + Sync {
    /// `sqlite`, `memory`, … — for logs and the health banner.
    fn name(&self) -> &'static str;

    /// Append `rows`, all or nothing.
    fn append<'a>(&'a self, rows: &'a [UsageRow]) -> RollupFuture<'a, ()>;

    /// Run one named report.
    fn report<'a>(&'a self, query: &'a ReportQuery) -> RollupFuture<'a, Report>;

    /// Delete rows with `timestamp < before`; returns how many.
    fn prune<'a>(&'a self, before: &'a str) -> RollupFuture<'a, u64>;

    /// How many rows the store holds (tests, the health banner).
    fn count(&self) -> RollupFuture<'_, u64>;
}

/// Rows in a `Vec`, reports computed here. The reference implementation
/// the conformance suite holds the SQL adapter to.
#[derive(Debug, Default)]
pub struct InMemoryRollupStore {
    rows: Mutex<Vec<UsageRow>>,
    fail: std::sync::atomic::AtomicBool,
}

impl InMemoryRollupStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Make every operation fail with [`RollupError::UNAVAILABLE`].
    pub fn set_failing(&self, failing: bool) {
        self.fail
            .store(failing, std::sync::atomic::Ordering::Release);
    }

    fn check(&self) -> Result<(), RollupError> {
        if self.fail.load(std::sync::atomic::Ordering::Acquire) {
            Err(RollupError::new(
                RollupError::UNAVAILABLE,
                "store is failing",
            ))
        } else {
            Ok(())
        }
    }

    /// Every row, in insertion order.
    #[must_use]
    pub fn rows(&self) -> Vec<UsageRow> {
        self.rows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Compute a report over rows — shared by the in-memory adapter and by
/// any adapter that fetches rows and reduces here.
#[must_use]
pub fn compute(rows: &[UsageRow], query: &ReportQuery) -> Report {
    match query {
        ReportQuery::Totals { window } => Report::Totals(totals(rows, window)),
        ReportQuery::ByPrincipal { window } => Report::Groups {
            rows: grouped(rows, window, |row| &row.subject, false),
        },
        ReportQuery::ByVendor { window } => Report::Groups {
            rows: grouped(rows, window, |row| &row.vendor, false),
        },
        ReportQuery::ByTool { window } => Report::Groups {
            rows: grouped(rows, window, |row| &row.tool_name, false),
        },
        ReportQuery::DenialsByEnvironment { window } => Report::Groups {
            rows: grouped(rows, window, |row| &row.environment, true),
        },
        ReportQuery::Timeline { window, bucket } => Report::Timeline {
            rows: timeline(rows, window, *bucket),
        },
    }
}

fn is_allow(row: &UsageRow) -> bool {
    row.decision == "allow"
}

/// Ratios and report means are deliberately floating-point. Counts above
/// 2^53 lose sub-unit precision, which is immaterial once divided for a
/// human-facing aggregate and avoids leaking an adapter-specific decimal.
#[allow(clippy::cast_precision_loss)]
pub(crate) fn ratio(numerator: u64, denominator: u64) -> f64 {
    numerator as f64 / denominator as f64
}

fn totals(rows: &[UsageRow], window: &Window) -> Totals {
    let mut out = Totals::default();
    let mut subjects = std::collections::BTreeSet::new();
    let mut vendors = std::collections::BTreeSet::new();
    let mut duration_total: u64 = 0;
    // (subject, vendor) → environments with an allowed call.
    let mut allowed_envs: BTreeMap<(&str, &str), std::collections::BTreeSet<&str>> =
        BTreeMap::new();
    let mut denied: Vec<&UsageRow> = Vec::new();
    for row in rows.iter().filter(|row| window.contains(&row.timestamp)) {
        out.rows += 1;
        subjects.insert(row.subject.as_str());
        vendors.insert(row.vendor.as_str());
        if is_allow(row) {
            out.allowed += 1;
            duration_total += row.duration_ms;
            if row.outcome != "success" {
                out.failed += 1;
            }
            allowed_envs
                .entry((&row.subject, &row.vendor))
                .or_default()
                .insert(&row.environment);
        } else {
            out.denied += 1;
            denied.push(row);
        }
        if out
            .first_timestamp
            .as_deref()
            .is_none_or(|first| row.timestamp.as_str() < first)
        {
            out.first_timestamp = Some(row.timestamp.clone());
        }
        if out
            .last_timestamp
            .as_deref()
            .is_none_or(|last| row.timestamp.as_str() > last)
        {
            out.last_timestamp = Some(row.timestamp.clone());
        }
    }
    out.subjects = subjects.len() as u64;
    out.vendors = vendors.len() as u64;
    if out.rows > 0 {
        out.allow_share = Some(ratio(out.allowed, out.rows));
    }
    if out.allowed > 0 {
        out.mean_duration_ms = Some(ratio(duration_total, out.allowed));
    }
    out.cross_environment_attempts = denied
        .iter()
        .filter(|row| {
            allowed_envs
                .get(&(row.subject.as_str(), row.vendor.as_str()))
                .is_some_and(|envs| envs.iter().any(|env| *env != row.environment))
        })
        .count() as u64;
    out
}

fn grouped<'a>(
    rows: &'a [UsageRow],
    window: &Window,
    key: impl Fn(&'a UsageRow) -> &'a str,
    denials_only: bool,
) -> Vec<GroupRow> {
    let mut groups: BTreeMap<&str, (GroupRow, u64)> = BTreeMap::new();
    for row in rows.iter().filter(|row| window.contains(&row.timestamp)) {
        if denials_only && is_allow(row) {
            continue;
        }
        let (group, duration_total) = groups.entry(key(row)).or_default();
        group.rows += 1;
        if is_allow(row) {
            group.allowed += 1;
            *duration_total += row.duration_ms;
            if row.outcome != "success" {
                group.failed += 1;
            }
        } else {
            group.denied += 1;
        }
        if group
            .first_timestamp
            .as_deref()
            .is_none_or(|first| row.timestamp.as_str() < first)
        {
            group.first_timestamp = Some(row.timestamp.clone());
        }
        if group
            .last_timestamp
            .as_deref()
            .is_none_or(|last| row.timestamp.as_str() > last)
        {
            group.last_timestamp = Some(row.timestamp.clone());
        }
    }
    groups
        .into_iter()
        .map(|(key, (mut group, duration_total))| {
            key.clone_into(&mut group.key);
            if group.allowed > 0 {
                group.mean_duration_ms = Some(ratio(duration_total, group.allowed));
            }
            group
        })
        .collect()
}

fn timeline(rows: &[UsageRow], window: &Window, bucket: Bucket) -> Vec<TimelineRow> {
    let mut buckets: BTreeMap<&str, TimelineRow> = BTreeMap::new();
    for row in rows.iter().filter(|row| window.contains(&row.timestamp)) {
        let entry = buckets.entry(bucket.label(&row.timestamp)).or_default();
        entry.rows += 1;
        if is_allow(row) {
            entry.allowed += 1;
        } else {
            entry.denied += 1;
        }
    }
    buckets
        .into_iter()
        .map(|(label, mut row)| {
            label.clone_into(&mut row.bucket);
            row
        })
        .collect()
}

impl RollupStore for InMemoryRollupStore {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn append<'a>(&'a self, rows: &'a [UsageRow]) -> RollupFuture<'a, ()> {
        Box::pin(async move {
            self.check()?;
            self.rows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(rows);
            Ok(())
        })
    }

    fn report<'a>(&'a self, query: &'a ReportQuery) -> RollupFuture<'a, Report> {
        Box::pin(async move {
            self.check()?;
            let rows = self
                .rows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Ok(compute(&rows, query))
        })
    }

    fn prune<'a>(&'a self, before: &'a str) -> RollupFuture<'a, u64> {
        Box::pin(async move {
            self.check()?;
            let mut rows = self
                .rows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before_len = rows.len();
            rows.retain(|row| row.timestamp.as_str() >= before);
            Ok((before_len - rows.len()) as u64)
        })
    }

    fn count(&self) -> RollupFuture<'_, u64> {
        Box::pin(async move {
            self.check()?;
            Ok(self
                .rows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len() as u64)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_bounds_are_inclusive_since_exclusive_until() {
        let window = Window {
            since: Some("2026-09-04T00:00:00.000Z".into()),
            until: Some("2026-09-05T00:00:00.000Z".into()),
        };
        assert!(window.contains("2026-09-04T00:00:00.000Z"));
        assert!(window.contains("2026-09-04T23:59:59.999Z"));
        assert!(!window.contains("2026-09-05T00:00:00.000Z"));
        assert!(!window.contains("2026-09-03T23:59:59.999Z"));
        assert!(Window::all().contains("1970-01-01T00:00:00.000Z"));
    }

    #[test]
    fn bucket_labels() {
        assert_eq!(
            Bucket::Hour.label("2026-09-04T12:34:56.000Z"),
            "2026-09-04T12"
        );
        assert_eq!(Bucket::Day.label("2026-09-04T12:34:56.000Z"), "2026-09-04");
        assert_eq!(Bucket::Day.label("short"), "short");
    }
}

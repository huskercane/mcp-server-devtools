//! Design-partner trial metrics from the journal (plan §7, WP B.7).
//!
//! Everything §7 asks the journal for, computed offline from a copy:
//!
//! | §7 metric | Here |
//! |---|---|
//! | Time to provision (group add → first successful call) | `subjects[*].first_seen` and `first_allowed`; the identity-provider side of the interval is not in the journal, so `time_to_first_allow_ms` measures first attempt → first success |
//! | Time for revocation to take effect | `subjects[*].revocation_window_ms`: the `revocation_changed` record → that subject's first `revoked_token_rejected`; and `deny_after_allow_ms`: a subject's last allowed call → their first policy denial (the group-removal proxy) |
//! | Share of requests covered by an explicit allow rule | `explicit_allow_share` |
//! | Cross-environment access attempts blocked | `cross_environment_attempts`: denied calls by a subject who has an allowed call for the same vendor in another environment |
//! | Time to produce a report | printed by the CLI (`elapsed_ms`) |
//!
//! Counts are over `tool_call_intent` records (one per call asked for);
//! outcomes, egress denials, and control records are counted separately.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use super::reader::JournalReader;

/// Per-subject figures.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SubjectMetrics {
    pub calls: u64,
    pub allowed: u64,
    pub denied: u64,
    pub first_seen: Option<String>,
    pub first_allowed: Option<String>,
    pub last_allowed: Option<String>,
    /// First attempt → first success.
    pub time_to_first_allow_ms: Option<i64>,
    /// Last allowed call → first policy denial after it.
    pub deny_after_allow_ms: Option<i64>,
    /// Revocation-list change → this subject's first refused request.
    pub revocation_window_ms: Option<i64>,
    pub revoked_rejections: u64,
}

/// The report.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Metrics {
    pub records: u64,
    pub first_timestamp: Option<String>,
    pub last_timestamp: Option<String>,
    /// `tool_call_intent` records.
    pub calls: u64,
    pub allowed_by_rule: u64,
    /// Allowed under `AllowAll` (no rule, no policy version): local dry runs.
    pub allowed_without_policy: u64,
    pub denied_by_rule: u64,
    pub denied_by_default: u64,
    /// Denied for a reason other than a rule or the default: the fresh-
    /// token rule for writes, an unclassified resource.
    pub denied_other: u64,
    /// `allowed_by_rule / calls`, or `null` with no calls.
    pub explicit_allow_share: Option<f64>,
    pub egress_denials: u64,
    pub outcomes: BTreeMap<String, u64>,
    pub denials_by_environment: BTreeMap<String, u64>,
    pub cross_environment_attempts: u64,
    pub policy_changes: u64,
    pub policy_rejections: u64,
    pub revocation_changes: u64,
    pub revoked_token_rejections: u64,
    pub checkpoints: u64,
    pub subjects: BTreeMap<String, SubjectMetrics>,
    /// Set when the journal could not be read to the end.
    pub stopped: Option<String>,
}

fn millis(timestamp: &str) -> Option<i64> {
    super::export::instant(timestamp)
}

fn between(from: &str, to: &str) -> Option<i64> {
    Some(millis(to)? - millis(from)?)
}

fn text<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(key)?;
    }
    cursor.as_str()
}

/// Compute the report over the journal at `journal`.
///
/// # Errors
///
/// When the journal cannot be opened.
#[allow(clippy::too_many_lines)] // one pass over the records; splitting it would mean several
pub fn metrics(journal: &Path, since: Option<&str>) -> io::Result<Metrics> {
    let reader = JournalReader::open(journal)?;
    let mut report = Metrics::default();
    // (subject, vendor) → environments with an allowed call.
    let mut allowed_environments: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    // Denied calls, to re-check for cross-environment once every allow is known.
    let mut denied_calls: Vec<(String, String, String)> = Vec::new();
    let mut last_revocation_change: Option<String> = None;

    for item in reader {
        let record = match item {
            Ok(record) => record,
            Err(error) => {
                report.stopped = Some(error.to_string());
                break;
            }
        };
        let timestamp = record.timestamp().unwrap_or_default().to_owned();
        if let Some(since) = since
            && super::export::before(&timestamp, since)
        {
            continue;
        }
        report.records += 1;
        if report.first_timestamp.is_none() {
            report.first_timestamp = Some(timestamp.clone());
        }
        report.last_timestamp = Some(timestamp.clone());
        let value = &record.value;
        match record.kind.as_str() {
            "checkpoint" => report.checkpoints += 1,
            "tool_call_intent" => {
                report.calls += 1;
                let subject = text(value, &["principal", "subject"]).unwrap_or("-");
                let vendor = text(value, &["vendor"]).unwrap_or("-").to_owned();
                let environment = text(value, &["action", "environment"])
                    .unwrap_or("unclassified")
                    .to_owned();
                let effect = text(value, &["decision", "effect"]).unwrap_or("-");
                let rule_id = text(value, &["decision", "rule_id"]);
                let policy_version = text(value, &["decision", "policy_version"]);
                let subject_metrics = report.subjects.entry(subject.to_owned()).or_default();
                subject_metrics.calls += 1;
                if subject_metrics.first_seen.is_none() {
                    subject_metrics.first_seen = Some(timestamp.clone());
                }
                if effect == "allow" {
                    // An allow with no rule and no policy version is the
                    // `AllowAll` decision: nothing explicit allowed it.
                    if rule_id.is_none() && policy_version.is_none() {
                        report.allowed_without_policy += 1;
                    } else {
                        report.allowed_by_rule += 1;
                    }
                    subject_metrics.allowed += 1;
                    if subject_metrics.first_allowed.is_none() {
                        subject_metrics.first_allowed = Some(timestamp.clone());
                        subject_metrics.time_to_first_allow_ms = subject_metrics
                            .first_seen
                            .as_deref()
                            .and_then(|first| between(first, &timestamp));
                    }
                    subject_metrics.last_allowed = Some(timestamp.clone());
                    // A later denial resets the window measurement.
                    subject_metrics.deny_after_allow_ms = None;
                    allowed_environments
                        .entry((subject.to_owned(), vendor))
                        .or_default()
                        .insert(environment);
                } else {
                    let reason = text(value, &["decision", "reason"]).unwrap_or("");
                    match rule_id {
                        Some(_) => report.denied_by_rule += 1,
                        None if reason.contains("default deny") => report.denied_by_default += 1,
                        None => report.denied_other += 1,
                    }
                    subject_metrics.denied += 1;
                    if subject_metrics.deny_after_allow_ms.is_none()
                        && let Some(last_allowed) = &subject_metrics.last_allowed
                    {
                        subject_metrics.deny_after_allow_ms = between(last_allowed, &timestamp);
                    }
                    *report
                        .denials_by_environment
                        .entry(environment.clone())
                        .or_default() += 1;
                    denied_calls.push((subject.to_owned(), vendor, environment));
                }
            }
            "tool_call_outcome" => {
                let outcome = text(value, &["outcome"]).unwrap_or("-").to_owned();
                *report.outcomes.entry(outcome).or_default() += 1;
            }
            "egress_decision" => report.egress_denials += 1,
            "policy_changed" => report.policy_changes += 1,
            "policy_rejected" => report.policy_rejections += 1,
            "revocation_changed" => {
                report.revocation_changes += 1;
                last_revocation_change = Some(timestamp.clone());
            }
            "revoked_token_rejected" => {
                report.revoked_token_rejections += 1;
                let subject = text(value, &["principal", "subject"]).unwrap_or("-");
                let subject_metrics = report.subjects.entry(subject.to_owned()).or_default();
                subject_metrics.revoked_rejections += 1;
                if subject_metrics.revocation_window_ms.is_none()
                    && let Some(changed) = &last_revocation_change
                {
                    subject_metrics.revocation_window_ms = between(changed, &timestamp);
                }
            }
            _ => {}
        }
    }

    for (subject, vendor, environment) in denied_calls {
        if allowed_environments
            .get(&(subject, vendor))
            .is_some_and(|environments| environments.iter().any(|allowed| *allowed != environment))
        {
            report.cross_environment_attempts += 1;
        }
    }
    if report.calls > 0 {
        #[allow(clippy::cast_precision_loss)] // a share, not a count
        {
            report.explicit_allow_share = Some(report.allowed_by_rule as f64 / report.calls as f64);
        }
    }
    Ok(report)
}

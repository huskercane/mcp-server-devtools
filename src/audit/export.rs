//! Exports from the journal and the policy (WP B.5): the two reports a
//! design partner must be able to produce unaided.
//!
//! - **Activity**: one row per journal record, flattened to the columns an
//!   auditor filters on (who, what, which vendor and environment, the
//!   decision, the rule, the policy version, the upstream identity, the
//!   outcome), as JSON Lines or CSV. Rows keep the `request_id`, so intent
//!   and outcome can be joined downstream; a row is never synthesized from
//!   two records here, because the journal's own granularity is the
//!   evidence.
//! - **Access review**: from the policy and a groups file (group →
//!   members, exported from the identity provider), every rule that applies
//!   to every member — "who can do what" as the policy would decide it,
//!   without a single call being made.
//!
//! Neither report contains anything the journal does not: no tokens, no
//! request bodies, no response content (§3.3). A read problem ends the
//! export at the last good record and is reported alongside the rows, so a
//! damaged journal exports what it can and says so.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use super::reader::JournalReader;
use crate::policy::{FilePolicy, Principal, PrincipalAuthority, RuleDescription};

/// Output encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Jsonl,
    Csv,
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
#[derive(Debug, Clone, Default, Serialize)]
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

/// CSV column order for [`ActivityRow`].
pub const ACTIVITY_COLUMNS: &[&str] = &[
    "seq",
    "timestamp",
    "kind",
    "request_id",
    "subject",
    "tenant",
    "groups",
    "tool",
    "vendor",
    "environment",
    "normalized_action",
    "resource_type",
    "resource_scope",
    "request_risk",
    "effect",
    "rule_id",
    "policy_version",
    "reason",
    "upstream_label",
    "upstream_authority",
    "outcome",
    "duration_ms",
    "egress_allowed",
    "egress_denied",
    "egress_attempted",
    "version",
];

/// The rows, plus why the read stopped early if it did.
#[derive(Debug, Default, Serialize)]
pub struct ActivityExport {
    pub rows: Vec<ActivityRow>,
    /// Records read, including the ones the filter dropped.
    pub records_read: u64,
    /// Set when the journal could not be read to the end.
    pub stopped: Option<String>,
}

fn text(value: &Value, path: &[&str]) -> Option<String> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(key)?;
    }
    match cursor {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn joined(value: &Value, path: &[&str]) -> Option<String> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(key)?;
    }
    let items = cursor.as_array()?;
    Some(
        items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(";"),
    )
}

fn scope_label(value: &Value) -> Option<String> {
    let scope = value.get("action")?.get("resource_scope")?;
    match scope.get("kind").and_then(Value::as_str)? {
        "ids" => Some(format!(
            "ids:{}",
            scope
                .get("ids")
                .and_then(Value::as_array)
                .map(|ids| ids
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(";"))
                .unwrap_or_default()
        )),
        other => Some(other.to_owned()),
    }
}

/// Flatten one record.
#[must_use]
pub fn flatten(seq: u64, kind: &str, value: &Value) -> ActivityRow {
    let mut row = ActivityRow {
        seq,
        timestamp: text(value, &["timestamp"]).unwrap_or_default(),
        kind: kind.to_owned(),
        request_id: text(value, &["request_id"]),
        subject: text(value, &["principal", "subject"]),
        tenant: text(value, &["principal", "tenant"]),
        groups: joined(value, &["principal", "groups"]),
        tool: text(value, &["tool_name"]),
        vendor: text(value, &["vendor"]),
        environment: text(value, &["action", "environment"])
            .or_else(|| text(value, &["upstream_identity", "environment"])),
        normalized_action: text(value, &["action", "normalized_action"]),
        resource_type: text(value, &["action", "resource_type"]),
        resource_scope: scope_label(value),
        request_risk: text(value, &["action", "request_risk"]),
        effect: text(value, &["decision", "effect"]),
        rule_id: text(value, &["decision", "rule_id"]),
        policy_version: text(value, &["decision", "policy_version"]),
        reason: text(value, &["decision", "reason"]).or_else(|| text(value, &["reason"])),
        upstream_label: text(value, &["upstream_identity", "label"]),
        upstream_authority: text(value, &["upstream_identity", "authority"]),
        outcome: text(value, &["outcome"]),
        duration_ms: value.get("duration_ms").and_then(Value::as_u64),
        version: text(value, &["version"]),
        ..ActivityRow::default()
    };
    if let Some(requests) = value
        .get("egress")
        .and_then(|egress| egress.get("requests"))
        .and_then(Value::as_array)
    {
        let allowed = requests
            .iter()
            .filter(|request| request.get("effect").and_then(Value::as_str) == Some("allow"))
            .count();
        let attempted = requests
            .iter()
            .filter(|request| {
                request
                    .get("dispatch")
                    .and_then(|dispatch| dispatch.get("state"))
                    .and_then(Value::as_str)
                    == Some("attempted")
            })
            .count();
        row.egress_allowed = Some(allowed as u64);
        row.egress_denied = Some((requests.len() - allowed) as u64);
        row.egress_attempted = Some(attempted as u64);
    }
    row
}

/// An RFC 3339 timestamp as milliseconds since the epoch, for durations
/// between records (`metrics`). `None` when it does not parse.
#[must_use]
pub fn instant(timestamp: &str) -> Option<i64> {
    parse(timestamp).map(|parsed| parsed.timestamp_millis())
}

fn parse(timestamp: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(timestamp.trim()).ok()
}

/// `timestamp < bound`, chronologically at full precision when both parse
/// — a bound written as `…00.0005Z` is after a record at `…00Z`, not equal
/// to it — and lexically otherwise, so a malformed record is compared
/// rather than dropped.
#[must_use]
pub fn before(timestamp: &str, bound: &str) -> bool {
    match (parse(timestamp), parse(bound)) {
        (Some(left), Some(right)) => left < right,
        _ => timestamp < bound,
    }
}

impl ActivityFilter {
    fn keeps(&self, row: &ActivityRow) -> bool {
        if row.kind == super::checkpoint::CHECKPOINT_KIND {
            return false;
        }
        if !self.kinds.is_empty() && !self.kinds.contains(&row.kind) {
            return false;
        }
        if let Some(since) = &self.since
            && before(&row.timestamp, since)
        {
            return false;
        }
        if let Some(until) = &self.until
            && !before(&row.timestamp, until)
        {
            return false;
        }
        if let Some(subject) = &self.subject
            && row.subject.as_deref() != Some(subject.as_str())
        {
            return false;
        }
        if let Some(vendor) = &self.vendor
            && row.vendor.as_deref() != Some(vendor.as_str())
        {
            return false;
        }
        true
    }
}

/// Read the journal at `journal` and flatten every record the filter keeps.
///
/// # Errors
///
/// When the journal cannot be opened. A read that stops early is reported
/// in [`ActivityExport::stopped`], not as an error.
pub fn activity(journal: &Path, filter: &ActivityFilter) -> io::Result<ActivityExport> {
    let reader = JournalReader::open(journal)?;
    let mut export = ActivityExport::default();
    for item in reader {
        match item {
            Ok(record) => {
                export.records_read += 1;
                let row = flatten(record.seq, &record.kind, &record.value);
                if filter.keeps(&row) {
                    export.rows.push(row);
                }
            }
            Err(error) => {
                export.stopped = Some(error.to_string());
                break;
            }
        }
    }
    Ok(export)
}

/// Write rows in `format`.
///
/// # Errors
///
/// When the writer fails.
pub fn write_activity(rows: &[ActivityRow], format: Format, out: &mut dyn Write) -> io::Result<()> {
    match format {
        Format::Jsonl => {
            for row in rows {
                serde_json::to_writer(&mut *out, row)?;
                out.write_all(b"\n")?;
            }
            Ok(())
        }
        Format::Csv => {
            write_csv_line(
                out,
                ACTIVITY_COLUMNS
                    .iter()
                    .map(|column| Some((*column).to_owned())),
            )?;
            for row in rows {
                let value = serde_json::to_value(row)?;
                write_csv_line(
                    out,
                    ACTIVITY_COLUMNS
                        .iter()
                        .map(|column| text(&value, &[column])),
                )?;
            }
            Ok(())
        }
    }
}

/// RFC 4180: quote a field containing a comma, a quote, or a line break;
/// double embedded quotes. Hand-rolled because it is twelve lines and the
/// alternative is a dependency for one function.
///
/// Spreadsheet-safe as well: a field that a spreadsheet would evaluate as
/// a formula — one starting with `=`, `+`, `-`, `@`, a tab, or a carriage
/// return — is quoted and prefixed with an apostrophe, the convention
/// every common spreadsheet reads as "this is text". Subjects,
/// group names, rule ids, and denial reasons come from the identity
/// provider, the policy author, and the request, so an export that will be
/// opened rather than parsed must not let any of them run
/// `=HYPERLINK(...)`. The JSON Lines format is the one for machines.
fn write_csv_line(
    out: &mut dyn Write,
    fields: impl Iterator<Item = Option<String>>,
) -> io::Result<()> {
    let mut first = true;
    for field in fields {
        if !first {
            out.write_all(b",")?;
        }
        first = false;
        let Some(field) = field else {
            continue;
        };
        let formula_like = field.starts_with(['=', '+', '-', '@', '\t', '\r']);
        if formula_like || field.contains([',', '"', '\n', '\r']) {
            out.write_all(b"\"")?;
            if formula_like {
                out.write_all(b"'")?;
            }
            out.write_all(field.replace('"', "\"\"").as_bytes())?;
            out.write_all(b"\"")?;
        } else {
            out.write_all(field.as_bytes())?;
        }
    }
    out.write_all(b"\n")
}

// --- access review -----------------------------------------------------------

/// Group → members, as exported from the identity provider. JSON or YAML:
///
/// ```yaml
/// SRE: [alice@acme.example, bob@acme.example]
/// Developers: [carol@acme.example]
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct GroupsFile(pub BTreeMap<String, Vec<String>>);

impl GroupsFile {
    /// Parse JSON or YAML.
    ///
    /// # Errors
    ///
    /// When the text is neither.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        serde_norway::from_slice(bytes).map_err(|error| format!("groups file: {error}"))
    }

    /// Every subject with the groups it belongs to.
    #[must_use]
    pub fn subjects(&self) -> BTreeMap<String, Vec<String>> {
        let mut by_subject: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (group, members) in &self.0 {
            for member in members {
                by_subject
                    .entry(member.clone())
                    .or_default()
                    .insert(group.clone());
            }
        }
        by_subject
            .into_iter()
            .map(|(subject, groups)| (subject, groups.into_iter().collect()))
            .collect()
    }
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

/// CSV column order for [`AccessRow`]; the match keys follow.
pub const ACCESS_COLUMNS: &[&str] = &["subject", "groups", "rule_id", "effect"];
const MATCH_COLUMNS: &[&str] = &[
    "vendor",
    "environment",
    "normalized_action",
    "request_risk",
    "resource_type",
    "resource_id",
    "resource_scope",
    "constrained_by",
    "tool_name",
    "canonical_path",
    "method",
    "upstream_authority",
];

/// Who can do what: for every subject in `groups`, every rule whose
/// `subjects` clause matches a principal with that subject and those
/// groups (and the default required scope). Subjects a rule names directly
/// are included even when no group lists them.
#[must_use]
pub fn access_review(policy: &FilePolicy, groups: &GroupsFile, tenant: &str) -> Vec<AccessRow> {
    let mut subjects = groups.subjects();
    for rule in policy.describe_rules() {
        for named in &rule.subjects.subjects {
            if !named.contains('*') {
                subjects.entry(named.clone()).or_default();
            }
        }
    }
    let mut rows = Vec::new();
    for (subject, member_of) in subjects {
        let principal = Principal {
            tenant: tenant.to_owned(),
            subject: subject.clone(),
            groups: member_of.clone(),
            scopes: vec![crate::server::auth::DEFAULT_REQUIRED_SCOPE.to_owned()],
            authority: PrincipalAuthority::Okta,
        };
        for rule in policy.rules_for(&principal) {
            rows.push(row_for(&subject, &member_of, rule));
        }
    }
    rows
}

fn row_for(subject: &str, groups: &[String], rule: RuleDescription) -> AccessRow {
    AccessRow {
        subject: subject.to_owned(),
        groups: groups.to_vec(),
        rule_id: rule.id,
        effect: serde_json::to_value(rule.effect)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default(),
        matches: rule.matches,
    }
}

/// Write access rows in `format`.
///
/// # Errors
///
/// When the writer fails.
pub fn write_access_review(
    rows: &[AccessRow],
    format: Format,
    out: &mut dyn Write,
) -> io::Result<()> {
    match format {
        Format::Jsonl => {
            for row in rows {
                serde_json::to_writer(&mut *out, row)?;
                out.write_all(b"\n")?;
            }
            Ok(())
        }
        Format::Csv => {
            write_csv_line(
                out,
                ACCESS_COLUMNS
                    .iter()
                    .chain(MATCH_COLUMNS)
                    .map(|column| Some((*column).to_owned())),
            )?;
            for row in rows {
                let fixed = [
                    Some(row.subject.clone()),
                    Some(row.groups.join(";")),
                    Some(row.rule_id.clone()),
                    Some(row.effect.clone()),
                ];
                let matches = MATCH_COLUMNS
                    .iter()
                    .map(|column| row.matches.get(column).map(|values| values.join(";")));
                write_csv_line(out, fixed.into_iter().chain(matches))?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quotes_only_what_needs_quoting() {
        let mut out = Vec::new();
        write_csv_line(
            &mut out,
            [
                Some("plain".to_owned()),
                Some("has,comma".to_owned()),
                Some("has \"quote\"".to_owned()),
                None,
                Some("multi\nline".to_owned()),
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "plain,\"has,comma\",\"has \"\"quote\"\"\",,\"multi\nline\"\n"
        );
    }

    #[test]
    fn groups_file_inverts_to_subjects() {
        let groups = GroupsFile::parse(b"SRE: [alice, bob]\nDevelopers: [bob]\n").unwrap();
        let subjects = groups.subjects();
        assert_eq!(subjects["alice"], vec!["SRE".to_owned()]);
        assert_eq!(
            subjects["bob"],
            vec!["Developers".to_owned(), "SRE".to_owned()]
        );
        assert!(
            GroupsFile::parse(b"{\"SRE\": [\"alice\"]}").is_ok(),
            "JSON is YAML"
        );
        assert!(GroupsFile::parse(b"- not a map\n").is_err());
    }
}

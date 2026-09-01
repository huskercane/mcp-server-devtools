//! Durable journal adapter behind the [`AuditSink`] port (WP 0.7, ADR-011).
//!
//! Append-only JSONL file, one sequence-stamped event per line, written and
//! flushed synchronously **before** the tool dispatches. Sequence numbers
//! are monotonic across process restarts: opening the journal resumes from
//! the highest sequence already on disk, so a gap in the numbers is
//! evidence of tampering or loss, never of a restart.
//!
//! Enabled by `MCP_AUDIT_JOURNAL_DIR`. Fail-closed at both edges:
//!
//! - the server refuses to **start** if the journal cannot be opened
//!   (plan §1.2), and
//! - a call whose intent cannot be appended is refused, not dispatched
//!   (proved by `tests/audit_journal_tests.rs` — wiremock sees zero
//!   requests).
//!
//! Durability notes for this milestone: each append is `write_all` +
//! `flush` (kernel-buffered). Per-record `fsync` is deliberately absent —
//! §8 budgets fsync **batched per signed checkpoint**, and checkpoints are
//! Phase B work (B.6). The degraded-read mode (`MCP_AUDIT_DEGRADED_READS`)
//! is unresolved question 5 and intentionally not implemented.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::ports::audit_sink::{AuditEvent, AuditSink};

/// File name inside `MCP_AUDIT_JOURNAL_DIR`.
pub const JOURNAL_FILE_NAME: &str = "audit-journal.jsonl";

/// Append-only, sequence-numbered journal.
pub struct JournalAuditSink {
    inner: Mutex<JournalInner>,
    path: PathBuf,
}

struct JournalInner {
    file: File,
    next_seq: u64,
}

impl JournalAuditSink {
    /// Open (or create) the journal in `dir`, resuming the sequence from
    /// what is already on disk.
    ///
    /// # Errors
    ///
    /// Any failure to create the directory, read the existing journal, or
    /// open it for append. Callers treat this as a startup failure — there
    /// is no degraded mode.
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(JOURNAL_FILE_NAME);
        let last_seq = last_sequence(&path)?;
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            inner: Mutex::new(JournalInner {
                file,
                next_seq: last_seq,
            }),
            path,
        })
    }

    /// Path of the journal file (diagnostics and tests).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for JournalAuditSink {
    fn append(&self, event: &AuditEvent) -> io::Result<u64> {
        // Serialize outside the lock (per the CLAUDE.md concurrency
        // guidelines: no heavy work inside a critical section). The
        // sequence number is only assigned under the lock, where it is
        // spliced in as a prefix — line order and sequence order therefore
        // stay identical, which the tamper-evidence story depends on.
        let body = serde_json::to_vec(event)
            .map_err(|error| io::Error::other(format!("serialize audit event: {error}")))?;
        debug_assert!(
            body.len() > 2 && body.first() == Some(&b'{'),
            "AuditEvent must serialize to a non-empty JSON object"
        );

        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let seq = inner.next_seq + 1;
        let mut line = Vec::with_capacity(body.len() + 32);
        line.extend_from_slice(b"{\"seq\":");
        line.extend_from_slice(seq.to_string().as_bytes());
        line.push(b',');
        line.extend_from_slice(&body[1..]);
        line.push(b'\n');
        inner.file.write_all(&line)?;
        inner.file.flush()?;
        // Only advance after the write succeeded: a failed append leaves the
        // sequence unconsumed, so evidence never has silent gaps.
        inner.next_seq = seq;
        Ok(seq)
    }
}

/// Highest sequence number present in an existing journal file (0 when the
/// file does not exist or holds no parseable sequenced line). A torn or
/// corrupt trailing line does not lose the resume point of the lines before
/// it — the max over parseable lines wins.
fn last_sequence(path: &Path) -> io::Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let reader = BufReader::new(File::open(path)?);
    let mut last = 0u64;
    for line in reader.lines() {
        let line = line?;
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line)
            && let Some(seq) = value.get("seq").and_then(serde_json::Value::as_u64)
        {
            last = last.max(seq);
        }
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::policy::{
        ClientIdentity, EnvironmentClass, PolicyDecision, Principal, UpstreamAuthority,
        UpstreamIdentity,
    };
    use crate::ports::audit_sink::AuditEventKind;

    fn sample_event() -> AuditEvent {
        AuditEvent {
            timestamp: "2026-09-01T00:00:00.000Z".to_owned(),
            kind: AuditEventKind::ToolCallIntent,
            request_id: "1".to_owned(),
            tool_name: "jira_get".to_owned(),
            vendor: "jira".to_owned(),
            principal: Principal::local(),
            client: ClientIdentity::default(),
            decision: PolicyDecision::local_allow(),
            upstream_identity: UpstreamIdentity {
                label: "jira/ATLASSIAN_API_TOKEN/alice@example.com".to_owned(),
                vendor: "jira".to_owned(),
                environment: EnvironmentClass::Unclassified,
                authority: UpstreamAuthority::Shared,
            },
            outcome: None,
            duration_ms: None,
        }
    }

    fn journal_lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn appends_sequence_from_one_and_persist_every_field() {
        let dir = tempfile::tempdir().unwrap();
        let sink = JournalAuditSink::open(dir.path()).unwrap();
        assert_eq!(sink.append(&sample_event()).unwrap(), 1);
        assert_eq!(sink.append(&sample_event()).unwrap(), 2);

        let lines = journal_lines(sink.path());
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["seq"], 1);
        assert_eq!(lines[1]["seq"], 2);
        assert_eq!(lines[0]["kind"], "tool_call_intent");
        assert_eq!(
            lines[0]["upstream_identity"]["label"],
            "jira/ATLASSIAN_API_TOKEN/alice@example.com"
        );
        assert_eq!(lines[0]["principal"]["subject"], "local");
        assert_eq!(lines[0]["decision"]["effect"], "allow");
    }

    #[test]
    fn sequence_resumes_across_reopen_instead_of_restarting() {
        let dir = tempfile::tempdir().unwrap();
        {
            let sink = JournalAuditSink::open(dir.path()).unwrap();
            sink.append(&sample_event()).unwrap();
            sink.append(&sample_event()).unwrap();
        }
        let reopened = JournalAuditSink::open(dir.path()).unwrap();
        assert_eq!(
            reopened.append(&sample_event()).unwrap(),
            3,
            "restart must continue the sequence, not restart it"
        );
        assert_eq!(journal_lines(reopened.path()).len(), 3);
    }

    #[test]
    fn corrupt_trailing_line_does_not_lose_the_resume_point() {
        let dir = tempfile::tempdir().unwrap();
        {
            let sink = JournalAuditSink::open(dir.path()).unwrap();
            sink.append(&sample_event()).unwrap();
        }
        let path = dir.path().join(JOURNAL_FILE_NAME);
        let mut contents = std::fs::read_to_string(&path).unwrap();
        contents.push_str("{torn-write");
        std::fs::write(&path, contents).unwrap();

        let reopened = JournalAuditSink::open(dir.path()).unwrap();
        assert_eq!(reopened.append(&sample_event()).unwrap(), 2);
    }

    #[test]
    fn open_fails_when_the_journal_location_is_unusable() {
        let dir = tempfile::tempdir().unwrap();
        let file_in_the_way = dir.path().join("not-a-dir");
        std::fs::write(&file_in_the_way, b"x").unwrap();
        assert!(
            JournalAuditSink::open(&file_in_the_way).is_err(),
            "a journal dir that is actually a file must refuse to open"
        );
    }
}

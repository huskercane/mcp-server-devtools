//! Durable journal adapter behind the [`AuditSink`] port (WP 0.7, ADR-011).
//!
//! Append-only JSONL file, one sequence-stamped event per line, made durable
//! **before** the tool dispatches. Sequence numbers are contiguous from 1 and
//! monotonic across process restarts, so a gap in the numbers is evidence of
//! tampering or loss, never of a restart.
//!
//! Enabled by `MCP_AUDIT_JOURNAL_DIR`. Fail-closed at every edge:
//!
//! - the server refuses to **start** if the journal cannot be opened, is
//!   already held by another process, or is corrupt (plan §1.2);
//! - a call whose intent cannot be journaled is refused, not dispatched
//!   (proved by `tests/audit_journal_tests.rs` — wiremock sees zero
//!   requests);
//! - once a write or sync fails, the journal is **poisoned**: every later
//!   append fails, so every later call is refused. After a write error we
//!   cannot know what reached the disk, and continuing would produce
//!   evidence nobody can trust. There is no degraded mode.
//!
//! ## Durability: why a dedicated writer thread
//!
//! `write_all` + `flush` only moves bytes into the kernel page cache. The
//! plan claims **audit RPO = 0 for acknowledged records** (§7), and a
//! kernel-buffered write does not deliver that: a mutating vendor call could
//! run and the host could lose power before the intent record ever reached
//! storage, leaving the action with no evidence at all. Acknowledgement here
//! therefore means `sync_data` returned.
//!
//! That sync cannot sit on a Tokio worker. It is unbounded in practice — a
//! full disk, page reclaim, FUSE, or network-attached storage can stall it
//! far past the >1 ms offload threshold in CLAUDE.md, and the earlier
//! "kernel-buffered append is under budget, so it may run inline" exemption
//! did not survive the requirement above. So:
//!
//! - [`AuditSink::append`] is async and hands the record to one dedicated
//!   writer thread over a bounded channel, then awaits an acknowledgement.
//!   The worker thread stays free while the sync is in flight, and the
//!   bounded channel provides backpressure instead of unbounded queueing.
//! - The writer drains everything already queued into one batch, writes it
//!   with a single `write_all`, and issues **one** `sync_data` for the
//!   batch — group commit. Under load the per-record sync cost amortizes,
//!   which is why this is cheaper than the inline version it replaces, not
//!   just safer.
//! - Creating the journal also syncs its **parent directory**. A file sync
//!   makes contents durable but not the directory entry naming the file, so
//!   without this the very first acknowledged record could survive as bytes
//!   in a file that does not exist after a power loss.
//! - Sequence numbers are assigned *by the writer*, in write order. Nothing
//!   else can assign one, so line order and sequence order cannot diverge —
//!   the tamper-evidence story depends on that, and it now holds without a
//!   shared lock on the request path.
//!
//! Per-record signing and checkpointing remain Phase B work (B.6); this is
//! the durability floor they will build on.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use crate::ports::audit_sink::{AppendFuture, AuditEvent, AuditSink};

/// File name inside `MCP_AUDIT_JOURNAL_DIR`.
pub const JOURNAL_FILE_NAME: &str = "audit-journal.jsonl";

/// Queue depth between the request path and the writer thread. Bounded:
/// backpressure is the point — an audit queue that grows without limit
/// trades a memory blow-up for the durability guarantee it exists to keep.
const WRITE_QUEUE_DEPTH: usize = 1024;

/// Most records folded into a single `write_all` + `sync_data`.
const MAX_BATCH: usize = 256;

/// One record on its way to the writer.
struct WriteRequest {
    /// The serialized event, still carrying its leading `{`; the writer
    /// splices the sequence prefix in.
    body: Vec<u8>,
    ack: oneshot::Sender<Result<u64, Arc<io::Error>>>,
}

/// Append-only, sequence-numbered journal.
pub struct JournalAuditSink {
    /// `None` only while [`Drop`] is closing the channel.
    requests: Option<mpsc::Sender<WriteRequest>>,
    writer: Option<std::thread::JoinHandle<()>>,
    path: PathBuf,
}

impl JournalAuditSink {
    /// Open (or create) the journal in `dir`, take an exclusive lock on it,
    /// verify what is already there, and start the writer thread.
    ///
    /// # Errors
    ///
    /// Any failure to create the directory, lock the file, open it, or
    /// validate its existing contents. Callers treat this as a startup
    /// failure — there is no degraded mode.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let existed = dir.exists();
        std::fs::create_dir_all(dir)?;
        let path = dir.join(JOURNAL_FILE_NAME);
        let is_new = !path.exists();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;

        // `sync_data` on the file makes its *contents* durable; it says
        // nothing about the directory entry that names it. On a brand-new
        // journal that gap swallows the whole RPO=0 claim: the first intent
        // could be written and synced, the call could dispatch, and a power
        // loss before the parent directory's entry reached storage would
        // leave no `audit-journal.jsonl` at all on restart — an acknowledged
        // record with no file to be in. Sync the directory once, here, while
        // the file is new; every later append only changes contents.
        if is_new || !existed {
            sync_directory(dir)?;
        }

        // Two processes appending to one journal would each resume from the
        // same last sequence and issue the same numbers — duplicated
        // evidence that looks exactly like tampering. The lock makes the
        // second process fail to start instead.
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "the audit journal at {} is already held by another process; \
                         two writers would issue duplicate sequence numbers",
                        path.display()
                    ),
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }

        let last_seq = recover(&file, &path)?;

        let (requests, receiver) = mpsc::channel(WRITE_QUEUE_DEPTH);
        let writer = std::thread::Builder::new()
            .name("audit-journal".to_owned())
            .spawn(move || writer_loop(file, last_seq, receiver))?;

        Ok(Self {
            requests: Some(requests),
            writer: Some(writer),
            path,
        })
    }

    /// Path of the journal file (diagnostics and tests).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn sender(&self) -> io::Result<&mpsc::Sender<WriteRequest>> {
        self.requests
            .as_ref()
            .ok_or_else(|| io::Error::other("audit journal is shutting down"))
    }
}

impl Drop for JournalAuditSink {
    fn drop(&mut self) {
        // Close the channel first so the writer sees the end of the stream,
        // then wait for it: the thread owns the file handle and the lock,
        // and a reopen (a restart, or the next test) must not race it.
        self.requests = None;
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

impl AuditSink for JournalAuditSink {
    fn append<'a>(&'a self, event: &'a AuditEvent) -> AppendFuture<'a> {
        Box::pin(async move {
            let body = serde_json::to_vec(event)
                .map_err(|error| io::Error::other(format!("serialize audit event: {error}")))?;
            if body.len() < 3 || body.first() != Some(&b'{') {
                return Err(io::Error::other(
                    "audit event did not serialize to a JSON object",
                ));
            }

            let (ack, acked) = oneshot::channel();
            self.sender()?
                .send(WriteRequest { body, ack })
                .await
                .map_err(|_| io::Error::other("the audit journal writer has stopped"))?;

            match acked.await {
                Ok(Ok(seq)) => Ok(seq),
                // `io::Error` is not `Clone`, and one failure fans out to a
                // whole batch: rebuild an equivalent error per waiter.
                Ok(Err(error)) => Err(io::Error::new(error.kind(), error.to_string())),
                Err(_) => Err(io::Error::other(
                    "the audit journal writer dropped the record without acknowledging it",
                )),
            }
        })
    }
}

/// The writer thread: the only place a sequence number is assigned and the
/// only place the file is touched after `open`.
fn writer_loop(mut file: File, mut last_seq: u64, mut receiver: mpsc::Receiver<WriteRequest>) {
    let mut batch: Vec<WriteRequest> = Vec::with_capacity(MAX_BATCH);
    let mut buffer: Vec<u8> = Vec::new();
    // Set by the first failed write or sync; every later record is refused.
    let mut poison: Option<Arc<io::Error>> = None;

    while let Some(first) = receiver.blocking_recv() {
        batch.push(first);
        while batch.len() < MAX_BATCH {
            match receiver.try_recv() {
                Ok(next) => batch.push(next),
                Err(_) => break,
            }
        }

        if let Some(error) = &poison {
            for request in batch.drain(..) {
                let _ = request.ack.send(Err(Arc::clone(error)));
            }
            continue;
        }

        buffer.clear();
        // Checked throughout: at `u64::MAX` an unchecked increment would
        // wrap and start re-issuing numbers that are already on disk.
        let Some(mut seq) = last_seq.checked_add(1) else {
            fail_batch(&mut batch, &mut poison, &sequence_exhausted());
            continue;
        };
        let first_seq = seq;
        let mut exhausted = false;
        for request in &batch {
            buffer.extend_from_slice(b"{\"seq\":");
            let mut digits = [0u8; MAX_U64_DIGITS];
            buffer.extend_from_slice(render_u64(&mut digits, seq));
            buffer.push(b',');
            buffer.extend_from_slice(&request.body[1..]);
            buffer.push(b'\n');
            let Some(next) = seq.checked_add(1) else {
                exhausted = true;
                break;
            };
            seq = next;
        }

        let result = if exhausted {
            Err(sequence_exhausted())
        } else {
            write_batch(&mut file, &buffer)
        };

        match result {
            Ok(()) => {
                let mut acked = first_seq;
                for request in batch.drain(..) {
                    let _ = request.ack.send(Ok(acked));
                    acked += 1;
                }
                last_seq = acked - 1;
            }
            Err(error) => fail_batch(&mut batch, &mut poison, &error),
        }
    }

    // Release the exclusive lock explicitly, before the thread exits and
    // therefore before `Drop`'s `join()` returns. Closing the file would
    // release it too, but only as a side effect: making it an ordered step
    // means a restart (or the next test) can reopen the journal the moment
    // the sink is dropped, and it keeps holding if some future refactor
    // duplicates the descriptor.
    let _ = file.unlock();
}

/// Poison the journal and refuse every record in the current batch. After a
/// failed write we cannot know what reached the disk, so the only honest
/// posture is to refuse everything from here on — which refuses every
/// subsequent tool call.
fn fail_batch(
    batch: &mut Vec<WriteRequest>,
    poison: &mut Option<Arc<io::Error>>,
    error: &io::Error,
) {
    let error = Arc::new(io::Error::new(error.kind(), error.to_string()));
    tracing::error!(
        error = %error,
        records = batch.len(),
        "audit journal write failed; journal poisoned, all further calls refused"
    );
    *poison = Some(Arc::clone(&error));
    for request in batch.drain(..) {
        let _ = request.ack.send(Err(Arc::clone(&error)));
    }
}

fn sequence_exhausted() -> io::Error {
    io::Error::other("audit journal sequence space exhausted; refusing to reuse sequence numbers")
}

/// Make a directory's own entries durable, so a newly created file is still
/// there after a power loss.
///
/// Opening a directory read-only and calling `sync_all` on it is the portable
/// spelling of `fsync(dirfd)`. Windows has no directory handle to sync and
/// returns an error here; that is not a reason to refuse to start, so the
/// failure is logged and accepted — the platform's own write ordering is what
/// backs the guarantee there.
fn sync_directory(dir: &Path) -> io::Result<()> {
    match File::open(dir).and_then(|handle| handle.sync_all()) {
        Ok(()) => Ok(()),
        Err(error) if cfg!(windows) => {
            tracing::debug!(
                error = %error,
                path = %dir.display(),
                "directory sync unavailable on this platform"
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// One write, one sync. `sync_data` rather than `sync_all`: the bytes and
/// the file length must survive a crash; the metadata timestamps need not.
fn write_batch(file: &mut File, buffer: &[u8]) -> io::Result<()> {
    file.write_all(buffer)?;
    file.sync_data()
}

/// Decimal digits in `u64::MAX`.
const MAX_U64_DIGITS: usize = 20;

/// Render `value` into `buffer`, returning the digits. Avoids the
/// `to_string()` allocation the old inline writer did per record.
fn render_u64(buffer: &mut [u8; MAX_U64_DIGITS], mut value: u64) -> &[u8] {
    let mut index = MAX_U64_DIGITS;
    loop {
        index -= 1;
        // `value % 10` is always 0..=9, so the cast cannot fail; `0` keeps
        // the fallback inside the digit range rather than producing a byte
        // that would silently corrupt a sequence number.
        buffer[index] = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
        if value == 0 {
            break;
        }
    }
    &buffer[index..]
}

/// Validate an existing journal and return the last sequence it holds.
///
/// **Strict.** The journal's whole value is that a gap or a duplicate proves
/// something went wrong, so this refuses to open anything it cannot fully
/// account for: an unparseable record, a missing `seq`, a sequence that is
/// not exactly the previous one plus one (a gap, a duplicate, or a reversal)
/// is a startup failure, not something to skip past.
///
/// The **one** repair it performs is truncating a trailing partial line — a
/// write torn by a crash, which is the one corruption an append-only file
/// can legitimately produce. Leaving it in place was the earlier bug: the
/// next append landed directly after the torn bytes, so *that* record became
/// unparseable too, and the restart after it re-issued the same sequence
/// number. One lost record plus one duplicate, from one torn write.
fn recover(file: &File, path: &Path) -> io::Result<u64> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut line = Vec::new();
    let mut complete_len: u64 = 0;
    let mut expected: u64 = 1;

    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if line.last() != Some(&b'\n') {
            // Trailing partial line: the tail of a torn write. Drop it so
            // the next append starts on a record boundary.
            tracing::warn!(
                path = %path.display(),
                bytes = read,
                sequence = expected,
                "truncating a torn trailing record from the audit journal"
            );
            file.set_len(complete_len)?;
            break;
        }

        let seq = parse_seq(&line[..read - 1]).ok_or_else(|| {
            corrupt(
                path,
                expected,
                "record is not a JSON object with a numeric `seq`",
            )
        })?;
        if seq != expected {
            return Err(corrupt(
                path,
                expected,
                &format!("out-of-order or duplicated sequence {seq}"),
            ));
        }
        expected = expected
            .checked_add(1)
            .ok_or_else(|| corrupt(path, expected, "sequence space exhausted"))?;
        complete_len += u64::try_from(read)
            .map_err(|_| corrupt(path, expected, "record length does not fit a u64"))?;
    }

    Ok(expected - 1)
}

fn parse_seq(line: &[u8]) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_slice(line).ok()?;
    value.get("seq")?.as_u64()
}

fn corrupt(path: &Path, at: u64, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "the audit journal at {} is corrupt at record {at}: {detail}. \
             Refusing to start: appending to evidence that cannot be verified \
             would hide whatever damaged it. Archive the file and investigate.",
            path.display()
        ),
    )
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::policy::{
        ClientIdentity, CredentialLabel, EnvironmentClass, PolicyDecision, Principal, TestSlot,
        UpstreamAuthority, UpstreamIdentity,
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
                label: CredentialLabel::principal_slot(
                    "jira",
                    &TestSlot("ATLASSIAN_API_TOKEN"),
                    "alice@example.com",
                ),
                vendor: "jira".to_owned(),
                environment: EnvironmentClass::Unclassified,
                authority: UpstreamAuthority::Shared,
            },
            outcome: None,
            duration_ms: None,
        }
    }

    /// Every line, parsed. Panics on anything unparseable — which is the
    /// assertion: the journal is only evidence if all of it reads back.
    fn journal_lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str(line)
                    .unwrap_or_else(|error| panic!("unparseable journal line {line:?}: {error}"))
            })
            .collect()
    }

    #[tokio::test]
    async fn appends_sequence_from_one_and_persist_every_field() {
        let dir = tempfile::tempdir().unwrap();
        let sink = JournalAuditSink::open(dir.path()).unwrap();
        assert_eq!(sink.append(&sample_event()).await.unwrap(), 1);
        assert_eq!(sink.append(&sample_event()).await.unwrap(), 2);

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

    #[tokio::test]
    async fn sequence_resumes_across_reopen_instead_of_restarting() {
        let dir = tempfile::tempdir().unwrap();
        {
            let sink = JournalAuditSink::open(dir.path()).unwrap();
            sink.append(&sample_event()).await.unwrap();
            sink.append(&sample_event()).await.unwrap();
        }
        let reopened = JournalAuditSink::open(dir.path()).unwrap();
        assert_eq!(
            reopened.append(&sample_event()).await.unwrap(),
            3,
            "restart must continue the sequence, not restart it"
        );
        assert_eq!(journal_lines(reopened.path()).len(), 3);
    }

    /// The regression: a torn trailing write must be repaired, not appended
    /// after. Before the fix the next record landed on the torn bytes
    /// (unparseable), and the restart after that re-issued sequence 2.
    #[tokio::test]
    async fn a_torn_trailing_record_is_truncated_so_the_next_append_is_readable() {
        let dir = tempfile::tempdir().unwrap();
        {
            let sink = JournalAuditSink::open(dir.path()).unwrap();
            sink.append(&sample_event()).await.unwrap();
        }
        let path = dir.path().join(JOURNAL_FILE_NAME);
        let mut contents = std::fs::read(&path).unwrap();
        contents.extend_from_slice(b"{\"seq\":2,\"kind\":\"tool_call_int");
        std::fs::write(&path, contents).unwrap();

        {
            let reopened = JournalAuditSink::open(dir.path()).unwrap();
            assert_eq!(reopened.append(&sample_event()).await.unwrap(), 2);
            let lines = journal_lines(&path);
            assert_eq!(lines.len(), 2, "the torn bytes are gone");
            assert_eq!(lines[1]["seq"], 2);
        }

        // And the sequence is not re-issued on the *next* restart either,
        // which is what the old behaviour got wrong.
        let again = JournalAuditSink::open(dir.path()).unwrap();
        assert_eq!(again.append(&sample_event()).await.unwrap(), 3);
        let lines = journal_lines(&path);
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines
                .iter()
                .map(|line| line["seq"].as_u64())
                .collect::<Vec<_>>(),
            vec![Some(1), Some(2), Some(3)]
        );
    }

    #[tokio::test]
    async fn corruption_that_is_not_a_torn_tail_refuses_to_open() {
        for damage in [
            // A corrupt record in the middle.
            &b"{not json}\n{\"seq\":2}\n"[..],
            // A gap.
            &b"{\"seq\":1}\n{\"seq\":3}\n"[..],
            // A duplicate.
            &b"{\"seq\":1}\n{\"seq\":1}\n"[..],
            // A reversal.
            &b"{\"seq\":2}\n{\"seq\":1}\n"[..],
            // A record with no sequence at all.
            &b"{\"seq\":1}\n{\"kind\":\"tool_call_intent\"}\n"[..],
            // Not starting at 1.
            &b"{\"seq\":7}\n"[..],
            // An absurd sequence that would strand the counter.
            &b"{\"seq\":18446744073709551615}\n"[..],
            // A blank line.
            &b"{\"seq\":1}\n\n"[..],
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(JOURNAL_FILE_NAME), damage).unwrap();
            let opened = JournalAuditSink::open(dir.path());
            assert!(
                opened.is_err(),
                "must refuse to append to a journal it cannot verify: {:?}",
                String::from_utf8_lossy(damage)
            );
        }
    }

    #[test]
    fn a_second_writer_cannot_open_the_same_journal() {
        let dir = tempfile::tempdir().unwrap();
        let _held = JournalAuditSink::open(dir.path()).unwrap();
        let second = JournalAuditSink::open(dir.path());
        assert!(
            second.is_err(),
            "two writers would independently issue the same sequence numbers"
        );
    }

    #[tokio::test]
    async fn concurrent_appends_are_contiguous_and_ordered() {
        let dir = tempfile::tempdir().unwrap();
        let sink = Arc::new(JournalAuditSink::open(dir.path()).unwrap());
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..64 {
            let sink = Arc::clone(&sink);
            tasks.spawn(async move { sink.append(&sample_event()).await.unwrap() });
        }
        let mut seqs: Vec<u64> = Vec::new();
        while let Some(result) = tasks.join_next().await {
            seqs.push(result.unwrap());
        }
        seqs.sort_unstable();
        assert_eq!(
            seqs,
            (1..=64).collect::<Vec<u64>>(),
            "no gaps, no duplicates"
        );

        // Written order and sequence order are the same thing.
        let on_disk: Vec<u64> = journal_lines(sink.path())
            .iter()
            .map(|line| line["seq"].as_u64().unwrap())
            .collect();
        assert_eq!(on_disk, (1..=64).collect::<Vec<u64>>());
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

    #[test]
    fn sequence_digits_render_without_allocating() {
        let mut buffer = [0u8; MAX_U64_DIGITS];
        assert_eq!(render_u64(&mut buffer, 0), b"0");
        assert_eq!(render_u64(&mut buffer, 1), b"1");
        assert_eq!(render_u64(&mut buffer, 1234), b"1234");
        assert_eq!(render_u64(&mut buffer, u64::MAX), b"18446744073709551615");
    }
}

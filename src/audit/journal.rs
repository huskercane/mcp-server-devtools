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
//! - Startup syncs the journal **directory** — unconditionally, plus every
//!   ancestor directory it had to create. A file sync makes contents durable
//!   but not the directory entry naming the file, so without this the very
//!   first acknowledged record could survive as bytes in a file that does not
//!   exist after a power loss. Where the platform cannot fsync a directory at
//!   all, the server refuses to *create* the directory or the journal file —
//!   both must already exist — and never calls the sync it could not honor.
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
use std::sync::atomic::{AtomicBool, Ordering};

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
    /// Set by the writer on the first failed write or sync. Read by
    /// [`AuditSink::is_available`] so the HTTP health endpoint can report
    /// a gateway that will refuse every call.
    poisoned: Arc<AtomicBool>,
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
        // On a platform with no directory fsync there is no way to make a
        // *newly created* directory entry durable, so the honest posture is
        // to require the operator to create it in advance rather than to
        // create one and claim a guarantee we cannot deliver. The same
        // applies to the journal file itself: this function never calls
        // `sync_directory` on this platform (see below), so the file's own
        // directory entry must already be durable before `open` runs, not
        // merely created by it.
        if cfg!(windows) && !dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "the audit journal directory {} does not exist. On this platform the \
                     server will not create it: a newly created directory entry cannot be \
                     made durable here, and the audit RPO=0 guarantee depends on it. \
                     Create the directory (on a volume with write barriers enabled) and \
                     start again.",
                    dir.display()
                ),
            ));
        }
        let path = dir.join(JOURNAL_FILE_NAME);
        if cfg!(windows) && !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "the audit journal file {} does not exist. On this platform the server \
                     will not create it: a newly created file's directory entry cannot be \
                     made durable here, and the audit RPO=0 guarantee depends on it. Create \
                     an empty {JOURNAL_FILE_NAME} file (on a volume with write barriers \
                     enabled) and start again.",
                    path.display()
                ),
            ));
        }

        // Every directory this call has to create, outermost first, so each
        // new entry can be made durable in its own parent afterwards. On
        // Windows this is always empty: the directory check above already
        // required `dir` to exist.
        let created = create_dir_all_tracked(dir)?;
        // On every other platform the file may be newly created here, and
        // its directory entry is made durable below. On Windows the
        // preflight check above already required it to exist, so opening
        // never creates it.
        let file = OpenOptions::new()
            .create(!cfg!(windows))
            .read(true)
            .append(true)
            .open(&path)?;

        // `sync_data` on the file makes its *contents* durable; it says
        // nothing about the directory entry that names it. On a brand-new
        // journal that gap swallows the whole RPO=0 claim: the first intent
        // could be written and synced, the call could dispatch, and a power
        // loss before the entry reached storage would leave no
        // `audit-journal.jsonl` at all on restart — an acknowledged record
        // with no file to be in.
        //
        // Four things this has to get right, each of which was wrong once:
        //
        // 1. Syncing only when the file looked new left a retry hole: if the
        //    sync failed after the file was created, the next startup saw an
        //    existing file and skipped it forever. So the journal directory
        //    is synced **unconditionally**, every startup. It is one fsync
        //    per process against a directory whose entries rarely change.
        // 2. If `create_dir_all` created the directory itself, that
        //    directory's own entry lives in *its* parent and needs syncing
        //    too — and so on up the chain. Hence `created`, walked
        //    innermost-first below.
        // 3. It has to be true on every platform, not just the ones where
        //    the call happens to succeed — see `sync_directory`.
        // 4. On a platform where `sync_directory` cannot succeed at all, the
        //    preflight checks above — not this call — are what makes the
        //    guarantee hold: they refuse to start unless the directory and
        //    file were already durable before `open` ran, so there is never
        //    an unsynced creation to account for here. An earlier revision
        //    stated that as the reason `sync_directory` was safe to call
        //    unconditionally on every platform, but the call below ran
        //    regardless of platform and `sync_directory` fails by
        //    construction on a platform with no directory handle to sync —
        //    so `open` could never succeed there at all, pre-created
        //    directory or not. This call is skipped on that platform, not
        //    merely expected to succeed vacuously.
        for new_dir in created.iter().rev() {
            if let Some(parent) = new_dir.parent() {
                sync_directory(parent)?;
            }
        }
        if !cfg!(windows) {
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
        let poisoned = Arc::new(AtomicBool::new(false));
        let poison_flag = Arc::clone(&poisoned);
        let writer = std::thread::Builder::new()
            .name("audit-journal".to_owned())
            .spawn(move || writer_loop(file, last_seq, receiver, &poison_flag))?;

        Ok(Self {
            requests: Some(requests),
            writer: Some(writer),
            path,
            poisoned,
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

    fn is_available(&self) -> bool {
        self.requests.is_some() && !self.poisoned.load(Ordering::Acquire)
    }
}

/// The writer thread: the only place a sequence number is assigned and the
/// only place the file is touched after `open`.
fn writer_loop(
    mut file: File,
    mut last_seq: u64,
    mut receiver: mpsc::Receiver<WriteRequest>,
    poisoned: &AtomicBool,
) {
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
            fail_batch(&mut batch, &mut poison, poisoned, &sequence_exhausted());
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
            Err(error) => fail_batch(&mut batch, &mut poison, poisoned, &error),
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
    poisoned: &AtomicBool,
    error: &io::Error,
) {
    let error = Arc::new(io::Error::new(error.kind(), error.to_string()));
    tracing::error!(
        error = %error,
        records = batch.len(),
        "audit journal write failed; journal poisoned, all further calls refused"
    );
    *poison = Some(Arc::clone(&error));
    poisoned.store(true, Ordering::Release);
    for request in batch.drain(..) {
        let _ = request.ack.send(Err(Arc::clone(&error)));
    }
}

fn sequence_exhausted() -> io::Error {
    io::Error::other("audit journal sequence space exhausted; refusing to reuse sequence numbers")
}

/// `create_dir_all`, reporting which directories it actually created,
/// outermost first.
///
/// `std::fs::create_dir_all` does not say what it made, and the difference
/// matters: a directory it created has an entry in its parent that is not yet
/// durable.
fn create_dir_all_tracked(dir: &Path) -> io::Result<Vec<PathBuf>> {
    if dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut missing: Vec<PathBuf> = Vec::new();
    let mut cursor = Some(dir);
    while let Some(path) = cursor {
        if path.is_dir() {
            break;
        }
        missing.push(path.to_path_buf());
        cursor = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
    }
    std::fs::create_dir_all(dir)?;
    // Collected innermost-first; hand back outermost-first.
    missing.reverse();
    Ok(missing)
}

/// Make a directory's own entries durable, so a newly created file is still
/// there after a power loss.
///
/// Opening a directory read-only and calling `sync_all` on it is the portable
/// spelling of `fsync(dirfd)`. Windows has no directory handle to sync — this
/// call fails there by construction, for any directory, whether or not it
/// already existed. An earlier revision turned that failure into `Ok(())`,
/// which made the RPO=0 claim knowingly false on that platform rather than
/// merely unsupported; a later one propagated the error but still called
/// this function unconditionally on every platform, so [`JournalAuditSink::
/// open`] could never succeed on Windows at all. This function is never
/// called on Windows now: `open`'s preflight checks require the directory
/// *and* the journal file to already exist there, so there is never an
/// unsynced creation for this call to account for, and it does not run.
fn sync_directory(dir: &Path) -> io::Result<()> {
    File::open(dir).and_then(|handle| handle.sync_all())
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
            // `set_len` only changes what the file reports; without a sync
            // the shorter length can itself be lost to a second crash before
            // the next batch's `sync_data`, and recovery would replay the
            // same torn bytes again. `sync_all`, not `sync_data`: this
            // changes the file's length, which is metadata, and `sync_data`
            // is not required to persist metadata that isn't needed to
            // retrieve the data — length is exactly that case, so don't rely
            // on the platform treating it as such. This runs once at
            // startup, not on the hot append path, so the extra cost is
            // fine.
            file.sync_all()?;
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
                    &TestSlot::new("jira", "ATLASSIAN_API_TOKEN"),
                    "alice@example.com",
                ),
                vendor: "jira".to_owned(),
                environment: EnvironmentClass::Unclassified,
                authority: UpstreamAuthority::Shared,
            },
            action: None,
            outcome: None,
            duration_ms: None,
            egress: None,
        }
    }

    /// Satisfy the Windows-only preflight `open` now enforces: the
    /// directory and the journal file must already exist there, because
    /// this platform can never durably sync a newly created directory
    /// entry (see `sync_directory`). A no-op on every other platform, where
    /// `open` is the one that creates both.
    ///
    /// Tests that call `JournalAuditSink::open` on a fresh directory need
    /// this first; tests that write the journal file's contents directly
    /// before opening (`std::fs::write`) already satisfy it, because that
    /// write creates the file.
    fn ensure_windows_can_open(dir: &Path) {
        if cfg!(windows) {
            std::fs::create_dir_all(dir).unwrap();
            let path = dir.join(JOURNAL_FILE_NAME);
            if !path.exists() {
                File::create(&path).unwrap();
            }
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
        ensure_windows_can_open(dir.path());
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
        ensure_windows_can_open(dir.path());
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
        ensure_windows_can_open(dir.path());
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
        ensure_windows_can_open(dir.path());
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
        ensure_windows_can_open(dir.path());
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

    /// A file sync does not make the directory entry naming the file
    /// durable, and neither does syncing a directory whose own entry is new.
    ///
    /// Not on Windows: auto-creating a directory that does not exist yet is
    /// exactly what this platform's preflight check refuses to do, because
    /// it cannot durably sync the entry that creation would add. See
    /// `windows_refuses_to_auto_create_the_journal_directory` for the
    /// Windows-side counterpart of this test.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn creating_a_nested_journal_directory_syncs_every_new_entry() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("a").join("b").join("journal");
        assert!(!nested.exists());

        let sink = JournalAuditSink::open(&nested).unwrap();
        assert_eq!(sink.append(&sample_event()).await.unwrap(), 1);
        assert!(nested.join(JOURNAL_FILE_NAME).is_file());
        drop(sink);

        // Reopening an existing tree creates nothing and still syncs — the
        // retry hole was skipping the sync whenever the file already
        // existed, which made a failed first sync permanent.
        let reopened = JournalAuditSink::open(&nested).unwrap();
        assert_eq!(reopened.append(&sample_event()).await.unwrap(), 2);
    }

    /// The counterpart of `creating_a_nested_journal_directory_syncs_every_new_entry`
    /// for the platform that test is skipped on: `open` must refuse a
    /// directory that does not exist yet, not create it, because it cannot
    /// durably sync the new entry (`sync_directory` fails unconditionally
    /// on this platform).
    #[cfg(windows)]
    #[test]
    fn windows_refuses_to_auto_create_the_journal_directory() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("a").join("b").join("journal");
        assert!(!nested.exists());

        let opened = JournalAuditSink::open(&nested);
        assert!(
            opened.is_err(),
            "a journal directory that does not exist yet must not be \
             auto-created on this platform"
        );
    }

    /// The regression this fix closes: an earlier revision required only
    /// the directory to be pre-created here, then called `sync_directory`
    /// on it unconditionally regardless of platform. `sync_directory` fails
    /// by construction on this platform, so `open` could never succeed at
    /// all — a pre-created directory did not help. `open` must now succeed
    /// once both the directory and the journal file already exist, and
    /// refuse when only the directory does.
    #[cfg(windows)]
    #[test]
    fn windows_requires_both_the_directory_and_the_journal_file_precreated() {
        let dir = tempfile::tempdir().unwrap();

        let missing_file = JournalAuditSink::open(dir.path());
        assert!(
            missing_file.is_err(),
            "must refuse when only the directory is pre-created"
        );

        File::create(dir.path().join(JOURNAL_FILE_NAME)).unwrap();
        let sink = JournalAuditSink::open(dir.path());
        assert!(
            sink.is_ok(),
            "must open once both the directory and the journal file exist: {:?}",
            sink.err()
        );
    }

    #[test]
    fn create_dir_all_tracked_reports_only_what_it_made() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("x").join("y");

        let created = create_dir_all_tracked(&nested).unwrap();
        assert_eq!(
            created,
            vec![root.path().join("x"), nested.clone()],
            "outermost first, so each entry can be synced in its parent"
        );
        assert!(nested.is_dir());

        // Second call creates nothing, so there is nothing new to sync.
        assert!(create_dir_all_tracked(&nested).unwrap().is_empty());
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

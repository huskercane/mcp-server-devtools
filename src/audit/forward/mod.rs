//! Forwarding the journal to a SIEM (plan §3.3, §3.9 "Audit forwarding",
//! WP C.3).
//!
//! The journal is the source of truth and the gateway's append path never
//! waits on anything here. A [`Shipper`] runs on the `control` role (and in
//! `--role all`), *reads* the journal file from the last sequence the
//! receiver acknowledged, hands batches to an [`AuditForwarder`] adapter,
//! and persists its cursor once — and only once — the adapter has
//! acknowledged. A restart resumes from the cursor; a receiver outage
//! leaves the cursor where it was and the records where they are.
//!
//! ## Why a reader, not a second sink
//!
//! The journal's writer thread already does the one thing that must never
//! block a tool call — the durable append. Forwarding by tapping that
//! thread would put a network receiver on the request path by another
//! route; forwarding from a channel would lose what was queued when the
//! process died. Reading the file that is already durable costs nothing on
//! the request path, survives restarts by construction, and forwards the
//! same bytes `audit verify` checks — the receiver holds the journal's
//! lines, not a rendering of them.
//!
//! ## What the cursor guarantees
//!
//! The cursor is written after acknowledgement, so a crash between the two
//! re-sends the last batch: delivery is at least once, and the record's
//! `seq` is the receiver's deduplication key. It is never written ahead of
//! an acknowledgement, so a record is never skipped. It is written
//! atomically (temporary file, rename, directory sync), so a crash during
//! the write leaves the previous cursor. It records the byte offset and the
//! chain value beside the sequence, so a resume seeks rather than
//! re-reading the journal from the start, and the chain the shipper
//! carries is the same one `audit verify` recomputes.
//!
//! ## Failure posture
//!
//! A receiver that cannot be reached at startup does **not** stop the
//! process (ADR-011: forwarded *asynchronously*): the records are durable
//! locally, and turning a SIEM outage into an MCP outage would sacrifice
//! the evidence pipeline's independence for nothing. A configuration that
//! cannot be *built* — an unknown scheme, a CA file that does not parse, a
//! state directory that cannot be written — refuses startup, as every
//! other backend does (§3.9). At runtime, a failed delivery backs off
//! (doubling, capped at a minute), marks [`ForwardHealth`] degraded so the
//! health banner says forwarding is failing, and retries the same batch. A
//! journal the shipper cannot read past — a sequence gap, an unparseable
//! line — is reported and never skipped: the cursor stays before it, the
//! health banner degrades, and an operator runs `audit verify`. A torn
//! trailing line is the writer mid-append and is simply retried next round.

pub mod http;
pub mod syslog;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::checkpoint::Chain;
use super::reader::{JournalReader, Position, ReadError, Record};
use crate::ports::{AuditForwarder, ForwardError, ForwardRecord};

/// The cursor file's name inside the state directory.
pub const CURSOR_FILE_NAME: &str = "audit-forward-cursor.json";

/// Config key: where records are forwarded. `syslog+tls://host[:port]`,
/// `https://…/services/collector[/event]` (Splunk HEC), or any other
/// `https://` URL (generic JSON). Setting it enables forwarding on the
/// control role.
pub const URL_KEY: &str = "MCP_AUDIT_FORWARD_URL";
/// Config key: `hec` or `json`, when the URL alone does not say. Default:
/// `hec` when the path contains `/services/collector`, else `json`.
pub const FORMAT_KEY: &str = "MCP_AUDIT_FORWARD_FORMAT";
/// Config key: the HEC token or bearer token an HTTP receiver expects. May
/// be a secret reference. Never logged.
pub const TOKEN_KEY: &str = "MCP_AUDIT_FORWARD_TOKEN";
/// Config key: the journal directory to forward. Defaults to
/// `MCP_AUDIT_JOURNAL_DIR`; in the split topology the control replica
/// points it at the gateway's journal volume, mounted read-only.
pub const JOURNAL_DIR_KEY: &str = "MCP_AUDIT_FORWARD_JOURNAL_DIR";
/// Config key: where the cursor is kept. Defaults to the forwarded journal
/// directory; must be writable, so a read-only journal mount needs its own.
pub const STATE_DIR_KEY: &str = "MCP_AUDIT_FORWARD_STATE_DIR";
/// Config key: most records per delivery (default 256, 1–4096).
pub const BATCH_KEY: &str = "MCP_AUDIT_FORWARD_BATCH";
/// Config key: seconds between rounds when caught up (default 5, 1–3600).
pub const INTERVAL_KEY: &str = "MCP_AUDIT_FORWARD_INTERVAL_SECONDS";
/// Config key: the name this process reports itself as to the receiver
/// (syslog `HOSTNAME`, HEC `host`). Defaults to `$HOSTNAME`, else the
/// package name.
pub const ORIGIN_KEY: &str = "MCP_AUDIT_FORWARD_ORIGIN";
/// Config key: a PEM file holding the CA that signed the receiver's
/// certificate, for a private CA.
pub const CA_FILE_KEY: &str = "MCP_AUDIT_FORWARD_CA_FILE";
/// Config key (syslog): a PEM client certificate for mutual TLS.
pub const CLIENT_CERT_KEY: &str = "MCP_AUDIT_FORWARD_CLIENT_CERT";
/// Config key (syslog): the PEM (PKCS#8, SEC1, or PKCS#1) key for it.
pub const CLIENT_KEY_KEY: &str = "MCP_AUDIT_FORWARD_CLIENT_KEY";
/// Config key: per-delivery timeout in seconds (default 10, 1–300).
pub const TIMEOUT_KEY: &str = "MCP_AUDIT_FORWARD_TIMEOUT_SECONDS";

pub const DEFAULT_BATCH: usize = 256;
pub const MAX_BATCH: usize = 4096;
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);
pub const MIN_INTERVAL: Duration = Duration::from_secs(1);
pub const MAX_INTERVAL: Duration = Duration::from_hours(1);
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
pub const MIN_TIMEOUT: Duration = Duration::from_secs(1);
pub const MAX_TIMEOUT: Duration = Duration::from_mins(5);
/// The longest a failing shipper waits between retries.
pub const MAX_BACKOFF: Duration = Duration::from_mins(1);

/// The persisted cursor: the last acknowledged sequence and where the
/// next record starts. `journal` names the file it applies to, so a cursor
/// left behind for a different journal is not mistaken for this one's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// Last acknowledged sequence; `0` before anything was forwarded.
    pub acknowledged: u64,
    /// Byte offset of the next unforwarded record.
    pub offset: u64,
    /// Chain value over everything acknowledged (`sha256:…`).
    pub chain: String,
    /// The journal file this cursor is for.
    pub journal: String,
}

impl Cursor {
    fn fresh(journal: &Path) -> Self {
        Self {
            acknowledged: 0,
            offset: 0,
            chain: Chain::genesis().label(),
            journal: journal.display().to_string(),
        }
    }

    fn position(&self) -> Option<Position> {
        Some(Position {
            next_seq: self.acknowledged.checked_add(1)?,
            offset: self.offset,
            chain: Chain::parse(&self.chain)?,
        })
    }

    fn from_position(position: Position, journal: &Path) -> Self {
        Self {
            acknowledged: position.next_seq - 1,
            offset: position.offset,
            chain: position.chain.label(),
            journal: journal.display().to_string(),
        }
    }
}

/// Why a round did not forward.
#[derive(Debug)]
pub enum ShipError {
    /// The journal cannot be read past the cursor: a gap, an unparseable
    /// line, or an I/O error. Never skipped.
    Journal(ReadError),
    /// The receiver did not acknowledge.
    Deliver(ForwardError),
    /// The cursor could not be persisted after an acknowledgement. The
    /// batch will be re-sent (at least once).
    Cursor(io::Error),
}

impl ShipError {
    /// The health-banner category.
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            Self::Journal(_) => "journal_unreadable",
            Self::Deliver(error) => error.category,
            Self::Cursor(_) => "cursor_unwritable",
        }
    }
}

impl std::fmt::Display for ShipError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Journal(error) => write!(formatter, "journal unreadable: {error}"),
            Self::Deliver(error) => write!(formatter, "delivery failed: {error}"),
            Self::Cursor(error) => write!(formatter, "cursor not persisted: {error}"),
        }
    }
}

impl std::error::Error for ShipError {}

/// What one round forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Round {
    /// Records acknowledged this round.
    pub forwarded: u64,
    /// Whether the round stopped because the journal had no more complete
    /// records (as opposed to a full batch).
    pub caught_up: bool,
}

/// Whether forwarding is keeping up, for the health banner and tests.
#[derive(Debug, Default)]
pub struct ForwardHealth {
    degraded: Mutex<Option<&'static str>>,
    acknowledged: AtomicU64,
    rounds: AtomicU64,
}

impl ForwardHealth {
    /// The failure category while forwarding is failing.
    #[must_use]
    pub fn degraded(&self) -> Option<&'static str> {
        *self
            .degraded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set_degraded(&self, category: Option<&'static str>) {
        *self
            .degraded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = category;
    }

    /// The last sequence the receiver acknowledged.
    #[must_use]
    pub fn acknowledged(&self) -> u64 {
        self.acknowledged.load(Ordering::Acquire)
    }

    /// Rounds completed, successful or not; tests wait on it.
    #[must_use]
    pub fn rounds(&self) -> u64 {
        self.rounds.load(Ordering::Acquire)
    }
}

/// Reads the journal from the cursor and drives one forwarder.
pub struct Shipper {
    forwarder: Arc<dyn AuditForwarder>,
    journal: PathBuf,
    cursor_path: PathBuf,
    cursor: Cursor,
    batch: usize,
}

impl Shipper {
    /// Open the shipper for the journal in `journal_dir`, keeping its cursor
    /// in `state_dir`. An existing cursor for this journal is resumed; a
    /// cursor for another journal, or one that does not parse, is
    /// discarded with a warning (forwarding restarts from sequence 1 —
    /// duplicates at the receiver, never a hole).
    ///
    /// # Errors
    ///
    /// When `state_dir` cannot be created or is not writable.
    pub fn open(
        forwarder: Arc<dyn AuditForwarder>,
        journal_dir: &Path,
        state_dir: &Path,
        batch: usize,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let journal = journal_dir.join(super::journal::JOURNAL_FILE_NAME);
        let cursor_path = state_dir.join(CURSOR_FILE_NAME);
        // Prove the directory is writable now, not at the first
        // acknowledgement.
        let probe = state_dir.join(format!("{CURSOR_FILE_NAME}.probe"));
        std::fs::write(&probe, b"")?;
        let _ = std::fs::remove_file(&probe);
        let cursor = load_cursor(&cursor_path, &journal);
        Ok(Self {
            forwarder,
            journal,
            cursor_path,
            cursor,
            batch: batch.clamp(1, MAX_BATCH),
        })
    }

    /// The current cursor.
    #[must_use]
    pub fn cursor(&self) -> &Cursor {
        &self.cursor
    }

    /// The adapter in use.
    #[must_use]
    pub fn forwarder_name(&self) -> &'static str {
        self.forwarder.name()
    }

    /// Forward one batch: everything complete in the journal past the
    /// cursor, up to the batch size. `Ok(None)` when there was nothing.
    ///
    /// # Errors
    ///
    /// [`ShipError`]; the cursor is unchanged on every error.
    pub async fn forward_batch(&mut self) -> Result<Option<Round>, ShipError> {
        let journal = self.journal.clone();
        let position = self.cursor.position().unwrap_or_else(Position::start);
        let batch = self.batch;
        let read = tokio::task::spawn_blocking(move || read_batch(&journal, position, batch))
            .await
            .map_err(|error| ShipError::Journal(ReadError::Io(io::Error::other(error))))??;
        let Some(read) = read else {
            return Ok(None);
        };
        let views: Vec<ForwardRecord<'_>> = read.records.iter().map(view).collect();
        self.forwarder
            .deliver(&views)
            .await
            .map_err(ShipError::Deliver)?;
        drop(views);
        let forwarded = read.records.len() as u64;
        let cursor = Cursor::from_position(read.after, &self.journal);
        let path = self.cursor_path.clone();
        let to_write = cursor.clone();
        tokio::task::spawn_blocking(move || write_cursor(&path, &to_write))
            .await
            .map_err(io::Error::other)
            .and_then(|result| result)
            .map_err(ShipError::Cursor)?;
        self.cursor = cursor;
        Ok(Some(Round {
            forwarded,
            caught_up: read.caught_up,
        }))
    }

    /// Forward until the journal has nothing more, or a delivery fails.
    ///
    /// # Errors
    ///
    /// The first [`ShipError`]; everything before it was acknowledged and
    /// the cursor moved.
    pub async fn drain(&mut self) -> Result<u64, ShipError> {
        let mut forwarded = 0;
        loop {
            match self.forward_batch().await? {
                None => return Ok(forwarded),
                Some(round) => {
                    forwarded += round.forwarded;
                    if round.caught_up {
                        return Ok(forwarded);
                    }
                }
            }
        }
    }

    /// Run until `cancel` fires: drain, then wait `interval` (or a backoff
    /// after a failure), and drain again. Reports into `health`.
    pub async fn run(
        mut self,
        health: Arc<ForwardHealth>,
        interval: Duration,
        cancel: tokio_util::sync::CancellationToken,
    ) {
        let interval = interval.clamp(MIN_INTERVAL, MAX_INTERVAL);
        let mut failures: u32 = 0;
        loop {
            match self.drain().await {
                Ok(forwarded) => {
                    if forwarded > 0 {
                        tracing::debug!(
                            forwarder = self.forwarder.name(),
                            forwarded,
                            acknowledged = self.cursor.acknowledged,
                            "audit records forwarded"
                        );
                    }
                    if health.degraded().is_some() {
                        tracing::info!(
                            forwarder = self.forwarder.name(),
                            acknowledged = self.cursor.acknowledged,
                            "audit forwarding recovered"
                        );
                    }
                    failures = 0;
                    health.set_degraded(None);
                }
                Err(error) => {
                    let category = error.category();
                    if health.degraded() != Some(category) {
                        tracing::warn!(
                            forwarder = self.forwarder.name(),
                            failure = category,
                            acknowledged = self.cursor.acknowledged,
                            "audit forwarding failed; journal retained, will retry: {error}"
                        );
                    }
                    health.set_degraded(Some(category));
                    failures = failures.saturating_add(1);
                }
            }
            health
                .acknowledged
                .store(self.cursor.acknowledged, Ordering::Release);
            health.rounds.fetch_add(1, Ordering::AcqRel);
            let wait = if failures == 0 {
                interval
            } else {
                interval
                    .saturating_mul(1u32 << failures.min(10))
                    .min(MAX_BACKOFF)
                    .max(interval)
            };
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(wait) => {}
            }
        }
    }
}

/// A batch read from the journal and where the reader stood after it.
struct ReadBatch {
    records: Vec<Record>,
    after: Position,
    caught_up: bool,
}

/// Read up to `batch` complete records from `position`. `Ok(None)` when
/// there is nothing (no journal yet, or nothing past the cursor).
fn read_batch(
    journal: &Path,
    position: Position,
    batch: usize,
) -> Result<Option<ReadBatch>, ShipError> {
    let mut reader = match JournalReader::resume(journal, position) {
        Ok(reader) => reader,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ShipError::Journal(ReadError::Io(error))),
    };
    let mut records = Vec::with_capacity(batch);
    let mut caught_up = true;
    for next in reader.by_ref() {
        match next {
            Ok(record) => {
                records.push(record);
                if records.len() == batch {
                    caught_up = false;
                    break;
                }
            }
            // The writer is mid-append; what precedes the tear is complete.
            Err(ReadError::TornTail { .. }) => break,
            Err(error) => return Err(ShipError::Journal(error)),
        }
    }
    if records.is_empty() {
        return Ok(None);
    }
    Ok(Some(ReadBatch {
        after: reader.position(),
        records,
        caught_up,
    }))
}

/// The forwarder's view of a record.
fn view(record: &Record) -> ForwardRecord<'_> {
    let json = record.line.strip_suffix(b"\n").unwrap_or(&record.line);
    ForwardRecord {
        seq: record.seq,
        kind: &record.kind,
        timestamp: record.timestamp(),
        adverse: is_adverse(record),
        json,
    }
}

/// A denial or a refusal: an egress denial record, a `*_rejected` control
/// record, or a tool-call record whose decision is `deny`.
fn is_adverse(record: &Record) -> bool {
    if record.kind.ends_with("_rejected") || record.kind == "egress_decision" {
        return true;
    }
    record
        .value
        .get("decision")
        .and_then(|decision| decision.get("effect"))
        .and_then(serde_json::Value::as_str)
        == Some("deny")
}

fn load_cursor(path: &Path, journal: &Path) -> Cursor {
    let fresh = Cursor::fresh(journal);
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return fresh,
        Err(error) => {
            tracing::warn!(path = %path.display(), error = %error, "audit forward cursor unreadable; forwarding from the start");
            return fresh;
        }
    };
    match serde_json::from_slice::<Cursor>(&bytes) {
        Ok(cursor) if cursor.journal == fresh.journal && cursor.position().is_some() => cursor,
        Ok(cursor) => {
            tracing::warn!(
                path = %path.display(),
                cursor_journal = %cursor.journal,
                journal = %fresh.journal,
                "audit forward cursor is for another journal; forwarding from the start"
            );
            fresh
        }
        Err(error) => {
            tracing::warn!(path = %path.display(), error = %error, "audit forward cursor does not parse; forwarding from the start");
            fresh
        }
    }
}

/// Write the cursor atomically: temporary file, sync, rename, directory
/// sync — the `DirectoryCheckpointSink` recipe.
fn write_cursor(path: &Path, cursor: &Cursor) -> io::Result<()> {
    use std::io::Write as _;
    let temp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec(cursor).map_err(io::Error::other)?;
    let mut file = std::fs::File::create(&temp)?;
    let written = file.write_all(&bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    std::fs::rename(&temp, path)?;
    if let Some(dir) = path.parent()
        && let Ok(handle) = std::fs::File::open(dir)
    {
        let _ = handle.sync_all();
    }
    Ok(())
}

/// Read [`BATCH_KEY`], clamped.
#[must_use]
pub fn batch_size(config: &crate::config::Config) -> usize {
    config
        .get(BATCH_KEY)
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_BATCH)
        .clamp(1, MAX_BATCH)
}

/// Read [`INTERVAL_KEY`], clamped.
#[must_use]
pub fn interval(config: &crate::config::Config) -> Duration {
    config
        .get(INTERVAL_KEY)
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map_or(DEFAULT_INTERVAL, Duration::from_secs)
        .clamp(MIN_INTERVAL, MAX_INTERVAL)
}

/// Read [`TIMEOUT_KEY`], clamped.
#[must_use]
pub fn timeout(config: &crate::config::Config) -> Duration {
    config
        .get(TIMEOUT_KEY)
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map_or(DEFAULT_TIMEOUT, Duration::from_secs)
        .clamp(MIN_TIMEOUT, MAX_TIMEOUT)
}

/// Read [`ORIGIN_KEY`], else `$HOSTNAME`, else the package name.
#[must_use]
pub fn origin(config: &crate::config::Config) -> String {
    config
        .get(ORIGIN_KEY)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            std::env::var("HOSTNAME")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| crate::constants::PACKAGE_NAME.to_owned())
}

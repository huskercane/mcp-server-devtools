//! Structured, self-rotating audit log for MCP tool calls.
//!
//! Audit records deliberately exclude tool arguments and response content. The
//! log is independent of `tracing` and `RUST_LOG`, so diagnostic filtering
//! cannot accidentally disable the audit trail. Request threads only enqueue
//! serialized records; a dedicated worker owns all file I/O and rotation.

pub mod checkpoint;
pub mod export;
pub mod journal;
pub mod metrics;
pub mod reader;
pub mod verify;

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;

use crate::constants::UNSCOPED_PACKAGE_NAME;

const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_MAX_FILES: usize = 5;
const DEFAULT_RETENTION_DAYS: u64 = 30;
const DEFAULT_RETENTION_MAX_BYTES: u64 = 100 * 1024 * 1024;

static AUDIT_LOG: OnceLock<Option<AuditLog>> = OnceLock::new();

struct AuditLog {
    session_id: String,
    sender: mpsc::Sender<AuditMessage>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

enum AuditMessage {
    Record(Vec<u8>),
    Shutdown,
}

struct RotatingWriter {
    path: PathBuf,
    file: Option<File>,
    len: u64,
    max_bytes: u64,
    max_files: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditRecord<'a> {
    timestamp: String,
    event: &'a str,
    session_id: &'a str,
    process_id: u32,
    call_id: &'a str,
    request_id: &'a str,
    tool: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u128>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CacheEvent<'a> {
    pub timestamp: String,
    pub event: &'static str,
    pub session_id: &'a str,
    pub process_id: u32,
    pub vendor: &'a str,
    pub cache_key: &'a str,
    pub outcome: &'a str,
    pub reason: Option<&'a str>,
    pub action: Option<&'a str>,
    pub ttl_ms: Option<u128>,
    pub age_ms: Option<u128>,
    pub remaining_ttl_ms: Option<u128>,
    pub upstream_latency_ms: Option<u128>,
    pub response_bytes: Option<usize>,
    pub entry_bytes: Option<usize>,
    pub compressed: Option<bool>,
    pub cumulative_hits: u64,
    pub cumulative_misses: u64,
    pub entries: usize,
    pub cache_bytes: usize,
}

/// In-flight tool-call audit state. Dropping it without calling [`complete`]
/// leaves the start record behind, making interrupted calls visible.
pub struct AuditCall {
    call_id: String,
    request_id: String,
    tool: String,
    client_name: Option<String>,
    client_version: Option<String>,
    started: Instant,
}

impl AuditCall {
    /// Tool name this call was started for. Used by the enterprise audit
    /// path so the outcome event names the same tool without re-borrowing
    /// the (already consumed) request.
    pub fn tool_name(&self) -> &str {
        &self.tool
    }

    /// MCP request id this call was started for. Read by the enterprise
    /// audit path instead of keeping a second owned copy alive across the
    /// whole call — local mode allocates the id exactly once.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn start(
        tool: &str,
        request_id: String,
        client_name: Option<String>,
        client_version: Option<String>,
    ) -> Self {
        let call = Self {
            call_id: uuid::Uuid::new_v4().to_string(),
            request_id,
            tool: tool.to_owned(),
            client_name,
            client_version,
            started: Instant::now(),
        };
        write_record(&call, "tool_call_started", None, None);
        call
    }

    pub fn complete(self, outcome: &str) {
        let duration_ms = self.started.elapsed().as_millis();
        write_record(
            &self,
            "tool_call_completed",
            Some(outcome),
            Some(duration_ms),
        );
    }
}

/// Initialise the audit log for this process session. Idempotent.
pub fn init(log_dir: &Path, session_id: &str) {
    AUDIT_LOG.get_or_init(|| {
        if !enabled(std::env::var("AUDIT_LOG").ok().as_deref()) {
            return None;
        }

        let max_bytes = env_u64("AUDIT_LOG_MAX_BYTES", DEFAULT_MAX_BYTES).max(1);
        let max_files = env_usize("AUDIT_LOG_MAX_FILES", DEFAULT_MAX_FILES).max(1);
        let path = log_dir.join(format!("{UNSCOPED_PACKAGE_NAME}.{session_id}.audit.jsonl"));
        let writer = RotatingWriter::open(path, max_bytes, max_files).ok()?;
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("audit-writer".into())
            .spawn(move || audit_worker(writer, &receiver))
            .ok()?;

        let retention_days = env_u64("AUDIT_LOG_RETENTION_DAYS", DEFAULT_RETENTION_DAYS);
        let retention_bytes = env_u64("AUDIT_LOG_RETENTION_MAX_BYTES", DEFAULT_RETENTION_MAX_BYTES);
        let dir = log_dir.to_owned();
        let keep_prefix = format!("{UNSCOPED_PACKAGE_NAME}.{session_id}.audit.jsonl");
        std::thread::Builder::new()
            .name("audit-retention".into())
            .spawn(move || {
                let _ = sweep_retention(
                    &dir,
                    &keep_prefix,
                    Duration::from_secs(retention_days.saturating_mul(86_400)),
                    retention_bytes,
                    SystemTime::now(),
                );
            })
            .ok();

        Some(AuditLog {
            session_id: session_id.to_owned(),
            sender,
            worker: Mutex::new(Some(worker)),
        })
    });
}

/// Drain queued records and stop the background writer on clean process exit.
pub fn shutdown() {
    let Some(log) = AUDIT_LOG.get().and_then(Option::as_ref) else {
        return;
    };
    let _ = log.sender.send(AuditMessage::Shutdown);
    if let Ok(mut worker) = log.worker.lock()
        && let Some(worker) = worker.take()
    {
        let _ = worker.join();
    }
}

/// Record cache-policy context and outcomes without exposing URLs,
/// credentials, or response data.
pub(crate) fn cache_event(mut event: CacheEvent<'_>) {
    let Some(log) = AUDIT_LOG.get().and_then(Option::as_ref) else {
        return;
    };
    event.timestamp = crate::logger::iso_timestamp();
    event.session_id = &log.session_id;
    event.process_id = std::process::id();
    write_json(log, &event);
}

fn write_record(call: &AuditCall, event: &str, outcome: Option<&str>, duration_ms: Option<u128>) {
    let Some(log) = AUDIT_LOG.get().and_then(Option::as_ref) else {
        return;
    };
    let record = AuditRecord {
        timestamp: crate::logger::iso_timestamp(),
        event,
        session_id: &log.session_id,
        process_id: std::process::id(),
        call_id: &call.call_id,
        request_id: &call.request_id,
        tool: &call.tool,
        client_name: call.client_name.as_deref(),
        client_version: call.client_version.as_deref(),
        outcome,
        duration_ms,
    };
    write_json(log, &record);
}

fn write_json<T: Serialize>(log: &AuditLog, record: &T) {
    let Ok(mut line) = serde_json::to_vec(record) else {
        return;
    };
    line.push(b'\n');
    let _ = log.sender.send(AuditMessage::Record(line));
}

fn audit_worker(mut writer: RotatingWriter, receiver: &mpsc::Receiver<AuditMessage>) {
    while let Ok(message) = receiver.recv() {
        match message {
            AuditMessage::Record(line) => {
                let _ = writer.write_record(&line);
            }
            AuditMessage::Shutdown => break,
        }
    }
}

impl RotatingWriter {
    fn open(path: PathBuf, max_bytes: u64, max_files: usize) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            path,
            file: Some(file),
            len,
            max_bytes,
            max_files,
        })
    }

    fn write_record(&mut self, line: &[u8]) -> io::Result<()> {
        let incoming = u64::try_from(line.len()).unwrap_or(u64::MAX);
        if self.len > 0 && self.len.saturating_add(incoming) > self.max_bytes {
            self.rotate()?;
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("audit log file is not open"))?;
        file.write_all(line)?;
        file.flush()?;
        self.len = self.len.saturating_add(incoming);
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }
        if self.max_files > 1 {
            for index in (1..self.max_files).rev() {
                let source = rotated_path(&self.path, index - 1);
                let destination = rotated_path(&self.path, index);
                if source.exists() {
                    if destination.exists() {
                        std::fs::remove_file(&destination)?;
                    }
                    std::fs::rename(source, destination)?;
                }
            }
        } else if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        self.file = Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?,
        );
        self.len = 0;
        Ok(())
    }
}

fn rotated_path(path: &Path, index: usize) -> PathBuf {
    if index == 0 {
        path.to_owned()
    } else {
        PathBuf::from(format!("{}.{index}", path.display()))
    }
}

fn enabled(raw: Option<&str>) -> bool {
    !raw.is_some_and(|value| {
        ["off", "false", "0", "no"]
            .iter()
            .any(|disabled| value.trim().eq_ignore_ascii_case(disabled))
    })
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn sweep_retention(
    dir: &Path,
    keep_prefix: &str,
    max_age: Duration,
    max_total_bytes: u64,
    now: SystemTime,
) -> io::Result<()> {
    let package_prefix = format!("{UNSCOPED_PACKAGE_NAME}.");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with(&package_prefix)
            || !name.contains(".audit.jsonl")
            || name.starts_with(keep_prefix)
        {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.is_file() {
            files.push((path, metadata.modified().unwrap_or(now), metadata.len()));
        }
    }

    files.retain(|(path, modified, _)| match now.duration_since(*modified) {
        Ok(age) if age > max_age => {
            let _ = std::fs::remove_file(path);
            false
        }
        _ => true,
    });
    files.sort_by_key(|(_, modified, _)| *modified);
    let mut total = files.iter().map(|(_, _, size)| size).sum::<u64>();
    for (path, _, size) in files {
        if total <= max_total_bytes {
            break;
        }
        if std::fs::remove_file(path).is_ok() {
            total = total.saturating_sub(size);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_rotates_and_bounds_archive_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = RotatingWriter::open(path.clone(), 10, 3).unwrap();

        for line in [b"first\n".as_slice(), b"second\n", b"third\n", b"fourth\n"] {
            writer.write_record(line).unwrap();
        }

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "fourth\n");
        assert_eq!(
            std::fs::read_to_string(rotated_path(&path, 1)).unwrap(),
            "third\n"
        );
        assert_eq!(
            std::fs::read_to_string(rotated_path(&path, 2)).unwrap(),
            "second\n"
        );
        assert!(!rotated_path(&path, 3).exists());
    }

    #[test]
    fn oversized_record_is_kept_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut writer = RotatingWriter::open(path.clone(), 4, 2).unwrap();
        writer.write_record(b"larger-than-limit\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "larger-than-limit\n"
        );
    }

    #[test]
    fn audit_can_be_disabled_with_common_off_values() {
        assert!(enabled(None));
        assert!(enabled(Some("on")));
        for value in ["off", "FALSE", " 0 ", "No"] {
            assert!(!enabled(Some(value)));
        }
    }

    #[test]
    fn worker_drains_records_before_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = RotatingWriter::open(path.clone(), 1024, 2).unwrap();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || audit_worker(writer, &receiver));

        sender
            .send(AuditMessage::Record(b"one\n".to_vec()))
            .unwrap();
        sender
            .send(AuditMessage::Record(b"two\n".to_vec()))
            .unwrap();
        sender.send(AuditMessage::Shutdown).unwrap();
        worker.join().unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "one\ntwo\n");
    }
}

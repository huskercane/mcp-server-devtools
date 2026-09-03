//! `CheckpointSink` port: where signed audit checkpoints are copied so a
//! truncated journal is detectable from outside it (plan §3.3, WP B.6).
//!
//! The chain inside the journal proves that nothing *before* a checkpoint
//! was altered; it cannot prove that the file was not cut short after one.
//! Exporting every checkpoint to a second place — a directory another
//! process ships to object storage or a SIEM — gives the verifier something
//! the journal cannot be rewritten to agree with: a checkpoint the export
//! holds and the journal does not is a truncation.
//!
//! Two implementations: [`DirectoryCheckpointSink`] (one file per
//! checkpoint, written atomically) and [`InMemoryCheckpointSink`] for
//! tests. A SIEM forwarder (Phase C.3) is a third.
//!
//! Called from the journal's writer thread, so the port is synchronous and
//! an implementation may do file I/O. An export failure is logged and does
//! **not** poison the journal: the checkpoint is already durable in the
//! journal itself, and refusing every tool call because a copy failed
//! would turn an observability gap into an outage. The verifier reports
//! the gap in **both** directions instead — an export the journal lacks
//! (truncation) and a journal checkpoint the export lacks
//! ([`crate::audit::verify::Problem::ExportMissing`]) — so a failed copy is
//! a finding an auditor sees, not a silent hole a later truncation could
//! hide in. An export failure is therefore an operator alert, not noise.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Receives every checkpoint the journal writes.
pub trait CheckpointSink: Send + Sync {
    /// Export the checkpoint written as sequence `seq`. `line` is the exact
    /// journal line (with its trailing newline), so an export can be
    /// compared to the journal byte for byte.
    ///
    /// # Errors
    ///
    /// When the copy could not be made. The journal logs and continues.
    fn export(&self, seq: u64, line: &[u8]) -> io::Result<()>;
}

/// One file per checkpoint, `checkpoint-<seq, zero-padded to 20>.jsonl`,
/// written to a temporary name and renamed so a reader never sees a
/// partial file.
pub struct DirectoryCheckpointSink {
    dir: PathBuf,
}

impl DirectoryCheckpointSink {
    /// Use (creating if needed) `dir`.
    ///
    /// # Errors
    ///
    /// When the directory cannot be created.
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// The file name for sequence `seq`.
    #[must_use]
    pub fn file_name(seq: u64) -> String {
        format!("checkpoint-{seq:020}.jsonl")
    }

    /// Every exported checkpoint in `dir`, as `(seq, line)`, ascending.
    ///
    /// # Errors
    ///
    /// When the directory cannot be read.
    pub fn read_all(dir: &Path) -> io::Result<Vec<(u64, Vec<u8>)>> {
        let mut exported = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(seq) = name
                .to_str()
                .and_then(|name| name.strip_prefix("checkpoint-"))
                .and_then(|rest| rest.strip_suffix(".jsonl"))
                .and_then(|digits| digits.parse::<u64>().ok())
            else {
                continue;
            };
            exported.push((seq, std::fs::read(entry.path())?));
        }
        exported.sort_by_key(|(seq, _)| *seq);
        Ok(exported)
    }
}

impl CheckpointSink for DirectoryCheckpointSink {
    fn export(&self, seq: u64, line: &[u8]) -> io::Result<()> {
        use std::io::Write as _;
        let final_path = self.dir.join(Self::file_name(seq));
        let temp_path = self.dir.join(format!("{}.tmp", Self::file_name(seq)));
        let mut file = std::fs::File::create(&temp_path)?;
        let written = file.write_all(line).and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = written {
            let _ = std::fs::remove_file(&temp_path);
            return Err(error);
        }
        std::fs::rename(&temp_path, &final_path)?;
        // Best effort, as in `policy::signing`: the file exists either way.
        if let Ok(handle) = std::fs::File::open(&self.dir) {
            let _ = handle.sync_all();
        }
        Ok(())
    }
}

/// Collects exports in memory, for tests.
#[derive(Debug, Default)]
pub struct InMemoryCheckpointSink {
    exported: Mutex<Vec<(u64, Vec<u8>)>>,
}

impl InMemoryCheckpointSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything exported so far, in order.
    #[must_use]
    pub fn exported(&self) -> Vec<(u64, Vec<u8>)> {
        self.exported
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl CheckpointSink for InMemoryCheckpointSink {
    fn export(&self, seq: u64, line: &[u8]) -> io::Result<()> {
        self.exported
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((seq, line.to_vec()));
        Ok(())
    }
}

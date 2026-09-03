//! Offline journal verification (WP B.6): the checks an auditor runs
//! against a copy of the journal, with no gateway and no network.
//!
//! What is checked, in order, for every line:
//!
//! 1. it parses and its sequence is the previous one plus one;
//! 2. for a checkpoint: the chain value it asserts equals the chain
//!    recomputed over every line before it, it covers exactly the range
//!    since the previous checkpoint, and — when verifying keys are given —
//!    its signature verifies with the key it names;
//! 3. when an export directory is given: every exported checkpoint is in
//!    the journal, byte for byte, none lies beyond the journal's end (a
//!    truncated tail), no sequence is exported twice — and every checkpoint
//!    the journal holds has an export. The last one is what makes the
//!    export usable as evidence: a checkpoint whose copy never landed is a
//!    checkpoint the journal could later be cut back to without the export
//!    contradicting it, so a missing export is reported, not assumed.
//!
//! The result is a report, not a verdict: every problem found, plus the
//! counts an auditor needs — how many records, how many are sealed by a
//! checkpoint, how many trail the last one unsealed.

use std::path::Path;

use serde::Serialize;

use super::checkpoint::Checkpoint;
use super::reader::{JournalReader, Record};
use crate::policy::signing::VerifyingKey;
use crate::ports::checkpoint_sink::DirectoryCheckpointSink;

/// One thing wrong with the journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum Problem {
    /// The file could not be read past this point.
    Unreadable { detail: String },
    /// A checkpoint's chain value does not match the recomputed chain: a
    /// line before it was altered, inserted, or removed.
    ChainMismatch {
        seq: u64,
        expected: String,
        found: String,
    },
    /// A checkpoint covers a different range than the records since the
    /// previous one.
    CoverageMismatch { seq: u64, detail: String },
    /// A checkpoint's signature does not verify, or names an unknown key.
    BadSignature { seq: u64, detail: String },
    /// Keys were given but this checkpoint is unsigned.
    Unsigned { seq: u64 },
    /// A checkpoint the export holds is not in the journal at that sequence.
    ExportMissingFromJournal { seq: u64 },
    /// The export and the journal disagree about a checkpoint's bytes.
    ExportDiffers { seq: u64 },
    /// The export holds a checkpoint past the journal's last record — the
    /// journal was truncated after it was written.
    ExportBeyondJournal { seq: u64, journal_last_seq: u64 },
    /// The journal holds a checkpoint the export does not: its copy failed
    /// (the gateway logs `audit checkpoint export failed`) or was removed.
    /// Until it is restored from wherever the exports were shipped, a
    /// truncation back to this checkpoint would go undetected.
    ExportMissing { seq: u64 },
    /// Two exported files name the same sequence.
    ExportDuplicate { seq: u64 },
}

/// What verification found.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Verification {
    /// Lines that parsed and were in sequence.
    pub records: u64,
    pub checkpoints: u64,
    pub signed_checkpoints: u64,
    /// The last sequence read.
    pub last_seq: u64,
    /// The last sequence a checkpoint covers; everything after it is
    /// unsealed.
    pub sealed_through: Option<u64>,
    /// Records after the last checkpoint (the checkpoint itself excluded).
    pub unsealed_records: u64,
    /// Exported checkpoints compared against the journal.
    pub exports_checked: u64,
    /// Chain value after the last record, for the record.
    pub chain: String,
    pub problems: Vec<Problem>,
}

impl Verification {
    /// Whether nothing was found wrong.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Verify the journal at `journal` (a directory or the file itself).
///
/// `keys` are the audit signing public keys; with none given, signatures
/// are not checked (chain and coverage still are). `exports` is the
/// checkpoint export directory, if any.
///
/// # Errors
///
/// Only when the journal file cannot be opened at all; every other finding
/// is a [`Problem`] in the report.
pub fn verify(
    journal: &Path,
    keys: &[VerifyingKey],
    exports: Option<&Path>,
) -> std::io::Result<Verification> {
    let reader = JournalReader::open(journal)?;
    let mut report = Verification::default();
    let mut previous_checkpoint: Option<u64> = None;
    let mut checkpoint_lines: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut final_chain = reader.chain_state();

    for item in reader {
        let record = match item {
            Ok(record) => record,
            Err(error) => {
                report.problems.push(Problem::Unreadable {
                    detail: error.to_string(),
                });
                break;
            }
        };
        report.records += 1;
        report.last_seq = record.seq;
        let mut chain_after = record.chain_before;
        chain_after.extend(&record.line);
        final_chain = chain_after;

        if !record.is_checkpoint() {
            report.unsealed_records += 1;
            continue;
        }
        report.checkpoints += 1;
        let Some(checkpoint) = check_checkpoint(&record, previous_checkpoint, keys, &mut report)
        else {
            continue;
        };
        previous_checkpoint = Some(record.seq);
        report.sealed_through = Some(checkpoint.covers_to);
        report.unsealed_records = 0;
        checkpoint_lines.push((record.seq, record.line));
    }
    report.chain = final_chain.label();

    if let Some(dir) = exports {
        let exported = DirectoryCheckpointSink::read_all(dir)?;
        // Which journal checkpoints an export vouched for; the rest are
        // reported missing below. Parallel to `checkpoint_lines`.
        let mut covered = vec![false; checkpoint_lines.len()];
        let mut previous_seq: Option<u64> = None;
        for (seq, line) in exported {
            report.exports_checked += 1;
            if previous_seq == Some(seq) {
                report.problems.push(Problem::ExportDuplicate { seq });
                continue;
            }
            previous_seq = Some(seq);
            if seq > report.last_seq {
                report.problems.push(Problem::ExportBeyondJournal {
                    seq,
                    journal_last_seq: report.last_seq,
                });
                continue;
            }
            match checkpoint_lines.binary_search_by_key(&seq, |(seq, _)| *seq) {
                Err(_) => report
                    .problems
                    .push(Problem::ExportMissingFromJournal { seq }),
                Ok(index) if checkpoint_lines[index].1 != line => {
                    report.problems.push(Problem::ExportDiffers { seq });
                }
                Ok(index) => covered[index] = true,
            }
        }
        for ((seq, _), _) in checkpoint_lines
            .iter()
            .zip(covered)
            .filter(|(_, covered)| !covered)
        {
            report.problems.push(Problem::ExportMissing { seq: *seq });
        }
    }
    Ok(report)
}

/// Check one checkpoint record against the recomputed chain, the coverage
/// since the previous checkpoint, and the keys. Records every finding in
/// `report`; returns the parsed checkpoint unless it did not parse.
fn check_checkpoint(
    record: &Record,
    previous_checkpoint: Option<u64>,
    keys: &[VerifyingKey],
    report: &mut Verification,
) -> Option<Checkpoint> {
    let checkpoint: Checkpoint = match serde_json::from_value(record.value.clone()) {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            report.problems.push(Problem::Unreadable {
                detail: format!("checkpoint {} does not parse: {error}", record.seq),
            });
            return None;
        }
    };
    let expected_chain = record.chain_before.label();
    if checkpoint.chain != expected_chain {
        report.problems.push(Problem::ChainMismatch {
            seq: record.seq,
            expected: expected_chain,
            found: checkpoint.chain.clone(),
        });
    }
    let expected_from = previous_checkpoint.map_or(1, |seq| seq + 1);
    if checkpoint.covers_from != expected_from
        || checkpoint.covers_to != record.seq - 1
        || checkpoint.previous_checkpoint != previous_checkpoint
    {
        report.problems.push(Problem::CoverageMismatch {
            seq: record.seq,
            detail: format!(
                "covers {}..={} after checkpoint {:?}; expected {expected_from}..={} after {:?}",
                checkpoint.covers_from,
                checkpoint.covers_to,
                checkpoint.previous_checkpoint,
                record.seq - 1,
                previous_checkpoint
            ),
        });
    }
    // With no keys given, signatures are not checked at all — not even
    // for a known key id — so `signed_checkpoints` counts verified ones only.
    if !keys.is_empty() {
        match checkpoint.verify(record.seq, keys) {
            Ok(Some(_)) => report.signed_checkpoints += 1,
            Ok(None) => report.problems.push(Problem::Unsigned { seq: record.seq }),
            Err(detail) => report.problems.push(Problem::BadSignature {
                seq: record.seq,
                detail,
            }),
        }
    }
    Some(checkpoint)
}

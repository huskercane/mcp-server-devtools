//! `mcp-devtools audit …`: offline work on a copy of the audit journal
//! (WPs B.5, B.6, B.7).
//!
//! - `keygen --out <file>` creates the gateway's checkpoint signing key
//!   (`MCP_AUDIT_SIGNING_KEY`); the public half is what `verify` needs.
//! - `verify <journal> [--public-key …]… [--checkpoints <dir>]` recomputes
//!   the hash chain, checks every checkpoint's coverage and signature, and
//!   compares the exported checkpoints. Exit 0 when nothing is wrong, 1 when
//!   something is.
//!
//! Local administration: reads files, builds no `CliRuntime`.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::audit::verify::{Problem, Verification};
use crate::error::McpError;
use crate::policy::signing::{SigningKey, VerifyingKey};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate the Ed25519 key that signs audit checkpoints.
    Keygen(KeygenOpts),
    /// Verify a journal's chain, checkpoints, signatures, and exports.
    Verify(VerifyOpts),
}

#[derive(Debug, Args)]
pub struct KeygenOpts {
    /// Where to write the private key (PKCS#8 DER, owner-only). Refuses to
    /// overwrite an existing file.
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
    /// Print the result as a JSON object instead of text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct VerifyOpts {
    /// The journal directory (`MCP_AUDIT_JOURNAL_DIR`) or the journal file.
    pub journal: PathBuf,
    /// A base64 audit signing public key. Repeatable, so a journal that
    /// spans a key rotation verifies with both keys. With none given,
    /// signatures are not checked.
    #[arg(long = "public-key", value_name = "BASE64")]
    pub public_keys: Vec<String>,
    /// The checkpoint export directory (`MCP_AUDIT_CHECKPOINT_EXPORT_DIR`),
    /// to detect a truncated journal.
    #[arg(long, value_name = "DIR")]
    pub checkpoints: Option<PathBuf>,
    /// Print the report as JSON instead of text.
    #[arg(long)]
    pub json: bool,
}

/// Run an `audit` subcommand.
///
/// # Errors
///
/// [`McpError`] when a file cannot be read or a key does not parse — and,
/// for `verify`, when the journal has any problem (so the exit code says so).
pub fn dispatch(command: Command) -> Result<(), McpError> {
    match command {
        Command::Keygen(opts) => keygen(&opts),
        Command::Verify(opts) => verify(&opts),
    }
}

fn failure(message: impl std::fmt::Display) -> McpError {
    crate::error::unexpected(message.to_string(), None)
}

fn keygen(opts: &KeygenOpts) -> Result<(), McpError> {
    let (key, pkcs8) = SigningKey::generate().map_err(failure)?;
    crate::policy::signing::write_key_file(&opts.out, &pkcs8)
        .map_err(|error| failure(format!("cannot write {}: {error}", opts.out.display())))?;
    let public = key.verifying_key();
    if opts.json {
        println!(
            "{}",
            serde_json::json!({
                "private_key_file": opts.out.display().to_string(),
                "public_key": public.to_base64(),
                "key_id": public.key_id(),
            })
        );
    } else {
        println!(
            "Private key written to {} — set MCP_AUDIT_SIGNING_KEY to this path on the gateway.\n\
             Public key ({}) — give this to whoever verifies the journal (`audit verify --public-key`):\n{}",
            opts.out.display(),
            public.key_id(),
            public.to_base64()
        );
    }
    Ok(())
}

fn verify(opts: &VerifyOpts) -> Result<(), McpError> {
    let keys = opts
        .public_keys
        .iter()
        .map(|text| VerifyingKey::from_base64(text))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| failure(format!("--public-key: {error}")))?;
    let report = crate::audit::verify::verify(&opts.journal, &keys, opts.checkpoints.as_deref())
        .map_err(|error| failure(format!("cannot read {}: {error}", opts.journal.display())))?;
    if opts.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| failure(error.to_string()))?
        );
    } else {
        print_report(&report);
    }
    if report.ok() {
        Ok(())
    } else {
        Err(failure(format!(
            "{} problem(s) found in {}",
            report.problems.len(),
            opts.journal.display()
        )))
    }
}

fn print_report(report: &Verification) {
    println!(
        "records: {}  checkpoints: {} ({} signed)  last seq: {}",
        report.records, report.checkpoints, report.signed_checkpoints, report.last_seq
    );
    match report.sealed_through {
        Some(seq) => println!(
            "sealed through seq {seq}; {} record(s) after the last checkpoint are unsealed",
            report.unsealed_records
        ),
        None => println!(
            "no checkpoint yet; all {} record(s) are unsealed",
            report.unsealed_records
        ),
    }
    if report.exports_checked > 0 {
        println!("exported checkpoints checked: {}", report.exports_checked);
    }
    println!("chain: {}", report.chain);
    if report.problems.is_empty() {
        println!("OK: no problems found");
        return;
    }
    println!("PROBLEMS:");
    for problem in &report.problems {
        println!("  - {}", describe(problem));
    }
}

fn describe(problem: &Problem) -> String {
    match problem {
        Problem::Unreadable { detail } => format!("unreadable: {detail}"),
        Problem::ChainMismatch {
            seq,
            expected,
            found,
        } => format!(
            "checkpoint {seq}: chain mismatch — a record before it was altered \
             (recomputed {expected}, checkpoint says {found})"
        ),
        Problem::CoverageMismatch { seq, detail } => {
            format!("checkpoint {seq}: coverage mismatch — {detail}")
        }
        Problem::BadSignature { seq, detail } => format!("checkpoint {seq}: {detail}"),
        Problem::Unsigned { seq } => format!("checkpoint {seq}: unsigned"),
        Problem::ExportMissingFromJournal { seq } => {
            format!("exported checkpoint {seq} is not in the journal")
        }
        Problem::ExportDiffers { seq } => {
            format!("exported checkpoint {seq} differs from the journal's")
        }
        Problem::ExportBeyondJournal {
            seq,
            journal_last_seq,
        } => format!(
            "exported checkpoint {seq} lies beyond the journal's last record ({journal_last_seq}): \
             the journal was truncated"
        ),
    }
}

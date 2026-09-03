//! `mcp-devtools audit …`: offline work on a copy of the audit journal
//! (WPs B.5, B.6, B.7).
//!
//! - `keygen --out <file>` creates the gateway's checkpoint signing key
//!   (`MCP_AUDIT_SIGNING_KEY`); the public half is what `verify` needs.
//! - `verify <journal> [--public-key …]… [--checkpoints <dir>]` recomputes
//!   the hash chain, checks every checkpoint's coverage and signature, and
//!   compares the exported checkpoints. Exit 0 when nothing is wrong, 1 when
//!   something is.
//! - `export activity <journal>` flattens the journal to JSON Lines or CSV;
//!   `export access-review --policy … --groups …` lists who can do what.
//! - `metrics <journal>` computes the §7 trial metrics.
//!
//! Every report prints how long it took on stderr (`elapsed_ms`): §7 counts
//! "time to produce an access-review or activity report" as a metric.
//!
//! Local administration: reads files, builds no `CliRuntime`.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::audit::export::{ActivityFilter, Format, GroupsFile};
use crate::audit::verify::{Problem, Verification};
use crate::error::McpError;
use crate::policy::FilePolicy;
use crate::policy::signing::{SigningKey, VerifyingKey};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate the Ed25519 key that signs audit checkpoints.
    Keygen(KeygenOpts),
    /// Verify a journal's chain, checkpoints, signatures, and exports.
    Verify(VerifyOpts),
    /// Export the journal (activity) or the policy (access review).
    Export {
        #[command(subcommand)]
        report: ExportCommand,
    },
    /// Trial metrics (plan §7) from the journal.
    Metrics(MetricsOpts),
}

#[derive(Debug, Subcommand)]
pub enum ExportCommand {
    /// One row per journal record, as JSON Lines or CSV.
    Activity(ActivityOpts),
    /// Who can do what: every rule that applies to every member of a
    /// groups file, from the policy alone.
    AccessReview(AccessReviewOpts),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Jsonl,
    Csv,
}

impl From<OutputFormat> for Format {
    fn from(format: OutputFormat) -> Self {
        match format {
            OutputFormat::Jsonl => Self::Jsonl,
            OutputFormat::Csv => Self::Csv,
        }
    }
}

#[derive(Debug, Args)]
pub struct ActivityOpts {
    /// The journal directory or file.
    pub journal: PathBuf,
    /// Keep records at or after this RFC 3339 instant.
    #[arg(long)]
    pub since: Option<String>,
    /// Keep records before this RFC 3339 instant.
    #[arg(long)]
    pub until: Option<String>,
    /// Keep one subject's records.
    #[arg(long)]
    pub subject: Option<String>,
    /// Keep one vendor's records.
    #[arg(long)]
    pub vendor: Option<String>,
    /// Keep these record kinds (repeatable); default: every kind but checkpoints.
    #[arg(long = "kind")]
    pub kinds: Vec<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Jsonl)]
    pub format: OutputFormat,
    /// Write here instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct AccessReviewOpts {
    /// The policy document.
    #[arg(long, value_name = "FILE")]
    pub policy: PathBuf,
    /// Verify the policy's signature against this public key first.
    #[arg(long, value_name = "BASE64")]
    pub public_key: Option<String>,
    /// Group → members (JSON or YAML), as exported from the identity provider.
    #[arg(long, value_name = "FILE")]
    pub groups: PathBuf,
    /// Tenant label for the synthetic principals (`MCP_TENANT`).
    #[arg(long, default_value = "tenant")]
    pub tenant: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Csv)]
    pub format: OutputFormat,
    /// Write here instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct MetricsOpts {
    /// The journal directory or file.
    pub journal: PathBuf,
    /// Count records at or after this RFC 3339 instant.
    #[arg(long)]
    pub since: Option<String>,
    /// Print the report as JSON instead of text.
    #[arg(long)]
    pub json: bool,
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
        Command::Export {
            report: ExportCommand::Activity(opts),
        } => timed(|| activity(&opts)),
        Command::Export {
            report: ExportCommand::AccessReview(opts),
        } => timed(|| access_review(&opts)),
        Command::Metrics(opts) => timed(|| metrics(&opts)),
    }
}

/// Run a report and print how long it took (§7: time to produce a report).
fn timed(report: impl FnOnce() -> Result<(), McpError>) -> Result<(), McpError> {
    let started = std::time::Instant::now();
    let result = report();
    eprintln!("elapsed_ms={}", started.elapsed().as_millis());
    result
}

fn output(path: Option<&std::path::Path>) -> Result<Box<dyn std::io::Write>, McpError> {
    match path {
        Some(path) => Ok(Box::new(std::io::BufWriter::new(
            std::fs::File::create(path)
                .map_err(|error| failure(format!("cannot create {}: {error}", path.display())))?,
        ))),
        None => Ok(Box::new(std::io::stdout().lock())),
    }
}

fn activity(opts: &ActivityOpts) -> Result<(), McpError> {
    let filter = ActivityFilter {
        since: opts.since.clone(),
        until: opts.until.clone(),
        subject: opts.subject.clone(),
        vendor: opts.vendor.clone(),
        kinds: opts.kinds.clone(),
    };
    let export = crate::audit::export::activity(&opts.journal, &filter)
        .map_err(|error| failure(format!("cannot read {}: {error}", opts.journal.display())))?;
    let mut out = output(opts.out.as_deref())?;
    crate::audit::export::write_activity(&export.rows, opts.format.into(), &mut *out)
        .map_err(|error| failure(format!("cannot write: {error}")))?;
    out.flush().map_err(|error| failure(error.to_string()))?;
    eprintln!(
        "rows={} records_read={}",
        export.rows.len(),
        export.records_read
    );
    match export.stopped {
        Some(reason) => Err(failure(format!(
            "the journal could not be read to the end: {reason}"
        ))),
        None => Ok(()),
    }
}

fn access_review(opts: &AccessReviewOpts) -> Result<(), McpError> {
    let policy = match &opts.public_key {
        Some(text) => FilePolicy::load_verified(
            &opts.policy,
            VerifyingKey::from_base64(text)
                .map_err(|error| failure(format!("--public-key: {error}")))?,
        ),
        None => FilePolicy::load(&opts.policy),
    }
    .map_err(failure)?;
    let groups = std::fs::read(&opts.groups)
        .map_err(|error| failure(format!("cannot read {}: {error}", opts.groups.display())))
        .and_then(|bytes| GroupsFile::parse(&bytes).map_err(failure))?;
    let rows = crate::audit::export::access_review(&policy, &groups, &opts.tenant);
    let mut out = output(opts.out.as_deref())?;
    crate::audit::export::write_access_review(&rows, opts.format.into(), &mut *out)
        .map_err(|error| failure(format!("cannot write: {error}")))?;
    out.flush().map_err(|error| failure(error.to_string()))?;
    eprintln!(
        "rows={} subjects={} policy={}",
        rows.len(),
        rows.iter()
            .map(|row| row.subject.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        crate::ports::PolicyDecisionPoint::version(&policy).unwrap_or_default()
    );
    Ok(())
}

fn metrics(opts: &MetricsOpts) -> Result<(), McpError> {
    let report = crate::audit::metrics::metrics(&opts.journal, opts.since.as_deref())
        .map_err(|error| failure(format!("cannot read {}: {error}", opts.journal.display())))?;
    if opts.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| failure(error.to_string()))?
        );
    } else {
        println!(
            "records: {}  calls: {}  span: {} → {}",
            report.records,
            report.calls,
            report.first_timestamp.as_deref().unwrap_or("-"),
            report.last_timestamp.as_deref().unwrap_or("-")
        );
        println!(
            "allowed by rule: {}  allowed without policy: {}  denied by rule: {}  denied by default: {}  denied (other): {}",
            report.allowed_by_rule,
            report.allowed_without_policy,
            report.denied_by_rule,
            report.denied_by_default,
            report.denied_other
        );
        println!(
            "explicit allow share: {}  egress denials: {}  cross-environment attempts blocked: {}",
            report
                .explicit_allow_share
                .map_or("-".to_owned(), |share| format!("{:.1}%", share * 100.0)),
            report.egress_denials,
            report.cross_environment_attempts
        );
        println!(
            "policy changes: {} (rejected {})  revocation changes: {}  revoked-token rejections: {}  checkpoints: {}",
            report.policy_changes,
            report.policy_rejections,
            report.revocation_changes,
            report.revoked_token_rejections,
            report.checkpoints
        );
        for (environment, count) in &report.denials_by_environment {
            println!("denials in {environment}: {count}");
        }
        for (subject, figures) in &report.subjects {
            println!(
                "{subject}: calls {} allowed {} denied {} first-allow {} deny-after-allow {} revocation-window {}",
                figures.calls,
                figures.allowed,
                figures.denied,
                figures
                    .time_to_first_allow_ms
                    .map_or("-".to_owned(), |ms| format!("{ms}ms")),
                figures
                    .deny_after_allow_ms
                    .map_or("-".to_owned(), |ms| format!("{ms}ms")),
                figures
                    .revocation_window_ms
                    .map_or("-".to_owned(), |ms| format!("{ms}ms")),
            );
        }
    }
    match report.stopped {
        Some(reason) => Err(failure(format!(
            "the journal could not be read to the end: {reason}"
        ))),
        None => Ok(()),
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
        Problem::ExportMissing { seq } => format!(
            "checkpoint {seq} has no export: its copy failed or was removed, so a truncation \
             back to it would not be caught until the export is restored"
        ),
        Problem::ExportDuplicate { seq } => {
            format!("checkpoint {seq} is exported more than once")
        }
    }
}

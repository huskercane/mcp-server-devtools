//! `mcp-devtools policy check <file>`: compile a policy document the way
//! the server will at startup, and report what it found (WP A.7).
//!
//! Exits non-zero on any document the server would refuse, so a CI step
//! can gate policy changes before they reach a gateway. Local
//! administration only — it reads a file and builds no `CliRuntime`, so it
//! is not subject to the unaudited-CLI refusal.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::error::McpError;
use crate::policy::FilePolicy;
use crate::ports::PolicyDecisionPoint as _;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Parse and compile a policy document; print its version and rule
    /// count, or the reason the server would refuse it.
    Check(CheckOpts),
}

#[derive(Debug, Args)]
pub struct CheckOpts {
    /// Path to the YAML policy document.
    pub file: PathBuf,
    /// Print the result as a JSON object instead of text.
    #[arg(long)]
    pub json: bool,
}

/// Run a `policy` subcommand.
///
/// # Errors
///
/// [`McpError`] when the document cannot be read or does not compile; the
/// message is the same reason the server logs at startup.
pub fn dispatch(command: Command) -> Result<(), McpError> {
    match command {
        Command::Check(opts) => check(&opts),
    }
}

fn check(opts: &CheckOpts) -> Result<(), McpError> {
    let policy = FilePolicy::load(&opts.file)
        .map_err(|error| crate::error::unexpected(error.to_string(), None))?;
    let version = policy.version().unwrap_or_default();
    let rules = policy.rule_count();
    if opts.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "file": opts.file.display().to_string(),
                "policy_version": version,
                "rules": rules,
            })
        );
    } else {
        println!(
            "OK: {} compiles — policy {version}, {rules} rule{}",
            opts.file.display(),
            if rules == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

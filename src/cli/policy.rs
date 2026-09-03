//! `mcp-devtools policy …`: local administration of policy documents
//! (WPs A.7, B.2, B.3).
//!
//! - `check <file> [--public-key <b64>]` compiles a document the way the
//!   server will at startup — and, with a key, verifies its detached
//!   signature — so a CI step can gate policy changes before they reach a
//!   gateway.
//! - `keygen --out <file>` creates the Ed25519 signing key pair; the
//!   private half is written owner-only, the public half is printed for
//!   `MCP_POLICY_PUBLIC_KEY`.
//! - `sign <file> --key <keyfile>` writes `<file>.sig`.
//!
//! All of these read files and build no `CliRuntime`, so they are not
//! subject to the unaudited-CLI refusal.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::error::McpError;
use crate::policy::FilePolicy;
use crate::policy::signing::{Domain, SigningKey, VerifyingKey};
use crate::ports::PolicyDecisionPoint as _;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Parse and compile a policy document; print its version and rule
    /// count, or the reason the server would refuse it.
    Check(CheckOpts),
    /// Generate an Ed25519 signing key pair for policy bundles.
    Keygen(KeygenOpts),
    /// Sign a policy document (or revocation list), writing `<file>.sig`.
    Sign(SignOpts),
}

#[derive(Debug, Args)]
pub struct CheckOpts {
    /// Path to the YAML policy document.
    pub file: PathBuf,
    /// Verify the detached signature in `<file>.sig` against this base64
    /// Ed25519 public key (the value of `MCP_POLICY_PUBLIC_KEY`).
    #[arg(long, value_name = "BASE64")]
    pub public_key: Option<String>,
    /// Print the result as a JSON object instead of text.
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
pub struct SignOpts {
    /// The document to sign.
    pub file: PathBuf,
    /// The private key written by `policy keygen`.
    #[arg(long, value_name = "FILE")]
    pub key: PathBuf,
    /// Sign as a revocation list rather than a policy document. The two
    /// are signed under different domains, so a signature over one never
    /// verifies as the other.
    #[arg(long)]
    pub revocation_list: bool,
    /// Print the result as a JSON object instead of text.
    #[arg(long)]
    pub json: bool,
}

/// Run a `policy` subcommand.
///
/// # Errors
///
/// [`McpError`] when the document cannot be read, does not compile, or its
/// signature does not verify; the message is the same reason the server
/// logs at startup.
pub fn dispatch(command: Command) -> Result<(), McpError> {
    match command {
        Command::Check(opts) => check(&opts),
        Command::Keygen(opts) => keygen(&opts),
        Command::Sign(opts) => sign(&opts),
    }
}

fn failure(message: impl std::fmt::Display) -> McpError {
    crate::error::unexpected(message.to_string(), None)
}

fn check(opts: &CheckOpts) -> Result<(), McpError> {
    let verifier = opts
        .public_key
        .as_deref()
        .map(VerifyingKey::from_base64)
        .transpose()
        .map_err(|error| failure(format!("--public-key: {error}")))?;
    let policy = match verifier {
        Some(verifier) => FilePolicy::load_verified(&opts.file, verifier),
        None => FilePolicy::load(&opts.file),
    }
    .map_err(failure)?;
    let version = policy.version().unwrap_or_default();
    let rules = policy.rule_count();
    let signature = policy.signature();
    if opts.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "file": opts.file.display().to_string(),
                "policy_version": version,
                "rules": rules,
                "signature": signature,
            })
        );
    } else {
        let signed = match &signature {
            Some(status) => format!(
                ", signature verified (key {})",
                status.key_id.as_deref().unwrap_or("-")
            ),
            None => String::new(),
        };
        println!(
            "OK: {} compiles — policy {version}, {rules} rule{}{signed}",
            opts.file.display(),
            if rules == 1 { "" } else { "s" }
        );
    }
    Ok(())
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
            "Private key written to {} (keep it with whoever signs policy; never on a gateway).\n\
             Public key ({}) — set this as MCP_POLICY_PUBLIC_KEY on every gateway:\n{}",
            opts.out.display(),
            public.key_id(),
            public.to_base64()
        );
    }
    Ok(())
}

fn sign(opts: &SignOpts) -> Result<(), McpError> {
    let key = SigningKey::load(&opts.key).map_err(failure)?;
    let bytes = std::fs::read(&opts.file)
        .map_err(|error| failure(format!("cannot read {}: {error}", opts.file.display())))?;
    let domain = if opts.revocation_list {
        Domain::RevocationList
    } else {
        // Signing an unparseable policy is a mistake worth catching here
        // rather than at the gateway, which would refuse it anyway.
        FilePolicy::from_bytes(&bytes)
            .map_err(|error| failure(format!("{}: {error}", opts.file.display())))?;
        Domain::PolicyBundle
    };
    let signature = key.sign(domain, &bytes);
    let sidecar = crate::policy::signing::write_detached(&opts.file, &signature)
        .map_err(|error| failure(format!("cannot write signature: {error}")))?;
    let public = key.verifying_key();
    if opts.json {
        println!(
            "{}",
            serde_json::json!({
                "file": opts.file.display().to_string(),
                "signature_file": sidecar.display().to_string(),
                "key_id": public.key_id(),
            })
        );
    } else {
        println!(
            "Signed {} with key {}; signature in {}",
            opts.file.display(),
            public.key_id(),
            sidecar.display()
        );
    }
    Ok(())
}

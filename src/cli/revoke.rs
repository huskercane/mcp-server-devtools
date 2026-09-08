//! `mcp-devtools revoke …`: edit and re-sign the revocation list (WP B.4).
//!
//! The list is the emergency stop (`crate::auth::revocation`). Every
//! subcommand here reads the current file, verifies its signature with the
//! public half of `--key` (so a tampered list is noticed before it is
//! extended, not silently re-signed), rewrites the whole document
//! deterministically, and writes a fresh `<file>.sig`. Gateways watching
//! the file apply the change within one poll interval and journal it.
//!
//! - `init` writes an empty, signed list — the state a new deployment
//!   starts in (`MCP_REVOCATION_FILE` must exist, signed, in okta mode).
//! - `subject <sub>` / `token <jti>` add an entry (idempotent).
//! - `all` sets `not_before` to now: every token issued before this moment
//!   is refused. The `revoke-all` of plan §3.6, for a key compromise or a
//!   suspected gateway breach after the identity provider's key is rotated.
//! - `remove subject|token <id>` and `clear-all` undo the above.
//! - `show` prints the list and verifies its signature.
//!
//! Local administration: reads and writes files, builds no `CliRuntime`.
//!
//! Two operators editing the same list at once must not lose each other's
//! entry: every edit holds an exclusive advisory lock on `<file>.lock` from
//! the read through the write ([`lock_for_edit`]), and `init` installs its
//! file without replacing one that appeared in the meantime.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use atomicwrites::{AllowOverwrite, AtomicFile, DisallowOverwrite, OverwriteBehavior};
use clap::{Args, Subcommand};

use crate::auth::revocation::{NotBefore, RevocationFile, RevokedSubject, RevokedToken};
use crate::error::McpError;
use crate::policy::signing::{Domain, SigningKey, VerifyingKey, read_detached, write_detached};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create an empty, signed revocation list.
    Init(FileOpts),
    /// Revoke every token of a subject (the identity provider's `sub`).
    Subject(EntryOpts),
    /// Revoke one token by its `jti`.
    Token(EntryOpts),
    /// Revoke every token issued before now (`not_before` = now).
    All(AllOpts),
    /// Remove a subject or token entry.
    Remove(RemoveOpts),
    /// Drop the `not_before` cut-off.
    ClearAll(FileOpts),
    /// Print the list and verify its signature.
    Show(ShowOpts),
}

#[derive(Debug, Args)]
pub struct FileOpts {
    /// The revocation list (the value of `MCP_REVOCATION_FILE`).
    #[arg(long, value_name = "FILE")]
    pub file: PathBuf,
    /// The policy signing key from `policy keygen`.
    #[arg(long, value_name = "FILE")]
    pub key: PathBuf,
    /// Print the result as a JSON object instead of text.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct EntryOpts {
    /// The subject (`sub`) or token id (`jti`).
    pub id: String,
    /// Why, for the record.
    #[arg(long)]
    pub reason: Option<String>,
    #[command(flatten)]
    pub file: FileOpts,
}

#[derive(Debug, Args)]
pub struct AllOpts {
    /// Why, for the record.
    #[arg(long)]
    pub reason: Option<String>,
    #[command(flatten)]
    pub file: FileOpts,
}

#[derive(Debug, Args)]
pub struct RemoveOpts {
    /// `subject` or `token`.
    #[arg(value_parser = ["subject", "token"])]
    pub kind: String,
    /// The subject or token id to remove.
    pub id: String,
    #[command(flatten)]
    pub file: FileOpts,
}

#[derive(Debug, Args)]
pub struct ShowOpts {
    /// The revocation list.
    #[arg(long, value_name = "FILE")]
    pub file: PathBuf,
    /// Verify the signature against this base64 public key
    /// (`MCP_POLICY_PUBLIC_KEY`). Without it the list is shown unverified.
    #[arg(long, value_name = "BASE64")]
    pub public_key: Option<String>,
    /// Print the list as JSON instead of YAML.
    #[arg(long)]
    pub json: bool,
}

/// Run a `revoke` subcommand.
///
/// # Errors
///
/// [`McpError`] when the key or list cannot be read, the existing list's
/// signature does not verify, or the files cannot be written.
pub fn dispatch(command: Command) -> Result<(), McpError> {
    match command {
        Command::Init(opts) => {
            let key = load_key(&opts.key)?;
            let _lock = lock_for_edit(&opts.file)?;
            if opts.file.exists() {
                return Err(failure(format!(
                    "{} already exists; edit it with `revoke subject|token|all` instead",
                    opts.file.display()
                )));
            }
            let list = RevocationFile::empty();
            // No-replace: a list that appears between the check above and
            // this write is refused, not overwritten with an empty one.
            write_signed(&opts.file, &list, &key, DisallowOverwrite)?;
            report(&opts, &list, "initialized");
            Ok(())
        }
        Command::Subject(opts) => {
            let subject = opts.id.trim().to_owned();
            if subject.is_empty() {
                return Err(failure("subject is empty"));
            }
            edit(&opts.file, "revoked subject", |list| {
                if !list.subjects.iter().any(|entry| entry.subject == subject) {
                    list.subjects.push(RevokedSubject {
                        subject,
                        revoked_at: crate::logger::iso_timestamp(),
                        reason: opts.reason,
                    });
                }
                Ok(())
            })
        }
        Command::Token(opts) => {
            let token_id = opts.id.trim().to_owned();
            if token_id.is_empty() {
                return Err(failure("token id is empty"));
            }
            edit(&opts.file, "revoked token", |list| {
                if !list
                    .token_ids
                    .iter()
                    .any(|entry| entry.token_id == token_id)
                {
                    list.token_ids.push(RevokedToken {
                        token_id,
                        revoked_at: crate::logger::iso_timestamp(),
                        reason: opts.reason,
                    });
                }
                Ok(())
            })
        }
        Command::All(opts) => edit(
            &opts.file,
            "revoked every token issued before now",
            |list| {
                list.not_before = Some(NotBefore {
                    at: crate::logger::iso_timestamp(),
                    reason: opts.reason,
                });
                Ok(())
            },
        ),
        Command::Remove(opts) => edit(&opts.file, "removed", |list| {
            let before = list.subjects.len() + list.token_ids.len();
            if opts.kind == "subject" {
                list.subjects.retain(|entry| entry.subject != opts.id);
            } else {
                list.token_ids.retain(|entry| entry.token_id != opts.id);
            }
            if before == list.subjects.len() + list.token_ids.len() {
                return Err(failure(format!(
                    "no {} entry {:?} in {}",
                    opts.kind,
                    opts.id,
                    opts.file.file.display()
                )));
            }
            Ok(())
        }),
        Command::ClearAll(opts) => edit(&opts, "cleared the not_before cut-off", |list| {
            list.not_before = None;
            Ok(())
        }),
        Command::Show(opts) => show(&opts),
    }
}

/// One read-modify-write of the list under the edit lock: load the key,
/// take the lock, read and verify, apply `mutate`, write and re-sign,
/// report. The lock spans the read *and* the write, so two concurrent
/// edits serialize instead of the second silently dropping the first's
/// entry.
fn edit(
    opts: &FileOpts,
    action: &str,
    mutate: impl FnOnce(&mut RevocationFile) -> Result<(), McpError>,
) -> Result<(), McpError> {
    let key = load_key(&opts.key)?;
    let _lock = lock_for_edit(&opts.file)?;
    let mut list = read_verified(&opts.file, &key)?;
    mutate(&mut list)?;
    write_signed(&opts.file, &list, &key, AllowOverwrite)?;
    report(opts, &list, action);
    Ok(())
}

/// An exclusive advisory lock on `<file>.lock`, held for the lifetime of
/// the value. Every edit of the list takes it (see [`edit`]); a gateway
/// never does, since it only reads the list and never blocks on an
/// operator. Advisory, so a writer that bypasses this module is not
/// stopped — but every path in this module goes through it.
pub struct EditLock {
    _held: std::fs::File,
}

/// Take the edit lock for `file`, blocking until any other holder releases
/// it.
///
/// # Errors
///
/// When the lock file cannot be created or locked.
pub fn lock_for_edit(file: &Path) -> Result<EditLock, McpError> {
    let mut name = file.file_name().unwrap_or_default().to_owned();
    name.push(".lock");
    let path = file.with_file_name(name);
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|error| failure(format!("cannot open {}: {error}", path.display())))?;
    lock.lock()
        .map_err(|error| failure(format!("cannot lock {}: {error}", path.display())))?;
    Ok(EditLock { _held: lock })
}

fn failure(message: impl std::fmt::Display) -> McpError {
    crate::error::unexpected(message.to_string(), None)
}

fn load_key(path: &Path) -> Result<SigningKey, McpError> {
    SigningKey::load(path).map_err(failure)
}

/// Read the list and verify its signature with the key that is about to
/// re-sign it. Editing a list whose signature does not verify would launder
/// a tampered file into a signed one.
fn read_verified(path: &Path, key: &SigningKey) -> Result<RevocationFile, McpError> {
    let bytes = std::fs::read(path)
        .map_err(|error| failure(format!("cannot read {}: {error}", path.display())))?;
    let signature = read_detached(path).map_err(|error| {
        failure(format!(
            "{error}; refusing to edit an unsigned list (use `revoke init` for a new one)"
        ))
    })?;
    key.verifying_key()
        .verify(Domain::RevocationList, &bytes, &signature)
        .map_err(|error| {
            failure(format!(
                "{}: existing signature {error} with this key; refusing to re-sign a list \
                 this key did not sign",
                path.display()
            ))
        })?;
    RevocationFile::parse(&bytes).map_err(|error| failure(format!("{}: {error}", path.display())))
}

/// Write the document atomically, then its signature. A watcher may see
/// the new document with the old signature for one poll and journal a
/// rejected reload before it picks up the pair; that record is truthful.
fn write_signed(
    path: &Path,
    list: &RevocationFile,
    key: &SigningKey,
    overwrite: OverwriteBehavior,
) -> Result<(), McpError> {
    let yaml = list.to_yaml().map_err(failure)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    AtomicFile::new_with_tmpdir(path, overwrite, &parent)
        .write(|file| file.write_all(yaml.as_bytes()))
        .map_err(|error| failure(format!("cannot write {}: {error}", path.display())))?;
    write_detached(path, &key.sign(Domain::RevocationList, yaml.as_bytes()))
        .map_err(|error| failure(format!("cannot write signature: {error}")))?;
    Ok(())
}

fn report(opts: &FileOpts, list: &RevocationFile, action: &str) {
    if opts.json {
        println!(
            "{}",
            serde_json::json!({
                "file": opts.file.display().to_string(),
                "action": action,
                "subjects": list.subjects.len(),
                "token_ids": list.token_ids.len(),
                "not_before": list.not_before.as_ref().map(|cutoff| cutoff.at.clone()),
            })
        );
    } else {
        println!(
            "{action}: {} now revokes {} subject(s), {} token(s){}; signed",
            opts.file.display(),
            list.subjects.len(),
            list.token_ids.len(),
            list.not_before
                .as_ref()
                .map(|cutoff| format!(", and every token issued before {}", cutoff.at))
                .unwrap_or_default()
        );
    }
}

fn show(opts: &ShowOpts) -> Result<(), McpError> {
    let bytes = std::fs::read(&opts.file)
        .map_err(|error| failure(format!("cannot read {}: {error}", opts.file.display())))?;
    let verified = match &opts.public_key {
        Some(text) => {
            let key = VerifyingKey::from_base64(text)
                .map_err(|error| failure(format!("--public-key: {error}")))?;
            let signature = read_detached(&opts.file).map_err(failure)?;
            key.verify(Domain::RevocationList, &bytes, &signature)
                .map_err(|error| failure(format!("{}: {error}", opts.file.display())))?;
            Some(key.key_id())
        }
        None => None,
    };
    let list = RevocationFile::parse(&bytes)
        .map_err(|error| failure(format!("{}: {error}", opts.file.display())))?;
    if opts.json {
        println!(
            "{}",
            serde_json::json!({
                "file": opts.file.display().to_string(),
                "verified_with": verified,
                "list": list,
            })
        );
    } else {
        match verified {
            Some(key_id) => println!("# signature verified (key {key_id})"),
            None => println!("# signature not checked (pass --public-key)"),
        }
        print!("{}", list.to_yaml().map_err(failure)?);
    }
    Ok(())
}

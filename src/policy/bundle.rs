//! A signed, hot-reloaded document whose changes are journaled before they
//! take effect (WPs B.3 and B.4).
//!
//! Two documents share this shape — the policy (`MCP_POLICY_FILE`,
//! [`super::engine`]) and the revocation list (`MCP_REVOCATION_FILE`,
//! [`crate::auth::revocation`]) — and the plan calls the pair the *policy
//! bundle*: what a gateway pulls from its control plane and applies as one
//! unit of authorization state. [`SignedBundle`] is the machinery they have
//! in common; a [`BundleDocument`] is what differs (how the bytes compile,
//! what the version label is, which control-record kinds describe it).
//!
//! ## Lifecycle
//!
//! - **Load** reads the file, verifies its detached signature when a
//!   verifying key is configured ([`super::signing`]), and compiles it. A
//!   failure at startup is fatal to the caller; enterprise mode never runs
//!   on a guess.
//! - **Stage** does the same for a changed file without putting the result
//!   in force. **Commit** swaps it in; in-flight readers keep the snapshot
//!   they started with.
//! - The **watcher** polls the file and, with a journal, appends a
//!   `*_loaded` record when it starts, a `*_changed` record **before** each
//!   commit, and a `*_rejected` record once per distinct failure. A change
//!   whose record cannot be made durable within the bound is not applied,
//!   and [`SignedBundle::degraded`] says so until the journal recovers.
//! - A file that vanishes, does not verify, or does not compile leaves the
//!   **last good document in force**, indefinitely, with the reason in
//!   [`SignedBundle::degraded`] for the health banner. Deleting a file is
//!   never an emergency stop; the revocation list is (`revoke all`).
//!
//! Signing is a separate step from writing the file, so a change lands as
//! two files. The watcher may see the pair mid-update as a rejected reload;
//! it picks the pair up on the next tick once both are in place.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use crate::ports::audit_sink::{
    AuditFailure, AuditSink, ControlEvent, ControlEventKind, SignatureStatus,
};

use super::signing::{Domain, VerifyingKey};

/// How often the watcher looks at the file.
pub const WATCH_INTERVAL: Duration = Duration::from_millis(500);

/// Largest document accepted, of either kind.
pub const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

/// Why a document was refused. Carries the document's own text (rule ids,
/// key names, the path), never anything from a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleError(String);

impl BundleError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BundleError {}

/// What a document type tells the bundle about itself.
pub trait BundleDocument: Send + Sync + Sized + 'static {
    /// Which signature domain the file is signed under.
    const DOMAIN: Domain;
    /// Noun for messages: `"policy"`, `"revocation list"`.
    const NOUN: &'static str;
    /// The control-record kinds that describe this document's lifecycle,
    /// in the order loaded / changed / rejected.
    const KINDS: [ControlEventKind; 3];

    /// Compile the exact file bytes. Errors are the reasons the operator
    /// reads; they never include request data.
    ///
    /// # Errors
    ///
    /// When the bytes are not a valid document.
    fn compile(bytes: &[u8]) -> Result<Self, BundleError>;

    /// The version label: the document's own version number plus the
    /// bundle hash (`v<n>+sha256:<16 hex>` of the exact bytes), so a record
    /// names the document that decided it.
    fn version(&self) -> &str;

    /// Add document-specific fields to a control record about it (counts,
    /// effective times). The default adds nothing.
    fn describe(&self, _event: &mut ControlEvent) {}
}

/// A compiled document together with how it was authenticated.
pub struct Loaded<D> {
    pub document: D,
    /// `None` when no verifying key is configured; `Some` (always
    /// `verified: true`) when one is.
    pub signature: Option<SignatureStatus>,
}

/// A document that has been read, verified, and compiled but not yet put
/// in force. Produced by [`SignedBundle::stage`], consumed by
/// [`SignedBundle::commit`]; the gap between them is where the change
/// record is made durable.
pub struct Staged<D> {
    loaded: Loaded<D>,
    bytes: Vec<u8>,
}

impl<D: BundleDocument> Staged<D> {
    #[must_use]
    pub fn version(&self) -> &str {
        self.loaded.document.version()
    }

    #[must_use]
    pub fn signature(&self) -> Option<&SignatureStatus> {
        self.loaded.signature.as_ref()
    }

    #[must_use]
    pub fn document(&self) -> &D {
        &self.loaded.document
    }
}

/// What [`SignedBundle::commit`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleChange {
    pub previous_version: String,
    pub version: String,
    pub signature: Option<SignatureStatus>,
}

/// Where the watcher journals bundle events.
#[derive(Clone)]
pub struct BundleAudit {
    pub sink: Arc<dyn AuditSink>,
    pub append_timeout: Duration,
}

/// Called by the watcher after a change is committed, with the document
/// that was in force and the one that now is. Runs on the watcher task;
/// anything slow should be spawned.
pub type ChangeHook<D> = Box<dyn Fn(&Arc<Loaded<D>>, &Arc<Loaded<D>>) + Send + Sync>;

/// A document on disk, verified, compiled, hot-reloadable.
pub struct SignedBundle<D> {
    path: PathBuf,
    /// The key documents must be signed with; `None` for unsigned local
    /// dry runs.
    verifier: Option<VerifyingKey>,
    current: RwLock<Arc<Loaded<D>>>,
    /// The bytes the current snapshot was compiled from, for the watcher.
    loaded_bytes: RwLock<Vec<u8>>,
    /// Why the last reload failed, while the last good document stays in
    /// force. Cleared by the next successful reload. Off the request path:
    /// written by the watcher, read by health.
    last_reload_error: Mutex<Option<String>>,
}

impl<D: BundleDocument> SignedBundle<D> {
    /// Read and compile the document at `path`, unsigned.
    ///
    /// # Errors
    ///
    /// When the file cannot be read or does not compile.
    pub fn load(path: &Path) -> Result<Arc<Self>, BundleError> {
        Self::load_with(path, None)
    }

    /// Read, verify against `verifier`, and compile the document at
    /// `path`. The detached signature must be in `<path>.sig`.
    ///
    /// # Errors
    ///
    /// When the file or its signature cannot be read, the signature does
    /// not verify, or the document does not compile.
    pub fn load_verified(path: &Path, verifier: VerifyingKey) -> Result<Arc<Self>, BundleError> {
        Self::load_with(path, Some(verifier))
    }

    /// Load with an optional verifier — the shape configuration hands over.
    ///
    /// # Errors
    ///
    /// As for [`Self::load`] and [`Self::load_verified`].
    pub fn load_with(
        path: &Path,
        verifier: Option<VerifyingKey>,
    ) -> Result<Arc<Self>, BundleError> {
        let (bytes, signature) = read_document::<D>(path, verifier.as_ref())?;
        let document = D::compile(&bytes).map_err(|error| {
            BundleError::new(format!("{} {}: {error}", D::NOUN, path.display()))
        })?;
        Ok(Arc::new(Self {
            path: path.to_owned(),
            verifier,
            current: RwLock::new(Arc::new(Loaded {
                document,
                signature,
            })),
            loaded_bytes: RwLock::new(bytes),
            last_reload_error: Mutex::new(None),
        }))
    }

    /// Compile a document from bytes, for `policy check` and tests. Not
    /// reloadable (there is no file to watch) and never signed.
    ///
    /// # Errors
    ///
    /// When the document does not compile.
    pub fn from_bytes(bytes: &[u8]) -> Result<Arc<Self>, BundleError> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(BundleError::new(format!(
                "{} document is too large",
                D::NOUN
            )));
        }
        let document = D::compile(bytes)?;
        Ok(Arc::new(Self {
            path: PathBuf::new(),
            verifier: None,
            current: RwLock::new(Arc::new(Loaded {
                document,
                signature: None,
            })),
            loaded_bytes: RwLock::new(bytes.to_vec()),
            last_reload_error: Mutex::new(None),
        }))
    }

    /// The document in force. One `Arc` clone; readers keep their snapshot
    /// across a concurrent commit.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Loaded<D>> {
        Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Version label of the document in force.
    #[must_use]
    pub fn version(&self) -> String {
        self.snapshot().document.version().to_owned()
    }

    /// How the document in force was authenticated.
    #[must_use]
    pub fn signature(&self) -> Option<SignatureStatus> {
        self.snapshot().signature.clone()
    }

    /// Whether documents must carry a verified signature.
    #[must_use]
    pub const fn requires_signature(&self) -> bool {
        self.verifier.is_some()
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Why the last reload failed — the file vanished, became unreadable,
    /// failed verification, or does not compile — while the last good
    /// document stays in force. `None` when the document in force is the
    /// one on disk.
    #[must_use]
    pub fn degraded(&self) -> Option<String> {
        self.last_reload_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn note_reload<T>(&self, outcome: &Result<T, BundleError>) {
        *self
            .last_reload_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            outcome.as_ref().err().map(ToString::to_string);
    }

    fn note_failure(&self, reason: &str) {
        *self
            .last_reload_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(reason.to_owned());
    }

    /// Re-read the file and put a changed document in force at once —
    /// [`Self::stage`] then [`Self::commit`], with nothing journaled in
    /// between. For tests and unaudited local dry runs. `Ok(false)` means
    /// the bytes on disk are the ones already in force.
    ///
    /// # Errors
    ///
    /// When the file cannot be read, its signature does not verify, or it
    /// does not compile. The current document stays in force and the
    /// failure is reported by [`Self::degraded`].
    pub fn reload(&self) -> Result<bool, BundleError> {
        match self.stage()? {
            Some(staged) => {
                self.commit(staged);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Read, verify, and compile the file without putting it in force.
    /// `Ok(None)` when the bytes on disk are the ones already in force.
    /// Records the outcome for [`Self::degraded`].
    ///
    /// # Errors
    ///
    /// When the file cannot be read, its signature does not verify, or it
    /// does not compile.
    pub fn stage(&self) -> Result<Option<Staged<D>>, BundleError> {
        let outcome = self.stage_inner();
        self.note_reload(&outcome);
        outcome
    }

    fn stage_inner(&self) -> Result<Option<Staged<D>>, BundleError> {
        let (bytes, signature) = read_document::<D>(&self.path, self.verifier.as_ref())?;
        let unchanged = *self
            .loaded_bytes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            == bytes;
        if unchanged {
            return Ok(None);
        }
        let document = D::compile(&bytes).map_err(|error| {
            BundleError::new(format!("{} {}: {error}", D::NOUN, self.path.display()))
        })?;
        Ok(Some(Staged {
            loaded: Loaded {
                document,
                signature,
            },
            bytes,
        }))
    }

    /// Put a staged document in force. Returns the change and the
    /// snapshot that was replaced.
    pub fn commit(&self, staged: Staged<D>) -> (BundleChange, Arc<Loaded<D>>) {
        let previous = {
            let mut current = self
                .current
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut *current, Arc::new(staged.loaded))
        };
        *self
            .loaded_bytes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = staged.bytes;
        let now = self.snapshot();
        (
            BundleChange {
                previous_version: previous.document.version().to_owned(),
                version: now.document.version().to_owned(),
                signature: now.signature.clone(),
            },
            previous,
        )
    }

    /// The label a rejected document is journaled under: its own bundle
    /// hash when it could be read, so the refused bytes are identifiable.
    fn rejected_version(&self) -> Option<String> {
        std::fs::read(&self.path)
            .ok()
            .map(|bytes| digest_label(&bytes))
    }

    /// Poll the file and reload on change, on the current Tokio runtime.
    /// Holds only a `Weak`, so the task ends with the bundle. A no-op with
    /// a warning outside a runtime, like the config watcher.
    ///
    /// With `audit`, the document in force is journaled when the watcher
    /// starts, every change is journaled **before** it is committed, and
    /// each distinct rejected reload is journaled once. A change whose
    /// record cannot be made durable is not applied. `on_change` runs after
    /// each commit.
    pub fn spawn_watcher(
        self: &Arc<Self>,
        audit: Option<BundleAudit>,
        on_change: Option<ChangeHook<D>>,
    ) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(path = %self.path.display(), noun = D::NOUN, "bundle watcher requires a Tokio runtime");
            return;
        };
        let weak: Weak<Self> = Arc::downgrade(self);
        runtime.spawn(async move {
            if let Some(audit) = &audit
                && let Some(bundle) = weak.upgrade()
            {
                bundle.journal_loaded(audit).await;
            }
            let mut interval = tokio::time::interval(WATCH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let Some(bundle) = weak.upgrade() else {
                    return;
                };
                bundle.tick(audit.as_ref(), on_change.as_ref()).await;
            }
        });
    }

    /// The `*_loaded` record: what is in force when the watcher starts.
    async fn journal_loaded(&self, audit: &BundleAudit) {
        let snapshot = self.snapshot();
        let mut event = ControlEvent::now(D::KINDS[0]);
        event.source = Some(self.path.display().to_string());
        event.version = Some(snapshot.document.version().to_owned());
        event.signature = snapshot.signature.clone();
        snapshot.document.describe(&mut event);
        if let Err(error) = append_control(audit, &event).await {
            tracing::error!(
                failure = %AuditFailure::classify(&error),
                noun = D::NOUN,
                "failed to journal the document in force at startup"
            );
        }
    }

    /// One poll: stage, journal, commit — or journal the rejection.
    async fn tick(
        self: &Arc<Self>,
        audit: Option<&BundleAudit>,
        on_change: Option<&ChangeHook<D>>,
    ) {
        let previous_error = self.degraded();
        let path = self.path.clone();
        // Reading, verifying, and compiling is file I/O plus parsing: off
        // the worker threads.
        let staging = Arc::clone(self);
        let outcome = tokio::task::spawn_blocking(move || staging.stage()).await;
        match outcome {
            Ok(Ok(None)) => {}
            Ok(Ok(Some(staged))) => {
                if let Some(audit) = audit {
                    let mut event = ControlEvent::now(D::KINDS[1]);
                    event.source = Some(path.display().to_string());
                    event.previous_version = Some(self.version());
                    event.version = Some(staged.version().to_owned());
                    event.signature = staged.signature().cloned();
                    staged.document().describe(&mut event);
                    if let Err(error) = append_control(audit, &event).await {
                        // Not applied: the record is the evidence that the
                        // document changed, and a change nobody can prove
                        // is a change that did not happen. The next tick
                        // tries again.
                        let reason = format!(
                            "{} change could not be journaled; last good {} in force",
                            D::NOUN,
                            D::NOUN
                        );
                        self.note_failure(&reason);
                        tracing::error!(
                            path = %path.display(),
                            failure = %AuditFailure::classify(&error),
                            "{reason}"
                        );
                        return;
                    }
                }
                let (change, previous) = self.commit(staged);
                tracing::info!(
                    path = %path.display(),
                    noun = D::NOUN,
                    from = %change.previous_version,
                    to = %change.version,
                    signed = change.signature.as_ref().is_some_and(|status| status.verified),
                    "reloaded"
                );
                if let Some(hook) = on_change {
                    hook(&previous, &self.snapshot());
                }
            }
            Ok(Err(error)) => {
                tracing::warn!(
                    path = %path.display(),
                    noun = D::NOUN,
                    %error,
                    "cannot be reloaded; keeping the previous document in force"
                );
                let reason = error.to_string();
                if let Some(audit) = audit
                    && previous_error.as_deref() != Some(reason.as_str())
                {
                    let mut event = ControlEvent::now(D::KINDS[2]).with_reason(&reason);
                    event.source = Some(path.display().to_string());
                    event.previous_version = Some(self.version());
                    event.version = self.rejected_version();
                    if let Err(error) = append_control(audit, &event).await {
                        tracing::error!(
                            failure = %AuditFailure::classify(&error),
                            noun = D::NOUN,
                            "failed to journal a rejected reload"
                        );
                    }
                }
            }
            Err(error) => tracing::warn!(%error, noun = D::NOUN, "reload task failed"),
        }
    }
}

/// Bounded control-record append for the watcher (CF-14 semantics: the
/// bound limits the wait, and a timeout means "not proven durable").
async fn append_control(audit: &BundleAudit, event: &ControlEvent) -> std::io::Result<u64> {
    super::egress::append_control_bounded(audit.sink.as_ref(), event, audit.append_timeout).await
}

/// Read the document at `path` and, when a verifying key is configured,
/// its detached signature. Returns the bytes and the signature status.
fn read_document<D: BundleDocument>(
    path: &Path,
    verifier: Option<&VerifyingKey>,
) -> Result<(Vec<u8>, Option<SignatureStatus>), BundleError> {
    let bytes = std::fs::read(path).map_err(|error| {
        BundleError::new(format!(
            "cannot read {} {}: {error}",
            D::NOUN,
            path.display()
        ))
    })?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(BundleError::new(format!(
            "{} {} is too large",
            D::NOUN,
            path.display()
        )));
    }
    let Some(verifier) = verifier else {
        return Ok((bytes, None));
    };
    let signature = super::signing::read_detached(path)
        .map_err(|error| BundleError::new(format!("{} {}: {error}", D::NOUN, path.display())))?;
    verifier
        .verify(D::DOMAIN, &bytes, &signature)
        .map_err(|error| {
            BundleError::new(format!(
                "{} {}: {error} (key {})",
                D::NOUN,
                path.display(),
                verifier.key_id()
            ))
        })?;
    Ok((
        bytes,
        Some(SignatureStatus {
            verified: true,
            key_id: Some(verifier.key_id()),
        }),
    ))
}

/// `v<version>+sha256:<16 hex>` of the exact bytes.
#[must_use]
pub fn version_label(version: u32, bytes: &[u8]) -> String {
    let mut label = format!("v{version}+");
    push_digest_label(&mut label, bytes);
    label
}

/// `sha256:<16 hex>` of `bytes` — the bundle hash on its own, for a
/// document that was refused before its version number could be read.
#[must_use]
pub fn digest_label(bytes: &[u8]) -> String {
    let mut label = String::with_capacity(23);
    push_digest_label(&mut label, bytes);
    label
}

fn push_digest_label(label: &mut String, bytes: &[u8]) {
    use std::fmt::Write as _;

    use sha2::{Digest as _, Sha256};

    let digest = Sha256::digest(bytes);
    label.push_str("sha256:");
    for byte in &digest[..8] {
        let _ = write!(label, "{byte:02x}");
    }
}

//! Two-person approval: the `MutationGate` adapter selected by
//! `MCP_ADMIN_APPROVALS=required` (plan §3.10.3, WP D.2).
//!
//! A gated mutation — policy install, deny-list replacement — is not
//! applied. [`ApprovalGate::admit`] journals an `admin_proposal` control
//! record carrying the exact candidate and answers `Deferred`; the
//! boundary answers `202`. A different administrator of the same tenant
//! approves it ([`ProposalRegistry::approve`]): an `admin_approval` record
//! is made durable, the stored candidate's digest is re-checked, and the
//! boundary applies those exact bytes through the ordinary mutation path,
//! which journals its own `admin_mutation` intent. Rejection and observed
//! expiry are `admin_rejection` records.
//!
//! The journal is the source of truth. This adapter keeps an in-memory
//! projection of it, rebuilt by [`ApprovalGate::open`] from the control
//! journal at startup, so a `control` restart loses no proposal and adds
//! no backend. Completion requires an explicit `admin_application` record.
//! Uncertain decision appends block retries until restart; approved applications
//! without completion require operator reconciliation.
//!
//! Not gated, by decision (§3.10.3): policy reload, session revoke, and
//! artifact purge pass straight through as `Apply`.
//!
//! This module, its endpoints (`server::admin::proposals`), and the CLI
//! group are the files that would move under ADR-012 (CF-18).
use crate::{
    audit::{
        export::instant,
        reader::{JournalReader, ReadError},
    },
    policy::{Principal, egress::append_control_bounded},
    ports::{
        Admission, AdmissionFuture, Approval, AuditSink, Candidate, ControlEvent, ControlEventKind,
        MutationGate, MutationIntent, MutationKind, Party, Proposal, ProposalError, ProposalFuture,
        ProposalRecord, ProposalRegistry, ProposalState,
    },
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    io,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

/// One proposal as the projection holds it: what the API reports plus the
/// candidate it applies.
#[derive(Debug, Clone)]
struct Entry {
    proposal: Proposal,
    candidate: Candidate,
    /// Whether the `admin_rejection { reason: expired }` record exists, so
    /// expiry is journaled once however often it is observed.
    expiry_journaled: bool,
    /// An append may finish after cancellation; never issue another decision on a guess.
    decision_started: bool,
}

/// The adapter. Cheap to share; the boundary holds it as both ports.
pub struct ApprovalGate {
    sink: Arc<dyn AuditSink>,
    append_timeout: Duration,
    ttl: Duration,
    /// The projection. A standard mutex: every section is a lookup or an
    /// update, and none spans an await.
    entries: Mutex<BTreeMap<String, Entry>>,
    /// Serialises decisions, which do span the append: two administrators
    /// approving at once must produce one approval and one apply.
    decisions: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for ApprovalGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalGate")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl ApprovalGate {
    /// An adapter with an empty projection.
    #[must_use]
    pub fn new(sink: Arc<dyn AuditSink>, append_timeout: Duration, ttl: Duration) -> Self {
        Self {
            sink,
            append_timeout,
            ttl,
            entries: Mutex::new(BTreeMap::new()),
            decisions: tokio::sync::Mutex::new(()),
        }
    }

    /// An adapter whose projection is rebuilt from the control journal at
    /// `journal` (a directory holding `audit-journal.jsonl`, or the file).
    /// A journal that does not exist yet is an empty projection.
    ///
    /// # Errors
    ///
    /// When the journal exists but cannot be read to its end: a control
    /// plane must not start with a partial view of what is pending.
    pub fn open(
        sink: Arc<dyn AuditSink>,
        append_timeout: Duration,
        ttl: Duration,
        journal: &Path,
    ) -> io::Result<Self> {
        let gate = Self::new(sink, append_timeout, ttl);
        let reader = match JournalReader::open(journal) {
            Ok(reader) => reader,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(gate),
            Err(error) => return Err(error),
        };
        let mut entries = BTreeMap::new();
        for record in reader {
            let record = record.map_err(|error| match error {
                ReadError::Io(error) => error,
                other => io::Error::other(format!("{other:?}")),
            })?;
            if record.is_checkpoint() {
                continue;
            }
            replay(&mut entries, record.seq, &record.kind, &record.value);
        }
        *gate
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = entries;
        Ok(gate)
    }

    /// How many proposals are pending right now.
    #[must_use]
    pub fn pending(&self) -> usize {
        let now = now_millis();
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|entry| entry.proposal.is_pending() && !expired_at(&entry.proposal, now))
            .count()
    }

    async fn append(&self, event: &ControlEvent) -> Result<u64, ProposalError> {
        append_control_bounded(self.sink.as_ref(), event, self.append_timeout)
            .await
            .map_err(|_| ProposalError::AuditUnavailable)
    }

    fn snapshot(&self, tenant: &str, id: &str) -> Option<Entry> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries
            .get(id)
            .filter(|entry| entry.proposal.proposer.tenant == tenant)
            .cloned()
    }

    fn update(&self, id: &str, apply: impl FnOnce(&mut Entry)) -> Option<Proposal> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = entries.get_mut(id)?;
        apply(entry);
        Some(entry.proposal.clone())
    }

    /// A pending proposal that has passed its expiry: journal the
    /// rejection once, mark it, and report `Expired`.
    async fn expire(&self, entry: &Entry) -> ProposalError {
        if !entry.expiry_journaled {
            let mut event =
                ControlEvent::now(ControlEventKind::AdminRejection).with_reason("expired");
            event.source = Some(entry.proposal.operation.to_owned());
            event.version = Some(entry.proposal.target.clone());
            event.proposal = Some(ProposalRecord {
                id: entry.proposal.id.clone(),
                candidate_digest: None,
                expires: Some(entry.proposal.expires.clone()),
                document: None,
                signature: None,
            });
            self.update(&entry.proposal.id, |entry| entry.decision_started = true);
            if self.append(&event).await.is_err() {
                return ProposalError::AuditUnavailable;
            }
            self.update(&entry.proposal.id, |entry| {
                entry.expiry_journaled = true;
                entry.proposal.state = ProposalState::Expired;
                entry.proposal.reason = Some("expired".into());
            });
        }
        ProposalError::Expired
    }
}

/// Which mutations wait for a second administrator.
const fn gated(kind: MutationKind) -> bool {
    matches!(
        kind,
        MutationKind::PolicyInstall | MutationKind::DenyListReplace
    )
}

impl MutationGate for ApprovalGate {
    fn admit<'a>(&'a self, intent: &'a MutationIntent<'a>) -> AdmissionFuture<'a> {
        Box::pin(async move {
            if !gated(intent.kind) {
                return Admission::Apply;
            }
            let (Some(candidate), Some(signature), Some(target)) =
                (intent.candidate, intent.signature, intent.target)
            else {
                return Admission::Refused("proposal_candidate_missing");
            };
            let Ok(document) = std::str::from_utf8(candidate) else {
                return Admission::Refused("proposal_candidate_invalid");
            };
            let now = SystemTime::now();
            let id = format!("p-{:016x}", rand::random::<u64>());
            let candidate_digest = digest(document, signature);
            let proposal = Proposal {
                id: id.clone(),
                operation: intent.kind.operation(),
                target: target.to_owned(),
                candidate_digest: candidate_digest.clone(),
                proposer: Party::from(intent.principal),
                created: crate::logger::iso_timestamp_at(now),
                expires: crate::logger::iso_timestamp_at(now + self.ttl),
                state: ProposalState::Pending,
                decided_by: None,
                decided: None,
                reason: None,
                applied_seq: None,
            };
            let mut event = ControlEvent::now(ControlEventKind::AdminProposal);
            event.principal = Some(intent.principal.clone());
            event.source = Some(proposal.operation.to_owned());
            event.version = Some(proposal.target.clone());
            event.proposal = Some(ProposalRecord {
                id: id.clone(),
                candidate_digest: Some(candidate_digest),
                expires: Some(proposal.expires.clone()),
                document: Some(document.to_owned()),
                signature: Some(signature.to_owned()),
            });
            if self.append(&event).await.is_err() {
                return Admission::Refused("audit_unavailable");
            }
            let entry = Entry {
                proposal,
                candidate: Candidate {
                    kind: intent.kind,
                    document: document.to_owned(),
                    signature: signature.to_owned(),
                },
                expiry_journaled: false,
                decision_started: false,
            };
            self.entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(id.clone(), entry);
            Admission::Deferred { proposal: id }
        })
    }
    fn name(&self) -> &'static str {
        "approval"
    }
}

impl ProposalRegistry for ApprovalGate {
    fn list(&self, tenant: &str) -> Vec<Proposal> {
        let now = now_millis();
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|entry| entry.proposal.proposer.tenant == tenant)
            .map(|entry| reported(&entry.proposal, now))
            .collect()
    }

    fn get(&self, tenant: &str, id: &str) -> Option<Proposal> {
        self.snapshot(tenant, id)
            .map(|entry| reported(&entry.proposal, now_millis()))
    }

    fn approve<'a>(&'a self, id: &'a str, approver: &'a Principal) -> ProposalFuture<'a, Approval> {
        Box::pin(async move {
            let _decision = self.decisions.lock().await;
            let entry = self
                .snapshot(&approver.tenant, id)
                .ok_or(ProposalError::NotFound)?;
            if entry.decision_started && entry.proposal.is_pending() {
                return Err(ProposalError::Incomplete);
            }
            match entry.proposal.state {
                ProposalState::Approved => {
                    if entry.proposal.applied_seq.is_none() {
                        return Err(ProposalError::Incomplete);
                    }
                    return Ok(Approval {
                        apply: None,
                        proposal: entry.proposal,
                    });
                }
                ProposalState::Rejected => return Err(ProposalError::Decided),
                ProposalState::Expired => return Err(self.expire(&entry).await),
                ProposalState::Pending => {}
            }
            if expired_at(&entry.proposal, now_millis()) {
                return Err(self.expire(&entry).await);
            }
            if entry.proposal.proposer == Party::from(approver) {
                return Err(ProposalError::SelfApproval);
            }
            if digest(&entry.candidate.document, &entry.candidate.signature)
                != entry.proposal.candidate_digest
            {
                return Err(ProposalError::DigestMismatch);
            }
            let mut event = ControlEvent::now(ControlEventKind::AdminApproval);
            event.principal = Some(approver.clone());
            event.source = Some(entry.proposal.operation.to_owned());
            event.version = Some(entry.proposal.target.clone());
            event.proposal = Some(ProposalRecord {
                id: id.to_owned(),
                candidate_digest: Some(entry.proposal.candidate_digest.clone()),
                expires: None,
                document: None,
                signature: None,
            });
            self.update(id, |entry| entry.decision_started = true);
            self.append(&event).await?;
            let decided = event.timestamp;
            let proposal = self
                .update(id, |entry| {
                    entry.proposal.state = ProposalState::Approved;
                    entry.proposal.decided_by = Some(Party::from(approver));
                    entry.proposal.decided = Some(decided);
                })
                .ok_or(ProposalError::NotFound)?;
            Ok(Approval {
                proposal,
                apply: Some(entry.candidate),
            })
        })
    }

    fn applied<'a>(&'a self, id: &'a str, audit_seq: u64) -> ProposalFuture<'a, ()> {
        Box::pin(async move {
            let _decision = self.decisions.lock().await;
            let proposal = self
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(id)
                .map(|entry| entry.proposal.clone())
                .ok_or(ProposalError::NotFound)?;
            let mut event = ControlEvent::now(ControlEventKind::AdminApplication);
            event.source = Some(proposal.operation.to_owned());
            event.version = Some(proposal.target.clone());
            event.applied_seq = Some(audit_seq);
            event.proposal = Some(ProposalRecord {
                id: id.to_owned(),
                candidate_digest: Some(proposal.candidate_digest),
                expires: None,
                document: None,
                signature: None,
            });
            self.append(&event).await?;
            self.update(id, |entry| entry.proposal.applied_seq = Some(audit_seq));
            Ok(())
        })
    }

    fn reject<'a>(
        &'a self,
        id: &'a str,
        principal: &'a Principal,
        reason: Option<&'a str>,
    ) -> ProposalFuture<'a, Proposal> {
        Box::pin(async move {
            let _decision = self.decisions.lock().await;
            let entry = self
                .snapshot(&principal.tenant, id)
                .ok_or(ProposalError::NotFound)?;
            if entry.decision_started && entry.proposal.is_pending() {
                return Err(ProposalError::Incomplete);
            }
            match entry.proposal.state {
                ProposalState::Approved | ProposalState::Rejected => {
                    return Err(ProposalError::Decided);
                }
                ProposalState::Expired => return Err(self.expire(&entry).await),
                ProposalState::Pending => {}
            }
            if expired_at(&entry.proposal, now_millis()) {
                return Err(self.expire(&entry).await);
            }
            let reason = reason
                .map(str::trim)
                .filter(|reason| !reason.is_empty())
                .unwrap_or("rejected");
            let mut event = ControlEvent::now(ControlEventKind::AdminRejection).with_reason(reason);
            event.principal = Some(principal.clone());
            event.source = Some(entry.proposal.operation.to_owned());
            event.version = Some(entry.proposal.target.clone());
            event.proposal = Some(ProposalRecord {
                id: id.to_owned(),
                candidate_digest: None,
                expires: None,
                document: None,
                signature: None,
            });
            self.update(id, |entry| entry.decision_started = true);
            self.append(&event).await?;
            let decided = event.timestamp;
            let reason = event.reason;
            self.update(id, |entry| {
                entry.proposal.state = ProposalState::Rejected;
                entry.proposal.decided_by = Some(Party::from(principal));
                entry.proposal.decided = Some(decided);
                entry.proposal.reason = reason;
            })
            .ok_or(ProposalError::NotFound)
        })
    }
}

/// `sha256:<hex>` over the document bytes, a NUL, and the signature text.
#[must_use]
pub fn digest(document: &str, signature: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(document.as_bytes());
    hasher.update([0u8]);
    hasher.update(signature.trim().as_bytes());
    let bytes = hasher.finalize();
    let mut text = String::with_capacity(7 + 64);
    text.push_str("sha256:");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

/// Whether a pending proposal's expiry has passed. An expiry that does not
/// parse counts as passed: a proposal is never applied on a guess.
fn expired_at(proposal: &Proposal, now: i64) -> bool {
    instant(&proposal.expires).is_none_or(|expires| expires <= now)
}

/// The proposal as reported: a pending one past its expiry reads as
/// expired even before a decision has journaled that.
fn reported(proposal: &Proposal, now: i64) -> Proposal {
    let mut reported = proposal.clone();
    if reported.is_pending() && expired_at(proposal, now) {
        reported.state = ProposalState::Expired;
    }
    reported
}

fn text(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(key)?;
    }
    current.as_str().map(str::to_owned)
}

fn party(value: &Value) -> Option<Party> {
    Some(Party {
        tenant: text(value, &["principal", "tenant"])?,
        subject: text(value, &["principal", "subject"])?,
    })
}

/// Fold one journal record into the projection. Unknown or malformed
/// records are skipped: the projection reports what the journal proves.
fn replay(entries: &mut BTreeMap<String, Entry>, seq: u64, kind: &str, value: &Value) {
    match kind {
        "admin_proposal" => {
            let Some(id) = text(value, &["proposal", "id"]) else {
                return;
            };
            let Some(kind) = text(value, &["source"]).and_then(|operation| {
                [MutationKind::PolicyInstall, MutationKind::DenyListReplace]
                    .into_iter()
                    .find(|kind| kind.operation() == operation)
            }) else {
                return;
            };
            let (
                Some(document),
                Some(signature),
                Some(candidate_digest),
                Some(expires),
                Some(target),
                Some(proposer),
            ) = (
                text(value, &["proposal", "document"]),
                text(value, &["proposal", "signature"]),
                text(value, &["proposal", "candidate_digest"]),
                text(value, &["proposal", "expires"]),
                text(value, &["version"]),
                party(value),
            )
            else {
                return;
            };
            entries.insert(
                id.clone(),
                Entry {
                    proposal: Proposal {
                        id,
                        operation: kind.operation(),
                        target,
                        candidate_digest,
                        proposer,
                        created: text(value, &["timestamp"]).unwrap_or_default(),
                        expires,
                        state: ProposalState::Pending,
                        decided_by: None,
                        decided: None,
                        reason: None,
                        applied_seq: None,
                    },
                    candidate: Candidate {
                        kind,
                        document,
                        signature,
                    },
                    expiry_journaled: false,
                    decision_started: false,
                },
            );
        }
        "admin_approval" | "admin_rejection" => {
            let Some(entry) = text(value, &["proposal", "id"]).and_then(|id| entries.get_mut(&id))
            else {
                return;
            };
            let reason = text(value, &["reason"]);
            entry.proposal.decided = text(value, &["timestamp"]);
            entry.proposal.decided_by = party(value);
            if kind == "admin_approval" {
                entry.proposal.state = ProposalState::Approved;
            } else if reason.as_deref() == Some("expired") {
                entry.proposal.state = ProposalState::Expired;
                entry.proposal.reason = reason;
                entry.expiry_journaled = true;
            } else {
                entry.proposal.state = ProposalState::Rejected;
                entry.proposal.reason = reason;
            }
        }
        "admin_application" => {
            let Some(entry) = text(value, &["proposal", "id"]).and_then(|id| entries.get_mut(&id))
            else {
                return;
            };
            if entry.proposal.state == ProposalState::Approved
                && text(value, &["proposal", "candidate_digest"]).as_deref()
                    == Some(&entry.proposal.candidate_digest)
                && text(value, &["source"]).as_deref() == Some(entry.proposal.operation)
                && text(value, &["version"]).as_deref() == Some(&entry.proposal.target)
            {
                entry.proposal.applied_seq = value
                    .get("applied_seq")
                    .and_then(Value::as_u64)
                    .filter(|applied| *applied < seq);
            }
        }
        _ => {}
    }
}

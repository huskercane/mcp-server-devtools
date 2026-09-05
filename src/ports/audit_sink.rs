//! `AuditSink` port: durable, sequenced compliance evidence (WP 0.7,
//! plan §3.3 / ADR-011).
//!
//! This is the **evidence** pipeline: append-only, sequence-numbered,
//! written *before* dispatch, and fail-closed — a call whose intent cannot
//! be journaled is not dispatched. It never shares a pipeline with the lossy
//! usage telemetry ([`super::usage_sink`]), and it is distinct from the
//! legacy best-effort `AUDIT_LOG` JSONL (`crate::audit`), which keeps its
//! existing shape and behaviour untouched.
//!
//! Two implementations from day one: the durable journal adapter
//! (`crate::audit::journal::JournalAuditSink`) and [`InMemoryAuditSink`]
//! for tests — including tests that *force* append failures to prove the
//! fail-closed path.
//!
//! Contents rule (§3.3): never a token, never tool arguments, never
//! response content. The types here can only express metadata and the
//! §3.2 identity/decision vocabulary, which is the structural version of
//! that promise.
//!
//! Consumed as `Arc<dyn AuditSink>`: the sink is stored in the composition
//! root and used once per tool call on a path that performs file I/O, so
//! static dispatch would buy nothing and a generic parameter would ripple
//! through `DevtoolsServer` and every `#[tool_router]` block (deviation
//! from the ports-prefer-generics note in `ports::mod`, documented per the
//! architecture conventions).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;

use crate::policy::{
    ActionContext, ClientIdentity, EgressSummary, PolicyDecision, Principal, UpstreamIdentity,
};

/// Lifecycle stage an audit event records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    /// Written **before** the tool dispatches: what was asked, by whom, the
    /// decision taken, and the upstream identity that would act.
    ToolCallIntent,
    /// Written after the dispatch completes, with the outcome.
    ToolCallOutcome,
    /// Written when the egress chokepoint **denies** an upstream request
    /// the tool was about to send (WP A.7). Every egress decision, allow or
    /// deny, is also listed on the call's outcome record
    /// ([`AuditEvent::egress`]).
    EgressDecision,
}

/// One enterprise audit event. Metadata and §3.2 identity/decision types
/// only — no arguments, no response content, no secrets.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub kind: AuditEventKind,
    /// MCP request id, correlating intent and outcome.
    pub request_id: String,
    pub tool_name: String,
    /// Canonical vendor the tool addresses; `"unknown"` when the tool name
    /// maps to no vendor (the attempt is still evidence).
    pub vendor: String,
    pub principal: Principal,
    /// Telemetry only — never an authorization input.
    pub client: ClientIdentity,
    pub decision: PolicyDecision,
    /// The identity that acts (or would act) upstream. Present in **every**
    /// event (WP 0.6).
    pub upstream_identity: UpstreamIdentity,
    /// The canonical action the decision was about (WP A.7): on intent and
    /// egress records; absent on outcome records, which the intent's
    /// `request_id` already ties to it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionContext>,
    /// Outcome label for [`AuditEventKind::ToolCallOutcome`] events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u128>,
    /// Every upstream request the egress chokepoint decided on during the
    /// call, in order, with the decision each received. On outcome records
    /// of enforcing calls that reached the transport; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressSummary>,
}

/// Kinds of control-plane record: what the gateway itself did, as opposed
/// to what a caller asked it to do (WPs B.3 and B.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ControlEventKind {
    /// An administrator authorized a mutation; durable before its effects.
    AdminMutation,
    /// The policy document in force when the gateway started.
    PolicyLoaded,
    /// A changed policy document was verified and compiled; it is put in
    /// force **after** this record is durable, never before.
    PolicyChanged,
    /// A changed policy document was refused — the signature did not
    /// verify, it did not compile, or it could not be read — and the last
    /// good document stays in force. Written once per distinct failure,
    /// not once per poll.
    PolicyRejected,
    /// The revocation list in force when the gateway started.
    RevocationLoaded,
    /// A changed revocation list was verified and applied; cached
    /// validations were dropped and affected sessions closed.
    RevocationChanged,
    /// A changed revocation list was refused; the last good list stays.
    RevocationRejected,
    /// A request carrying a validated token was refused because the
    /// revocation list names its subject, its token id, or its issue time.
    RevokedTokenRejected,
}

/// Whether a loaded document carried a verified signature, and from which
/// key. `verified: false` with no key is an unsigned load in a deployment
/// that does not require signatures (local dry runs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureStatus {
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

/// A control-plane audit record. Same journal, same sequence, same
/// durability as tool-call events; a different shape, because there is no
/// tool, no decision, and no upstream identity to report. Every field
/// beyond `kind` and `timestamp` is optional so one type covers policy
/// loads, revocation changes, and revoked-token refusals without inventing
/// placeholder principals.
#[derive(Debug, Clone, Serialize)]
pub struct ControlEvent {
    pub timestamp: String,
    pub kind: ControlEventKind,
    /// The principal a request-driven record is about (a revoked-token
    /// refusal). Absent for watcher-driven records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<Principal>,
    /// Where the document came from — an operator-configured path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Version label of the document previously in force, on a change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<String>,
    /// Version label of the document this record is about: the one loaded,
    /// put in force, or refused (the refused document's own hash, so the
    /// bytes that were rejected can be identified later).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureStatus>,
    /// A bounded, operator-facing reason on rejections and refusals. Names
    /// a category or a parser's complaint about an operator-authored file;
    /// never request content, never key material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Revocation-list contents summary, on revocation records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_subjects: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_tokens: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
}

impl ControlEvent {
    /// A record with only a kind and the current timestamp; callers fill
    /// in what applies.
    #[must_use]
    pub fn now(kind: ControlEventKind) -> Self {
        Self {
            timestamp: crate::logger::iso_timestamp(),
            kind,
            principal: None,
            source: None,
            previous_version: None,
            version: None,
            signature: None,
            reason: None,
            revoked_subjects: None,
            revoked_tokens: None,
            not_before: None,
        }
    }

    /// Attach a reason, bounded so a parser's complaint about a large
    /// document cannot balloon a record.
    #[must_use]
    pub fn with_reason(mut self, reason: &str) -> Self {
        const MAX_REASON: usize = 512;
        let mut text = reason.to_owned();
        if text.len() > MAX_REASON {
            let mut cut = MAX_REASON;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text.truncate(cut);
            text.push('…');
        }
        self.reason = Some(text);
        self
    }
}

/// Why an audit append failed, as a closed set of categories.
///
/// A sink adapter's own error text is **not** part of this. A sink is free to
/// be an HTTP client, and an adapter error can quote a request header — an
/// earlier revision logged `Display` at the call site, and the logger's
/// redaction regexes only recognise a handful of token shapes, so an
/// `X-API-Key: <value>` in an I/O error was emitted verbatim. Categories are
/// what the operator actually acts on ("the journal is unwritable" vs "the
/// sink is unreachable"); the detail belongs in the adapter's own logs, where
/// it can be scrubbed by whoever owns the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditFailure {
    /// The record could not be made durable (I/O, full disk, failed sync).
    Storage,
    /// The sink refused or could not be reached.
    Unavailable,
    /// The event could not be encoded.
    Encoding,
    /// The sink is in a state that refuses all further records.
    Poisoned,
}

impl AuditFailure {
    /// Classify an `io::Error` from a sink without retaining its message.
    #[must_use]
    pub fn classify(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::InvalidData => Self::Encoding,
            io::ErrorKind::BrokenPipe | io::ErrorKind::NotConnected => Self::Unavailable,
            _ => Self::Storage,
        }
    }

    /// Stable, secret-free label for logs and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Unavailable => "unavailable",
            Self::Encoding => "encoding",
            Self::Poisoned => "poisoned",
        }
    }
}

impl std::fmt::Display for AuditFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The future [`AuditSink::append`] returns.
///
/// Boxed because the sink is consumed as `Arc<dyn AuditSink>` (see the
/// module docs); one box per audited call, on a path that is about to wait
/// for a disk sync anyway.
pub type AppendFuture<'a> = Pin<Box<dyn Future<Output = io::Result<u64>> + Send + 'a>>;

/// Durable, sequenced audit evidence.
pub trait AuditSink: Send + Sync {
    /// Append `event`, assigning and returning the sequence number it was
    /// **durably** recorded under.
    ///
    /// Async on purpose. "Durably" means the record survives loss of the
    /// host, which means waiting for a filesystem sync — and that wait must
    /// not happen on a Tokio worker thread. Implementations that touch a
    /// disk hand the record to a dedicated writer and resolve this future
    /// when the writer acknowledges the sync, so the worker stays free
    /// while the sync is in flight.
    ///
    /// # Errors
    ///
    /// Any error means the evidence was **not** durably recorded; callers on
    /// the dispatch path must fail closed (refuse the call), never proceed.
    fn append<'a>(&'a self, event: &'a AuditEvent) -> AppendFuture<'a>;

    /// Append a control-plane record ([`ControlEvent`]) under the same
    /// sequence and durability contract as [`Self::append`].
    ///
    /// # Errors
    ///
    /// As for [`Self::append`]: any error means the record is not durable.
    /// Callers that are about to *change* the gateway's behaviour on the
    /// strength of the record (put a new policy in force) must not proceed.
    fn append_control<'a>(&'a self, event: &'a ControlEvent) -> AppendFuture<'a>;

    /// Whether the sink can currently accept records. A poisoned journal
    /// answers `false`, and the HTTP health endpoint reports it: a gateway
    /// that will refuse every tool call must not look healthy to the load
    /// balancer that keeps sending it traffic. Cheap and non-blocking — it
    /// is polled by health probes.
    fn is_available(&self) -> bool {
        true
    }
}

/// A sequence-stamped event as a sink persists it.
#[derive(Serialize)]
pub(crate) struct SequencedEvent<'a> {
    pub seq: u64,
    #[serde(flatten)]
    pub event: &'a AuditEvent,
}

/// A sequence-stamped control record as a sink persists it.
#[derive(Serialize)]
pub(crate) struct SequencedControlEvent<'a> {
    pub seq: u64,
    #[serde(flatten)]
    pub event: &'a ControlEvent,
}

/// In-memory sink for tests: sequences like the journal, records the exact
/// JSON shape persisted, and can be switched into a failing mode to prove
/// fail-closed behaviour.
#[derive(Debug, Default)]
pub struct InMemoryAuditSink {
    state: Mutex<InMemoryState>,
    failing: AtomicBool,
}

#[derive(Debug, Default)]
struct InMemoryState {
    next_seq: u64,
    events: Vec<serde_json::Value>,
}

impl InMemoryAuditSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Make every subsequent [`AuditSink::append`] fail (simulates an
    /// unwritable journal), or restore it.
    pub fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }

    /// The synchronous body of [`AuditSink::append`]. Kept separate so this
    /// test double stays trivially callable from sync test code.
    ///
    /// # Errors
    ///
    /// When [`Self::set_failing`] is on, or the event does not serialize.
    pub fn append_now(&self, event: &AuditEvent) -> io::Result<u64> {
        self.record(|seq| serde_json::to_value(SequencedEvent { seq, event }))
    }

    /// The synchronous body of [`AuditSink::append_control`].
    ///
    /// # Errors
    ///
    /// As for [`Self::append_now`].
    pub fn append_control_now(&self, event: &ControlEvent) -> io::Result<u64> {
        self.record(|seq| serde_json::to_value(SequencedControlEvent { seq, event }))
    }

    fn record(
        &self,
        serialize: impl FnOnce(u64) -> serde_json::Result<serde_json::Value>,
    ) -> io::Result<u64> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(io::Error::other("audit sink is failing (test switch)"));
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.next_seq += 1;
        let seq = state.next_seq;
        let value = serialize(seq)
            .map_err(|error| io::Error::other(format!("serialize audit event: {error}")))?;
        state.events.push(value);
        Ok(seq)
    }

    /// Everything appended so far, in sequence order, as persisted JSON.
    #[must_use]
    pub fn events(&self) -> Vec<serde_json::Value> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .events
            .clone()
    }
}

impl AuditSink for InMemoryAuditSink {
    fn append<'a>(&'a self, event: &'a AuditEvent) -> AppendFuture<'a> {
        // No I/O to wait for: resolve immediately.
        Box::pin(std::future::ready(self.append_now(event)))
    }

    fn append_control<'a>(&'a self, event: &'a ControlEvent) -> AppendFuture<'a> {
        Box::pin(std::future::ready(self.append_control_now(event)))
    }

    /// The failing switch doubles as "unavailable", so health-endpoint
    /// tests can drive it.
    fn is_available(&self) -> bool {
        !self.failing.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::policy::{CredentialLabel, EnvironmentClass, TestSlot, UpstreamAuthority};

    fn sample_event() -> AuditEvent {
        AuditEvent {
            timestamp: "2026-09-01T00:00:00.000Z".to_owned(),
            kind: AuditEventKind::ToolCallIntent,
            request_id: "1".to_owned(),
            tool_name: "jira_get".to_owned(),
            vendor: "jira".to_owned(),
            principal: Principal::local(),
            client: ClientIdentity::default(),
            decision: PolicyDecision::local_allow(),
            upstream_identity: UpstreamIdentity {
                label: CredentialLabel::principal_slot(
                    &TestSlot::new("jira", "ATLASSIAN_API_TOKEN"),
                    "alice@example.com",
                ),
                vendor: "jira".to_owned(),
                environment: EnvironmentClass::Unclassified,
                authority: UpstreamAuthority::Shared,
                provenance: None,
            },
            action: None,
            outcome: None,
            duration_ms: None,
            egress: None,
        }
    }

    #[test]
    fn appends_are_sequenced_from_one() {
        let sink = InMemoryAuditSink::new();
        assert_eq!(sink.append_now(&sample_event()).unwrap(), 1);
        assert_eq!(sink.append_now(&sample_event()).unwrap(), 2);
        let events = sink.events();
        assert_eq!(events[0]["seq"], 1);
        assert_eq!(events[1]["seq"], 2);
        assert_eq!(
            events[0]["upstream_identity"]["label"],
            "jira/ATLASSIAN_API_TOKEN/alice@example.com"
        );
    }

    #[test]
    fn failing_mode_returns_an_error_and_records_nothing() {
        let sink = InMemoryAuditSink::new();
        sink.set_failing(true);
        assert!(sink.append_now(&sample_event()).is_err());
        assert!(sink.events().is_empty());
        sink.set_failing(false);
        assert_eq!(sink.append_now(&sample_event()).unwrap(), 1);
    }
}

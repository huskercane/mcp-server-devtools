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

use crate::policy::{ClientIdentity, PolicyDecision, Principal, UpstreamIdentity};

/// Lifecycle stage an audit event records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    /// Written **before** the tool dispatches: what was asked, by whom, the
    /// decision taken, and the upstream identity that would act.
    ToolCallIntent,
    /// Written after the dispatch completes, with the outcome.
    ToolCallOutcome,
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
    /// Outcome label for [`AuditEventKind::ToolCallOutcome`] events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u128>,
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
}

/// A sequence-stamped event as a sink persists it.
#[derive(Serialize)]
pub(crate) struct SequencedEvent<'a> {
    pub seq: u64,
    #[serde(flatten)]
    pub event: &'a AuditEvent,
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
        if self.failing.load(Ordering::SeqCst) {
            return Err(io::Error::other("audit sink is failing (test switch)"));
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.next_seq += 1;
        let seq = state.next_seq;
        let value = serde_json::to_value(SequencedEvent { seq, event })
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
                    "jira",
                    &TestSlot("ATLASSIAN_API_TOKEN"),
                    "alice@example.com",
                ),
                vendor: "jira".to_owned(),
                environment: EnvironmentClass::Unclassified,
                authority: UpstreamAuthority::Shared,
            },
            outcome: None,
            duration_ms: None,
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

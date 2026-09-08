//! `UsageSink` port: lossy usage telemetry (WP 0.7, plan §3.3).
//!
//! The *other* pipeline. Usage events feed dashboards, capacity planning,
//! and rate limits; they are metadata-only, delivered off the request path,
//! and explicitly allowed to drop under pressure — with the drops counted,
//! never silent. They must never share a pipeline with audit evidence
//! ([`super::audit_sink`]): backpressure on telemetry must not be able to
//! delay or fail a tool call, and audit durability must not depend on a
//! dashboard consumer keeping up.
//!
//! Two implementations from day one: [`BoundedUsageChannel`] (bounded,
//! drop-with-counter — the enterprise adapter) and [`NoopUsageSink`]
//! (local community mode, where no telemetry consumer exists).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// One usage event. Metadata only — no arguments, no content, no secrets.
/// The subject and tenant are here since C.6, because per-principal usage
/// (who calls what, how often, how often denied) is what the rollups are
/// for; both are already on every audit record, and rollup retention
/// bounds how long they stay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsageEvent {
    pub timestamp: String,
    pub tenant: String,
    pub subject: String,
    pub tool_name: String,
    pub vendor: String,
    /// `prod` … `unclassified` — the upstream account's classification.
    pub environment: String,
    /// `allow` or `deny`: the tool-level decision.
    pub decision: String,
    /// `read`, `write`, or `destructive`.
    pub risk: String,
    pub outcome: String,
    pub duration_ms: u128,
}

/// Non-blocking usage telemetry. [`record`](UsageSink::record) must never
/// block and must never fail the caller; overflow drops the event.
pub trait UsageSink: Send + Sync {
    fn record(&self, event: UsageEvent);

    /// Events dropped so far due to backpressure.
    fn dropped(&self) -> u64;
}

/// Local-mode sink: no consumer, nothing recorded, nothing dropped.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopUsageSink;

impl UsageSink for NoopUsageSink {
    fn record(&self, _event: UsageEvent) {}

    fn dropped(&self) -> u64 {
        0
    }
}

/// Bounded-channel sink: `try_send` semantics, drop-with-counter on
/// overflow. The receiving half goes to whatever rollup consumer exists
/// (none yet in M0 — tests drain it; the `control` role consumes it in
/// later phases).
#[derive(Debug, Clone)]
pub struct BoundedUsageChannel {
    sender: tokio::sync::mpsc::Sender<UsageEvent>,
    dropped: Arc<AtomicU64>,
}

impl BoundedUsageChannel {
    /// Create the sink and its consumer end.
    #[must_use]
    pub fn new(capacity: usize) -> (Self, tokio::sync::mpsc::Receiver<UsageEvent>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
        (
            Self {
                sender,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            receiver,
        )
    }
}

impl UsageSink for BoundedUsageChannel {
    fn record(&self, event: UsageEvent) {
        if self.sender.try_send(event).is_err() {
            // Full or closed: lossy by contract, but counted.
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn event(tool: &str) -> UsageEvent {
        UsageEvent {
            timestamp: "2026-09-01T00:00:00.000Z".to_owned(),
            tenant: "acme".to_owned(),
            subject: "alice".to_owned(),
            tool_name: tool.to_owned(),
            vendor: "jira".to_owned(),
            environment: "qa".to_owned(),
            decision: "allow".to_owned(),
            risk: "read".to_owned(),
            outcome: "success".to_owned(),
            duration_ms: 5,
        }
    }

    #[tokio::test]
    async fn overflow_drops_events_and_counts_them_without_blocking() {
        let (sink, mut receiver) = BoundedUsageChannel::new(2);
        sink.record(event("one"));
        sink.record(event("two"));
        sink.record(event("three")); // over capacity: dropped, counted
        sink.record(event("four")); // dropped, counted

        assert_eq!(sink.dropped(), 2);
        assert_eq!(receiver.recv().await.unwrap().tool_name, "one");
        assert_eq!(receiver.recv().await.unwrap().tool_name, "two");
        assert!(receiver.try_recv().is_err(), "dropped events never arrive");
    }

    #[tokio::test]
    async fn closed_consumer_counts_drops_instead_of_erroring() {
        let (sink, receiver) = BoundedUsageChannel::new(2);
        drop(receiver);
        sink.record(event("orphan"));
        assert_eq!(sink.dropped(), 1);
    }

    #[test]
    fn noop_sink_records_and_drops_nothing() {
        let sink = NoopUsageSink;
        sink.record(event("ignored"));
        assert_eq!(sink.dropped(), 0);
    }
}

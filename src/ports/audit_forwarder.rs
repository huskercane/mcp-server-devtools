//! `AuditForwarder` port: deliver a batch of journal records to an external
//! receiver and acknowledge (plan §3.9 "Audit forwarding", WP C.3).
//!
//! The journal ([`crate::audit::journal`]) is the source of truth and stays
//! so: forwarding is a *copy* of records that are already durable, made
//! from the `control` role after the fact, and the only thing that comes
//! back across this port is an acknowledgement. Nothing about a receiver —
//! its wire framing, its endpoint types, its authentication — is visible
//! on this side of it, which is what lets a syslog receiver, a Splunk HTTP
//! Event Collector, and a generic JSON endpoint be the same port.
//!
//! Three implementations from day one: syslog (RFC 5424 over TLS,
//! [`crate::audit::forward::syslog`]), HTTP (Splunk HEC and generic JSON,
//! [`crate::audit::forward::http`]), and [`InMemoryAuditForwarder`] for
//! tests — including tests that make delivery *fail* to prove nothing is
//! acknowledged, and therefore nothing is skipped, when it does.
//!
//! ## Acknowledgement semantics
//!
//! `Ok(())` from [`AuditForwarder::deliver`] means **every** record in the
//! batch reached the receiver as far as the adapter can tell: an HTTP
//! `2xx`, or a TLS stream that accepted and flushed the bytes. Anything
//! less is an error, and the caller ([`crate::audit::forward::Shipper`])
//! retries the whole batch from its last acknowledged sequence. Delivery
//! is therefore **at least once**: a receiver may see a record twice after
//! a failure mid-batch, and the record's `seq` is how it deduplicates.
//! Never at most once — a record that might not have arrived is re-sent,
//! because a SIEM with a hole in it is the outcome this port exists to
//! prevent.
//!
//! Consumed as `Arc<dyn AuditForwarder>` (boxed future per *batch*, not
//! per record): the forwarder is selected from configuration in
//! `bootstrap/`, runs on a background task, and touches nothing on the
//! request path — the documented deviation from ports-prefer-generics, for
//! the same reason as `SecretSource`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// One journal record as the forwarder sees it: the sequence, the kind,
/// the timestamp the record carries, and the record's exact JSON bytes
/// (the journal line without its trailing newline). Borrowed from the
/// reader — a batch is a slice of views, not a copy of the journal.
#[derive(Debug, Clone, Copy)]
pub struct ForwardRecord<'a> {
    pub seq: u64,
    pub kind: &'a str,
    /// The record's own `timestamp`, when it has one (checkpoints do).
    pub timestamp: Option<&'a str>,
    /// Whether the record is a denial or a refusal — a receiver may want
    /// to rank it higher (syslog severity). Derived by the shipper from
    /// the record, so an adapter never parses the JSON to find out.
    pub adverse: bool,
    pub json: &'a [u8],
}

/// Why a batch was not acknowledged. `category` is a fixed vocabulary for
/// the health banner and the log; `detail` is bounded operator text that
/// never contains the receiver's credential or a record's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardError {
    pub category: &'static str,
    pub detail: String,
}

impl ForwardError {
    /// The receiver could not be reached (DNS, connect, TLS handshake).
    pub const UNREACHABLE: &'static str = "receiver_unreachable";
    /// The receiver answered, and said no (an HTTP status outside `2xx`).
    pub const REJECTED: &'static str = "receiver_rejected";
    /// The connection or request did not complete in time.
    pub const TIMEOUT: &'static str = "receiver_timeout";
    /// The stream broke while the batch was in flight; the receiver may
    /// hold part of it.
    pub const INTERRUPTED: &'static str = "delivery_interrupted";

    #[must_use]
    pub fn new(category: &'static str, detail: impl Into<String>) -> Self {
        const MAX_DETAIL: usize = 256;
        let mut detail: String = detail.into();
        if detail.len() > MAX_DETAIL {
            let mut cut = MAX_DETAIL;
            while !detail.is_char_boundary(cut) {
                cut -= 1;
            }
            detail.truncate(cut);
            detail.push('…');
        }
        Self { category, detail }
    }
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.detail.is_empty() {
            formatter.write_str(self.category)
        } else {
            write!(formatter, "{}: {}", self.category, self.detail)
        }
    }
}

impl std::error::Error for ForwardError {}

/// The future [`AuditForwarder::deliver`] returns.
pub type DeliverFuture<'a> = Pin<Box<dyn Future<Output = Result<(), ForwardError>> + Send + 'a>>;

/// Delivers batches of journal records to one receiver.
pub trait AuditForwarder: Send + Sync {
    /// A short, fixed name for logs and the health banner (`syslog`,
    /// `splunk-hec`, `http-json`, `memory`). Never the receiver's address.
    fn name(&self) -> &'static str;

    /// Deliver `batch` — non-empty, in ascending `seq` — and acknowledge
    /// all of it, or fail without acknowledging any of it.
    fn deliver<'a>(&'a self, batch: &'a [ForwardRecord<'a>]) -> DeliverFuture<'a>;
}

/// A captured record, for assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedRecord {
    pub seq: u64,
    pub kind: String,
    pub adverse: bool,
    pub json: Vec<u8>,
}

/// Collects every delivered record in memory; can be told to refuse the
/// next `n` batches so the retry path is testable.
#[derive(Debug, Default)]
pub struct InMemoryAuditForwarder {
    received: Mutex<Vec<CapturedRecord>>,
    refuse: AtomicU64,
    down: AtomicBool,
    deliveries: AtomicU64,
}

impl InMemoryAuditForwarder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything acknowledged so far, in delivery order.
    #[must_use]
    pub fn received(&self) -> Vec<CapturedRecord> {
        self.received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The sequences acknowledged so far.
    #[must_use]
    pub fn sequences(&self) -> Vec<u64> {
        self.received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|record| record.seq)
            .collect()
    }

    /// Refuse the next `batches` deliveries with [`ForwardError::UNREACHABLE`].
    pub fn refuse_next(&self, batches: u64) {
        self.refuse.store(batches, Ordering::Release);
    }

    /// Refuse every delivery until told otherwise.
    pub fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::Release);
    }

    /// How many `deliver` calls were made, acknowledged or not.
    #[must_use]
    pub fn deliveries(&self) -> u64 {
        self.deliveries.load(Ordering::Acquire)
    }
}

impl AuditForwarder for InMemoryAuditForwarder {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn deliver<'a>(&'a self, batch: &'a [ForwardRecord<'a>]) -> DeliverFuture<'a> {
        Box::pin(async move {
            self.deliveries.fetch_add(1, Ordering::AcqRel);
            if self.down.load(Ordering::Acquire) {
                return Err(ForwardError::new(
                    ForwardError::UNREACHABLE,
                    "receiver is down",
                ));
            }
            let refusing = self
                .refuse
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                    left.checked_sub(1)
                })
                .is_ok();
            if refusing {
                return Err(ForwardError::new(
                    ForwardError::UNREACHABLE,
                    "receiver refused the batch",
                ));
            }
            let mut received = self
                .received
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            received.reserve(batch.len());
            received.extend(batch.iter().map(|record| CapturedRecord {
                seq: record.seq,
                kind: record.kind.to_owned(),
                adverse: record.adverse,
                json: record.json.to_vec(),
            }));
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(seq: u64) -> ForwardRecord<'static> {
        ForwardRecord {
            seq,
            kind: "tool_call_intent",
            timestamp: Some("2026-09-04T00:00:00.000Z"),
            adverse: false,
            json: b"{\"seq\":1}",
        }
    }

    #[tokio::test]
    async fn refuse_next_fails_that_many_batches_then_acknowledges() {
        let forwarder = InMemoryAuditForwarder::new();
        forwarder.refuse_next(2);
        assert!(forwarder.deliver(&[record(1)]).await.is_err());
        assert!(forwarder.deliver(&[record(1)]).await.is_err());
        forwarder.deliver(&[record(1), record(2)]).await.unwrap();
        assert_eq!(forwarder.sequences(), vec![1, 2]);
        assert_eq!(forwarder.deliveries(), 3);
    }

    #[test]
    fn error_detail_is_bounded() {
        let error = ForwardError::new(ForwardError::REJECTED, "x".repeat(1000));
        assert!(error.detail.len() < 300);
        assert!(error.to_string().starts_with("receiver_rejected: xxx"));
    }
}

//! The usage consumer: drains the bounded usage channel into a
//! [`RollupStore`] in batches, and prunes on a cadence (WP C.6).
//!
//! Off the request path by construction: the sink's `record` is a
//! `try_send`, and this task is the only thing that touches the store.
//! A store that fails keeps the events it could not append in the batch
//! and retries with backoff; the channel keeps filling, and past its
//! capacity the sink drops with a counter — lossy by contract (§3.3), and
//! the health banner says so.
//!
//! Retention runs on its own timer, not on traffic: a control plane that
//! goes quiet (a weekend, a gateway that stopped sending) still prunes on
//! the cadence, so expired rows never outlive the retention window just
//! because nothing new arrived.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc::Receiver;

use crate::ports::{RollupStore, UsageEvent, UsageRow};

/// Most events per append.
pub const BATCH: usize = 256;
/// How long a partial batch waits for more events before it is appended.
pub const LINGER: Duration = Duration::from_millis(500);
/// The longest a failing store is left alone between retries.
pub const MAX_BACKOFF: Duration = Duration::from_mins(1);
/// How often retention is applied, with or without traffic.
pub const PRUNE_INTERVAL: Duration = Duration::from_hours(1);

/// Whether rollups are keeping up, for the health banner and tests.
#[derive(Debug, Default)]
pub struct RollupHealth {
    degraded: Mutex<Option<&'static str>>,
    appended: AtomicU64,
    batches: AtomicU64,
    pruned: AtomicU64,
}

impl RollupHealth {
    #[must_use]
    pub fn degraded(&self) -> Option<&'static str> {
        *self
            .degraded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set_degraded(&self, category: Option<&'static str>) {
        *self
            .degraded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = category;
    }

    /// Rows appended so far.
    #[must_use]
    pub fn appended(&self) -> u64 {
        self.appended.load(Ordering::Acquire)
    }

    /// Append attempts so far, successful or not; tests wait on it.
    #[must_use]
    pub fn batches(&self) -> u64 {
        self.batches.load(Ordering::Acquire)
    }

    /// Rows pruned so far.
    #[must_use]
    pub fn pruned(&self) -> u64 {
        self.pruned.load(Ordering::Acquire)
    }
}

/// Turn an event into a row. Owned by the consumer so the sink's `record`
/// stays a move into a channel.
#[must_use]
pub fn row_from(event: UsageEvent) -> UsageRow {
    UsageRow {
        timestamp: event.timestamp,
        tenant: event.tenant,
        subject: event.subject,
        vendor: event.vendor,
        environment: event.environment,
        tool_name: event.tool_name,
        decision: event.decision,
        risk: event.risk,
        outcome: event.outcome,
        duration_ms: u64::try_from(event.duration_ms).unwrap_or(u64::MAX),
    }
}

/// The consumer task.
pub struct Consumer {
    store: Arc<dyn RollupStore>,
    receiver: Receiver<UsageEvent>,
    health: Arc<RollupHealth>,
    retention: Option<Duration>,
    prune_interval: Duration,
}

impl Consumer {
    /// `retention = None` keeps everything.
    #[must_use]
    pub fn new(
        store: Arc<dyn RollupStore>,
        receiver: Receiver<UsageEvent>,
        health: Arc<RollupHealth>,
        retention: Option<Duration>,
    ) -> Self {
        Self {
            store,
            receiver,
            health,
            retention,
            prune_interval: PRUNE_INTERVAL,
        }
    }

    /// Apply retention every `interval` instead of [`PRUNE_INTERVAL`]
    /// (tests).
    #[must_use]
    pub const fn prune_every(mut self, interval: Duration) -> Self {
        self.prune_interval = interval;
        self
    }

    /// Run until the channel closes (every sender dropped) or `cancel`
    /// fires; on either, what is buffered is appended before returning.
    /// Retention is applied every `prune_interval` whether or not events
    /// arrive.
    pub async fn run(mut self, cancel: tokio_util::sync::CancellationToken) {
        let mut pending: Vec<UsageRow> = Vec::with_capacity(BATCH);
        let mut failures: u32 = 0;
        let prune_timer = tokio::time::sleep(self.prune_interval);
        tokio::pin!(prune_timer);
        loop {
            if pending.is_empty() {
                // Block for the first event of a batch — or the prune
                // timer, which must not wait for one.
                let first = tokio::select! {
                    () = cancel.cancelled() => None,
                    event = self.receiver.recv() => event,
                    () = &mut prune_timer, if self.retention.is_some() => {
                        self.prune_and_reschedule(prune_timer.as_mut()).await;
                        continue;
                    }
                };
                let Some(first) = first else {
                    // Closed or cancelled: append whatever is buffered and
                    // whatever is still queued, then stop.
                    self.receiver.close();
                    while let Ok(event) = self.receiver.try_recv() {
                        pending.push(row_from(event));
                    }
                    if !pending.is_empty() {
                        let _ = self.append(&mut pending).await;
                    }
                    return;
                };
                pending.push(row_from(first));
                // Linger briefly for more, so a busy gateway appends 256 at
                // a time and a quiet one appends within half a second.
                let linger = tokio::time::sleep(LINGER);
                tokio::pin!(linger);
                while pending.len() < BATCH {
                    tokio::select! {
                        () = &mut linger => break,
                        event = self.receiver.recv() => match event {
                            Some(event) => pending.push(row_from(event)),
                            None => break,
                        },
                    }
                }
            } else {
                // Retrying a batch the store refused: top it up without
                // waiting for a new event.
                while pending.len() < BATCH {
                    match self.receiver.try_recv() {
                        Ok(event) => pending.push(row_from(event)),
                        Err(_) => break,
                    }
                }
            }
            if self.append(&mut pending).await.is_ok() {
                failures = 0;
            } else {
                failures = failures.saturating_add(1);
                let wait = LINGER
                    .saturating_mul(1u32 << failures.min(10))
                    .min(MAX_BACKOFF);
                tokio::select! {
                    () = cancel.cancelled() => {
                        let _ = self.append(&mut pending).await;
                        return;
                    }
                    () = tokio::time::sleep(wait) => {}
                }
            }
            if self.retention.is_some() && prune_timer.is_elapsed() {
                self.prune_and_reschedule(prune_timer.as_mut()).await;
            }
        }
    }

    /// Apply retention now and arm the timer for the next cadence.
    async fn prune_and_reschedule(&self, timer: std::pin::Pin<&mut tokio::time::Sleep>) {
        if let Some(retention) = self.retention {
            self.prune(retention).await;
        }
        timer.reset(tokio::time::Instant::now() + self.prune_interval);
    }

    /// Append `pending` and clear it on success; keep it on failure.
    async fn append(&self, pending: &mut Vec<UsageRow>) -> Result<(), ()> {
        self.health.batches.fetch_add(1, Ordering::AcqRel);
        match self.store.append(pending).await {
            Ok(()) => {
                self.health
                    .appended
                    .fetch_add(pending.len() as u64, Ordering::AcqRel);
                if self.health.degraded().is_some() {
                    tracing::info!(store = self.store.name(), "usage rollups recovered");
                }
                self.health.set_degraded(None);
                pending.clear();
                Ok(())
            }
            Err(error) => {
                if self.health.degraded() != Some(error.category) {
                    tracing::warn!(
                        store = self.store.name(),
                        failure = error.category,
                        buffered = pending.len(),
                        "usage rollup append failed; will retry: {error}"
                    );
                }
                self.health.set_degraded(Some(error.category));
                // Bound the buffer: past four batches, the oldest go — the
                // channel behind it is already dropping, and this is the
                // lossy pipeline.
                if pending.len() > BATCH * 4 {
                    let excess = pending.len() - BATCH * 4;
                    pending.drain(..excess);
                }
                Err(())
            }
        }
    }

    /// Apply retention once.
    pub async fn prune(&self, retention: Duration) {
        let cutoff = std::time::SystemTime::now()
            .checked_sub(retention)
            .unwrap_or(std::time::UNIX_EPOCH);
        let before = crate::logger::iso_timestamp_at(cutoff);
        match self.store.prune(&before).await {
            Ok(pruned) => {
                if pruned > 0 {
                    tracing::info!(store = self.store.name(), pruned, before = %before, "usage rollups pruned");
                }
                self.health.pruned.fetch_add(pruned, Ordering::AcqRel);
            }
            Err(error) => {
                tracing::warn!(
                    store = self.store.name(),
                    failure = error.category,
                    "usage rollup prune failed: {error}"
                );
            }
        }
    }
}

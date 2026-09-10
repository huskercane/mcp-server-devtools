//! HTTP transport for Atlassian product API calls.
//!
//! Vendor-neutral. The base URL, path normalisation, and non-2xx error
//! envelope parsing are all delegated to the [`Vendor`] trait
//! ([`crate::vendor`]). Everything else (auth header, request building,
//! 10 MB response cap, body classification, raw-response persistence) is
//! shared across vendors.
//!
//! Response classifier (matches the TS reference for both Bitbucket and
//! Jira via [`fetch`]):
//! - `204` → empty object, no raw path
//! - `text/plain` → raw text pass-through (e.g. Bitbucket diffs), no raw
//!   path
//! - empty body → empty object, no raw path
//! - JSON parse success → parsed value + raw response persisted to disk
//! - JSON parse failure → raw text, no raw path
//!
//! ## Back-compat shims
//!
//! [`fetch_bitbucket`] and [`fetch_bitbucket_with_base`] are preserved as
//! thin shims that construct a [`BitbucketVendor`] and call [`fetch`].
//! New code should call [`fetch`] directly with the vendor it needs.

pub mod client;
pub mod image;
pub mod multipart;
pub mod raw_response;
mod redirect;
mod response_cache;
mod retry;

/// Expire idle cache entries and close observations before the audit writer stops.
/// The caller must stop serving requests before signaling shutdown.
pub async fn maintain_response_cache(mut shutdown: tokio::sync::oneshot::Receiver<()>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let closing = tokio::select! {
            _ = &mut shutdown => true,
            _ = interval.tick() => false,
        };
        if let Err(error) =
            tokio::task::spawn_blocking(move || response_cache::maintain(closing)).await
        {
            tracing::warn!(%error, "cache observation maintenance failed");
        }
        if closing {
            break;
        }
    }
}

/// Re-export of the Bitbucket error parser at its old path. Kept so
/// downstream tests (`tests/bitbucket_error_tests.rs`) and any external
/// consumers continue to compile after the parser moved into
/// [`crate::vendor::bitbucket::error`].
pub use crate::vendor::bitbucket::error as bitbucket_error;
pub use client::{HttpClient, HttpClientBuilder, HttpError, HttpRequest, HttpResponse};

use rustc_hash::FxHashMap;
use std::collections::{BTreeMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use futures::TryStreamExt as _;
use http::header::{
    ACCEPT, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue,
};
use http::{Method, StatusCode};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, BufReader};
use tokio_util::io::StreamReader;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::auth::Credentials;
use crate::config::Config;
use crate::constants::{data_limits::MAX_RESPONSE_SIZE, network_timeouts::DEFAULT_REQUEST};
use crate::error::{McpError, OriginalError, api_error, auth_invalid, unexpected};
use crate::vendor::Vendor;
use crate::vendor::bitbucket::BitbucketVendor;

fn sanitized_log_url(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return "<unparseable-url>".to_owned();
    };
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.into()
}

fn elapsed_millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

fn bytes_per_second(bytes: u64, elapsed: Duration) -> u64 {
    let nanos = elapsed.as_nanos().max(1);
    let rate = u128::from(bytes)
        .saturating_mul(1_000_000_000)
        .checked_div(nanos)
        .unwrap_or(0);
    u64::try_from(rate).unwrap_or(u64::MAX)
}

fn transport_error_kind(error: &HttpError) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_request() {
        "request"
    } else if error.is_body() {
        "body"
    } else if error.is_decode() {
        "decode"
    } else {
        "other"
    }
}

fn is_retryable_stream_request_error(error: &HttpError) -> bool {
    // The adapter classifies some connection resets while sending as request
    // errors rather than connect errors. All current streaming endpoints are
    // read-only queries, including Splunk's POST export endpoint.
    error.is_connect() || error.is_timeout() || error.is_request()
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct HttpCallLog<'a> {
    component: &'a str,
    method: &'a str,
    url: &'a str,
    started: Instant,
    attempt: usize,
    max_attempts: usize,
}

impl<'a> HttpCallLog<'a> {
    pub(crate) fn new(component: &'a str, method: &'a str, url: &'a str) -> Self {
        Self {
            component,
            method,
            url,
            started: Instant::now(),
            attempt: 1,
            max_attempts: 1,
        }
    }

    fn for_attempt(mut self, attempt: usize, max_attempts: usize) -> Self {
        self.started = Instant::now();
        self.attempt = attempt;
        self.max_attempts = max_attempts;
        self
    }
}

pub(crate) fn log_http_transport_failure(
    call: HttpCallLog<'_>,
    error: &HttpError,
    will_retry: bool,
) {
    warn!(
        component = call.component,
        method = call.method,
        url = %sanitized_log_url(call.url),
        error_kind = transport_error_kind(error),
        elapsed_ms = elapsed_millis(call.started.elapsed()),
        attempt = call.attempt,
        max_attempts = call.max_attempts,
        will_retry,
        "outbound HTTP call failed"
    );
}

pub(crate) fn log_http_status_failure(call: HttpCallLog<'_>, status: StatusCode, will_retry: bool) {
    warn!(
        component = call.component,
        method = call.method,
        url = %sanitized_log_url(call.url),
        status = status.as_u16(),
        elapsed_ms = elapsed_millis(call.started.elapsed()),
        attempt = call.attempt,
        max_attempts = call.max_attempts,
        will_retry,
        "outbound HTTP call returned a non-success status"
    );
}

fn log_http_timeout_failure(call: HttpCallLog<'_>, will_retry: bool) {
    warn!(
        component = call.component,
        method = call.method,
        url = %sanitized_log_url(call.url),
        error_kind = "deadline",
        elapsed_ms = elapsed_millis(call.started.elapsed()),
        attempt = call.attempt,
        max_attempts = call.max_attempts,
        will_retry,
        "outbound HTTP call failed"
    );
}

fn log_streamed_download(
    component: &str,
    method: &str,
    url: &str,
    filename_prefix: &str,
    artifact: &raw_response::StreamedArtifact,
    elapsed: Duration,
    attempts: usize,
) {
    info!(
        component,
        method,
        url = %sanitized_log_url(url),
        filename_prefix,
        encoded_bytes = artifact.encoded_bytes,
        decoded_bytes = artifact.decoded_bytes,
        elapsed_ms = elapsed_millis(elapsed),
        encoded_bytes_per_second = bytes_per_second(artifact.encoded_bytes, elapsed),
        decoded_bytes_per_second = bytes_per_second(artifact.decoded_bytes, elapsed),
        attempts,
        "completed streamed log download"
    );
}

#[derive(Debug, Clone)]
pub struct StreamingPolicy {
    pub max_encoded_bytes: u64,
    pub max_decoded_bytes: u64,
    pub idle_read_timeout: Duration,
    pub total_deadline: Duration,
    pub max_attempts: usize,
    pub cancellation: CancellationToken,
    pub aggregate: Option<Arc<StreamingAggregateQuota>>,
    pub disk: Option<Arc<StreamingDiskQuota>>,
    pub operation: Option<raw_response::ArtifactOperation>,
}

#[derive(Debug)]
pub struct StreamingAggregateQuota {
    encoded: AtomicU64,
    decoded: AtomicU64,
    pub max_encoded_bytes: u64,
    pub max_decoded_bytes: u64,
}

/// One request's private view of the process-wide streaming disk coordinator.
/// The owner identifier and its reservation leases never cross a public tool
/// boundary.
#[derive(Debug)]
pub struct StreamingDiskQuota {
    coordinator: Arc<StreamingDiskCoordinator>,
    owner: u64,
    cancellation: CancellationToken,
    deadline: tokio::time::Instant,
}

#[derive(Debug)]
struct StreamingDiskCoordinator {
    limit: u64,
    state: Mutex<StreamingDiskState>,
}

// Waiters use strict FIFO ordering. A request at the head of the queue is the
// only request considered until enough bytes are released for it, preventing
// smaller later writes from starving an earlier writer. Every wait is bounded
// by its transaction cancellation token and absolute deadline.

#[derive(Debug, Default)]
struct StreamingDiskState {
    reserved: u64,
    peak: u64,
    next_reservation: u64,
    next_waiter: u64,
    // IDs are generated internally, never selected by callers; collision
    // attack resistance is unnecessary for these two integer maps.
    transactions: FxHashMap<u64, TransactionReservation>,
    reservations: FxHashMap<u64, OwnedReservation>,
    waiters: VecDeque<ReservationWaiter>,
}

#[derive(Debug)]
struct TransactionReservation {
    reserved: u64,
    limit: u64,
}

#[derive(Debug)]
struct OwnedReservation {
    owner: u64,
    amount: u64,
}

#[derive(Debug)]
struct ReservationWaiter {
    id: u64,
    reservation: u64,
    owner: u64,
    amount: u64,
    status: Arc<AtomicU8>,
    notify: Arc<tokio::sync::Notify>,
}

/// A narrow, exactly-once reservation owned by one writer or committed file.
#[derive(Debug)]
pub(crate) struct StreamingDiskLease {
    transaction: Arc<StreamingDiskQuota>,
    reservation: u64,
}

static STREAMING_DISK_COORDINATOR: OnceLock<Arc<StreamingDiskCoordinator>> = OnceLock::new();
static NEXT_STREAMING_TRANSACTION: AtomicU64 = AtomicU64::new(1);

impl StreamingDiskCoordinator {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            state: Mutex::new(StreamingDiskState::default()),
        }
    }

    fn register_transaction(&self, owner: u64, limit: u64) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .transactions
            .insert(owner, TransactionReservation { reserved: 0, limit });
    }

    fn register_reservation(&self, owner: u64) -> std::io::Result<u64> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.transactions.contains_key(&owner) {
            return Err(std::io::Error::other(
                "disk reservation transaction is closed",
            ));
        }
        state.next_reservation = state
            .next_reservation
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("disk reservation identifier overflow"))?;
        let reservation = state.next_reservation;
        state
            .reservations
            .insert(reservation, OwnedReservation { owner, amount: 0 });
        Ok(reservation)
    }

    fn can_grant(state: &StreamingDiskState, limit: u64, amount: u64) -> bool {
        state
            .reserved
            .checked_add(amount)
            .is_some_and(|next| next <= limit)
    }

    fn grant_locked(
        state: &mut StreamingDiskState,
        limit: u64,
        reservation: u64,
        owner: u64,
        amount: u64,
    ) -> std::io::Result<u64> {
        let transaction = state
            .transactions
            .get(&owner)
            .ok_or_else(|| std::io::Error::other("disk reservation transaction is closed"))?;
        let transaction_next = transaction
            .reserved
            .checked_add(amount)
            .filter(|next| *next <= transaction.limit)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::FileTooLarge,
                    "transaction disk reservation quota exceeded or counter overflow",
                )
            })?;
        let global_next = state
            .reserved
            .checked_add(amount)
            .filter(|next| *next <= limit)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::FileTooLarge,
                    "server-wide disk reservation quota exceeded or counter overflow",
                )
            })?;
        let reservation_entry = state.reservations.get(&reservation).ok_or_else(|| {
            std::io::Error::other("disk reservation lease is no longer registered")
        })?;
        if reservation_entry.owner != owner {
            return Err(std::io::Error::other("disk reservation owner mismatch"));
        }
        let reservation_next = reservation_entry
            .amount
            .checked_add(amount)
            .ok_or_else(|| std::io::Error::other("disk reservation counter overflow"))?;
        state.reserved = global_next;
        state.peak = state.peak.max(global_next);
        state
            .transactions
            .get_mut(&owner)
            .expect("transaction validated above")
            .reserved = transaction_next;
        state
            .reservations
            .get_mut(&reservation)
            .expect("reservation validated above")
            .amount = reservation_next;
        Ok(reservation_next)
    }

    fn wake_waiters_locked(state: &mut StreamingDiskState, limit: u64) {
        while !state.waiters.is_empty() {
            let amount = state.waiters.front().expect("waiter exists").amount;
            if !Self::can_grant(state, limit, amount) {
                break;
            }
            let waiter = state.waiters.pop_front().expect("front waiter exists");
            if Self::grant_locked(
                state,
                limit,
                waiter.reservation,
                waiter.owner,
                waiter.amount,
            )
            .is_ok()
            {
                waiter.status.store(1, Ordering::Release);
            } else {
                waiter.status.store(2, Ordering::Release);
            }
            waiter.notify.notify_one();
        }
    }

    async fn acquire(
        &self,
        reservation: u64,
        owner: u64,
        amount: u64,
        cancellation: &CancellationToken,
        deadline: tokio::time::Instant,
    ) -> std::io::Result<u64> {
        if amount == 0 {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            return state
                .reservations
                .get(&reservation)
                .filter(|entry| entry.owner == owner)
                .map(|entry| entry.amount)
                .ok_or_else(|| std::io::Error::other("disk reservation owner mismatch"));
        }
        let status = Arc::new(AtomicU8::new(0));
        let notify = Arc::new(tokio::sync::Notify::new());
        let waiter_id;
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let transaction = state
                .transactions
                .get(&owner)
                .ok_or_else(|| std::io::Error::other("disk reservation transaction is closed"))?;
            transaction
                .reserved
                .checked_add(amount)
                .filter(|next| *next <= transaction.limit)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::FileTooLarge,
                        "transaction disk reservation quota exceeded or counter overflow",
                    )
                })?;
            if state.waiters.is_empty() && Self::can_grant(&state, self.limit, amount) {
                return Self::grant_locked(&mut state, self.limit, reservation, owner, amount);
            }
            state.next_waiter = state
                .next_waiter
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("disk waiter identifier overflow"))?;
            waiter_id = state.next_waiter;
            state.waiters.push_back(ReservationWaiter {
                id: waiter_id,
                reservation,
                owner,
                amount,
                status: status.clone(),
                notify: notify.clone(),
            });
        }
        let outcome = tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "disk reservation wait cancelled")),
            () = tokio::time::sleep_until(deadline) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "disk reservation wait deadline exceeded")),
            () = notify.notified() => Ok(()),
        };
        if outcome.is_err() || status.load(Ordering::Acquire) != 1 {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(index) = state
                .waiters
                .iter()
                .position(|waiter| waiter.id == waiter_id)
            {
                state.waiters.remove(index);
                status.store(2, Ordering::Release);
                Self::wake_waiters_locked(&mut state, self.limit);
            } else if status.swap(2, Ordering::AcqRel) == 1 {
                Self::release_locked(&mut state, reservation, owner, amount)?;
                Self::wake_waiters_locked(&mut state, self.limit);
            }
            return outcome.and(Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "disk reservation waiter could not be granted",
            )));
        }
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(state
            .reservations
            .get(&reservation)
            .expect("granted reservation remains registered")
            .amount)
    }

    fn release_locked(
        state: &mut StreamingDiskState,
        reservation: u64,
        owner: u64,
        amount: u64,
    ) -> std::io::Result<u64> {
        let entry = state
            .reservations
            .get(&reservation)
            .ok_or_else(|| std::io::Error::other("disk reservation already released"))?;
        if entry.owner != owner {
            return Err(std::io::Error::other("disk reservation owner mismatch"));
        }
        let reservation_next = entry
            .amount
            .checked_sub(amount)
            .ok_or_else(|| std::io::Error::other("disk reservation release underflow"))?;
        let transaction = state
            .transactions
            .get(&owner)
            .ok_or_else(|| std::io::Error::other("disk reservation transaction is closed"))?;
        let transaction_next = transaction
            .reserved
            .checked_sub(amount)
            .ok_or_else(|| std::io::Error::other("transaction reservation release underflow"))?;
        let global_next = state
            .reserved
            .checked_sub(amount)
            .ok_or_else(|| std::io::Error::other("server reservation release underflow"))?;
        state
            .reservations
            .get_mut(&reservation)
            .expect("reservation validated above")
            .amount = reservation_next;
        state
            .transactions
            .get_mut(&owner)
            .expect("transaction validated above")
            .reserved = transaction_next;
        state.reserved = global_next;
        Ok(reservation_next)
    }

    fn release(&self, reservation: u64, owner: u64, amount: u64) -> std::io::Result<u64> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remaining = Self::release_locked(&mut state, reservation, owner, amount)?;
        Self::wake_waiters_locked(&mut state, self.limit);
        Ok(remaining)
    }

    fn unregister_reservation(&self, reservation: u64, owner: u64) -> std::io::Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = state
            .reservations
            .get(&reservation)
            .ok_or_else(|| std::io::Error::other("disk reservation already released"))?;
        if entry.owner != owner {
            return Err(std::io::Error::other("disk reservation owner mismatch"));
        }
        if entry.amount != 0 {
            return Err(std::io::Error::other(
                "cannot unregister a live disk reservation",
            ));
        }
        state.reservations.remove(&reservation);
        Ok(())
    }
}

impl StreamingDiskQuota {
    fn next_owner() -> u64 {
        NEXT_STREAMING_TRANSACTION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .expect("streaming disk transaction identifier space exhausted")
    }

    #[cfg(test)]
    pub fn new(limit: u64) -> Self {
        let coordinator = Arc::new(StreamingDiskCoordinator::new(limit));
        let owner = Self::next_owner();
        coordinator.register_transaction(owner, limit);
        Self {
            coordinator,
            owner,
            cancellation: CancellationToken::new(),
            deadline: tokio::time::Instant::now() + Duration::from_secs(30),
        }
    }

    fn with_coordinator(
        coordinator: Arc<StreamingDiskCoordinator>,
        limit: u64,
        cancellation: CancellationToken,
        deadline: tokio::time::Instant,
    ) -> Arc<Self> {
        let owner = Self::next_owner();
        coordinator.register_transaction(owner, limit);
        Arc::new(Self {
            coordinator,
            owner,
            cancellation,
            deadline,
        })
    }

    pub fn server_transaction(cancellation: CancellationToken) -> Arc<Self> {
        raw_response::reconcile_missing_artifacts();
        let limit = crate::constants::data_limits::MAX_STREAMED_ARTIFACT_SIZE;
        let coordinator = STREAMING_DISK_COORDINATOR
            .get_or_init(|| Arc::new(StreamingDiskCoordinator::new(limit)))
            .clone();
        Self::with_coordinator(
            coordinator,
            limit,
            cancellation,
            tokio::time::Instant::now()
                + crate::constants::data_limits::STREAM_TOTAL_REQUEST_TIMEOUT,
        )
    }

    pub(crate) fn lease(self: &Arc<Self>) -> std::io::Result<StreamingDiskLease> {
        let reservation = self.coordinator.register_reservation(self.owner)?;
        Ok(StreamingDiskLease {
            transaction: self.clone(),
            reservation,
        })
    }

    pub fn reserved_bytes(&self) -> u64 {
        self.coordinator
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .transactions
            .get(&self.owner)
            .map_or(0, |transaction| transaction.reserved)
    }

    pub fn peak_reserved_bytes(&self) -> u64 {
        self.coordinator
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .peak
    }
}

impl Drop for StreamingDiskQuota {
    fn drop(&mut self) {
        let mut state = self
            .coordinator
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let removable = state
            .transactions
            .get(&self.owner)
            .is_some_and(|transaction| transaction.reserved == 0)
            && !state
                .reservations
                .values()
                .any(|reservation| reservation.owner == self.owner)
            && !state
                .waiters
                .iter()
                .any(|waiter| waiter.owner == self.owner);
        if removable {
            state.transactions.remove(&self.owner);
        }
    }
}

impl StreamingDiskLease {
    pub(crate) async fn grow(&self, amount: u64) -> std::io::Result<u64> {
        self.transaction
            .coordinator
            .acquire(
                self.reservation,
                self.transaction.owner,
                amount,
                &self.transaction.cancellation,
                self.transaction.deadline,
            )
            .await
    }

    pub(crate) fn shrink(&self, amount: u64) -> std::io::Result<u64> {
        self.transaction
            .coordinator
            .release(self.reservation, self.transaction.owner, amount)
    }

    pub(crate) fn amount(&self) -> u64 {
        self.transaction
            .coordinator
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reservations
            .get(&self.reservation)
            .filter(|reservation| reservation.owner == self.transaction.owner)
            .map_or(0, |reservation| reservation.amount)
    }

    pub(crate) fn same_transaction(&self, transaction: &Arc<StreamingDiskQuota>) -> bool {
        Arc::ptr_eq(&self.transaction, transaction)
    }
}

impl Drop for StreamingDiskLease {
    fn drop(&mut self) {
        let amount = self.amount();
        if amount != 0 {
            let released = self.shrink(amount);
            debug_assert!(released.is_ok());
        }
        let unregistered = self
            .transaction
            .coordinator
            .unregister_reservation(self.reservation, self.transaction.owner);
        debug_assert!(unregistered.is_ok());
    }
}

impl StreamingAggregateQuota {
    pub const fn new(max_encoded_bytes: u64, max_decoded_bytes: u64) -> Self {
        Self {
            encoded: AtomicU64::new(0),
            decoded: AtomicU64::new(0),
            max_encoded_bytes,
            max_decoded_bytes,
        }
    }

    fn add(counter: &AtomicU64, amount: u64, limit: u64, label: &str) -> std::io::Result<()> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(amount).filter(|next| *next <= limit)
            })
            .map(|_| ())
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::FileTooLarge,
                    format!("aggregate {label} quota exceeded or counter overflow"),
                )
            })
    }

    pub fn add_encoded(&self, amount: u64) -> std::io::Result<()> {
        Self::add(
            &self.encoded,
            amount,
            self.max_encoded_bytes,
            "encoded-byte",
        )
    }
    pub fn add_decoded(&self, amount: u64) -> std::io::Result<()> {
        Self::add(
            &self.decoded,
            amount,
            self.max_decoded_bytes,
            "decoded-byte",
        )
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded.load(Ordering::Acquire)
    }
    pub fn decoded_bytes(&self) -> u64 {
        self.decoded.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod http_observability_tests {
    use std::time::Duration;

    use super::{bytes_per_second, sanitized_log_url};

    #[test]
    fn logged_urls_remove_credentials_queries_and_fragments() {
        assert_eq!(
            sanitized_log_url(
                "https://operator:password@example.com/log/output?circle-token=secret#fragment"
            ),
            "https://example.com/log/output"
        );
        assert_eq!(sanitized_log_url("not a URL"), "<unparseable-url>");
    }

    #[test]
    fn transfer_rate_uses_checked_saturating_arithmetic() {
        assert_eq!(bytes_per_second(1_000, Duration::from_secs(2)), 500);
        assert_eq!(bytes_per_second(1, Duration::ZERO), 1_000_000_000);
        assert_eq!(
            bytes_per_second(u64::MAX, Duration::from_nanos(1)),
            u64::MAX
        );
    }
}

#[cfg(test)]
mod aggregate_quota_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;

    use super::{StreamingAggregateQuota, StreamingDiskCoordinator, StreamingDiskQuota};

    fn shared_transaction(
        coordinator: &Arc<StreamingDiskCoordinator>,
        limit: u64,
        cancellation: CancellationToken,
        deadline: tokio::time::Instant,
    ) -> Arc<StreamingDiskQuota> {
        StreamingDiskQuota::with_coordinator(coordinator.clone(), limit, cancellation, deadline)
    }

    #[test]
    fn checked_aggregate_counters_reject_limits_and_overflow() {
        let quota = StreamingAggregateQuota::new(3, u64::MAX);
        quota.add_encoded(2).unwrap();
        assert!(quota.add_encoded(2).is_err());
        let overflow = StreamingAggregateQuota::new(u64::MAX, u64::MAX);
        overflow.add_decoded(u64::MAX).unwrap();
        assert!(overflow.add_decoded(1).is_err());
    }

    #[tokio::test]
    async fn checked_disk_reservation_rejects_quota_underflow_and_overflow() {
        let quota = std::sync::Arc::new(StreamingDiskQuota::new(10));
        let lease = quota.lease().unwrap();
        assert_eq!(lease.grow(4).await.unwrap(), 4);
        assert_eq!(lease.grow(6).await.unwrap(), 10);
        assert!(lease.grow(1).await.is_err());
        assert_eq!(lease.shrink(6).unwrap(), 4);
        assert_eq!(lease.shrink(4).unwrap(), 0);
        assert!(lease.shrink(1).is_err());
        let overflow = std::sync::Arc::new(StreamingDiskQuota::new(u64::MAX));
        let overflow_lease = overflow.lease().unwrap();
        overflow_lease.grow(u64::MAX).await.unwrap();
        assert!(overflow_lease.grow(1).await.is_err());
    }

    #[tokio::test]
    async fn independent_splunk_and_loki_transactions_share_one_ceiling() {
        let coordinator = Arc::new(StreamingDiskCoordinator::new(10));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let splunk = shared_transaction(&coordinator, 10, CancellationToken::new(), deadline);
        let loki = shared_transaction(&coordinator, 10, CancellationToken::new(), deadline);
        let splunk_file = splunk.lease().unwrap();
        let loki_file = loki.lease().unwrap();
        splunk_file.grow(6).await.unwrap();
        let waiting = tokio::spawn(async move {
            let result = loki_file.grow(5).await;
            (loki_file, result)
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        assert_eq!(coordinator.state.lock().unwrap().reserved, 6);
        splunk_file.shrink(1).unwrap();
        let (loki_file, result) = waiting.await.unwrap();
        assert_eq!(result.unwrap(), 5);
        assert_eq!(splunk.reserved_bytes(), 5);
        assert_eq!(loki.reserved_bytes(), 5);
        assert!(coordinator.state.lock().unwrap().peak <= 10);
        drop(splunk_file);
        drop(loki_file);
        assert_eq!(splunk.reserved_bytes(), 0);
        assert_eq!(loki.reserved_bytes(), 0);
    }

    #[tokio::test]
    async fn circleci_waits_behind_ingestion_in_fifo_order() {
        let coordinator = Arc::new(StreamingDiskCoordinator::new(4));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let holder = shared_transaction(&coordinator, 4, CancellationToken::new(), deadline);
        let splunk = shared_transaction(&coordinator, 4, CancellationToken::new(), deadline);
        let circleci = shared_transaction(&coordinator, 4, CancellationToken::new(), deadline);
        let held = holder.lease().unwrap();
        held.grow(4).await.unwrap();
        let first_lease = splunk.lease().unwrap();
        let first = tokio::spawn(async move {
            first_lease.grow(3).await.unwrap();
            first_lease
        });
        while coordinator.state.lock().unwrap().waiters.len() != 1 {
            tokio::task::yield_now().await;
        }
        let second_lease = circleci.lease().unwrap();
        let second = tokio::spawn(async move {
            second_lease.grow(3).await.unwrap();
            second_lease
        });
        while coordinator.state.lock().unwrap().waiters.len() != 2 {
            tokio::task::yield_now().await;
        }
        held.shrink(3).unwrap();
        let first_lease = first.await.unwrap();
        assert!(!second.is_finished());
        drop(first_lease);
        let second_lease = second.await.unwrap();
        assert_eq!(circleci.reserved_bytes(), 3);
        drop(second_lease);
        drop(held);
        assert_eq!(coordinator.state.lock().unwrap().reserved, 0);
    }

    #[tokio::test]
    async fn cancellation_rolls_back_only_the_waiting_transaction() {
        let coordinator = Arc::new(StreamingDiskCoordinator::new(4));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let holder = shared_transaction(&coordinator, 4, CancellationToken::new(), deadline);
        let cancellation = CancellationToken::new();
        let waiter = shared_transaction(&coordinator, 4, cancellation.clone(), deadline);
        let held = holder.lease().unwrap();
        held.grow(4).await.unwrap();
        let waiting_lease = waiter.lease().unwrap();
        let waiting = tokio::spawn(async move { waiting_lease.grow(1).await });
        while coordinator.state.lock().unwrap().waiters.is_empty() {
            tokio::task::yield_now().await;
        }
        cancellation.cancel();
        let error = waiting.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(waiter.reserved_bytes(), 0);
        assert_eq!(holder.reserved_bytes(), 4);
        assert!(coordinator.state.lock().unwrap().waiters.is_empty());
        drop(held);
        assert_eq!(coordinator.state.lock().unwrap().reserved, 0);
    }

    #[tokio::test]
    async fn deadline_quota_exhaustion_and_owner_isolation_are_explicit() {
        let coordinator = Arc::new(StreamingDiskCoordinator::new(2));
        let holder = shared_transaction(
            &coordinator,
            2,
            CancellationToken::new(),
            tokio::time::Instant::now() + Duration::from_secs(1),
        );
        let waiter = shared_transaction(
            &coordinator,
            2,
            CancellationToken::new(),
            tokio::time::Instant::now() + Duration::from_millis(10),
        );
        let held = holder.lease().unwrap();
        held.grow(2).await.unwrap();
        let waiting = waiter.lease().unwrap();
        let error = waiting.grow(1).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(waiter.reserved_bytes(), 0);
        assert!(
            coordinator
                .release(held.reservation, waiter.owner, 1)
                .is_err()
        );
        assert_eq!(holder.reserved_bytes(), 2);
        assert!(waiting.shrink(1).is_err());
        drop(waiting);
        drop(held);
        assert_eq!(coordinator.state.lock().unwrap().reserved, 0);
    }
}

impl StreamingPolicy {
    pub fn new(max_encoded_bytes: u64, max_decoded_bytes: u64) -> Self {
        Self {
            max_encoded_bytes,
            max_decoded_bytes,
            idle_read_timeout: crate::constants::data_limits::STREAM_IDLE_READ_TIMEOUT,
            total_deadline: crate::constants::data_limits::STREAM_TOTAL_REQUEST_TIMEOUT,
            max_attempts: crate::constants::data_limits::STREAM_MAX_ATTEMPTS,
            cancellation: CancellationToken::new(),
            aggregate: None,
            disk: None,
            operation: None,
        }
    }
}

// Keep the retry state, deadline, and per-attempt attribution together.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn fetch_streamed_artifact_with_policy(
    vendor: &dyn Vendor,
    credentials: &Credentials,
    config: &Config,
    path: &str,
    options: RequestOptions,
    filename_prefix: &str,
    extension: &str,
    content_type: &str,
    policy: StreamingPolicy,
) -> Result<raw_response::StreamedArtifact, McpError> {
    let base = vendor.base_url(config)?;
    let target = canonical_target(path)?;
    let method = options.method.unwrap_or(HttpMethod::Get);
    // Plan §1.3: the request about to go on the wire is the fact policy is
    // evaluated on. Outside an enforcing call scope this is one lookup.
    let destination = redirect::destination(&target.url_under(&base))?;
    let ticket = if vendor.name() == "artifactory" && method == HttpMethod::Get {
        crate::policy::authorize_download_egress(vendor.name(), &target, &destination).await?
    } else {
        crate::policy::authorize_egress_at(
            vendor.name(),
            method,
            &target,
            options.body.as_ref(),
            Some(&destination),
        )
        .await?
    };
    // Each wire attempt, and how the last one ended, for the egress record.
    let report = |status, failure| report_attempt(ticket.as_ref(), status, failure);
    let url = target.url_under(&base);
    let (auth_name, auth_header) = validate_auth(credentials)?;
    let client = streaming_client()?;
    let attempts = policy.max_attempts.max(1);
    let deadline = tokio::time::Instant::now() + policy.total_deadline;
    let download_started = Instant::now();
    for attempt in 1..=attempts {
        if policy.cancellation.is_cancelled() {
            return Err(api_error("streaming request cancelled", Some(499), None));
        }
        let remaining = remaining_until(deadline)?;
        let request = build_request(
            client,
            method,
            &url,
            &auth_name,
            &auth_header,
            &options,
            remaining,
        );
        let call =
            HttpCallLog::new(vendor.name(), method.as_str(), &url).for_attempt(attempt, attempts);
        let response = tokio::select! {
            () = policy.cancellation.cancelled() => {
                // The send was in flight: the vendor may have observed it.
                report(None, Some("cancelled"));
                return Err(api_error("streaming request cancelled", Some(499), None));
            }
            result = tokio::time::timeout(remaining, request.send()) => match result {
                Ok(Ok(response)) => response,
                Ok(Err(error)) if attempt < attempts && is_retryable_stream_request_error(&error) => {
                    report(None, Some("transport_error"));
                    log_http_transport_failure(call, &error, true);
                    retry_stream_attempt(attempt, &policy, deadline, None).await?;
                    continue;
                }
                Ok(Err(error)) => {
                    report(None, Some("transport_error"));
                    log_http_transport_failure(call, &error, false);
                    return Err(map_transport_error(&error, &url));
                }
                Err(_) if attempt < attempts => {
                    report(None, Some("timeout"));
                    log_http_timeout_failure(call, true);
                    retry_stream_attempt(attempt, &policy, deadline, None).await?;
                    continue;
                }
                Err(_) => {
                    report(None, Some("timeout"));
                    log_http_timeout_failure(call, false);
                    return Err(api_error("streaming request exceeded total deadline", Some(408), None));
                }
            }
        };
        report(Some(response.status().as_u16()), None);
        let response = redirect::follow(
            client,
            vendor.name(),
            config,
            &url,
            response,
            method,
            &options,
            Some((&auth_name, &auth_header)),
            deadline,
            &policy.cancellation,
        )
        .await?;
        let status = response.status();
        if !status.is_success() {
            let will_retry = attempt < attempts && matches!(status.as_u16(), 429 | 502 | 503 | 504);
            log_http_status_failure(call, status, will_retry);
            if will_retry {
                let delay = retry::parse(response.headers(), std::time::SystemTime::now());
                drop(response);
                retry_stream_attempt(attempt, &policy, deadline, delay).await?;
                continue;
            }
            let delay = retry::parse(response.headers(), std::time::SystemTime::now());
            let redirected = response.url().as_str() != url;
            let body = bounded_body(response, &policy, deadline).await?;
            let error = if redirected {
                api_error("Redirected download failed", Some(status.as_u16()), None)
            } else {
                vendor.classify_error(status, &body)
            };
            return Err(retry::metadata(error, delay));
        }
        enforce_streamed_length_cap(&response, &policy)?;
        let artifact = tokio::time::timeout(
            remaining_until(deadline)?,
            persist_decoded_response(response, filename_prefix, extension, content_type, &policy),
        )
        .await
        .map_err(|_| api_error("streaming request exceeded total deadline", Some(408), None))??;
        log_streamed_download(
            vendor.name(),
            method.as_str(),
            &url,
            filename_prefix,
            &artifact,
            download_started.elapsed(),
            attempt,
        );
        return Ok(artifact);
    }
    unreachable!("bounded streaming retry loop returns")
}

type BoxRead = Pin<Box<dyn AsyncRead + Send>>;
type BoxBufRead = Pin<Box<dyn AsyncBufRead + Send>>;

fn decoded_reader(
    response: HttpResponse,
    policy: &StreamingPolicy,
    encoded: Arc<AtomicU64>,
) -> Result<BoxRead, McpError> {
    let encodings = response
        .headers()
        .get_all(CONTENT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let encoded_limit = policy.max_encoded_bytes;
    let aggregate = policy.aggregate.clone();
    let stream = response
        .bytes_stream()
        .map_err(|_| std::io::Error::other("upstream response body interrupted"))
        .and_then(move |chunk| {
            let counter = encoded.clone();
            let aggregate = aggregate.clone();
            async move {
                let amount = u64::try_from(chunk.len()).map_err(std::io::Error::other)?;
                let next = counter
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                        current
                            .checked_add(amount)
                            .filter(|value| *value <= encoded_limit)
                    })
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::FileTooLarge,
                            "encoded response exceeds streamed artifact limit or counter overflow",
                        )
                    })?;
                let _ = next;
                if let Some(aggregate) = &aggregate {
                    aggregate.add_encoded(amount)?;
                }
                Ok(chunk)
            }
        });
    let mut reader: BoxRead = Box::pin(StreamReader::new(stream));
    for encoding in encodings.iter().rev() {
        let buffered: BoxBufRead = Box::pin(BufReader::with_capacity(
            crate::constants::data_limits::STREAM_WRITE_BUFFER_SIZE,
            reader,
        ));
        reader = match encoding.as_str() {
            "identity" => Box::pin(buffered),
            "gzip" | "x-gzip" => Box::pin(async_compression::tokio::bufread::GzipDecoder::new(
                buffered,
            )),
            "br" => Box::pin(async_compression::tokio::bufread::BrotliDecoder::new(
                buffered,
            )),
            "deflate" => Box::pin(async_compression::tokio::bufread::DeflateDecoder::new(
                buffered,
            )),
            "zstd" => Box::pin(async_compression::tokio::bufread::ZstdDecoder::new(
                buffered,
            )),
            other => {
                return Err(api_error(
                    format!("unsupported Content-Encoding: {other}"),
                    Some(415),
                    None,
                ));
            }
        };
    }
    Ok(reader)
}

async fn persist_decoded_response(
    response: HttpResponse,
    filename_prefix: &str,
    extension: &str,
    content_type: &str,
    policy: &StreamingPolicy,
) -> Result<raw_response::StreamedArtifact, McpError> {
    let expected_checksum = response
        .headers()
        .get("x-checksum-sha256")
        .map(|header| {
            header
                .to_str()
                .ok()
                .filter(|value| {
                    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                .map(str::to_ascii_lowercase)
                .ok_or_else(|| api_error("Invalid upstream SHA-256", Some(502), None))
        })
        .transpose()?;
    let encoded = std::sync::Arc::new(AtomicU64::new(0));
    let mut reader = decoded_reader(response, policy, encoded.clone())?;
    let mut writer = raw_response::begin_artifact_in_operation(
        filename_prefix,
        extension,
        content_type,
        policy.max_decoded_bytes,
        policy.operation.as_ref(),
    )
    .await
    .map_err(|error| unexpected(format!("failed to create streamed artifact: {error}"), None))?;
    if let Some(disk) = &policy.disk {
        writer.set_disk_quota(disk);
    }
    let mut buffer = vec![0_u8; crate::constants::data_limits::STREAM_WRITE_BUFFER_SIZE];
    loop {
        let read = tokio::select! {
            () = policy.cancellation.cancelled() => return Err(api_error("streaming request cancelled", Some(499), None)),
            result = tokio::time::timeout(policy.idle_read_timeout, reader.read(&mut buffer)) => result
                .map_err(|_| api_error("streaming response idle-read timeout", Some(408), None))?
                .map_err(|error| {
                    let status = (error.kind() == std::io::ErrorKind::FileTooLarge).then_some(413);
                    api_error(format!("failed to decode streaming response: {error}"), status, None)
                })?,
        };
        if read == 0 {
            break;
        }
        if let Some(aggregate) = &policy.aggregate {
            let read = u64::try_from(read).map_err(|error| {
                api_error(
                    format!("decoded byte count overflow: {error}"),
                    Some(413),
                    None,
                )
            })?;
            aggregate
                .add_decoded(read)
                .map_err(|error| api_error(error.to_string(), Some(413), None))?;
        }
        writer.write_chunk(&buffer[..read]).await.map_err(|error| {
            let status = (error.kind() == std::io::ErrorKind::FileTooLarge).then_some(413);
            api_error(
                format!("failed to persist decoded response: {error}"),
                status,
                None,
            )
        })?;
    }
    let mut artifact = writer.commit().await.map_err(|error| {
        unexpected(format!("failed to commit streamed artifact: {error}"), None)
    })?;
    if expected_checksum
        .as_ref()
        .is_some_and(|expected| expected != &artifact.sha256)
    {
        raw_response::remove_artifact(&artifact.artifact.path)
            .await
            .map_err(|_| {
                api_error(
                    "Checksum mismatch; artifact cleanup failed",
                    Some(502),
                    None,
                )
            })?;
        return Err(api_error(
            "Upstream SHA-256 checksum mismatch",
            Some(502),
            None,
        ));
    }
    artifact.encoded_bytes = encoded.load(Ordering::Relaxed);
    artifact.decoded_bytes = artifact.artifact.size;
    Ok(artifact)
}

/// Stream an absolute, unauthenticated URL (for example a signed log-output
/// URL) through the same explicit wire accounting and decoder path.
// Keep the retry state, deadline, and per-attempt attribution together.
#[allow(clippy::too_many_lines)]
pub async fn fetch_streamed_url(
    vendor: &str,
    config: &Config,
    url: &str,
    filename_prefix: &str,
    extension: &str,
    content_type: &str,
    policy: StreamingPolicy,
) -> Result<raw_response::StreamedArtifact, McpError> {
    let destination = redirect::destination(url)?;
    let ticket = redirect::authorize(vendor, &destination).await?;
    if !redirect::allowed(config, vendor, &destination) {
        return Err(api_error(
            "Download origin is not in MCP_DOWNLOAD_ALLOWED_ORIGINS",
            Some(403),
            None,
        ));
    }
    let client = streaming_client()?;
    let deadline = tokio::time::Instant::now() + policy.total_deadline;
    let attempts = policy.max_attempts.max(1);
    let download_started = Instant::now();
    for attempt in 1..=attempts {
        let remaining = remaining_until(deadline)?;
        let call = HttpCallLog::new(vendor, "GET", url).for_attempt(attempt, attempts);
        let response = tokio::select! {
            () = policy.cancellation.cancelled() => {
                report_attempt(ticket.as_ref(), None, Some("cancelled"));
                return Err(api_error("streaming request cancelled", Some(499), None));
            },
            result = tokio::time::timeout(remaining, client.get(url).timeout(remaining).send()) => match result {
                Ok(Ok(response)) => response,
                Ok(Err(error)) if attempt < attempts && is_retryable_stream_request_error(&error) => {
                    report_attempt(ticket.as_ref(), None, Some("transport_error"));
                    log_http_transport_failure(call, &error, true);
                    retry_stream_attempt(attempt, &policy, deadline, None).await?;
                    continue;
                }
                Ok(Err(error)) => {
                    report_attempt(ticket.as_ref(), None, Some("transport_error"));
                    log_http_transport_failure(call, &error, false);
                    return Err(api_error("Download request failed", Some(if error.is_timeout() { 408 } else { 502 }), None));
                }
                Err(_) if attempt < attempts => {
                    report_attempt(ticket.as_ref(), None, Some("timeout"));
                    log_http_timeout_failure(call, true);
                    retry_stream_attempt(attempt, &policy, deadline, None).await?;
                    continue;
                }
                Err(_) => {
                    report_attempt(ticket.as_ref(), None, Some("timeout"));
                    log_http_timeout_failure(call, false);
                    return Err(api_error("streaming request exceeded total deadline", Some(408), None));
                }
            }
        };
        report_attempt(ticket.as_ref(), Some(response.status().as_u16()), None);
        let response = redirect::follow(
            client,
            vendor,
            config,
            url,
            response,
            HttpMethod::Get,
            &RequestOptions::default(),
            None,
            deadline,
            &policy.cancellation,
        )
        .await?;
        let status = response.status();
        if !status.is_success() {
            let will_retry = attempt < attempts && matches!(status.as_u16(), 429 | 502 | 503 | 504);
            log_http_status_failure(call, status, will_retry);
            if will_retry {
                let delay = retry::parse(response.headers(), std::time::SystemTime::now());
                drop(response);
                retry_stream_attempt(attempt, &policy, deadline, delay).await?;
                continue;
            }
            let delay = retry::parse(response.headers(), std::time::SystemTime::now());
            // Consume under the same bounds, but never echo an object-store error
            // body: it can contain the signed URL or credentials.
            let _ = bounded_body(response, &policy, deadline).await?;
            return Err(retry::metadata(
                api_error(
                    format!("streaming request failed with status {}", status.as_u16()),
                    Some(status.as_u16()),
                    None,
                ),
                delay,
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > policy.max_encoded_bytes)
        {
            return Err(api_error(
                "encoded response exceeds streamed artifact limit",
                Some(413),
                None,
            ));
        }
        let artifact = tokio::time::timeout(
            remaining_until(deadline)?,
            persist_decoded_response(response, filename_prefix, extension, content_type, &policy),
        )
        .await
        .map_err(|_| api_error("streaming request exceeded total deadline", Some(408), None))??;
        log_streamed_download(
            vendor,
            "GET",
            url,
            filename_prefix,
            &artifact,
            download_started.elapsed(),
            attempt,
        );
        return Ok(artifact);
    }
    unreachable!("bounded streaming retry loop returns")
}

fn remaining_until(deadline: tokio::time::Instant) -> Result<Duration, McpError> {
    deadline
        .checked_duration_since(tokio::time::Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| api_error("streaming request exceeded total deadline", Some(408), None))
}

async fn retry_stream_attempt(
    attempt: usize,
    policy: &StreamingPolicy,
    deadline: tokio::time::Instant,
    requested: Option<Duration>,
) -> Result<(), McpError> {
    let delay = requested.unwrap_or_else(|| retry::jitter(attempt));
    if delay >= remaining_until(deadline)? {
        return Err(api_error(
            "retry delay exceeds remaining request deadline",
            Some(408),
            Some(OriginalError::Json(
                serde_json::json!({"retryAfterMs": u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)}),
            )),
        ));
    }
    tokio::select! {
        () = policy.cancellation.cancelled() => Err(api_error("streaming request cancelled", Some(499), None)),
        () = tokio::time::sleep_until(deadline) => Err(api_error("streaming request exceeded total deadline", Some(408), None)),
        () = tokio::time::sleep(delay) => Ok(()),
    }
}

/// HTTP verb set accepted by the generic API client. Mirrors the TS
/// `RequestOptions.method` union.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }

    fn as_method(self) -> Method {
        match self {
            Self::Get => Method::GET,
            Self::Post => Method::POST,
            Self::Put => Method::PUT,
            Self::Patch => Method::PATCH,
            Self::Delete => Method::DELETE,
        }
    }
}

/// Request options for a single API call. Matches TS `RequestOptions`.
#[derive(Debug, Clone, Default)]
pub struct RequestOptions {
    /// Bypass local cache lookup and admission for this request.
    pub fresh: bool,
    /// Sensitive response: bypass caching and raw-response persistence.
    pub sensitive_response: bool,
    pub method: Option<HttpMethod>,
    pub headers: Vec<(String, String)>,
    pub body: Option<Value>,
    /// URL-encoded form body. Used by APIs such as Splunk whose POST
    /// endpoints do not accept JSON. Mutually exclusive with `body`;
    /// `form` takes precedence if both are supplied.
    pub form: Option<BTreeMap<String, String>>,
    /// Plain-text request body (`Content-Type: text/plain`). Used by APIs
    /// whose query language is not JSON — Artifactory's AQL search endpoint
    /// is a `POST` with the query as the body. Lowest precedence of the three
    /// body forms: `form`, then `body`, then `text_body`.
    pub text_body: Option<String>,
    pub timeout: Option<Duration>,
}

/// What the TS code calls `TransportResponse<T>`. `data` is the successfully
/// parsed body (JSON value, raw text for `text/plain`, or `{}` for empties);
/// `raw_response_path` points at the on-disk persisted JSON body when one was
/// written.
#[derive(Debug, Clone)]
pub struct TransportResponse {
    pub cache: CacheMetadata,
    pub data: ResponseBody,
    pub raw_response_path: Option<std::path::PathBuf>,
    /// Upstream response headers. Purpose-built tools read pagination
    /// headers from here (Sentry's `Link` cursor, GitHub's `Link`), which the
    /// body does not carry. Empty on a local cache hit — the cache stores
    /// bodies, and a cursor into a page that was served from cache is the
    /// same cursor the origin would have returned when it was stored, so
    /// list tools bypass the cache (see `Vendor::cache_reads`).
    pub headers: http::HeaderMap,
}

/// Provenance of the local HTTP response, independent of upstream cache age.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheMetadata {
    pub hit: bool,
    pub age_ms: u128,
    pub fetched_at: String,
}

/// Typed response body. `Json` is the canonical successful case; the other
/// variants preserve the TS contract for diffs and DELETEs.
#[derive(Debug, Clone)]
pub enum ResponseBody {
    Json(Value),
    Text(String),
    Empty,
}

impl ResponseBody {
    pub fn as_json(&self) -> Option<&Value> {
        if let Self::Json(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

fn log_ninjaone_request(vendor_name: &str, url: &str, method: HttpMethod, body: Option<&Value>) {
    if vendor_name != "ninjaone" {
        return;
    }

    let body = body.map_or(Value::Null, crate::vendor::ninjaone::sanitized_http_json);
    debug!(
        target: crate::vendor::ninjaone::HTTP_LOG_TARGET,
        %url,
        method = method.as_str(),
        body = %body,
        "ninjaone HTTP request"
    );
}

fn log_ninjaone_error_response(
    vendor_name: &str,
    url: &str,
    method: HttpMethod,
    status: StatusCode,
    body_text: &str,
) {
    if vendor_name != "ninjaone" {
        return;
    }

    debug!(
        target: crate::vendor::ninjaone::HTTP_LOG_TARGET,
        %url,
        method = method.as_str(),
        status = status.as_u16(),
        body = %crate::vendor::ninjaone::sanitized_http_text(body_text),
        "ninjaone HTTP response"
    );
}

fn log_ninjaone_response(
    vendor_name: &str,
    url: &str,
    method: HttpMethod,
    status: StatusCode,
    body: &ResponseBody,
) {
    if vendor_name != "ninjaone" {
        return;
    }

    let body = match body {
        ResponseBody::Json(value) => crate::vendor::ninjaone::sanitized_http_json(value),
        _ => serde_json::json!({ "nonJsonBody": "<omitted>" }),
    };
    debug!(
        target: crate::vendor::ninjaone::HTTP_LOG_TARGET,
        %url,
        method = method.as_str(),
        status = status.as_u16(),
        body = %body,
        "ninjaone HTTP response"
    );
}

/// Vendor-neutral entry point. Resolves the vendor's base URL, builds the
/// auth header, sends the request, and classifies the response. Non-2xx
/// responses go through [`Vendor::classify_error`] for vendor-specific
/// envelope parsing.
///
/// The `path` parameter is forwarded as-is; callers (typically the
/// controller layer) are expected to have already applied
/// [`Vendor::normalize_path`] so that path normalisation lives in one
/// place. The transport itself only joins base + path.
#[allow(clippy::too_many_lines)] // Cache lookup, upstream fetch, and admission form one request lifecycle.
pub async fn fetch(
    client: &HttpClient,
    vendor: &dyn Vendor,
    credentials: &Credentials,
    config: &Config,
    path: &str,
    options: RequestOptions,
) -> Result<TransportResponse, McpError> {
    let base = vendor.base_url(config)?;
    let target = canonical_target(path)?;
    let method = options.method.unwrap_or(HttpMethod::Get);
    // Plan §1.3: the request about to go on the wire is the fact policy is
    // evaluated on. Outside an enforcing call scope this is one lookup.
    let destination = redirect::destination(&target.url_under(&base))?;
    let ticket = crate::policy::authorize_egress_at(
        vendor.name(),
        method,
        &target,
        options.body.as_ref(),
        Some(&destination),
    )
    .await?;
    let url = target.url_under(&base);

    let (auth_name, auth_header) = validate_auth(credentials)?;
    let timeout = resolve_timeout(config, options.timeout);
    let deadline = tokio::time::Instant::now() + timeout;

    let cache_config = response_cache::CacheConfig::from_config(config);
    // Partitioned by the acting principal (WP A.5). `OwnerKey::current`
    // allocates only inside an enterprise call scope; local mode hashes a
    // constant.
    let cache_key = response_cache::CacheKey::new(
        vendor.name(),
        &url,
        &auth_name,
        &auth_header,
        &options.headers,
        &crate::policy::OwnerKey::current(),
    );
    if options.fresh {
        response_cache::invalidate(&cache_key);
    }
    let cacheable = cache_config.enabled
        && !options.fresh
        && !options.sensitive_response
        && vendor.cache_reads(path)
        && response_cache::request_is_cacheable(&url, &auth_name, &options);
    if method != HttpMethod::Get {
        response_cache::invalidate_namespace(vendor.name(), &base);
    } else if cacheable && let Some((body, metadata)) = response_cache::get(&cache_key) {
        report_cache_hit(ticket.as_ref());
        debug!(vendor = vendor.name(), %url, "HTTP response cache hit");
        return Ok(TransportResponse {
            data: body,
            cache: metadata,
            raw_response_path: None,
            headers: http::HeaderMap::new(),
        });
    }

    let request_body_for_log = request_body_for_log(&options);
    let req = build_request(
        client,
        method,
        &url,
        &auth_name,
        &auth_header,
        &options,
        timeout,
    );

    debug!(
        %url,
        method = method.as_str(),
        vendor = vendor.name(),
        "dispatching API request"
    );
    log_ninjaone_request(vendor.name(), &url, method, request_body_for_log.as_ref());

    let call = HttpCallLog::new(vendor.name(), method.as_str(), &url);
    let start = call.started;
    let response = req.send().await.map_err(|error| {
        report_attempt(ticket.as_ref(), None, Some("transport_error"));
        log_http_transport_failure(call, &error, false);
        map_transport_error(&error, &url)
    })?;
    report_attempt(ticket.as_ref(), Some(response.status().as_u16()), None);
    let response = redirect::follow(
        client,
        vendor.name(),
        config,
        &url,
        response,
        method,
        &options,
        Some((&auth_name, &auth_header)),
        deadline,
        &CancellationToken::new(),
    )
    .await?;
    let duration = start.elapsed();

    let status = response.status();
    if !status.is_success() {
        log_http_status_failure(call, status, false);
    }
    enforce_content_length_cap(&response)?;

    let response_headers = response.headers().clone();
    if !status.is_success() {
        let policy = StreamingPolicy::new(MAX_RESPONSE_SIZE as u64, MAX_RESPONSE_SIZE as u64);
        let redirected = response.url().as_str() != url;
        let body_text = bounded_body(response, &policy, deadline).await?;
        if redirected {
            return Err(retry::metadata(
                api_error("Redirected request failed", Some(status.as_u16()), None),
                retry::parse(&response_headers, std::time::SystemTime::now()),
            ));
        }
        log_ninjaone_error_response(vendor.name(), &url, method, status, &body_text);
        return Err(retry::metadata(
            vendor.classify_error(status, &body_text),
            retry::parse(&response_headers, std::time::SystemTime::now()),
        ));
    }

    let body = classify_body(response).await?;
    log_ninjaone_response(vendor.name(), &url, method, status, &body);

    // Some APIs (notably Slack's Web API) return `200 OK` with an
    // application-level error envelope in the body (`{"ok": false, ...}`). Give
    // the vendor a chance to reclassify such a "success" as a typed error
    // before we treat the body as data or persist it. No-op for vendors whose
    // HTTP status already reflects failure.
    if let ResponseBody::Json(value) = &body
        && let Some(err) = vendor.classify_success_json(value)
    {
        return Err(err);
    }

    let metadata = CacheMetadata {
        hit: false,
        age_ms: 0,
        fetched_at: crate::logger::iso_timestamp(),
    };
    if method == HttpMethod::Get && cacheable {
        response_cache::store(
            cache_key,
            &body,
            &response_headers,
            &cache_config,
            start.elapsed(),
            &metadata,
        );
    }

    let raw_path = if !options.sensitive_response
        && let ResponseBody::Json(value) = &body
    {
        raw_response::save(
            &url,
            method.as_str(),
            request_body_for_log.as_ref(),
            value,
            status.as_u16(),
            duration,
        )
        .await
    } else {
        None
    };

    Ok(TransportResponse {
        data: body,
        cache: metadata,
        raw_response_path: raw_path,
        headers: response_headers,
    })
}

/// Bitbucket-specialised shim. Equivalent to calling [`fetch`] with a
/// fresh [`BitbucketVendor`]. Preserved for back-compat; new code should
/// call [`fetch`] with the vendor explicitly.
pub async fn fetch_bitbucket(
    client: &HttpClient,
    credentials: &Credentials,
    config: &Config,
    path: &str,
    options: RequestOptions,
) -> Result<TransportResponse, McpError> {
    let vendor = BitbucketVendor::new();
    fetch(client, &vendor, credentials, config, path, options).await
}

/// Bitbucket-specialised shim that overrides the base URL (e.g. to point at
/// a wiremock in tests). Equivalent to calling [`fetch`] with
/// [`BitbucketVendor::with_base_url`].
pub async fn fetch_bitbucket_with_base(
    base_url: &str,
    client: &HttpClient,
    credentials: &Credentials,
    config: &Config,
    path: &str,
    options: RequestOptions,
) -> Result<TransportResponse, McpError> {
    let vendor = BitbucketVendor::with_base_url(base_url);
    fetch(client, &vendor, credentials, config, path, options).await
}

/// Construct the shared vendor HTTP client with sensible defaults. Callers
/// should cache this for the lifetime of the process.
pub fn build_client() -> Result<HttpClient, McpError> {
    HttpClient::builder()
        .crate_user_agent()
        .no_redirects()
        .build()
        .map_err(|e| unexpected(format!("failed to build HTTP client: {e}"), None))
}

/// Dedicated client for ingestion bodies. Automatic decompression is disabled
/// so the transport can account for wire bytes before bounded decoding.
fn streaming_client() -> Result<&'static HttpClient, McpError> {
    static CLIENT: OnceLock<Result<HttpClient, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            HttpClient::builder()
                .crate_user_agent()
                .no_redirects()
                .no_decompression()
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| {
            unexpected(
                format!("failed to build streaming HTTP client: {error}"),
                None,
            )
        })
}

// ---- helpers ----

/// Refuse a streamed response whose declared length already exceeds the
/// encoded-bytes cap, before a byte of the body is read.
fn enforce_streamed_length_cap(
    response: &HttpResponse,
    policy: &StreamingPolicy,
) -> Result<(), McpError> {
    if response
        .content_length()
        .is_some_and(|length| length > policy.max_encoded_bytes)
    {
        return Err(api_error(
            "encoded response exceeds streamed artifact limit",
            Some(413),
            None,
        ));
    }
    Ok(())
}

/// Report one wire attempt on the request's egress record, when the call
/// runs inside an enforcing scope (outside one there is no ticket).
fn report_attempt(
    ticket: Option<&crate::policy::EgressTicket>,
    status: Option<u16>,
    failure: Option<&'static str>,
) {
    if let Some(ticket) = ticket {
        ticket.attempted(status, failure);
    }
}

/// Report that the request was answered from the response cache.
fn report_cache_hit(ticket: Option<&crate::policy::EgressTicket>) {
    if let Some(ticket) = ticket {
        ticket.cache_hit();
    }
}

/// The request body as the diagnostic log and raw-response record show it:
/// the JSON body, or the form encoded as JSON.
fn request_body_for_log(options: &RequestOptions) -> Option<Value> {
    options
        .body
        .clone()
        .or_else(|| {
            options
                .form
                .as_ref()
                .and_then(|form| serde_json::to_value(form).ok())
        })
        .or_else(|| options.text_body.clone().map(Value::String))
}

/// Canonicalize the caller's path-and-query (plan §3.5) before it is joined
/// onto the configured base. This is the one place an upstream URL is
/// built from request data, so the form policy evaluates is the form sent.
/// A path with no canonical form — an absolute URL, an invalid escape, a
/// control byte — is refused with a 400-shaped error rather than sent.
fn canonical_target(path: &str) -> Result<crate::policy::CanonicalTarget, McpError> {
    crate::policy::CanonicalTarget::parse(path)
        .map_err(|error| api_error(format!("Invalid request path: {error}"), Some(400), None))
}

fn validate_auth(credentials: &Credentials) -> Result<(HeaderName, HeaderValue), McpError> {
    // Scheme-agnostic: `auth_header()` emits Basic for the Atlassian variants,
    // Bearer for Zoom's resolved token, and a bare key for a custom-header API
    // key. `auth_header_name()` picks the header that value rides in —
    // `Authorization` for everything except `ApiKeyHeader`.
    let name = credentials.auth_header_name()?;
    let raw = credentials.auth_header();
    let value =
        HeaderValue::from_str(&raw).map_err(|_| auth_invalid("Invalid authentication header"))?;
    Ok((name, value))
}

fn resolve_timeout(config: &Config, override_timeout: Option<Duration>) -> Duration {
    if let Some(t) = override_timeout {
        return t;
    }
    let env_ms = config.get_int(
        "ATLASSIAN_REQUEST_TIMEOUT",
        i64::try_from(DEFAULT_REQUEST.as_millis()).unwrap_or(30_000),
    );
    if env_ms <= 0 {
        DEFAULT_REQUEST
    } else {
        Duration::from_millis(u64::try_from(env_ms).unwrap_or(30_000))
    }
}

fn build_request(
    client: &HttpClient,
    method: HttpMethod,
    url: &str,
    auth_name: &HeaderName,
    auth: &HeaderValue,
    options: &RequestOptions,
    timeout: Duration,
) -> HttpRequest {
    let mut req = client
        .request(method.as_method(), url)
        .timeout(timeout)
        .header(auth_name.clone(), auth.clone())
        .header(ACCEPT, HeaderValue::from_static("application/json"));

    for (k, v) in &options.headers {
        req = req.header(k, v);
    }

    if let Some(form) = options.form.as_ref() {
        req = req.form(form);
    } else if let Some(body) = options.body.as_ref() {
        req = req.json(body);
    } else if let Some(text) = options.text_body.as_ref() {
        req = req
            .header(CONTENT_TYPE, HeaderValue::from_static("text/plain"))
            .body(text.clone());
    } else {
        req = req.header(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    req
}

fn enforce_content_length_cap(response: &HttpResponse) -> Result<(), McpError> {
    let Some(value) = response.headers().get(CONTENT_LENGTH) else {
        return Ok(());
    };
    let Ok(text) = value.to_str() else {
        return Ok(());
    };
    let Ok(size) = text.parse::<u64>() else {
        return Ok(());
    };
    let cap = MAX_RESPONSE_SIZE as u64;
    if size > cap {
        let mb = size / (1024 * 1024);
        let cap_mb = cap / (1024 * 1024);
        let info = serde_json::json!({ "responseSize": size, "limit": MAX_RESPONSE_SIZE });
        return Err(api_error(
            format!("Response size ({mb}MB) exceeds maximum limit of {cap_mb}MB"),
            Some(413),
            Some(OriginalError::Json(info)),
        ));
    }
    Ok(())
}

/// Read decoded bodies with actual byte, idle, cancellation and total limits.
/// No artifact/cache entry is created for an error response.
pub(crate) async fn bounded_body(
    response: HttpResponse,
    policy: &StreamingPolicy,
    deadline: tokio::time::Instant,
) -> Result<String, McpError> {
    let cap = policy.max_decoded_bytes.min(MAX_RESPONSE_SIZE as u64);
    let mut reader = decoded_reader(response, policy, Arc::new(AtomicU64::new(0)))?;
    let mut body = Vec::with_capacity(8192.min(usize::try_from(cap).unwrap_or(8192)));
    let mut buffer = vec![0; 8192];
    loop {
        let count = tokio::select! {
            () = policy.cancellation.cancelled() => return Err(api_error("response read cancelled", Some(499), None)),
            () = tokio::time::sleep_until(deadline) => return Err(api_error("response body exceeded total deadline", Some(408), None)),
            result = tokio::time::timeout(policy.idle_read_timeout, reader.read(&mut buffer)) => {
                result.map_err(|_| api_error("response body idle timeout", Some(408), None))?
                    .map_err(|error| {
                        let status = if error.kind() == std::io::ErrorKind::FileTooLarge { 413 } else { 502 };
                        api_error(format!("failed to read bounded response: {error}"), Some(status), None)
                    })?
            }
        };
        if count == 0 {
            break;
        }
        if body.len() as u64 + count as u64 > cap {
            return Err(api_error(
                "response body exceeds maximum size",
                Some(413),
                None,
            ));
        }
        if let Some(aggregate) = &policy.aggregate {
            aggregate
                .add_decoded(count as u64)
                .map_err(|error| api_error(error.to_string(), Some(413), None))?;
        }
        body.extend_from_slice(&buffer[..count]);
    }
    Ok(String::from_utf8(body)
        .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()))
}

async fn classify_body(response: HttpResponse) -> Result<ResponseBody, McpError> {
    if response.status() == StatusCode::NO_CONTENT {
        return Ok(ResponseBody::Empty);
    }

    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    let policy = StreamingPolicy::new(MAX_RESPONSE_SIZE as u64, MAX_RESPONSE_SIZE as u64);
    let text = bounded_body(
        response,
        &policy,
        tokio::time::Instant::now() + policy.total_deadline,
    )
    .await?;
    if content_type.contains("text/plain") {
        return Ok(ResponseBody::Text(text));
    }

    if text.trim().is_empty() {
        return Ok(ResponseBody::Empty);
    }

    match serde_json::from_str::<Value>(&text) {
        Ok(value) => Ok(ResponseBody::Json(value)),
        Err(_) => Ok(ResponseBody::Text(text)),
    }
}

fn map_transport_error(err: &HttpError, url: &str) -> McpError {
    if err.is_timeout() {
        return api_error(
            format!("Request timeout: API did not respond in time at {url}"),
            Some(408),
            Some(OriginalError::String(err.to_string())),
        );
    }
    if err.is_connect() {
        return api_error(
            format!("Network error connecting to API: {err}"),
            Some(503),
            Some(OriginalError::String(err.to_string())),
        );
    }
    unexpected(
        err.to_string(),
        Some(OriginalError::String(err.to_string())),
    )
}

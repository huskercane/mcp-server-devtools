//! Secret references at startup and in the background (plan §3.8, C.2a).
//!
//! The request path never fetches a secret: it reads the snapshot attached
//! to its [`Config`]. This module is everything that *fills* that snapshot.
//!
//! - [`resolve_startup`] resolves every reference in the configuration in
//!   force, **fails closed** if any cannot be resolved, and starts the
//!   refresher. A transport calls it before it binds, next to
//!   [`crate::tools::DevtoolsServer::journal_startup`].
//! - The refresher re-resolves on a cadence and swaps a new snapshot in
//!   when anything changed. A failed refresh keeps the **last good** values
//!   and marks [`SecretHealth`] degraded, which the health banner reports —
//!   the same contract as a policy reload (`MCP_POLICY_FILE`). A later
//!   success clears it.
//! - An upstream `401` requests one early refresh, rate-limited, because
//!   rotation windows overlap in practice: the file was rotated and the old
//!   token retired before the next tick.
//!
//! The global config watcher (`watcher.rs`) is the other writer of the
//! config handle; it resolves the references of a *reloaded* configuration
//! before swapping it in, and both writers derive under the handle's write
//! lock, so neither can drop the other's update.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use super::Components;
use crate::config::Config;
use crate::error::McpError;
use crate::secrets::{SecretResolver, SecretSnapshot};

/// Config key: seconds between background re-resolutions of every
/// reference. `file://` has no version to poll, so this is also how quickly
/// a rotated file is picked up. Clamped to [`MIN_REFRESH_INTERVAL`]–
/// [`MAX_REFRESH_INTERVAL`].
pub const REFRESH_INTERVAL_KEY: &str = "MCP_SECRET_REFRESH_INTERVAL_SECONDS";
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
pub const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
pub const MAX_REFRESH_INTERVAL: Duration = Duration::from_hours(1);

/// The least time between two early refreshes triggered by upstream `401`s.
/// A vendor that keeps answering `401` for a reason that is not rotation
/// must not turn every failed call into a provider read.
pub const EARLY_REFRESH_MIN_GAP: Duration = Duration::from_secs(10);

/// Read [`REFRESH_INTERVAL_KEY`], clamped.
#[must_use]
pub fn refresh_interval(config: &Config) -> Duration {
    let configured = config
        .get(REFRESH_INTERVAL_KEY)
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map_or(DEFAULT_REFRESH_INTERVAL, Duration::from_secs);
    configured.clamp(MIN_REFRESH_INTERVAL, MAX_REFRESH_INTERVAL)
}

/// Whether the background refresh is currently failing.
///
/// `degraded` holds the failure *category* (`secret_source_unavailable`,
/// …), never the reference or the cause text: the health banner is
/// unauthenticated and the category is all it says; the reference and the
/// detail go to the operator log with each failed refresh.
#[derive(Debug, Default)]
pub struct SecretHealth {
    degraded: Mutex<Option<&'static str>>,
    early_refresh: Notify,
    /// How many refreshes have completed (success or failure); tests wait
    /// on it instead of sleeping in units of the interval.
    refreshes: AtomicU64,
}

impl SecretHealth {
    /// The failure category when refreshes are failing.
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

    /// Ask the refresher to run now rather than at its next tick. Called on
    /// an upstream `401`; the refresher rate-limits it.
    pub fn request_early_refresh(&self) {
        self.early_refresh.notify_one();
    }

    #[must_use]
    pub fn refreshes(&self) -> u64 {
        self.refreshes.load(Ordering::Acquire)
    }
}

/// The process-wide early-refresh signal.
///
/// A `401` surfaces where a vendor error is turned into a tool result,
/// which has no path back to the server's components; a process-wide
/// signal is the honest shape of that (the same reason `auth::os_keychain`
/// is process-wide). Every refresher in the process listens; a nudge with
/// no refresher, or with no references, is a no-op.
static EARLY_REFRESH: Notify = Notify::const_new();

/// Note that an upstream answered `401`: the credential may have rotated
/// under us. Cheap, non-blocking, safe from any thread.
pub fn note_upstream_unauthorized() {
    EARLY_REFRESH.notify_one();
}

/// Resolve every reference in the configuration in force, attach the
/// snapshot, and start the refresher when there is anything to refresh.
///
/// A configuration with no references does nothing — no snapshot, no task —
/// so the community path is untouched.
///
/// # Errors
///
/// [`McpError`] naming the first reference that did not resolve and why.
/// The caller refuses to start: a gateway that would serve with a missing
/// credential has no honest way to say so per call (plan §3.8, "Failure
/// posture").
pub async fn resolve_startup(components: &Arc<Components>) -> Result<(), McpError> {
    let config = components.config();
    if config.secret_references().next().is_none() {
        return Ok(());
    }
    let snapshot = components
        .secrets
        .resolve(config.secret_references())
        .await
        .map_err(|error| {
            crate::error::unexpected(
                format!("{error}; refusing to start (fail closed, plan §1.2)"),
                None,
            )
        })?;
    tracing::info!(references = snapshot.len(), "resolved secret references");
    attach(components, &snapshot);
    spawn_refresher(components, refresh_interval(&config));
    Ok(())
}

/// Attach `snapshot` on top of whatever the current configuration carries.
fn attach(components: &Components, snapshot: &SecretSnapshot) {
    components.config.update(|current| {
        let merged = Arc::new(current.secrets().merged_with(snapshot));
        current.clone().with_secrets(merged)
    });
}

/// Spawn the background refresher. Holds a [`Weak`] to the components, as
/// the config watcher does, so it ends with the server.
pub fn spawn_refresher(components: &Arc<Components>, interval: Duration) {
    let weak: Weak<Components> = Arc::downgrade(components);
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::warn!("secret refresher requires a Tokio runtime; references will not rotate");
        return;
    };
    runtime.spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately; the snapshot is fresh from
        // startup, so skip it.
        ticker.tick().await;
        let mut last_early: Option<Instant> = None;
        loop {
            let early = tokio::select! {
                _ = ticker.tick() => false,
                () = EARLY_REFRESH.notified() => true,
                () = notified_on(&weak) => true,
            };
            let Some(components) = weak.upgrade() else {
                return;
            };
            if early {
                if last_early.is_some_and(|at| at.elapsed() < EARLY_REFRESH_MIN_GAP) {
                    continue;
                }
                last_early = Some(Instant::now());
                tracing::info!("upstream 401: refreshing secret references early");
            }
            refresh_once(&components).await;
        }
    });
}

/// Wait for a per-server early-refresh request, or forever if the server
/// is gone (the select's other arm ends the task then).
async fn notified_on(weak: &Weak<Components>) {
    match weak.upgrade() {
        Some(components) => components.secret_health.early_refresh.notified().await,
        None => std::future::pending().await,
    }
}

/// One refresh: re-resolve the references of the configuration in force
/// and swap the snapshot in if anything changed.
pub async fn refresh_once(components: &Components) {
    let config = components.config();
    let health = &components.secret_health;
    if config.secret_references().next().is_none() {
        health.set_degraded(None);
        health.refreshes.fetch_add(1, Ordering::AcqRel);
        return;
    }
    match components.secrets.resolve(config.secret_references()).await {
        Ok(snapshot) => {
            if config.secrets().differs_from(&snapshot) {
                attach(components, &snapshot);
                tracing::info!(references = snapshot.len(), "secret references rotated");
            }
            if health.degraded().is_some() {
                tracing::info!("secret refresh recovered; current values in force");
            }
            health.set_degraded(None);
        }
        Err(error) => {
            let category = error.cause.category();
            if health.degraded() != Some(category) {
                tracing::warn!(
                    reference = %error.reference,
                    failure = category,
                    "secret refresh failed; last good values in force: {}",
                    error.cause
                );
            }
            health.set_degraded(Some(category));
        }
    }
    health.refreshes.fetch_add(1, Ordering::AcqRel);
}

/// Resolve the references of a *reloaded* configuration before it is
/// swapped in. The reload is refused (last good configuration stays) when
/// a reference does not resolve, exactly as a policy that fails to compile
/// is ignored on reload.
pub async fn resolve_reloaded(
    resolver: &SecretResolver,
    config: Config,
) -> Result<Config, crate::secrets::SecretResolveError> {
    if config.secret_references().next().is_none() {
        return Ok(config);
    }
    let snapshot = resolver.resolve(config.secret_references()).await?;
    Ok(config.with_secrets(Arc::new(snapshot)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(pairs: &[(&str, &str)]) -> Config {
        Config::from_map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<HashMap<_, _>>(),
        )
    }

    #[test]
    fn refresh_interval_is_clamped() {
        assert_eq!(refresh_interval(&config(&[])), DEFAULT_REFRESH_INTERVAL);
        assert_eq!(
            refresh_interval(&config(&[(REFRESH_INTERVAL_KEY, "0")])),
            MIN_REFRESH_INTERVAL
        );
        assert_eq!(
            refresh_interval(&config(&[(REFRESH_INTERVAL_KEY, "99999")])),
            MAX_REFRESH_INTERVAL
        );
        assert_eq!(
            refresh_interval(&config(&[(REFRESH_INTERVAL_KEY, " 5 ")])),
            Duration::from_secs(5)
        );
        assert_eq!(
            refresh_interval(&config(&[(REFRESH_INTERVAL_KEY, "soon")])),
            DEFAULT_REFRESH_INTERVAL
        );
    }
}

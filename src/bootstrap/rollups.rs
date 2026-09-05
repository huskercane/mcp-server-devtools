//! Usage rollups and metrics: select the `RollupStore` adapter, build the
//! usage sink chain, and start the consumer (plan §3.9, WP C.6).
//!
//! The only place `MCP_ROLLUP_STORE` is turned into an adapter:
//! `sqlite:///path` is [`SqliteRollupStore`], `memory://` the in-memory
//! store (development, tests), `postgres://…` a typed "not compiled in"
//! refusal naming the scheme — the second adapter is scoped, not built.
//!
//! The sink chain the server records into is assembled here too: the
//! Prometheus adapter when `MCP_METRICS=on`, the bounded channel to the
//! rollup consumer when a store is configured **and this process serves
//! the control plane** (a pure `gateway` replica has no consumer, so
//! attaching the channel there would only count drops — CF-33 covers the
//! push that would carry its usage to `control`). Both together fan out.

use std::sync::Arc;
use std::time::Duration;

use super::Components;
use crate::config::Config;
use crate::error::McpError;
use crate::metrics::PrometheusUsageSink;
use crate::ports::{BoundedUsageChannel, NoopUsageSink, RollupStore, UsageEvent, UsageSink};
use crate::rollups::{self, Consumer, RollupHealth, SqliteRollupStore};

/// Build the store the URI names.
///
/// # Errors
///
/// A message naming the scheme or the path at fault.
pub fn store_from_config(config: &Config) -> Result<Option<Arc<dyn RollupStore>>, String> {
    let Some(uri) = configured(config, rollups::STORE_KEY) else {
        return Ok(None);
    };
    let (scheme, rest) = uri.split_once("://").ok_or_else(|| {
        format!(
            "{}: {uri:?} is not a URI (expected `sqlite:///path`)",
            rollups::STORE_KEY
        )
    })?;
    match scheme.to_ascii_lowercase().as_str() {
        "sqlite" => {
            // `sqlite:///var/lib/mcp/usage.db` → `/var/lib/mcp/usage.db`;
            // `sqlite://relative/path.db` is refused so a cwd never decides
            // where usage lands.
            let path = rest.strip_prefix('/').ok_or_else(|| {
                format!(
                    "{}: {uri:?} must be `sqlite:///absolute/path.db` (three slashes)",
                    rollups::STORE_KEY
                )
            })?;
            let path = std::path::Path::new("/").join(path);
            let store = SqliteRollupStore::open(&path)
                .map_err(|error| format!("{}: {}: {error}", rollups::STORE_KEY, path.display()))?;
            Ok(Some(Arc::new(store)))
        }
        "memory" => Ok(Some(Arc::new(crate::ports::InMemoryRollupStore::new()))),
        "postgres" | "postgresql" => Err(format!(
            "{}: no `{scheme}://` rollup store is compiled into this binary (PostgreSQL is \
             scoped as the second adapter, plan §3.9; use `sqlite:///path`)",
            rollups::STORE_KEY
        )),
        other => Err(format!(
            "{}: no rollup store for `{other}://` (expected `sqlite:///path`)",
            rollups::STORE_KEY
        )),
    }
}

/// Retention from configuration; `None` keeps everything.
///
/// # Errors
///
/// When the value is not a non-negative integer.
pub fn retention_from_config(config: &Config) -> Result<Option<Duration>, String> {
    let days = match configured(config, rollups::RETENTION_DAYS_KEY) {
        None => rollups::DEFAULT_RETENTION_DAYS,
        Some(value) => value.parse::<u64>().map_err(|_| {
            format!(
                "{} must be a non-negative integer, got {value:?}",
                rollups::RETENTION_DAYS_KEY
            )
        })?,
    };
    Ok((days > 0).then(|| Duration::from_secs(days * 86_400)))
}

/// Channel capacity from configuration, clamped.
#[must_use]
pub fn channel_capacity(config: &Config) -> usize {
    configured(config, rollups::CHANNEL_CAPACITY_KEY)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(rollups::DEFAULT_CHANNEL_CAPACITY)
        .clamp(64, 65_536)
}

/// Whether `MCP_METRICS=on`.
#[must_use]
pub fn metrics_enabled(config: &Config) -> bool {
    configured(config, crate::metrics::METRICS_KEY)
        .is_some_and(|value| value.eq_ignore_ascii_case("on") || value.eq_ignore_ascii_case("true"))
}

/// The usage-side components `ServerBuilder::build` assembles.
pub struct UsageWiring {
    pub sink: Arc<dyn UsageSink>,
    pub metrics: Option<Arc<PrometheusUsageSink>>,
    pub store: Option<Arc<dyn RollupStore>>,
    pub receiver: Option<tokio::sync::mpsc::Receiver<UsageEvent>>,
    pub retention: Option<Duration>,
}

/// Assemble the sink chain. `serves_control` says whether a consumer will
/// run in this process.
///
/// # Errors
///
/// When the store or the retention setting cannot be built.
pub fn wire(config: &Config, serves_control: bool) -> Result<UsageWiring, String> {
    let metrics = metrics_enabled(config).then(|| Arc::new(PrometheusUsageSink::new()));
    let store = if serves_control {
        store_from_config(config)?
    } else {
        // Validate the URI even where no consumer runs, so a gateway with
        // a typo fails the same way control would.
        store_from_config(config)?;
        None
    };
    let retention = retention_from_config(config)?;
    let mut sinks: Vec<Arc<dyn UsageSink>> = Vec::with_capacity(2);
    if let Some(metrics) = &metrics {
        sinks.push(Arc::clone(metrics) as Arc<dyn UsageSink>);
    }
    let receiver = if store.is_some() {
        let (channel, receiver) = BoundedUsageChannel::new(channel_capacity(config));
        sinks.push(Arc::new(channel));
        Some(receiver)
    } else {
        None
    };
    let sink: Arc<dyn UsageSink> = match sinks.len() {
        0 => Arc::new(NoopUsageSink),
        1 => sinks.pop().expect("one sink"),
        _ => Arc::new(crate::metrics::FanOutUsageSink::new(sinks)),
    };
    Ok(UsageWiring {
        sink,
        metrics,
        store,
        receiver,
        retention,
    })
}

/// Start the consumer, if a store is configured and the receiver has not
/// been taken. Returns the store's name when it started.
///
/// # Errors
///
/// When there is no Tokio runtime.
pub fn spawn_consumer(
    components: &Arc<Components>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<Option<&'static str>, McpError> {
    let Some(store) = components.rollup_store.as_ref() else {
        return Ok(None);
    };
    let receiver = components
        .usage_receiver
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let Some(receiver) = receiver else {
        return Ok(None);
    };
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return Err(crate::error::unexpected(
            "usage rollups require a Tokio runtime; refusing to start".to_owned(),
            None,
        ));
    };
    let consumer = Consumer::new(
        Arc::clone(store),
        receiver,
        Arc::clone(&components.rollup_health),
        components.rollup_retention,
    );
    tracing::info!(store = store.name(), "usage rollups started");
    runtime.spawn(consumer.run(cancel));
    Ok(Some(store.name()))
}

/// A configured, non-blank value.
fn configured<'a>(config: &'a Config, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Re-exported for the health banner.
pub type Health = RollupHealth;

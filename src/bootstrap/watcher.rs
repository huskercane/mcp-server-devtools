//! Live global-config watcher.
//!
//! Polls the global config file and swaps a freshly loaded snapshot into the
//! shared [`ConfigHandle`] when the bytes change. Lives in `bootstrap` rather
//! than in the MCP adapter because reloading process configuration is a
//! composition concern, not an MCP one — the adapter should not own a
//! background task.
//!
//! Holds only a [`Weak`] reference to [`Components`], so the task stops on its
//! own when the server is dropped and never keeps the graph alive.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::Duration;

use super::Components;

/// Poll cadence. Public so tests can sleep in units of it rather than
/// hard-coding a duration that would silently decouple if this changed.
pub const CONFIG_WATCH_INTERVAL: Duration = Duration::from_millis(500);

/// A config file to watch plus the bytes it held at snapshot time.
pub struct PendingWatch {
    path: PathBuf,
    contents: Option<Vec<u8>>,
}

impl PendingWatch {
    /// Watch an explicit path, snapshotting its current bytes.
    #[must_use]
    pub fn for_path(path: PathBuf) -> Self {
        let contents = std::fs::read(&path).ok();
        Self { path, contents }
    }
}

/// Snapshot the global config file, if one is selected and present.
///
/// Called *before* `config::load()` so that an edit landing between the two is
/// still seen as a change by the first watcher tick, rather than being masked.
#[must_use]
pub fn pending_watch() -> Option<PendingWatch> {
    crate::config::global::default_path()
        .filter(|path| path.exists())
        .map(|path| {
            let contents = std::fs::read(&path).ok();
            PendingWatch { path, contents }
        })
}

/// Spawn the polling task against the current Tokio runtime.
///
/// A no-op (with a warning) when there is no runtime — the CLI path builds a
/// server outside one in some tests.
pub fn spawn(components: &Arc<Components>, pending: PendingWatch) {
    let PendingWatch {
        path,
        contents: mut last_contents,
    } = pending;

    let components: Weak<Components> = Arc::downgrade(components);
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(path = %path.display(), "global config watcher requires a Tokio runtime");
        return;
    };

    runtime.spawn(async move {
        let mut interval = tokio::time::interval(CONFIG_WATCH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // `interval` ticks immediately; the first comparison also closes the
        // startup race between the initial snapshot and `Config::load()`.
        loop {
            interval.tick().await;
            let Some(components) = components.upgrade() else {
                return;
            };
            let contents = match tokio::fs::read(&path).await {
                Ok(contents) => Some(contents),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    tracing::warn!(path = %path.display(), error = %err, "failed to watch global config");
                    continue;
                }
            };
            if contents == last_contents {
                continue;
            }
            last_contents = contents;

            if !reloadable(&path) {
                continue;
            }

            components
                .config
                .replace(crate::config::load_from_global_path(Some(&path)));
            components.workspace_cache.clear();
            tracing::info!(path = %path.display(), "reloaded global config");
        }
    });
}

/// An editor may briefly expose a partially-written file. Keep the last
/// known-good snapshot and retry when the bytes change again.
fn reloadable(path: &Path) -> bool {
    if !path.exists() {
        return true;
    }
    match crate::config::global::read_all_vendors(path, crate::constants::PACKAGE_NAME) {
        Ok(_) => true,
        Err(err) => {
            tracing::warn!(path = %path.display(), error = %err, "global config changed but is not valid JSON; keeping previous config");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::bootstrap::{ConfigHandle, Vendors};
    use crate::config::{Config, VENDOR_BITBUCKET};
    use crate::transport::build_client;
    use crate::workspace::WorkspaceCache;

    fn config_json(value: &str) -> String {
        format!(r#"{{"bitbucket":{{"environments":{{"LIVE_RELOAD_TEST_VALUE":"{value}"}}}}}}"#)
    }

    fn components(config: Config) -> Arc<Components> {
        Arc::new(Components {
            config: ConfigHandle::new(config),
            client: build_client().unwrap(),
            vendors: Vendors::default(),
            workspace_cache: WorkspaceCache::new(),
            credential_broker: Arc::new(crate::ports::ConfigCredentialBroker),
            audit_sink: None,
            usage_sink: Arc::new(crate::ports::NoopUsageSink),
        })
    }

    /// The watcher reloads on change, and a half-written file (invalid JSON)
    /// leaves the last known-good snapshot in place rather than blanking config.
    #[tokio::test]
    async fn reloads_changed_global_config_and_keeps_last_good_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("configs.json");
        std::fs::write(&path, config_json("before")).unwrap();

        let initial = Config::load_from_sources(Some(&path), None, &HashMap::new());
        let components = components(initial);
        spawn(&components, PendingWatch::for_path(path.clone()));

        std::fs::write(&path, "{").unwrap();
        tokio::time::sleep(CONFIG_WATCH_INTERVAL * 2).await;
        assert_eq!(
            components
                .config()
                .get_for(VENDOR_BITBUCKET, "LIVE_RELOAD_TEST_VALUE"),
            Some("before"),
            "invalid JSON must not clobber the last good config"
        );

        std::fs::write(&path, config_json("after")).unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if components
                    .config()
                    .get_for(VENDOR_BITBUCKET, "LIVE_RELOAD_TEST_VALUE")
                    == Some("after")
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("watcher did not load the changed config");
    }

    /// The watcher must not keep the dependency graph alive.
    #[tokio::test]
    async fn watcher_holds_only_a_weak_reference() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("configs.json");
        std::fs::write(&path, config_json("before")).unwrap();

        let components = components(Config::default());
        let weak = Arc::downgrade(&components);
        spawn(&components, PendingWatch::for_path(path));

        drop(components);
        tokio::time::sleep(CONFIG_WATCH_INTERVAL * 2).await;

        assert!(
            weak.upgrade().is_none(),
            "watcher task kept Components alive after the server was dropped"
        );
    }
}

//! Shared, swappable configuration snapshot.
//!
//! Both inbound adapters need a [`Config`], but with different lifecycles: the
//! MCP server hot-reloads it from a watched global config file, while a CLI
//! subcommand loads it once and exits. [`ConfigHandle`] is the single type both
//! use — the server spawns a watcher that calls [`ConfigHandle::replace`], the
//! CLI simply never does.
//!
//! ## Why `Arc` inside the lock
//!
//! Readers take a snapshot per request. Storing `Arc<Config>` rather than
//! `Config` means a snapshot is one atomic increment instead of a deep copy of
//! the credential maps (`HashMap` + `BTreeMap<String, HashMap>`). Reloads are
//! rare and swap the whole `Arc`, so a snapshot already handed out stays valid
//! and immutable for the life of the request that holds it — no torn reads, and
//! no lock held across an `.await`.

use std::sync::{Arc, RwLock};

use crate::config::Config;

/// Copy-on-write holder for the process configuration.
#[derive(Debug)]
pub struct ConfigHandle {
    inner: RwLock<Arc<Config>>,
}

impl ConfigHandle {
    /// Wrap an already-loaded snapshot.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            inner: RwLock::new(Arc::new(config)),
        }
    }

    /// Current snapshot. Cheap enough to call per request: one atomic
    /// increment, no allocation, and the read lock is released before the
    /// caller does any work with it.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Config> {
        Arc::clone(
            &self
                .inner
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Swap in a freshly loaded snapshot. Snapshots already handed out are
    /// unaffected and keep serving the config they were taken under.
    pub fn replace(&self, config: Config) {
        *self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(config);
    }
}

impl Default for ConfigHandle {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl From<Config> for ConfigHandle {
    fn from(config: Config) -> Self {
        Self::new(config)
    }
}

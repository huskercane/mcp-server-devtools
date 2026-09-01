//! Composition root.
//!
//! Every production dependency the process needs is assembled here and nowhere
//! else. Before this module existed the wiring was duplicated four ways:
//! `DevtoolsServer::new` built one graph, and `cli::bb`, `cli::jira`, and
//! `cli::conf` each rebuilt their own config + HTTP client + vendor by hand, so
//! a change to client construction had to be made in four places and was
//! silently inconsistent in between.
//!
//! Two entry points, one graph:
//!
//! - [`ServerBuilder`] — builds the MCP [`DevtoolsServer`], optionally with the
//!   live global-config watcher attached.
//! - [`CliRuntime`] — the same components for a one-shot CLI subcommand, minus
//!   the watcher (the process exits before a reload could matter).
//!
//! ## Dependency direction
//!
//! `bootstrap` sits at the top of the graph: it may depend on any layer, and no
//! layer may depend on it. That is what keeps the composition out of
//! `tools::mod`, which previously acted as adapter, container, composition root
//! and config watcher all at once.

pub mod config_handle;
pub mod vendors;
pub mod watcher;

use std::sync::Arc;

use reqwest::Client;

pub use config_handle::ConfigHandle;
pub use vendors::Vendors;

use crate::config::Config;
use crate::error::McpError;
use crate::ports::{AuditSink, ConfigCredentialBroker, CredentialBroker, NoopUsageSink, UsageSink};
use crate::tools::DevtoolsServer;
use crate::transport::build_client;
use crate::workspace::WorkspaceCache;

/// The assembled dependency graph, shared by both inbound adapters.
///
/// Held behind an `Arc` by the server so tool handlers borrow from it without
/// cloning; owned outright by the CLI, which uses it once and drops it.
pub struct Components {
    pub config: ConfigHandle,
    pub client: Client,
    pub vendors: Vendors,
    /// Per-instance workspace cache. Not a process global, so multi-server
    /// embedders never leak one account's default workspace into another's.
    pub workspace_cache: WorkspaceCache,
    /// Identifies which credential slot acts upstream (WP 0.6). `dyn` on
    /// purpose: consulted once per tool call on a path that already does
    /// file I/O, and a generic parameter here would ripple through
    /// `DevtoolsServer` and every `#[tool_router]` block for no hot-path
    /// gain — the documented deviation from ports-prefer-generics.
    pub credential_broker: Arc<dyn CredentialBroker>,
    /// Durable enterprise audit journal (WP 0.7). `None` in local mode:
    /// exactly the pre-enterprise behaviour, with only the legacy
    /// `AUDIT_LOG` running. When `Some`, every tool call journals its
    /// intent before dispatch and fails closed if that write fails.
    pub audit_sink: Option<Arc<dyn AuditSink>>,
    /// Lossy usage telemetry (WP 0.7). Defaults to no-op in local mode.
    pub usage_sink: Arc<dyn UsageSink>,
}

impl Components {
    /// Current config snapshot — one atomic increment, no deep copy.
    #[must_use]
    pub fn config(&self) -> Arc<Config> {
        self.config.snapshot()
    }
}

/// Builder for [`DevtoolsServer`].
///
/// Replaces a 14-positional-argument constructor that grew with every
/// integration. Callers override only what they care about; everything else
/// comes from [`Default`].
#[derive(Default)]
pub struct ServerBuilder {
    config: Option<Config>,
    client: Option<Client>,
    vendors: Option<Vendors>,
    watch_config: bool,
    credential_broker: Option<Arc<dyn CredentialBroker>>,
    audit_sink: Option<Arc<dyn AuditSink>>,
    usage_sink: Option<Arc<dyn UsageSink>>,
}

impl ServerBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Use an explicit config instead of the environment cascade.
    #[must_use]
    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Use a caller-supplied HTTP client (connection-pool sharing, custom
    /// timeouts, or a test client).
    #[must_use]
    pub fn client(mut self, client: Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Override the vendor set — typically `Vendors { jira: ..with_base_url(mock), ..default() }`.
    #[must_use]
    pub fn vendors(mut self, vendors: Vendors) -> Self {
        self.vendors = Some(vendors);
        self
    }

    /// Override the credential broker (tests pin identities with
    /// [`crate::ports::StaticCredentialBroker`]).
    #[must_use]
    pub fn credential_broker(mut self, broker: Arc<dyn CredentialBroker>) -> Self {
        self.credential_broker = Some(broker);
        self
    }

    /// Attach a durable audit sink explicitly, instead of (not in addition
    /// to) the `MCP_AUDIT_JOURNAL_DIR`-configured journal. Tests use
    /// [`crate::ports::InMemoryAuditSink`].
    #[must_use]
    pub fn audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// Override the usage sink (default: no-op in local mode).
    #[must_use]
    pub fn usage_sink(mut self, sink: Arc<dyn UsageSink>) -> Self {
        self.usage_sink = Some(sink);
        self
    }

    /// Attach the live global-config watcher. Off by default: tests and
    /// embedders that pass an explicit [`Config`] almost never want a
    /// background task rewriting it from a file on disk.
    #[must_use]
    pub fn watch_config(mut self, watch: bool) -> Self {
        self.watch_config = watch;
        self
    }

    /// Assemble the server.
    ///
    /// # Errors
    ///
    /// Returns [`McpError`] when the HTTP client cannot be constructed, or
    /// when `MCP_AUDIT_JOURNAL_DIR` is configured but the durable audit
    /// journal cannot be opened — the fail-closed startup rule (plan §1.2):
    /// no journal, no server.
    pub fn build(self) -> Result<DevtoolsServer, McpError> {
        // Snapshot the watched file *before* loading config, so an edit racing
        // startup is still observed by the watcher afterwards.
        let watched = if self.watch_config {
            watcher::pending_watch()
        } else {
            None
        };

        let config = match self.config {
            Some(config) => config,
            None => crate::config::load(),
        };
        let client = match self.client {
            Some(client) => client,
            None => build_client()?,
        };

        let audit_sink = match self.audit_sink {
            Some(sink) => Some(sink),
            None => open_configured_journal(&config)?,
        };

        let components = Arc::new(Components {
            config: ConfigHandle::new(config),
            client,
            vendors: self.vendors.unwrap_or_default(),
            workspace_cache: WorkspaceCache::new(),
            credential_broker: self
                .credential_broker
                .unwrap_or_else(|| Arc::new(ConfigCredentialBroker)),
            audit_sink,
            usage_sink: self.usage_sink.unwrap_or_else(|| Arc::new(NoopUsageSink)),
        });

        if let Some(pending) = watched {
            watcher::spawn(&components, pending);
        }

        Ok(DevtoolsServer::from_components(components))
    }
}

/// Open the durable audit journal when `MCP_AUDIT_JOURNAL_DIR` is
/// configured. Absent or blank means local mode (no journal). A configured
/// journal that cannot be opened is a hard startup error — never a warning.
fn open_configured_journal(config: &Config) -> Result<Option<Arc<dyn AuditSink>>, McpError> {
    let Some(dir) = config
        .get("MCP_AUDIT_JOURNAL_DIR")
        .map(str::trim)
        .filter(|dir| !dir.is_empty())
    else {
        return Ok(None);
    };
    let sink = crate::audit::journal::JournalAuditSink::open(std::path::Path::new(dir)).map_err(
        |error| {
            crate::error::unexpected(
                format!(
                    "cannot open the durable audit journal in MCP_AUDIT_JOURNAL_DIR={dir}: \
                     {error}; refusing to start (fail closed, plan §1.2)"
                ),
                None,
            )
        },
    )?;
    Ok(Some(Arc::new(sink)))
}

/// Dependencies for a one-shot CLI subcommand.
///
/// Same graph as the server minus the config watcher. Exists so `bb`, `jira`,
/// and `conf` stop each hand-rolling `config::load()` + `build_client()` +
/// `Vendor::new()`.
pub struct CliRuntime {
    pub config: Arc<Config>,
    pub client: Client,
    pub vendors: Vendors,
    pub workspace_cache: WorkspaceCache,
}

impl CliRuntime {
    /// Load config from the standard cascade and build the shared client.
    ///
    /// # Errors
    ///
    /// Returns [`McpError`] when the HTTP client cannot be constructed.
    pub fn load() -> Result<Self, McpError> {
        Ok(Self {
            config: Arc::new(crate::config::load()),
            client: build_client()?,
            vendors: Vendors::default(),
            workspace_cache: WorkspaceCache::new(),
        })
    }
}

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
pub mod forwarding;
pub mod secrets;
pub mod vendors;
pub mod watcher;

use std::sync::Arc;

use reqwest::Client;

pub use config_handle::ConfigHandle;
pub use vendors::Vendors;

use crate::config::Config;
use crate::error::McpError;
use crate::ports::{
    AllowAll, AuditSink, ConfigCredentialBroker, CredentialBroker, NoopUsageSink,
    PolicyDecisionPoint, SecretSource, UsageSink,
};
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
    /// Whether every tool call must carry a validated inbound principal
    /// (`MCP_AUTH_MODE=okta`). When true, a call that reaches `call_tool`
    /// without one — which the bearer middleware should make impossible —
    /// is refused rather than treated as local (WP A.2, fail closed).
    pub auth_required: bool,
    /// The policy decision point (WP A.7). [`AllowAll`] in local mode; the
    /// compiled `MCP_POLICY_FILE` otherwise. `dyn` for the same reason as
    /// the broker: consulted twice per call on a path that does file I/O.
    pub policy: Arc<dyn PolicyDecisionPoint>,
    /// The same policy as a file-backed bundle, when `MCP_POLICY_FILE`
    /// supplied it: what [`DevtoolsServer::journal_startup`] journals the
    /// `policy_loaded` record for. `None` under [`AllowAll`] or a policy the
    /// builder was handed directly.
    pub policy_file: Option<Arc<crate::policy::FilePolicy>>,
    /// Bound on how long an audit append may wait for durable
    /// acknowledgement before the call is refused (CF-14).
    pub audit_append_timeout: std::time::Duration,
    /// Outcome appends that outlived their caller's wait, so a shutdown can
    /// drain them (`DevtoolsServer::pending_audit`).
    pub pending_audit: tokio_util::task::TaskTracker,
    /// The secret sources compiled into this build (plan §3.8). Consulted
    /// at startup and by the background refresher, never per call.
    pub secrets: Arc<crate::secrets::SecretResolver>,
    /// Whether that refresh is currently failing (health banner).
    pub secret_health: secrets::SecretHealth,
    /// Whether audit forwarding (WP C.3) is keeping up, when the control
    /// plane runs here. Shared with the shipper task.
    pub forward_health: Arc<crate::audit::forward::ForwardHealth>,
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
    auth_required: bool,
    policy: Option<Arc<dyn PolicyDecisionPoint>>,
    secret_sources: Option<Vec<Arc<dyn SecretSource>>>,
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

    /// Require a validated inbound principal on every tool call (enterprise
    /// mode). The HTTP transport sets this when it installs the bearer
    /// middleware; a `call_tool` without a principal is then refused.
    #[must_use]
    pub fn require_inbound_auth(mut self, required: bool) -> Self {
        self.auth_required = required;
        self
    }

    /// Use an explicit policy decision point instead of (not in addition
    /// to) the `MCP_POLICY_FILE`-configured one. Tests pass a
    /// [`crate::policy::FilePolicy`] compiled from bytes.
    #[must_use]
    pub fn policy(mut self, policy: Arc<dyn PolicyDecisionPoint>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Use these secret sources instead of the compiled-in default set
    /// (`file://`). Tests pass an [`crate::ports::InMemorySecretSource`].
    #[must_use]
    pub fn secret_sources(mut self, sources: Vec<Arc<dyn SecretSource>>) -> Self {
        self.secret_sources = Some(sources);
        self
    }

    /// Assemble the server.
    ///
    /// Secret references (`file://…`) are **not** resolved here: this is
    /// synchronous, and a source is network I/O in general. The transport
    /// calls [`DevtoolsServer::resolve_secrets`] before it binds, as it
    /// calls `journal_startup`; a configuration whose references were
    /// never resolved refuses each credential by name at use.
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
        let audit_append_timeout = crate::policy::egress::audit_append_timeout(&config);
        let (policy, policy_file): (Arc<dyn PolicyDecisionPoint>, _) = match self.policy {
            Some(policy) => (policy, None),
            None => {
                match load_configured_policy(&config, audit_sink.as_ref(), audit_append_timeout)? {
                    Some(file) => (
                        Arc::clone(&file) as Arc<dyn PolicyDecisionPoint>,
                        Some(file),
                    ),
                    None => (Arc::new(AllowAll), None),
                }
            }
        };

        // Adapters are configured before the port is handed out: a
        // misconfigured provider is a startup refusal with a reason.
        let secrets = Arc::new(match self.secret_sources {
            Some(sources) => crate::secrets::SecretResolver::new(sources),
            None => crate::secrets::SecretResolver::from_config(&config).map_err(|error| {
                crate::error::unexpected(
                    format!(
                        "cannot configure the secret source {error}; refusing to start (fail \
                         closed, plan §1.2)"
                    ),
                    None,
                )
            })?,
        });

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
            auth_required: self.auth_required,
            policy,
            policy_file,
            audit_append_timeout,
            pending_audit: tokio_util::task::TaskTracker::new(),
            secrets,
            secret_health: secrets::SecretHealth::default(),
            forward_health: Arc::default(),
        });

        if let Some(pending) = watched {
            watcher::spawn(&components, pending);
        }

        Ok(DevtoolsServer::from_components(components))
    }
}

/// Config key enabling the durable audit journal.
pub const AUDIT_JOURNAL_DIR_KEY: &str = "MCP_AUDIT_JOURNAL_DIR";

/// The configured journal directory, if any. Blank counts as absent.
fn configured_journal_dir(config: &Config) -> Option<&str> {
    config
        .get(AUDIT_JOURNAL_DIR_KEY)
        .map(str::trim)
        .filter(|dir| !dir.is_empty())
}

/// Open the durable audit journal when `MCP_AUDIT_JOURNAL_DIR` is
/// configured. Absent or blank means local mode (no journal). A configured
/// journal that cannot be opened is a hard startup error — never a warning.
fn open_configured_journal(config: &Config) -> Result<Option<Arc<dyn AuditSink>>, McpError> {
    let Some(dir) = configured_journal_dir(config) else {
        return Ok(None);
    };
    let checkpoints = configured_checkpoint_policy(config)?;
    let sink =
        crate::audit::journal::JournalAuditSink::open_with(std::path::Path::new(dir), checkpoints)
            .map_err(|error| {
                crate::error::unexpected(
                    format!(
                        "cannot open the durable audit journal in MCP_AUDIT_JOURNAL_DIR={dir}: \
                 {error}; refusing to start (fail closed, plan §1.2)"
                    ),
                    None,
                )
            })?;
    Ok(Some(Arc::new(sink)))
}

/// The journal's checkpoint policy from configuration (WP B.6): cadence,
/// the signing key file, and the export directory. Each is optional here;
/// okta mode requires the signing key (`server::http`).
///
/// # Errors
///
/// When a value is malformed, the key file cannot be loaded, or the export
/// directory cannot be created.
pub fn configured_checkpoint_policy(
    config: &Config,
) -> Result<crate::audit::journal::CheckpointPolicy, McpError> {
    use crate::audit::journal::CheckpointPolicy;
    let mut policy = CheckpointPolicy::unsigned();
    if let Some(value) = configured(config, CheckpointPolicy::RECORDS_KEY) {
        policy.every_records = value
            .parse::<u64>()
            .ok()
            .filter(|n| *n >= 1)
            .ok_or_else(|| {
                crate::error::unexpected(
                    format!(
                        "{} must be a positive integer, got {value:?}",
                        CheckpointPolicy::RECORDS_KEY
                    ),
                    None,
                )
            })?;
    }
    if let Some(value) = configured(config, CheckpointPolicy::SECONDS_KEY) {
        let seconds = value
            .parse::<u64>()
            .ok()
            .filter(|n| *n >= 1)
            .ok_or_else(|| {
                crate::error::unexpected(
                    format!(
                        "{} must be a positive integer, got {value:?}",
                        CheckpointPolicy::SECONDS_KEY
                    ),
                    None,
                )
            })?;
        policy.every_seconds = std::time::Duration::from_secs(seconds);
    }
    if let Some(path) = configured(config, CheckpointPolicy::SIGNING_KEY_KEY) {
        let key = crate::policy::SigningKey::load(std::path::Path::new(path)).map_err(|error| {
            crate::error::unexpected(
                format!(
                    "{}: {error}; refusing to start",
                    CheckpointPolicy::SIGNING_KEY_KEY
                ),
                None,
            )
        })?;
        policy.signing_key = Some(key);
    }
    if let Some(dir) = configured(config, CheckpointPolicy::EXPORT_DIR_KEY) {
        let sink = crate::ports::DirectoryCheckpointSink::open(std::path::Path::new(dir)).map_err(
            |error| {
                crate::error::unexpected(
                    format!(
                        "{}={dir}: {error}; refusing to start",
                        CheckpointPolicy::EXPORT_DIR_KEY
                    ),
                    None,
                )
            },
        )?;
        policy.export = Some(Arc::new(sink));
    }
    Ok(policy)
}

/// A configured, non-blank value.
fn configured<'a>(config: &'a Config, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The verifying key named by `MCP_POLICY_PUBLIC_KEY`, if any. Blank counts
/// as absent; a value that is not a key is a startup error.
///
/// # Errors
///
/// When the value is set but is not a base64 Ed25519 public key.
pub fn configured_policy_public_key(
    config: &Config,
) -> Result<Option<crate::policy::VerifyingKey>, McpError> {
    let key = crate::policy::engine::POLICY_PUBLIC_KEY_KEY;
    config
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            crate::policy::VerifyingKey::from_base64(value).map_err(|error| {
                crate::error::unexpected(format!("{key}: {error}; refusing to start"), None)
            })
        })
        .transpose()
}

/// Load and start watching the policy named by `MCP_POLICY_FILE`; `None`
/// when none is configured (the caller uses [`AllowAll`]). A configured
/// policy that does not compile — or, with `MCP_POLICY_PUBLIC_KEY` set, is
/// not validly signed — is a hard startup error: enterprise mode never runs
/// on a guess, and local mode with a broken dry-run policy should say so.
/// With a journal, the watcher journals every later change; the policy in
/// force is journaled by [`DevtoolsServer::journal_startup`], before the
/// process is reachable.
fn load_configured_policy(
    config: &Config,
    audit_sink: Option<&Arc<dyn AuditSink>>,
    append_timeout: std::time::Duration,
) -> Result<Option<Arc<crate::policy::FilePolicy>>, McpError> {
    let Some(path) = config
        .get(crate::policy::engine::POLICY_FILE_KEY)
        .map(str::trim)
        .filter(|path| !path.is_empty())
    else {
        return Ok(None);
    };
    let verifier = configured_policy_public_key(config)?;
    let path = std::path::Path::new(path);
    let loaded = match verifier {
        Some(verifier) => crate::policy::FilePolicy::load_verified(path, verifier),
        None => crate::policy::FilePolicy::load(path),
    };
    let policy = loaded.map_err(|error| {
        crate::error::unexpected(
            format!(
                "cannot load the policy in {}={}: {error}; refusing to start (fail closed, \
                 plan §1.2)",
                crate::policy::engine::POLICY_FILE_KEY,
                path.display()
            ),
            None,
        )
    })?;
    policy.spawn_watcher(
        audit_sink.map(|sink| crate::policy::BundleAudit {
            sink: Arc::clone(sink),
            append_timeout,
        }),
        None,
    );
    Ok(Some(policy))
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
    /// Returns [`McpError`] when the HTTP client cannot be constructed, or
    /// when a durable audit journal is configured — see
    /// [`refuse_unaudited_cli`].
    pub fn load() -> Result<Self, McpError> {
        let config = crate::config::load();
        refuse_unaudited_cli(&config)?;
        refuse_unresolved_references(&config)?;
        Ok(Self {
            config: Arc::new(config),
            client: build_client()?,
            vendors: Vendors::default(),
            workspace_cache: WorkspaceCache::new(),
        })
    }
}

/// Refuse the one-shot CLI subcommands when the configuration holds secret
/// references (`file://…`).
///
/// Resolving them is an async step the server runs before it binds
/// ([`DevtoolsServer::resolve_secrets`]); [`CliRuntime::load`] is
/// synchronous and one-shot. Until the CLI paths share that step, a
/// reference here would either be sent upstream as if it were the token or
/// fail at the first call as "credential missing" — neither names the
/// cause. Refuse up front, by name (CF-28).
///
/// # Errors
///
/// [`McpError`] naming the first reference.
pub fn refuse_unresolved_references(config: &Config) -> Result<(), McpError> {
    if let Some(reference) = config.secret_references().next() {
        return Err(crate::error::unexpected(
            format!(
                "the configuration references a secret ({reference}), and the one-shot CLI \
                 subcommands do not resolve secret references yet. Use the MCP server \
                 (`mcp-devtools` stdio/http), or configure the credential as a literal or \
                 `keychain` for this session."
            ),
            None,
        ));
    }
    Ok(())
}

/// Refuse operational CLI subcommands while a durable audit journal is
/// configured.
///
/// `mcp-devtools jira post ...` reaches the same vendor APIs the MCP tools
/// do, but it goes straight through [`CliRuntime`] — no intent record, no
/// outcome record, nothing in the journal. On a deployment that has switched
/// journaling on, that is a hole straight through the evidence trail: the
/// same binary, the same credentials, no audit. Until the CLI paths route
/// through the audited boundary, an operator who has asked for durable
/// auditing gets a refusal rather than an unrecorded call.
///
/// This deliberately does **not** cover `creds`, `config`, or `--version`:
/// those are local administration, and they build no [`CliRuntime`].
///
/// # Errors
///
/// [`McpError`] when `MCP_AUDIT_JOURNAL_DIR` is set.
pub fn refuse_unaudited_cli(config: &Config) -> Result<(), McpError> {
    if configured_journal_dir(config).is_some() {
        return Err(crate::error::unexpected(
            format!(
                "{AUDIT_JOURNAL_DIR_KEY} is set, but the one-shot CLI subcommands do not \
                 write to the durable audit journal yet. Running them here would reach \
                 the vendor APIs with no evidence recorded. Use the MCP server \
                 (`mcp-devtools` stdio/http), or unset {AUDIT_JOURNAL_DIR_KEY} for an \
                 explicitly unaudited session."
            ),
            None,
        ));
    }
    Ok(())
}

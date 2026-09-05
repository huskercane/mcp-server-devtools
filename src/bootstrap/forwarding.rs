//! Audit forwarding: select the `AuditForwarder` adapter from configuration
//! and start the shipper (plan §3.9 "Selection is configuration", WP C.3).
//!
//! This is the only place a receiver URL is turned into an adapter. The
//! scheme picks it — `syslog+tls://` is [`SyslogForwarder`], `https://` (or
//! `http://` on loopback) is [`HttpForwarder`] — and a scheme with no
//! adapter is a typed startup error naming the scheme, so an operator sees
//! the cause rather than a silent no-op. Everything the adapters need (the
//! token, the CA file, the client certificate, the origin, the timeout) is
//! read here from the configuration cascade, after secret references were
//! resolved, so `MCP_AUDIT_FORWARD_TOKEN` may be a `file://` or `vault://`
//! reference like any other credential. The token is not copied into the
//! adapter: the running shipper's forwarder reads it from the components'
//! *current* configuration snapshot at each delivery, so a rotation the
//! secret refresher (or a config reload) swaps in reaches the receiver on
//! the next batch, not the next restart.
//!
//! The shipper runs on the roles that serve the control plane (`all`,
//! `control`), never on a pure `gateway` replica: forwarding is the
//! control plane's job (§3.4), and a gateway's process budget is the
//! request path. It holds a [`Weak`] to nothing — it owns its forwarder
//! and its cursor, reads the journal file, and reports into the
//! [`ForwardHealth`] the components share with the health banner; it ends
//! when the transport's cancellation token fires.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use super::Components;
use crate::audit::forward::http::{HttpFormat, HttpForwarder, TokenSource};
use crate::audit::forward::syslog::{SyslogForwarder, SyslogSettings, TlsOptions};
use crate::audit::forward::{self, Shipper};
use crate::config::Config;
use crate::error::McpError;
use crate::ports::AuditForwarder;

/// What the configuration asks for, resolved to paths and values.
#[derive(Debug)]
pub struct ForwardingSettings {
    pub url: String,
    pub journal_dir: PathBuf,
    pub state_dir: PathBuf,
    pub batch: usize,
    pub interval: std::time::Duration,
}

/// Build the adapter the URL names, with every setting it needs, the token
/// fixed to the value `config` holds now.
///
/// The running shipper is built by [`spawn_configured`], which reads the
/// token live instead; this is the one-shot form (validation, tests).
///
/// # Errors
///
/// A message naming the setting at fault: an unknown scheme, a malformed
/// URL, a missing token, a CA or certificate file that does not load.
pub fn forwarder_from_config(config: &Config) -> Result<Option<Arc<dyn AuditForwarder>>, String> {
    let token = config.get(forward::TOKEN_KEY).map(str::to_owned);
    build_forwarder(config, Arc::new(move || token.clone()))
}

/// The token as the components' current configuration has it, read at
/// each delivery. `None` once the server is gone.
fn live_token_source(components: &Arc<Components>) -> TokenSource {
    let weak: Weak<Components> = Arc::downgrade(components);
    Arc::new(move || {
        let components = weak.upgrade()?;
        let config = components.config();
        config.get(forward::TOKEN_KEY).map(str::to_owned)
    })
}

/// Build the adapter the URL names, taking the token from `token`.
fn build_forwarder(
    config: &Config,
    token: TokenSource,
) -> Result<Option<Arc<dyn AuditForwarder>>, String> {
    let Some(url) = configured(config, forward::URL_KEY) else {
        return Ok(None);
    };
    let origin = forward::origin(config);
    let timeout = forward::timeout(config);
    let ca_file = configured(config, forward::CA_FILE_KEY).map(PathBuf::from);
    let scheme = url.split("://").next().unwrap_or(url).to_ascii_lowercase();
    let forwarder: Arc<dyn AuditForwarder> = match scheme.as_str() {
        "syslog+tls" => {
            let settings = SyslogSettings::parse_url(url, origin, timeout)
                .map_err(|error| format!("{}: {error}", forward::URL_KEY))?;
            let tls = TlsOptions {
                ca_file,
                client_cert: configured(config, forward::CLIENT_CERT_KEY).map(PathBuf::from),
                client_key: configured(config, forward::CLIENT_KEY_KEY).map(PathBuf::from),
            };
            Arc::new(SyslogForwarder::new(settings, &tls)?)
        }
        "https" | "http" => {
            let format = configured(config, forward::FORMAT_KEY)
                .map(HttpFormat::parse)
                .transpose()?;
            Arc::new(
                HttpForwarder::with_token_source(
                    url,
                    format,
                    token,
                    origin,
                    ca_file.as_deref(),
                    timeout,
                )
                .map_err(|error| format!("{}: {error}", forward::URL_KEY))?,
            )
        }
        "syslog" | "syslog+tcp" | "syslog+udp" => {
            return Err(format!(
                "{}: `{scheme}://` is plaintext syslog, which is not supported; use \
                 `syslog+tls://host[:6514]`",
                forward::URL_KEY
            ));
        }
        other => {
            return Err(format!(
                "{}: no audit forwarder for `{other}://` is compiled into this binary \
                 (expected `syslog+tls://`, `https://`)",
                forward::URL_KEY
            ));
        }
    };
    Ok(Some(forwarder))
}

/// The directories and cadence the shipper runs with. `None` when
/// forwarding is not configured.
///
/// # Errors
///
/// When forwarding is configured but no journal directory is — there is
/// nothing to forward, and saying so beats a task that polls a path that
/// will never exist.
pub fn settings_from_config(config: &Config) -> Result<Option<ForwardingSettings>, String> {
    let Some(url) = configured(config, forward::URL_KEY) else {
        return Ok(None);
    };
    let journal_dir = configured(config, forward::JOURNAL_DIR_KEY)
        .or_else(|| configured(config, super::AUDIT_JOURNAL_DIR_KEY))
        .ok_or_else(|| {
            format!(
                "{} is set but neither {} nor {} names a journal to forward",
                forward::URL_KEY,
                forward::JOURNAL_DIR_KEY,
                super::AUDIT_JOURNAL_DIR_KEY
            )
        })?;
    let state_dir = configured(config, forward::STATE_DIR_KEY).unwrap_or(journal_dir);
    Ok(Some(ForwardingSettings {
        url: url.to_owned(),
        journal_dir: PathBuf::from(journal_dir),
        state_dir: PathBuf::from(state_dir),
        batch: forward::batch_size(config),
        interval: forward::interval(config),
    }))
}

/// Start the shipper if forwarding is configured. Returns the adapter's
/// name when it started, `None` when nothing is configured.
///
/// # Errors
///
/// [`McpError`] when the configuration cannot be turned into a running
/// shipper: the process refuses to start (§3.9 failure posture). An
/// *unreachable* receiver is not such an error — the first delivery will
/// fail, the health banner will say so, and the journal is retained.
pub fn spawn_configured(
    components: &Arc<Components>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<Option<&'static str>, McpError> {
    let config = components.config();
    let refuse = |error: String| {
        crate::error::unexpected(
            format!("cannot configure audit forwarding: {error}; refusing to start"),
            None,
        )
    };
    let Some(settings) = settings_from_config(&config).map_err(refuse)? else {
        return Ok(None);
    };
    let Some(forwarder) =
        build_forwarder(&config, live_token_source(components)).map_err(refuse)?
    else {
        return Ok(None);
    };
    let name = forwarder.name();
    let shipper = Shipper::open(
        forwarder,
        &settings.journal_dir,
        &settings.state_dir,
        settings.batch,
    )
    .map_err(|error| {
        refuse(format!(
            "{}={}: {error}",
            forward::STATE_DIR_KEY,
            settings.state_dir.display()
        ))
    })?;
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return Err(refuse(
            "audit forwarding requires a Tokio runtime".to_owned(),
        ));
    };
    tracing::info!(
        forwarder = name,
        journal = %settings.journal_dir.display(),
        acknowledged = shipper.cursor().acknowledged,
        "audit forwarding started"
    );
    let health = Arc::clone(&components.forward_health);
    runtime.spawn(shipper.run(health, settings.interval, cancel));
    Ok(Some(name))
}

/// A configured, non-blank value.
fn configured<'a>(config: &'a Config, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The directory a path names, for messages.
#[must_use]
pub fn display(path: &Path) -> String {
    path.display().to_string()
}

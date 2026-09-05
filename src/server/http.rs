//! Streamable-HTTP MCP transport.
//!
//! Wraps rmcp's [`StreamableHttpService`] in an Axum router that adds the
//! cross-cutting concerns the TS reference layered over Express:
//!
//! - Bind `127.0.0.1` only; port from `PORT`, default 3000.
//! - `Origin` allowlist (DNS-rebinding guard), globally applied.
//! - CORS with mirrored origins and headers, globally applied.
//! - 1 MB body cap on `/mcp` routes.
//! - `GET /` plaintext health endpoint.
//! - 30-minute idle session reap, sweeping every 5 minutes (see
//!   [`crate::server::session`]).
//!
//! Ported from `src/index.ts:113-360`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path as AxumPath, Request};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any_service, get};
use futures::StreamExt as _;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::net::TcpListener;
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn};

use crate::config::{AuthMode, Config};
use crate::constants::VERSION;
use crate::error::McpError;
use crate::policy::{BundleAudit, OwnerKey};
use crate::server::auth::{
    InboundAuth, InboundAuthSettings, PROTECTED_RESOURCE_METADATA_PATH,
    protected_resource_metadata, require_bearer,
};
use crate::server::session::{DEFAULT_IDLE_TTL, DEFAULT_SWEEP_INTERVAL, ReapingSessionManager};
use crate::server::shutdown;
use crate::tools::DevtoolsServer;

const BODY_LIMIT_BYTES: usize = 1_000_000;
const DEFAULT_PORT: u16 = 3000;

/// Config key selecting the process role (plan ADR-010, WP A.9).
pub const ROLE_KEY: &str = "MCP_ROLE";

/// What one process serves (plan §3.4). One image, one binary; the role is
/// a runtime flag, not a second codebase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Role {
    /// Data plane and control plane in one process — single-host deployments.
    #[default]
    All,
    /// The data plane: `/mcp`, artifacts, token validation, policy, egress,
    /// the local journal. Scaled horizontally behind the ingress.
    Gateway,
    /// The control plane: admin API, rollups, reports, console (Phases C
    /// and D). In Phase A it serves only the health banner and refuses
    /// tool traffic, so a misrouted request cannot be served by a replica
    /// that was never meant to hold vendor credentials.
    Control,
}

impl Role {
    /// Parse `MCP_ROLE`. Absent or empty is [`Role::All`]; anything else
    /// must be exactly one of the three names (case-insensitive) — a typo
    /// must not silently become "everything".
    ///
    /// # Errors
    ///
    /// A human-readable reason for an unrecognised value.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw.map(str::trim) {
            None | Some("") => Ok(Self::All),
            Some(value) if value.eq_ignore_ascii_case("all") => Ok(Self::All),
            Some(value) if value.eq_ignore_ascii_case("gateway") => Ok(Self::Gateway),
            Some(value) if value.eq_ignore_ascii_case("control") => Ok(Self::Control),
            Some(other) => Err(format!(
                "unrecognised {ROLE_KEY} {other:?} (expected \"all\", \"gateway\", or \"control\")"
            )),
        }
    }

    /// Whether this role serves the MCP data plane.
    #[must_use]
    pub const fn serves_gateway(self) -> bool {
        matches!(self, Self::All | Self::Gateway)
    }

    /// Whether this role runs the control plane's background work: audit
    /// forwarding (C.3), and the rollups and admin API to come.
    #[must_use]
    pub const fn serves_control(self) -> bool {
        matches!(self, Self::All | Self::Control)
    }
}

/// Boot the streamable-HTTP server on `127.0.0.1:${PORT:-3000}`.
///
/// Matches TS `startServer('http')`.
pub async fn run_http() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let role = Role::parse(std::env::var(ROLE_KEY).ok().as_deref())?;
    run_http_as(role).await
}

/// Boot the streamable-HTTP server in an explicit [`Role`] (the `serve
/// --role` subcommand); [`run_http`] reads the role from `MCP_ROLE`.
pub async fn run_http_as(role: Role) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    crate::transport::raw_response::start_retention_sweeper();
    let port = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);

    // Registered before the listener binds: once the port is open the process
    // is reachable, and a SIGTERM landing before the handler exists would kill
    // it outright instead of draining. See `shutdown::install`.
    let shutdown_signal = shutdown::install();

    // One config load for the transport's own settings; the server below
    // loads (and watches) its own copy through the composition root. The
    // auth mode is read through the cascade rather than the bare process
    // environment so `.env` and the global config can set it too — the same
    // trust level as the credentials they already hold.
    let config = crate::config::load();
    let auth_mode = AuthMode::parse(config.get("MCP_AUTH_MODE"))?;
    let ema = crate::auth::ema::enabled(&config)?;
    if ema && !auth_mode.requires_inbound_auth() {
        return Err("MCP_EMA_ENABLED requires OIDC authentication".into());
    }
    let addr = resolve_bind_addr(std::env::var("MCP_BIND_ADDR").ok().as_deref(), port)?;
    validate_startup_security(auth_mode, &addr)?;
    // Shared across rmcp (drops in-flight SSE on cancel) and axum (stops
    // accepting new connections + drains existing ones on cancel).
    let cancel = CancellationToken::new();
    // Built **before the port opens**. A `DevtoolsServer` that cannot be
    // assembled — an audit journal that will not open, say — used to be
    // stored as an error *inside* the router, so the process logged
    // "listening", held the port, and failed every call while a health check
    // marked it ready. Constructing first means a startup failure never
    // reaches the point of being reachable at all. The inbound-auth stack
    // is built from the server, because the revocation list journals to
    // the server's audit sink.
    let server = crate::bootstrap::ServerBuilder::new()
        .watch_config(true)
        .require_inbound_auth(auth_mode.requires_inbound_auth())
        .serves_control(role.serves_control())
        .build()?;
    let inbound_auth = match auth_mode {
        AuthMode::Off => None,
        AuthMode::Oidc(keys) => Some(Arc::new(enterprise_inbound_auth(&config, &server, keys)?)),
    };
    if ema {
        let auth = inbound_auth.as_ref().expect("EMA requires OIDC");
        crate::auth::ema::OidcExchange::new()?
            .verify_resource_issuer(&auth.settings().authorization_servers[0])
            .await?;
    }
    // Every secret reference resolves before the port opens, or the
    // process does not start (plan §3.8): a credential it cannot read is
    // not a credential it can vouch for per call.
    server.resolve_secrets().await?;
    // The startup evidence — which policy and which revocation list this
    // process runs under — is durable before the port opens. A journal
    // that cannot take these records is a journal that cannot take the
    // first tool call's intent either, so this fails the same way.
    server.journal_startup().await?;
    if let Some(auth) = &inbound_auth {
        auth.journal_startup().await.map_err(|error| {
            format!(
                "refusing to start: the revocation list in force could not be journaled ({})",
                crate::ports::AuditFailure::classify(&error)
            )
        })?;
    }
    // Forwarding the journal to a SIEM is the control plane's job (§3.4):
    // it starts here, after the startup records are durable, and only on
    // a role that serves the control plane. A misconfiguration refuses to
    // start; an unreachable receiver does not (ADR-011: asynchronous).
    if role.serves_control() {
        server.start_audit_forwarding(cancel.clone())?;
        server.start_rollups(cancel.clone())?;
    }
    let pending_audit = server.pending_audit();
    let app = build_app_for_role(
        role,
        server,
        inbound_auth,
        DEFAULT_IDLE_TTL,
        DEFAULT_SWEEP_INTERVAL,
        cancel.clone(),
    );

    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;

    info!(%bound, auth = ?auth_mode, role = ?role, "mcp-server-devtools listening on streamable-HTTP transport");
    let shutdown_cancel = cancel;
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal.wait().await;
            info!("shutdown signal received; draining HTTP sessions");
            shutdown_cancel.cancel();
        })
        .await;
    // Serving has stopped; nothing new can start an outcome append. Let the
    // ones already in flight reach the journal before the runtime goes.
    crate::tools::drain_pending_audit(&pending_audit).await;
    crate::transport::raw_response::shutdown_and_cleanup().await;
    result?;
    Ok(())
}

fn enterprise_resource_settings(
    config: &Config,
    keys: crate::config::OidcKeys,
    oidc: &crate::auth::oidc::OidcSettings,
) -> Result<InboundAuthSettings, String> {
    let ema = crate::auth::ema::enabled(config)?;
    // OIDC's legacy normalization stays compatible; EMA discovery uses the
    // configured identifier exactly, including a significant trailing slash.
    let issuer = if ema {
        config.get(keys.issuer()).unwrap_or(&oidc.issuer).trim()
    } else {
        &oidc.issuer
    };
    let settings = InboundAuthSettings::from_config(config, keys.mode(), vec![issuer.to_owned()])?;
    if ema && oidc.audience != settings.public_url {
        return Err("EMA requires the OIDC audience to equal MCP_PUBLIC_URL".to_owned());
    }
    Ok(settings)
}

/// Assemble the enterprise inbound-auth stack from configuration, refusing
/// anything incomplete (plan §1.2: no "temporarily permissive" mode).
///
/// Required together: the issuer and audience (under whichever key family
/// `MCP_AUTH_MODE` selected), the public URL clients are told to obtain a
/// token for, and the durable audit journal — evidence is the product, so
/// enterprise mode without a journal is not a mode.
fn enterprise_inbound_auth(
    config: &Config,
    server: &DevtoolsServer,
    keys: crate::config::OidcKeys,
) -> Result<InboundAuth, String> {
    let mode = keys.mode();
    let oidc = crate::auth::oidc::OidcSettings::from_config(config, keys)?;
    let settings = enterprise_resource_settings(config, keys, &oidc)?;
    let rate_limit = crate::server::rate_limit::RateLimitSettings::from_config(config)
        .map_err(|error| format!("refusing to start: {error}"))?;
    if config
        .get(crate::bootstrap::AUDIT_JOURNAL_DIR_KEY)
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        return Err(format!(
            "refusing to start: MCP_AUTH_MODE={mode} requires {} — enterprise mode without a \
             durable audit journal would authorize calls it cannot evidence (fail-closed; \
             see docs/enterprise-product-plan.md §1.2)",
            crate::bootstrap::AUDIT_JOURNAL_DIR_KEY
        ));
    }
    if config
        .get(crate::policy::engine::POLICY_FILE_KEY)
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        return Err(format!(
            "refusing to start: MCP_AUTH_MODE={mode} requires {} — enterprise mode with no \
             policy loaded would authenticate every caller and then allow everything \
             (fail-closed; see docs/enterprise-product-plan.md §1.2)",
            crate::policy::engine::POLICY_FILE_KEY
        ));
    }
    if config
        .get(crate::policy::engine::POLICY_PUBLIC_KEY_KEY)
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        return Err(format!(
            "refusing to start: MCP_AUTH_MODE={mode} requires {} — enterprise mode applies only \
             signed policy bundles, so a gateway with no verifying key could not tell an \
             authored policy from a planted one (fail-closed; plan §4 B.3). Generate a key \
             pair with `mcp-devtools policy keygen` and sign the policy with \
             `mcp-devtools policy sign`",
            crate::policy::engine::POLICY_PUBLIC_KEY_KEY
        ));
    }
    if config
        .get(crate::audit::journal::CheckpointPolicy::SIGNING_KEY_KEY)
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        return Err(format!(
            "refusing to start: MCP_AUTH_MODE={mode} requires {} — the audit journal's \
             checkpoints are signed so tampering is detectable offline, and an unsigned \
             journal is evidence only for whoever holds the disk (plan §3.3, B.6). Generate \
             a key with `mcp-devtools audit keygen`",
            crate::audit::journal::CheckpointPolicy::SIGNING_KEY_KEY
        ));
    }
    let revocation_path = config
        .get(crate::auth::revocation::REVOCATION_FILE_KEY)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!(
                "refusing to start: MCP_AUTH_MODE={mode} requires {} — the revocation list is \
                 the emergency stop (deny by subject, by token id, or `revoke all`), and a \
                 gateway without one has no way to cut a compromised token off before it \
                 expires (plan §3.6, B.4). Create an empty, signed list with \
                 `mcp-devtools revoke init`",
                crate::auth::revocation::REVOCATION_FILE_KEY
            )
        })?;
    let verifier = crate::bootstrap::configured_policy_public_key(config)
        .map_err(|error| error.message)?
        .ok_or_else(|| "MCP_POLICY_PUBLIC_KEY is required".to_owned())?;
    let revocations = crate::auth::revocation::RevocationList::load_verified(
        std::path::Path::new(revocation_path),
        verifier,
    )
    .map_err(|error| {
        format!(
            "cannot load the revocation list in {}={revocation_path}: {error}; refusing to \
             start (fail closed, plan §1.2)",
            crate::auth::revocation::REVOCATION_FILE_KEY
        )
    })?;
    let client = crate::transport::build_client().map_err(|error| error.message)?;
    let validator = Arc::new(crate::auth::oidc::OidcJwksValidator::new(oidc, client));
    let mut auth = InboundAuth::new(Arc::new(validator), settings).with_revocations(revocations);
    if let Some(sink) = server.audit_sink() {
        auth = auth.with_audit(BundleAudit {
            sink,
            append_timeout: server.audit_append_timeout(),
        });
    }
    if let Some(settings) = rate_limit {
        auth = auth.with_rate_limit(Arc::new(crate::server::rate_limit::RateLimiter::new(
            settings,
        )));
    }
    Ok(auth)
}

/// `GET /metrics` (`MCP_METRICS=on`): the Prometheus page, or 404 when
/// metrics are off. Unauthenticated, like the health banner: it carries
/// counts by vendor and tool, never a subject or a token.
fn metrics(server: &DevtoolsServer, auth: Option<&Arc<InboundAuth>>) -> Response {
    let rate_limited = auth
        .and_then(|auth| auth.rate_limiter())
        .map_or(0, |limiter| limiter.refused());
    match server.metrics_page(rate_limited) {
        Some(page) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            )],
            page,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Build the full Axum app with a caller-owned cancellation token. Tests use
/// the unparameterized [`build_app`].
///
/// # Errors
///
/// When the `DevtoolsServer` cannot be assembled — a configured audit
/// journal that will not open, most importantly. Returning it means the
/// caller binds and logs readiness only for a server that actually works.
pub fn build_app_with_cancel(
    idle_ttl: Duration,
    sweep_interval: Duration,
    cancel: CancellationToken,
) -> Result<Router, McpError> {
    // Stateless MCP means each request carries its own protocol metadata; it
    // does not mean application state should be reconstructed per request.
    // Build one handler and clone it: DevtoolsServer's clone shares its
    // Arc<Components>, including NinjaOne console sessions and other caches.
    let shared_server = DevtoolsServer::new()?;
    Ok(build_app_inner(
        true,
        shared_server,
        None,
        idle_ttl,
        sweep_interval,
        cancel,
    ))
}

/// Build the app around an already-assembled server. This is the seam
/// integration tests use to serve a `DevtoolsServer` with mock vendors,
/// pinned brokers, or in-memory audit sinks over the real HTTP transport.
pub fn build_app_with_server(
    server: DevtoolsServer,
    idle_ttl: Duration,
    sweep_interval: Duration,
    cancel: CancellationToken,
) -> Router {
    build_app_inner(true, server, None, idle_ttl, sweep_interval, cancel)
}

/// Like [`build_app_with_server`], with inbound bearer authentication in
/// front of `/mcp` and `/artifacts/{id}` and the RFC 9728 metadata route
/// mounted. The seam for enterprise-mode integration tests: a
/// [`crate::ports::StaticValidator`] or an Okta validator against a mock
/// JWKS, over the real router.
pub fn build_app_with_server_and_auth(
    server: DevtoolsServer,
    auth: Arc<InboundAuth>,
    idle_ttl: Duration,
    sweep_interval: Duration,
    cancel: CancellationToken,
) -> Router {
    build_app_inner(true, server, Some(auth), idle_ttl, sweep_interval, cancel)
}

/// The router for a [`Role`]. `All` and `Gateway` are the full data plane;
/// `Control` serves only the health banner in Phase A (see [`Role`]).
pub fn build_app_for_role(
    role: Role,
    server: DevtoolsServer,
    auth: Option<Arc<InboundAuth>>,
    idle_ttl: Duration,
    sweep_interval: Duration,
    cancel: CancellationToken,
) -> Router {
    if role.serves_gateway() {
        return build_app_inner(
            role.serves_control(),
            server,
            auth,
            idle_ttl,
            sweep_interval,
            cancel,
        );
    }
    // Control role: health only. Every other path is a 404 — there is no
    // data plane here, and nothing to hand a caller who reached the wrong
    // replica. The cross-cutting guards stay so the surface is uniform.
    let metrics_server = server.clone();
    let admin = auth.map_or_else(Router::new, |auth| {
        let manager = Arc::new(ReapingSessionManager::new(idle_ttl));
        watch_revocations(&auth, &manager);
        super::admin::router(
            server.clone(),
            &auth,
            None,
            None,
            admin_reports(&server, cancel.clone()),
        )
    });
    Router::new()
        .merge(admin)
        .route(
            "/",
            get(move || {
                let server = server.clone();
                async move { health(&server) }
            }),
        )
        .route(
            "/metrics",
            get(move || {
                let server = metrics_server.clone();
                async move { metrics(&server, None) }
            }),
        )
        .layer(middleware::from_fn(origin_allowlist))
}

fn admin_reports(
    server: &DevtoolsServer,
    cancel: CancellationToken,
) -> Option<Arc<dyn crate::ports::activity_reports::ActivityReports>> {
    let config = server.config();
    let directory = config.get(crate::bootstrap::AUDIT_JOURNAL_DIR_KEY)?;
    let rollups = config
        .get(crate::rollups::STORE_KEY)?
        .strip_prefix("sqlite://")?;
    let path = std::path::PathBuf::from(format!("{rollups}.activity.sqlite"));
    let store = crate::audit::activity_sqlite::SqliteActivityReports::open(&path).ok()?;
    store.spawn(
        std::path::PathBuf::from(directory).join(crate::audit::journal::JOURNAL_FILE_NAME),
        cancel,
    );
    Some(store)
}

fn build_app_inner(
    serves_control: bool,
    shared_server: DevtoolsServer,
    auth: Option<Arc<InboundAuth>>,
    idle_ttl: Duration,
    sweep_interval: Duration,
    cancel: CancellationToken,
) -> Router {
    let manager = Arc::new(ReapingSessionManager::new(idle_ttl));
    manager.spawn_reaper(sweep_interval);
    let admin = if serves_control {
        auth.as_ref().map_or_else(Router::new, |auth| {
            super::admin::router(
                shared_server.clone(),
                auth,
                Some(manager.clone()),
                Some(Arc::new(crate::transport::raw_response::LocalArtifactStore)),
                admin_reports(&shared_server, cancel.clone()),
            )
        })
    } else {
        Router::new()
    };
    let health_server = shared_server.clone();
    let streamable = StreamableHttpService::new(
        move || Ok(shared_server.clone()),
        Arc::clone(&manager),
        StreamableHttpServerConfig::default()
            // Keep initialized sessions for older clients while requiring the
            // self-contained protocol metadata mandated by MCP 2026-07-28 on
            // stateless requests. rmcp routes modern requests statelessly even
            // while legacy-session compatibility remains enabled.
            .with_stateless_protocol_metadata_required(true)
            .with_cancellation_token(cancel),
    );

    // Express `cors({ origin: true })` reflects the caller's Origin and mirrors
    // the requested headers on preflight. No credentials, no exposed headers —
    // TS parity.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::mirror_request())
        .allow_methods(AllowMethods::list([
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::OPTIONS,
        ]))
        .allow_headers(AllowHeaders::mirror_request());

    // 1 MB body cap applies only to /mcp routes — TS used `express.json({ limit
    // '1mb' })` which only activates on JSON bodies; the Rust parallel is to
    // scope the raw body-limit to /mcp, where the only body-bearing handlers
    // live.
    let mcp_routes = Router::new()
        .route("/mcp", any_service(streamable))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT_BYTES));

    // Everything a principal acts through. In enterprise mode the bearer
    // middleware wraps exactly this set; the health banner and the RFC 9728
    // metadata stay reachable without a token, because they are how a
    // client (and a load balancer) learns whether and how to authenticate.
    let mut protected = Router::new()
        .route("/artifacts/{id}", get(download_artifact))
        .merge(mcp_routes);
    let metrics_server = health_server.clone();
    let metrics_auth = auth.clone();
    let mut public = Router::new()
        .route(
            "/",
            get(move || {
                let server = health_server.clone();
                async move { health(&server) }
            }),
        )
        .route(
            "/metrics",
            get(move || {
                let server = metrics_server.clone();
                let auth = metrics_auth.clone();
                async move { metrics(&server, auth.as_ref()) }
            }),
        );
    if let Some(auth) = auth {
        watch_revocations(&auth, &manager);
        // Inner layer first: the session binding runs after the bearer
        // check has placed the principal in the extensions.
        protected = protected
            .route_layer(middleware::from_fn_with_state(
                Arc::clone(&manager),
                crate::server::session::enforce_session_owner,
            ))
            .route_layer(middleware::from_fn_with_state(
                Arc::clone(&auth),
                require_bearer,
            ));
        public = public.merge(
            Router::new()
                .route(
                    PROTECTED_RESOURCE_METADATA_PATH,
                    get(protected_resource_metadata),
                )
                .with_state(auth),
        );
    }

    // Origin guard + CORS apply globally — TS applies them via `app.use` before
    // registering the `/mcp` routes, so both cover the `GET /` health endpoint
    // as well.
    public
        .merge(admin)
        .merge(protected)
        .layer(middleware::from_fn(origin_allowlist))
        .layer(cors)
}

/// Start the revocation-list watcher (WP B.4). On every change: cached
/// validations are dropped so the next request revalidates, and the
/// sessions of newly revoked subjects are closed — every principal's
/// sessions when the `not_before` cut-off moved, since a session cannot
/// say which token created it. The middleware check is what actually
/// refuses a revoked token; this keeps nothing derived from one alive.
fn watch_revocations(auth: &Arc<InboundAuth>, manager: &Arc<ReapingSessionManager>) {
    let Some(list) = auth.revocations() else {
        return;
    };
    let validator = Arc::clone(auth.validator());
    let sessions = Arc::clone(manager);
    list.spawn_watcher(
        auth.audit().cloned(),
        Some(Box::new(move |previous, current| {
            validator.forget_validated();
            let cutoff_moved =
                previous.document.not_before_epoch() != current.document.not_before_epoch();
            let sessions = Arc::clone(&sessions);
            let current = Arc::clone(current);
            tokio::spawn(async move {
                let closed = sessions
                    .close_where(|owner| match owner {
                        OwnerKey::Principal { subject, .. } => {
                            cutoff_moved || current.document.revokes_subject(subject)
                        }
                        OwnerKey::Local => false,
                    })
                    .await;
                info!(
                    closed,
                    cutoff_moved,
                    revoked_subjects = current.document.subject_count(),
                    revoked_tokens = current.document.token_count(),
                    "revocation list changed; validated-token cache cleared"
                );
            });
        })),
    );
}

async fn download_artifact(AxumPath(id): AxumPath<String>, request: Request) -> Response {
    // WP A.4: only the principal that created an artifact may download it.
    // Without inbound auth there is no principal and the requester is
    // `local`, which is also what every locally created artifact is owned
    // by — so local mode is unchanged. A cross-owner request is the same
    // 404 as an unknown id.
    let requester = request
        .extensions()
        .get::<crate::policy::Principal>()
        .map_or(crate::policy::OwnerKey::Local, crate::policy::OwnerKey::of);
    let Some(pin) = crate::transport::raw_response::pin_artifact(&id, &requester) else {
        return (StatusCode::NOT_FOUND, "Artifact not found or expired").into_response();
    };
    let artifact = pin.metadata().clone();
    let requested_range = request
        .headers()
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let if_range_matches = request
        .headers()
        .get(header::IF_RANGE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| value == artifact.etag);
    let effective_range = requested_range.as_deref().filter(|_| if_range_matches);
    let range = match effective_range.map(|value| parse_range(value, artifact.size)) {
        Some(None) => {
            return Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{}", artifact.size))
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty()));
        }
        Some(Some(range)) => range,
        None => (0, artifact.size.saturating_sub(1)),
    };
    let (start, end) = range;
    let length = if artifact.size == 0 {
        0
    } else {
        end - start + 1
    };
    let Ok(mut file) = tokio::fs::File::open(&artifact.path).await else {
        return (StatusCode::GONE, "Artifact is no longer available").into_response();
    };
    if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let stream = ReaderStream::new(file.take(length)).map(move |result| {
        let _keep_generation_pinned = &pin;
        result
    });
    let status = if effective_range.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, artifact.content_type)
        .header(header::CONTENT_LENGTH, length)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::ETAG, artifact.etag)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", artifact.filename),
        );
    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(
            header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{}", artifact.size),
        );
    }
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn parse_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let range = value.strip_prefix("bytes=")?;
    if range.contains(',') || size == 0 {
        return None;
    }
    let (start, end) = range.split_once('-')?;
    if start.is_empty() {
        let suffix = end.parse::<u64>().ok()?.min(size);
        return (suffix > 0).then_some((size - suffix, size - 1));
    }
    let start = start.parse::<u64>().ok()?;
    if start >= size {
        return None;
    }
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>().ok()?.min(size - 1)
    };
    (start <= end).then_some((start, end))
}

/// Build the app without an externally-owned cancellation token. Convenience
/// for tests that don't exercise shutdown semantics.
///
/// # Errors
///
/// As [`build_app_with_cancel`].
pub fn build_app(idle_ttl: Duration, sweep_interval: Duration) -> Result<Router, McpError> {
    build_app_with_cancel(idle_ttl, sweep_interval, CancellationToken::new())
}

/// Plaintext health banner. Byte-identical to the pre-enterprise banner in
/// local mode. When a durable audit journal is configured and can no longer
/// accept records, the gateway will refuse every tool call, so it answers
/// 503 here rather than telling a load balancer it is fine (CF-6).
///
/// A policy that can no longer be reloaded is different: the gateway keeps
/// enforcing the last good document, which is a serving state, so the
/// banner stays 200 and says so — a probe that took every replica out of
/// rotation because one file went missing would turn a stale policy into
/// an outage.
fn health(server: &DevtoolsServer) -> Response {
    let content_type = (
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    if server.audit_available() {
        let mut banner = format!("mcp-server-devtools v{VERSION} is running");
        // A fixed category: this route is unauthenticated, and the reason
        // names the policy path and parser detail. Those go to the operator
        // log (the watcher warns on every failed reload), not to the world.
        if server.policy_degraded().is_some() {
            banner.push_str("; policy reload is failing; last good policy in force");
        }
        // Same posture, same reason: the category is all this route says.
        if server.secrets_degraded().is_some() {
            banner.push_str("; secret refresh is failing; last good values in force");
        }
        // Forwarding is a copy of durable evidence; failing to make the
        // copy degrades, it does not stop serving (ADR-011).
        if server.forwarding_degraded().is_some() {
            banner.push_str("; audit forwarding is failing; journal retained");
        }
        // Rollups are the lossy pipeline: a failing store drops usage,
        // counted, and never touches a call.
        if server.rollups_degraded().is_some() {
            banner.push_str("; usage rollups are failing; usage may be dropped");
        }
        (StatusCode::OK, [content_type], banner).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [content_type],
            format!("mcp-server-devtools v{VERSION} is running but its audit journal is unavailable; tool calls are refused"),
        )
            .into_response()
    }
}

/// Reject requests whose `Origin` is not a loopback scheme/host pair.
///
/// Absent `Origin` header is allowed (non-browser clients). CORS preflight
/// (OPTIONS) is handled by the outer [`CorsLayer`] before this middleware
/// sees the request, but we also short-circuit OPTIONS here as belt-and-
/// suspenders in case the layer ordering is ever changed.
async fn origin_allowlist(req: Request, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }
    let Some(origin) = req.headers().get(header::ORIGIN) else {
        return next.run(req).await;
    };

    let Ok(origin_str) = origin.to_str() else {
        warn!("rejected request with invalid origin encoding");
        return forbidden("Forbidden: invalid origin");
    };

    if is_allowed_origin(origin_str) {
        next.run(req).await
    } else {
        warn!(origin = origin_str, "rejected request with invalid origin");
        forbidden("Forbidden: invalid origin")
    }
}

fn forbidden(msg: &'static str) -> Response {
    (
        StatusCode::FORBIDDEN,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        msg,
    )
        .into_response()
}

fn is_allowed_origin(origin: &str) -> bool {
    // Same shape as TS: scheme + loopback host, optionally followed by ':port'.
    const ALLOWED: &[&str] = &[
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "https://localhost",
        "https://127.0.0.1",
        "https://[::1]",
    ];
    ALLOWED
        .iter()
        .any(|allowed| origin == *allowed || origin.starts_with(&format!("{allowed}:")))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::{Body, to_bytes};
    use axum::extract::Path as AxumPath;
    use axum::http::{Request, StatusCode, header};

    use super::{download_artifact, is_allowed_origin};

    #[test]
    fn loopback_origins_allowed() {
        for origin in [
            "http://localhost",
            "http://localhost:3000",
            "http://127.0.0.1:8080",
            "https://[::1]:9000",
            "https://localhost",
        ] {
            assert!(is_allowed_origin(origin), "should allow {origin}");
        }
    }

    #[test]
    fn non_loopback_origins_rejected() {
        for origin in [
            "http://evil.com",
            "http://localhost.evil.com",
            "https://127.0.0.1.evil.com",
            "ftp://localhost",
            "",
        ] {
            assert!(!is_allowed_origin(origin), "should reject {origin}");
        }
    }

    #[tokio::test]
    async fn full_and_range_downloads_hold_generation_pins_through_expiration() {
        let path = crate::transport::raw_response::save_artifact(
            "pinned-http-download",
            "0123456789abcdef",
        )
        .await
        .unwrap();
        let artifact = crate::transport::raw_response::artifact_for_path(&path).unwrap();
        crate::transport::raw_response::set_committed_at(&artifact.id, Duration::ZERO);

        let full = download_artifact(
            AxumPath(artifact.id.clone()),
            Request::builder().body(Body::empty()).unwrap(),
        )
        .await;
        let range = download_artifact(
            AxumPath(artifact.id.clone()),
            Request::builder()
                .header(header::RANGE, "bytes=4-9")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let cancelled = download_artifact(
            AxumPath(artifact.id.clone()),
            Request::builder().body(Body::empty()).unwrap(),
        )
        .await;
        let ids = vec![artifact.id.clone()];
        crate::transport::raw_response::sweep_artifacts_at(
            &ids,
            Duration::from_secs(2),
            Duration::from_secs(1),
        )
        .await;

        let rejected = download_artifact(
            AxumPath(artifact.id.clone()),
            Request::builder().body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::NOT_FOUND);
        assert!(path.exists());
        drop(cancelled);
        assert!(path.exists(), "other active responses retain their pins");
        assert_eq!(
            to_bytes(range.into_body(), 16).await.unwrap().as_ref(),
            b"456789"
        );
        assert!(path.exists(), "full response still owns its read pin");
        assert_eq!(
            to_bytes(full.into_body(), 16).await.unwrap().as_ref(),
            b"0123456789abcdef"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

/// Resolve the HTTP bind address. `MCP_BIND_ADDR` accepts an IP
/// (`127.0.0.1`, `::1`, `0.0.0.0`) or an `ip:port` pair (`0.0.0.0:8443`,
/// `[::1]:8443`); a bare IP takes its port from `PORT`. Absent means the
/// historical loopback default. A value that parses as neither is an error —
/// the server must not fall back to a bind the operator did not ask for.
fn resolve_bind_addr(raw: Option<&str>, default_port: u16) -> Result<SocketAddr, String> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(SocketAddr::from(([127, 0, 0, 1], default_port)));
    };
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    Err(format!(
        "unrecognised MCP_BIND_ADDR {raw:?} (expected an IP address or ip:port pair)"
    ))
}

/// Fail-closed startup gate (`docs/enterprise-product-plan.md` §1.2 / §3.7).
///
/// - Auth off + non-loopback bind: refuse. The loopback bind *is* the
///   community trust boundary; removing it without inbound authentication
///   would expose every configured credential to the network.
/// - Auth okta: any bind is acceptable *here* — the bearer middleware is the
///   trust boundary — but the rest of the enterprise configuration (issuer,
///   audience, public URL, policy, journal) is checked next, in
///   [`enterprise_inbound_auth`], and any gap refuses startup.
fn validate_startup_security(auth_mode: AuthMode, addr: &SocketAddr) -> Result<(), String> {
    match auth_mode {
        AuthMode::Off if addr.ip().is_loopback() => Ok(()),
        AuthMode::Off => Err(format!(
            "refusing to start: MCP_BIND_ADDR={} is not a loopback address and \
             MCP_AUTH_MODE=off means no inbound authentication exists. Bind a loopback \
             address, or configure inbound authentication (fail-closed; see \
             docs/enterprise-product-plan.md §1.2)",
            addr.ip()
        )),
        AuthMode::Oidc(_) => Ok(()),
    }
}

#[cfg(test)]
mod startup_security_tests {
    use std::net::SocketAddr;

    use crate::config::AuthMode;

    use super::{resolve_bind_addr, validate_startup_security};

    #[test]
    fn role_parses_the_three_names_and_refuses_everything_else() {
        use super::Role;
        assert_eq!(Role::parse(None), Ok(Role::All));
        assert_eq!(Role::parse(Some("")), Ok(Role::All));
        assert_eq!(Role::parse(Some("Gateway")), Ok(Role::Gateway));
        assert_eq!(Role::parse(Some(" control ")), Ok(Role::Control));
        assert!(Role::parse(Some("both")).unwrap_err().contains("MCP_ROLE"));
        assert!(Role::All.serves_gateway());
        assert!(Role::Gateway.serves_gateway());
        assert!(!Role::Control.serves_gateway());
        assert!(Role::All.serves_control());
        assert!(Role::Control.serves_control());
        assert!(!Role::Gateway.serves_control());
    }

    #[test]
    fn bind_addr_defaults_to_loopback_with_the_port_env_port() {
        assert_eq!(
            resolve_bind_addr(None, 3000).unwrap(),
            "127.0.0.1:3000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_bind_addr(Some("  "), 8080).unwrap(),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn bind_addr_accepts_ip_and_ip_port_forms() {
        assert_eq!(
            resolve_bind_addr(Some("0.0.0.0"), 3000).unwrap(),
            "0.0.0.0:3000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_bind_addr(Some("0.0.0.0:8443"), 3000).unwrap(),
            "0.0.0.0:8443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_bind_addr(Some("::1"), 3000).unwrap(),
            "[::1]:3000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            resolve_bind_addr(Some("[::1]:9000"), 3000).unwrap(),
            "[::1]:9000".parse::<SocketAddr>().unwrap()
        );
        assert!(resolve_bind_addr(Some("localhost"), 3000).is_err());
    }

    #[test]
    fn loopback_with_auth_off_is_todays_behaviour() {
        for addr in ["127.0.0.1:3000", "[::1]:3000"] {
            let addr: SocketAddr = addr.parse().unwrap();
            assert_eq!(validate_startup_security(AuthMode::Off, &addr), Ok(()));
        }
    }

    #[test]
    fn non_loopback_bind_without_auth_is_refused_with_a_clear_reason() {
        for addr in ["0.0.0.0:3000", "192.168.1.10:8443", "[::]:3000"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let reason = validate_startup_security(AuthMode::Off, &addr).unwrap_err();
            assert!(reason.contains("refusing to start"), "{reason}");
            assert!(reason.contains("MCP_AUTH_MODE=off"), "{reason}");
            assert!(reason.contains("loopback"), "{reason}");
        }
    }

    /// With inbound auth on, the bind address is no longer the trust
    /// boundary, so a non-loopback bind is fine at this gate; the rest of
    /// the enterprise configuration is checked by `enterprise_inbound_auth`.
    #[test]
    fn okta_mode_accepts_any_bind_at_this_gate() {
        for addr in ["127.0.0.1:3000", "0.0.0.0:8443", "[::]:3000"] {
            let addr: SocketAddr = addr.parse().unwrap();
            assert_eq!(
                validate_startup_security(AuthMode::Oidc(crate::config::OidcKeys::Okta), &addr),
                Ok(())
            );
        }
    }
}

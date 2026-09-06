//! The administration console (plan §3.10.2, WP D.1; ADR-007, ADR-009,
//! ADR-013), behind the `console` Cargo feature.
//!
//! A client of the admin API, nothing more: every page is one call through
//! [`AdminClient`](crate::ports::AdminClient) rendered by a compile-time
//! template, so the API stays the only enforcement surface and never grows
//! an HTML endpoint. The administrator signs in at their identity provider
//! (authorization code + PKCE); the access token that comes back is held
//! server-side in a bounded in-memory session keyed by an opaque
//! `HttpOnly; Secure; SameSite=Strict` cookie and presented as the bearer
//! of every render. The console holds no authority of its own: a token the
//! API refuses (its own 401) ends the session.
//!
//! ## Browser-side controls
//!
//! - `Content-Security-Policy: default-src 'none'; script-src 'self';
//!   style-src 'self'; img-src 'self'; connect-src 'self'; form-action
//!   'self'; frame-ancestors 'none'; base-uri 'none'`, no inline script or
//!   style; `Referrer-Policy: same-origin`; `X-Content-Type-Options:
//!   nosniff`; `Cache-Control: no-store` on every page.
//! - Every non-GET request must carry an `Origin` equal to `MCP_PUBLIC_URL`'s
//!   origin (or, with no `Origin`, `Sec-Fetch-Site: same-origin`). The
//!   console is mounted outside the transport's loopback-only origin guard,
//!   which exists for unauthenticated local servers; this check is the
//!   console's own.
//! - One vendored script (`console/static/htmx.min.js`, `console/VENDORED.md`),
//!   embedded and digest-checked; no CDN, no inline handlers.
//!
//! ## Routes
//!
//! | Route | Purpose |
//! |---|---|
//! | `GET /console` | Sign-in page, or on to the policy page |
//! | `GET /console/login` | Redirect to the provider's authorization endpoint |
//! | `GET <MCP_CONSOLE_REDIRECT_PATH>` | The callback: state check, code exchange, session |
//! | `POST /console/logout` | Drop the session |
//! | `GET /console/{policy,activity,access-review,usage,sessions,artifacts,proposals,health}` | The read-only pages |
//! | `POST /console/policy/explain`, `POST /console/access-review` | Forms that call a read-only endpoint |
//! | `GET /console/static/{file}` | The embedded assets |

mod authoring;
mod login;
mod pages;
mod session;

pub use pages::{ActivityPage, ActivityQuery};
pub use session::{PendingLogin, PendingLogins, SessionStore};

use std::{borrow::Cow, sync::Arc, time::Duration};

use askama::Template;
use axum::{
    Router,
    body::Body,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use tracing::{info, warn};

use crate::{
    auth::oidc::{AuthorizationEndpoints, OidcSettings, Profile},
    config::Config,
    ports::{AdminClient, AdminMethod, AdminRequest, AdminResponse},
};

/// Config key: the client id the console was registered under at the
/// identity provider (a public client; PKCE, no secret). Setting it is
/// what mounts the console.
pub const CLIENT_ID_KEY: &str = "MCP_CONSOLE_CLIENT_ID";
/// Config key: the path the provider redirects back to. Default
/// [`DEFAULT_REDIRECT_PATH`]; the redirect URI is `MCP_PUBLIC_URL` + this.
pub const REDIRECT_PATH_KEY: &str = "MCP_CONSOLE_REDIRECT_PATH";
/// Config key: the `scope` the authorization request asks for. Default
/// [`DEFAULT_SCOPES`]; Entra needs the resource-prefixed form.
pub const SCOPES_KEY: &str = "MCP_CONSOLE_SCOPES";
pub const DEFAULT_REDIRECT_PATH: &str = "/console/callback";
pub const DEFAULT_SCOPES: &str = "openid mcp:admin";

const SESSION_COOKIE: &str = "mcp_console_session";
const LOGIN_COOKIE: &str = "mcp_console_login";
/// Bound on live browser sessions per process.
const SESSION_CAP: usize = 256;
/// Bound on logins in flight, and how long one may take.
const PENDING_CAP: usize = 256;
const PENDING_TTL: Duration = Duration::from_mins(5);

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
                   connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// What the console needs from configuration (all of it validated at
/// startup, none of it secret).
#[derive(Debug, Clone)]
pub struct ConsoleSettings {
    pub client_id: String,
    pub redirect_path: String,
    pub scopes: String,
    /// The issuer the bearer boundary validates, without a trailing slash.
    pub issuer: String,
    /// The audience it validates: what the console asks the provider for.
    pub audience: String,
    pub profile: Profile,
    /// `MCP_PUBLIC_URL`, without a trailing slash.
    pub public_url: String,
}

impl ConsoleSettings {
    /// Read the console's settings. `Ok(None)` when `MCP_CONSOLE_CLIENT_ID`
    /// is unset: the console is compiled in but not configured, and is not
    /// mounted.
    ///
    /// # Errors
    ///
    /// A redirect path that is not an absolute path without query or
    /// fragment, or an empty scope list — each a startup refusal.
    pub fn from_config(
        config: &Config,
        oidc: &OidcSettings,
        public_url: &str,
    ) -> Result<Option<Self>, String> {
        let Some(client_id) = config
            .get(CLIENT_ID_KEY)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let redirect_path = config
            .get(REDIRECT_PATH_KEY)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_REDIRECT_PATH);
        if !redirect_path.starts_with('/')
            || redirect_path.contains(['?', '#', '{', '}', '*'])
            || redirect_path.contains("//")
        {
            return Err(format!(
                "{REDIRECT_PATH_KEY}: expected an absolute path with no query or fragment (got {redirect_path:?})"
            ));
        }
        let scopes = config
            .get(SCOPES_KEY)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_SCOPES);
        Ok(Some(Self {
            client_id: client_id.to_owned(),
            redirect_path: redirect_path.to_owned(),
            scopes: scopes.to_owned(),
            issuer: oidc.issuer.clone(),
            audience: oidc.audience.clone(),
            profile: oidc.profile,
            public_url: public_url.trim_end_matches('/').to_owned(),
        }))
    }

    /// The redirect URI registered at the provider.
    #[must_use]
    pub fn redirect_uri(&self) -> String {
        format!("{}{}", self.public_url, self.redirect_path)
    }

    /// The origin a browser at the public URL sends: what every non-GET
    /// request's `Origin` must equal.
    #[must_use]
    pub fn origin(&self) -> String {
        url::Url::parse(&self.public_url).map_or_else(
            |_| self.public_url.clone(),
            |url| url.origin().ascii_serialization(),
        )
    }
}

/// The health banner as the console shows it: the same text the
/// unauthenticated route answers.
pub struct HealthBanner {
    pub ok: bool,
    pub text: String,
}

/// Everything the HTTP composition needs to mount the console: the
/// validated settings and the client that talks to the provider.
pub struct Mount {
    pub settings: ConsoleSettings,
    pub http: reqwest::Client,
}

/// The console's state, shared by every handler.
pub struct Console {
    settings: ConsoleSettings,
    origin: String,
    client: Arc<dyn AdminClient>,
    http: reqwest::Client,
    sessions: SessionStore,
    pending: PendingLogins,
    endpoints: tokio::sync::OnceCell<AuthorizationEndpoints>,
    health: Box<dyn Fn() -> HealthBanner + Send + Sync>,
}

/// A live session: the cookie's id and the bearer it names.
pub(crate) struct Session {
    id: String,
    token: String,
}

/// What the base template needs from every page.
pub(crate) struct Page {
    title: &'static str,
    active: &'static str,
    signed_in: bool,
}

impl Page {
    const fn signed_in(title: &'static str, active: &'static str) -> Self {
        Self {
            title,
            active,
            signed_in: true,
        }
    }
    const fn anonymous(title: &'static str) -> Self {
        Self {
            title,
            active: "",
            signed_in: false,
        }
    }
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    page: Page,
    reason: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "landing.html")]
struct LandingPage {
    page: Page,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage<'a> {
    page: Page,
    status: u16,
    title: &'a str,
    detail: &'a str,
}

#[derive(rust_embed::Embed)]
#[folder = "console/static/"]
struct Assets;

/// The embedded bytes of a static asset, as the binary serves them.
#[must_use]
pub fn asset(name: &str) -> Option<Cow<'static, [u8]>> {
    Assets::get(name).map(|file| file.data)
}

impl Console {
    /// Compose the console over `client` (the in-process adapter in
    /// production) with `health` answering as the banner route does.
    pub fn new(
        mount: Mount,
        client: Arc<dyn AdminClient>,
        health: impl Fn() -> HealthBanner + Send + Sync + 'static,
    ) -> Self {
        let origin = mount.settings.origin();
        Self {
            settings: mount.settings,
            origin,
            client,
            http: mount.http,
            sessions: SessionStore::new(SESSION_CAP),
            pending: PendingLogins::new(PENDING_CAP, PENDING_TTL),
            endpoints: tokio::sync::OnceCell::new(),
            health: Box::new(health),
        }
    }

    #[must_use]
    pub fn settings(&self) -> &ConsoleSettings {
        &self.settings
    }

    /// Live browser sessions.
    #[must_use]
    pub fn sessions(&self) -> &SessionStore {
        &self.sessions
    }

    /// The provider's endpoints, discovered on first use and kept. A
    /// failed discovery is not kept, so the next login tries again.
    async fn endpoints(&self) -> Result<&AuthorizationEndpoints, String> {
        self.endpoints
            .get_or_try_init(|| {
                crate::auth::oidc::discover_endpoints(&self.http, &self.settings.issuer)
            })
            .await
    }

    fn render<T: Template>(template: &T) -> Response {
        match template.render() {
            Ok(body) => html(StatusCode::OK, body),
            Err(error) => {
                warn!(%error, "console template failed to render");
                (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response()
            }
        }
    }

    fn error_page(status: StatusCode, title: &str, detail: &str, signed_in: bool) -> Response {
        let page = ErrorPage {
            page: Page {
                title: "Error",
                active: "",
                signed_in,
            },
            status: status.as_u16(),
            title,
            detail,
        };
        match page.render() {
            Ok(body) => html(status, body),
            Err(_) => (status, detail.to_owned()).into_response(),
        }
    }

    /// The session the request's cookie names, or the redirect to sign in.
    /// The `Err` is the response the handler returns as it is; boxing it
    /// would add an allocation to every redirect for a lint's sake.
    #[allow(clippy::result_large_err)]
    fn session(&self, headers: &HeaderMap) -> Result<Session, Response> {
        let id = cookie(headers, SESSION_COOKIE).ok_or_else(|| redirect("/console"))?;
        match self.sessions.token(id) {
            Some(token) => Ok(Session {
                id: id.to_owned(),
                token,
            }),
            None => Err(self.end_session(None, "/console?reason=expired")),
        }
    }

    /// Drop `id` (when given) and send the browser to `location` with the
    /// session cookie cleared. `HX-Redirect` rides along so an in-place
    /// refresh navigates instead of swapping the sign-in page into a
    /// section; it is set unconditionally, never on `HX-Request`.
    fn end_session(&self, id: Option<&str>, location: &'static str) -> Response {
        if let Some(id) = id {
            self.sessions.remove(id);
        }
        let mut response = redirect(location);
        let headers = response.headers_mut();
        headers.append(header::SET_COOKIE, clear_cookie(SESSION_COOKIE, "/console"));
        headers.insert("hx-redirect", HeaderValue::from_static(location));
        response
    }

    /// One admin call as the session's bearer. A 401 is the API saying the
    /// token is no longer good (expired, revoked): the session ends. Any
    /// other answer is the page's to render.
    async fn api(
        &self,
        session: &Session,
        request: AdminRequest<'_>,
    ) -> Result<AdminResponse, Response> {
        match self.client.call(&session.token, request).await {
            Ok(response) if response.status == 401 => {
                info!("console session ended: the admin API refused its bearer");
                Err(self.end_session(Some(&session.id), "/console?reason=ended"))
            }
            Ok(response) => Ok(response),
            Err(error) => Err(Self::error_page(
                StatusCode::BAD_GATEWAY,
                "Admin API unreachable",
                error.code(),
                true,
            )),
        }
    }
}

/// Build the console's router over shared state. Mount it **after** the
/// transport's origin guard and CORS layers: the console carries its own
/// origin check and must not reflect origins.
pub fn router(console: Arc<Console>) -> Router {
    let callback = console.settings.redirect_path.clone();
    Router::new()
        .route("/console", get(index))
        .route("/console/login", get(login))
        .route(&callback, get(callback_handler))
        .route("/console/logout", post(logout))
        .route("/console/policy", get(pages::policy))
        .route(
            "/console/policy/edit",
            get(authoring::edit).post(authoring::preview),
        )
        .route("/console/policy/download", post(authoring::download))
        .route("/console/policy/upload", post(authoring::upload))
        .route("/console/proposals/{id}", get(authoring::proposal))
        .route("/console/proposals/{id}/approve", post(authoring::approve))
        .route("/console/proposals/{id}/reject", post(authoring::reject))
        .route("/console/policy/explain", post(pages::explain))
        .route("/console/activity", get(pages::activity))
        .route(
            "/console/access-review",
            get(pages::access_review_form).post(pages::access_review),
        )
        .route("/console/usage", get(pages::usage))
        .route("/console/sessions", get(pages::sessions))
        .route("/console/artifacts", get(pages::artifacts))
        .route("/console/proposals", get(pages::proposals))
        .route("/console/health", get(pages::health))
        .route("/console/static/{file}", get(static_file))
        // `route_layer`, not `layer`: the middleware belongs to these routes
        // only. `layer` would also wrap the router's default fallback, and
        // once merged that fallback is the whole server's — every unknown
        // POST path would then answer the console's 403 instead of a 404.
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&console),
            same_origin,
        ))
        .route_layer(middleware::from_fn(security_headers))
        .with_state(console)
}

// ------------------------------------------------------------ middleware

/// Every non-GET request must come from the console's own origin.
async fn same_origin(
    State(console): State<Arc<Console>>,
    request: Request,
    next: Next,
) -> Response {
    if matches!(*request.method(), Method::GET | Method::HEAD) {
        return next.run(request).await;
    }
    let headers = request.headers();
    let allowed = match headers.get(header::ORIGIN).map(HeaderValue::to_str) {
        Some(Ok(origin)) => origin.eq_ignore_ascii_case(&console.origin),
        Some(Err(_)) => false,
        None => headers
            .get("sec-fetch-site")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|site| site.eq_ignore_ascii_case("same-origin")),
    };
    if allowed {
        next.run(request).await
    } else {
        warn!("console refused a cross-site request");
        (
            StatusCode::FORBIDDEN,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            )],
            "Forbidden: cross-site request",
        )
            .into_response()
    }
}

/// The headers every console response carries.
async fn security_headers(request: Request, next: Next) -> Response {
    let is_asset = request.uri().path().starts_with("/console/static/");
    let mut response = next.run(request).await;
    // Only a served asset is cacheable; a 404 under the prefix is not.
    let is_asset = is_asset && response.status() == StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    // Suppress cross-origin referrers while preserving Origin on native form
    // POSTs. no-referrer makes browsers send Origin: null, which our CSRF guard
    // correctly refuses.
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if is_asset {
            "private, max-age=86400"
        } else {
            "no-store"
        }),
    );
    response
}

// -------------------------------------------------------------- handlers

#[derive(Deserialize, Default)]
struct IndexQuery {
    #[serde(default)]
    reason: String,
}

async fn index(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Query(query): Query<IndexQuery>,
) -> Response {
    if console.session(&headers).is_ok() {
        return redirect("/console/policy");
    }
    let reason = match query.reason.as_str() {
        "expired" => Some("Your session expired; sign in again."),
        "ended" => Some("The admin API no longer accepts your token; sign in again."),
        "signed-out" => Some("Signed out."),
        _ => None,
    };
    Console::render(&LoginPage {
        page: Page::anonymous("Sign in"),
        reason,
    })
}

/// Start the flow: a fresh PKCE pair and state bound to a pre-session
/// cookie scoped to the callback path, then the redirect.
async fn login(State(console): State<Arc<Console>>) -> Response {
    let endpoints = match console.endpoints().await {
        Ok(endpoints) => endpoints,
        Err(error) => {
            warn!(%error, "console login: provider discovery failed");
            return Console::error_page(
                StatusCode::BAD_GATEWAY,
                "Identity provider unavailable",
                "The provider's discovery document could not be read; try again.",
                false,
            );
        }
    };
    let pkce = login::pkce();
    let state = session::random_id();
    let location = match login::authorize_url(endpoints, &console.settings, &state, &pkce.challenge)
    {
        Ok(location) => location,
        Err(error) => {
            warn!(%error, "console login: authorization endpoint unusable");
            return Console::error_page(
                StatusCode::BAD_GATEWAY,
                "Identity provider unavailable",
                "The provider advertised an unusable authorization endpoint.",
                false,
            );
        }
    };
    let id = console.pending.insert(PendingLogin {
        state,
        verifier: pkce.verifier,
    });
    let Ok(location) = HeaderValue::from_str(&location) else {
        return Console::error_page(
            StatusCode::BAD_GATEWAY,
            "Identity provider unavailable",
            "The authorization URL is not a valid header value.",
            false,
        );
    };
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    response.headers_mut().insert(header::LOCATION, location);
    response.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(
            LOGIN_COOKIE,
            &id,
            &console.settings.redirect_path,
            "Lax",
            PENDING_TTL.as_secs(),
        ),
    );
    response
}

#[derive(Deserialize, Default)]
struct Callback {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    error: String,
    /// RFC 9207 `iss`. Absent from many providers' responses, so its
    /// absence cannot be an error; present and wrong is.
    #[serde(default)]
    iss: String,
}

/// What must hold before a code is redeemed: the provider did not report an
/// error, the response belongs to the login this browser started, and — when
/// the provider sends one — the RFC 9207 `iss` names the configured issuer.
///
/// Pure, so the refusals are testable without a provider: the caller turns an
/// `Err` into the error page and clears the pre-session cookie.
fn check_authorization_response(
    query: &Callback,
    pending: &PendingLogin,
    issuer: &str,
) -> Result<(), (StatusCode, &'static str)> {
    if !query.error.is_empty() {
        warn!("console login: the identity provider returned an error");
        return Err((
            StatusCode::FORBIDDEN,
            "The identity provider did not authorize the sign-in.",
        ));
    }
    if query.state.is_empty() || query.state != pending.state {
        warn!("console login: state mismatch");
        return Err((
            StatusCode::FORBIDDEN,
            "The sign-in response does not match the one this browser started.",
        ));
    }
    // RFC 9207: bind the authorization response to the authorization server
    // recorded before the redirect, so a code minted elsewhere cannot be
    // redeemed here. One issuer is configured today, which is why a mix-up
    // attack does not apply; this keeps that true if a second one is added.
    // A provider that omits `iss` cannot be refused for omitting it — the
    // mitigation depends on honest servers emitting it, and many do not.
    if !query.iss.is_empty() && query.iss.trim_end_matches('/') != issuer.trim_end_matches('/') {
        warn!("console login: the response names an unexpected issuer");
        return Err((
            StatusCode::FORBIDDEN,
            "The sign-in response came from a different identity provider than the one configured.",
        ));
    }
    if query.code.is_empty() || query.code.len() > 4096 {
        return Err((
            StatusCode::BAD_REQUEST,
            "The sign-in response carries no code.",
        ));
    }
    Ok(())
}

/// The provider's redirect back: the login bound to the pre-session
/// cookie is consumed (once), `state` must match it, an RFC 9207 `iss` (if
/// the provider sent one) must name the configured issuer, the code is
/// redeemed with the verifier, and the token is proven against the admin API
/// before a session exists for it.
async fn callback_handler(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Query(query): Query<Callback>,
) -> Response {
    let refuse = |status: StatusCode, detail: &str| {
        let mut response = Console::error_page(status, "Sign-in refused", detail, false);
        response.headers_mut().append(
            header::SET_COOKIE,
            clear_cookie(LOGIN_COOKIE, &console.settings.redirect_path),
        );
        response
    };
    let Some(pending) = cookie(&headers, LOGIN_COOKIE).and_then(|id| console.pending.take(id))
    else {
        return refuse(
            StatusCode::FORBIDDEN,
            "No sign-in is in progress for this browser, or it took longer than five minutes. Start again.",
        );
    };
    if let Err((status, detail)) =
        check_authorization_response(&query, &pending, &console.settings.issuer)
    {
        return refuse(status, detail);
    }
    let Ok(endpoints) = console.endpoints().await else {
        return refuse(
            StatusCode::BAD_GATEWAY,
            "The identity provider's discovery document could not be read.",
        );
    };
    let exchanged = match login::exchange(
        &console.http,
        endpoints,
        &console.settings,
        &query.code,
        &pending.verifier,
    )
    .await
    {
        Ok(exchanged) => exchanged,
        Err(category) => {
            warn!(category, "console login: code exchange failed");
            return refuse(StatusCode::BAD_GATEWAY, category);
        }
    };
    // The API is the enforcement surface: a token it refuses gets no
    // session. One read, through the same client every page uses.
    let probe = console
        .client
        .call(
            &exchanged.access_token,
            AdminRequest {
                method: AdminMethod::Get,
                operation: "policy",
                body: None,
            },
        )
        .await;
    match probe {
        Ok(response) if response.is_success() || response.status == 503 => {}
        Ok(response) => {
            warn!(
                status = response.status,
                "console login: the admin API refused the token"
            );
            return refuse(
                StatusCode::FORBIDDEN,
                "The identity provider issued a token the admin API refuses: check that the console's client receives the audience and mcp:admin the runbook describes.",
            );
        }
        Err(error) => return refuse(StatusCode::BAD_GATEWAY, error.code()),
    }
    let ttl = exchanged.ttl;
    let id = console.sessions.insert(exchanged.access_token, ttl);
    info!(ttl_seconds = ttl.as_secs(), "console session started");
    let mut response = Console::render(&LandingPage {
        page: Page::anonymous("Signed in"),
    });
    let headers = response.headers_mut();
    headers.append(
        header::SET_COOKIE,
        set_cookie(SESSION_COOKIE, &id, "/console", "Strict", ttl.as_secs()),
    );
    headers.append(
        header::SET_COOKIE,
        clear_cookie(LOGIN_COOKIE, &console.settings.redirect_path),
    );
    response
}

async fn logout(State(console): State<Arc<Console>>, headers: HeaderMap) -> Response {
    console.end_session(
        cookie(&headers, SESSION_COOKIE),
        "/console?reason=signed-out",
    )
}

async fn static_file(Path(file): Path<String>) -> Response {
    let Some(asset) = Assets::get(&file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let content_type = match file.rsplit('.').next() {
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        _ => "application/octet-stream",
    };
    let body = match asset.data {
        Cow::Borrowed(bytes) => Body::from(bytes),
        Cow::Owned(bytes) => Body::from(bytes),
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))],
        body,
    )
        .into_response()
}

// --------------------------------------------------------------- helpers

fn html(status: StatusCode, body: String) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

fn redirect(location: &'static str) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(location));
    response
}

/// The value of cookie `name` in the request, if present.
fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name && !value.is_empty()).then_some(value)
        })
}

/// `HttpOnly; Secure; SameSite=<mode>; Path=<path>; Max-Age=<seconds>`.
/// Ids are base64url, so the value needs no quoting.
fn set_cookie(name: &str, value: &str, path: &str, same_site: &str, max_age: u64) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{name}={value}; HttpOnly; Secure; SameSite={same_site}; Path={path}; Max-Age={max_age}"
    ))
    .expect("cookie attributes are ASCII")
}

fn clear_cookie(name: &str, path: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{name}=; HttpOnly; Secure; SameSite=Strict; Path={path}; Max-Age=0"
    ))
    .expect("cookie attributes are ASCII")
}

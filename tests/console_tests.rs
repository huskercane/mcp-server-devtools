//! WP D.1: the administration console over real HTTP (plan §3.10.2,
//! ADR-013). A wiremock identity provider serves discovery and the token
//! endpoint; the server runs the real router with the console mounted;
//! reqwest follows nothing and carries cookies by hand, so every redirect,
//! cookie attribute, and header is asserted on the bytes the server sent.
#![cfg(feature = "console")]

use std::{collections::HashMap, sync::Arc, time::Duration};

use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, get_current_timestamp};
use mcp_server_devtools::{
    auth::oidc::{JwksLocation, OidcJwksValidator, OidcSettings, Profile},
    bootstrap::ServerBuilder,
    config::Config,
    console::{ConsoleSettings, Mount, PendingLogin, PendingLogins, SessionStore},
    policy::{
        Principal, PrincipalAuthority,
        signing::{Domain, SigningKey, write_detached},
    },
    ports::{InMemoryAuditSink, StaticValidator, TokenValidator},
    server::{
        auth::{InboundAuth, InboundAuthSettings},
        http::{Role, build_app_for_role_with_console},
    },
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// The bearer the static validator maps to an administrator: distinctive,
/// so a page that leaked it would be caught by a substring check.
const ADMIN_TOKEN: &str = "tok-9f3b7c1e-console-bearer-never-rendered";
const PUBLIC_URL: &str = "https://mcp.example";
const POLICY: &[u8] = b"version: 1\ndefault: deny\nrules:\n  - id: sre-read-qa-loki\n    effect: allow\n    subjects: { groups: [SRE] }\n    match:\n      vendor: grafana\n      environment: qa\n      request_risk: read\n      resource_type: datasource\n      resource_id: [loki-qa]\n";

struct Fixture {
    _dir: tempfile::TempDir,
    url: String,
    key: SigningKey,
    idp: MockServer,
    client: reqwest::Client,
    cancel: CancellationToken,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn principal(subject: &str, scopes: &[&str]) -> Principal {
    Principal {
        tenant: "tenant".into(),
        subject: subject.into(),
        groups: vec![],
        scopes: scopes.iter().map(|s| (*s).into()).collect(),
        authority: PrincipalAuthority::oidc("https://issuer.example"),
    }
}

fn static_validator() -> Arc<dyn TokenValidator> {
    Arc::new(
        StaticValidator::new()
            .with(ADMIN_TOKEN, principal("alice", &["mcp:admin"]))
            .with("tools", principal("alice", &["mcp:tools"])),
    )
}

/// A signed policy and revocation list on disk, the identity provider on
/// wiremock (discovery + token endpoint answering `token_response`), the
/// role served on loopback with the console mounted.
/// A signed policy and an empty signed revocation list in `dir`.
fn sign_files(
    dir: &std::path::Path,
) -> (
    SigningKey,
    std::path::PathBuf,
    Arc<mcp_server_devtools::auth::revocation::RevocationList>,
) {
    let policy = dir.join("policy.yaml");
    let (key, _) = SigningKey::generate().unwrap();
    std::fs::write(&policy, POLICY).unwrap();
    write_detached(&policy, &key.sign(Domain::PolicyBundle, POLICY)).unwrap();
    let revocation_path = dir.join("revocations.yaml");
    let revocation_bytes = b"version: 1\nsubjects: []\ntoken_ids: []\n";
    std::fs::write(&revocation_path, revocation_bytes).unwrap();
    write_detached(
        &revocation_path,
        &key.sign(Domain::RevocationList, revocation_bytes),
    )
    .unwrap();
    let revocations = mcp_server_devtools::auth::revocation::RevocationList::load_verified(
        &revocation_path,
        key.verifying_key(),
    )
    .unwrap();
    (key, policy, revocations)
}

/// Discovery and the token endpoint on `idp`, answering `token_response`.
async fn mount_provider(idp: &MockServer, token_response: Value) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": idp.uri(),
            "jwks_uri": format!("{}/keys", idp.uri()),
            "authorization_endpoint": format!("{}/authorize", idp.uri()),
            "token_endpoint": format!("{}/token", idp.uri()),
        })))
        .mount(idp)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_response))
        .mount(idp)
        .await;
}

/// A signed policy and revocation list on disk, the identity provider on
/// wiremock (discovery + token endpoint answering `token_response`), the
/// role served on loopback with the console mounted.
async fn fixture_with(
    role: Role,
    validator: Arc<dyn TokenValidator>,
    token_response: Value,
    journal: bool,
    provider: Option<MockServer>,
) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (key, policy, revocations) = sign_files(dir.path());
    let idp = match provider {
        Some(idp) => idp,
        None => MockServer::start().await,
    };
    mount_provider(&idp, token_response).await;
    let mut map = HashMap::from([
        ("MCP_POLICY_FILE".to_owned(), policy.display().to_string()),
        (
            "MCP_POLICY_PUBLIC_KEY".to_owned(),
            key.verifying_key().to_base64(),
        ),
    ]);
    if journal {
        map.insert(
            "MCP_AUDIT_JOURNAL_DIR".to_owned(),
            dir.path().display().to_string(),
        );
        map.insert(
            "MCP_ROLLUP_STORE".to_owned(),
            format!("sqlite://{}", dir.path().join("rollups.sqlite").display()),
        );
    } else {
        map.insert("MCP_ROLLUP_STORE".to_owned(), "memory://".to_owned());
    }
    let mut builder = ServerBuilder::new()
        .config(Config::from_map(map))
        .serves_control(true);
    if !journal {
        builder = builder.audit_sink(Arc::new(InMemoryAuditSink::new()));
    }
    let server = builder.build().unwrap();
    if journal {
        server.journal_startup().await.unwrap();
    }
    let auth = Arc::new(
        InboundAuth::new(
            validator,
            InboundAuthSettings {
                public_url: PUBLIC_URL.into(),
                authorization_servers: vec![idp.uri()],
                required_scope: "mcp:tools".into(),
            },
        )
        .with_revocations(revocations),
    );
    let settings = ConsoleSettings {
        client_id: "console-client".into(),
        redirect_path: "/console/callback".into(),
        scopes: "openid mcp:admin".into(),
        issuer: idp.uri(),
        audience: PUBLIC_URL.into(),
        profile: Profile::Generic,
        public_url: PUBLIC_URL.into(),
    };
    let cancel = CancellationToken::new();
    let app = build_app_for_role_with_console(
        role,
        server,
        Some(auth),
        Some(Mount {
            settings,
            http: reqwest::Client::new(),
        }),
        Duration::from_mins(10),
        Duration::from_mins(10),
        cancel.clone(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let stop = cancel.clone();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(stop.cancelled_owned())
            .await
            .unwrap();
    });
    Fixture {
        _dir: dir,
        url,
        key,
        idp,
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        cancel,
    }
}

async fn fixture(role: Role) -> Fixture {
    fixture_with(
        role,
        static_validator(),
        json!({"access_token": ADMIN_TOKEN, "token_type": "Bearer", "expires_in": 300}),
        false,
        None,
    )
    .await
}

/// The `Set-Cookie` line for `name`, if the response set it.
fn set_cookie(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|line| line.starts_with(&format!("{name}=")))
        .map(str::to_owned)
}

/// `name=value` from a `Set-Cookie` line.
fn cookie_pair(line: &str) -> String {
    line.split(';').next().unwrap().trim().to_owned()
}

fn query_param(url: &url::Url, name: &str) -> String {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

/// Start the flow and complete the callback: the session cookie pair.
async fn sign_in(f: &Fixture) -> String {
    let start = f
        .client
        .get(format!("{}/console/login", f.url))
        .send()
        .await
        .unwrap();
    assert_eq!(start.status(), 303);
    let location = url::Url::parse(start.headers()["location"].to_str().unwrap()).unwrap();
    let login_cookie = cookie_pair(&set_cookie(&start, "mcp_console_login").unwrap());
    let state = query_param(&location, "state");
    let callback = f
        .client
        .get(format!(
            "{}/console/callback?code=authcode-1&state={state}",
            f.url
        ))
        .header("cookie", &login_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(callback.status(), 200, "{}", callback.text().await.unwrap());
    cookie_pair(&set_cookie(&callback, "mcp_console_session").unwrap())
}

async fn page(f: &Fixture, session: &str, route: &str) -> reqwest::Response {
    f.client
        .get(format!("{}{route}", f.url))
        .header("cookie", session)
        .send()
        .await
        .unwrap()
}

#[test]
fn htmx_is_vendored_at_the_recorded_digest_and_has_no_eval_path() {
    let record = include_str!("../console/VENDORED.md");
    let recorded = record
        .lines()
        .find(|line| line.contains("`static/htmx.min.js`"))
        .and_then(|line| line.split('`').rfind(|cell| cell.len() == 64))
        .expect("VENDORED.md records the htmx digest");
    let bytes = mcp_server_devtools::console::asset("htmx.min.js").expect("htmx is embedded");
    let digest = Sha256::digest(&bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        });
    assert_eq!(
        digest, recorded,
        "console/static/htmx.min.js changed without re-recording"
    );
    let source = std::str::from_utf8(&bytes).unwrap();
    for forbidden in ["eval(", "Function(", "localStorage", "sessionStorage"] {
        assert!(
            !source.contains(forbidden),
            "htmx build contains {forbidden}"
        );
    }
    assert!(
        source.contains("htmx-config"),
        "htmx reads its meta configuration"
    );
    assert!(mcp_server_devtools::console::asset("console.css").is_some());
    assert!(mcp_server_devtools::console::asset("../Cargo.toml").is_none());
}

#[test]
fn session_stores_are_bounded_and_expiring() {
    let sessions = SessionStore::new(4);
    let ids: Vec<String> = (0..4)
        .map(|n| sessions.insert(format!("token-{n}"), Duration::from_mins(5)))
        .collect();
    assert_eq!(sessions.len(), 4);
    assert_eq!(sessions.token(&ids[0]).as_deref(), Some("token-0"));
    // Past the cap with nothing expired, the entry nearest expiry goes.
    let short = sessions.insert("short".into(), Duration::from_secs(1));
    assert_eq!(sessions.len(), 4);
    let sixth = sessions.insert("sixth".into(), Duration::from_mins(5));
    assert_eq!(sessions.len(), 4);
    assert!(
        sessions.token(&short).is_none(),
        "the soonest-expiring entry was evicted"
    );
    assert_eq!(sessions.token(&sixth).as_deref(), Some("sixth"));
    assert!(sessions.remove(&sixth));
    assert!(!sessions.remove(&sixth));
    // An expired entry reads as absent.
    let expiring = sessions.insert("expiring".into(), Duration::from_millis(10));
    std::thread::sleep(Duration::from_millis(30));
    assert!(sessions.token(&expiring).is_none());
    // Ids are 256-bit base64url.
    assert_eq!(ids[0].len(), 43);
    assert!(
        ids[0]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );

    let pending = PendingLogins::new(2, Duration::from_mins(5));
    let login = |n: u8| PendingLogin {
        state: format!("state-{n}"),
        nonce: format!("nonce-{n}"),
        verifier: format!("verifier-{n}"),
    };
    let first = pending.insert(login(1));
    let _second = pending.insert(login(2));
    let _third = pending.insert(login(3));
    assert_eq!(pending.len(), 2);
    assert!(pending.take(&first).is_none(), "evicted past the cap");
    let fourth = pending.insert(login(4));
    assert_eq!(pending.take(&fourth).unwrap().state, "state-4");
    assert!(pending.take(&fourth).is_none(), "a login is consumed once");
}

#[test]
fn console_settings_are_read_and_validated() {
    let oidc = OidcSettings::new(
        Profile::Keycloak,
        "https://login.example/realms/acme/",
        "https://mcp.example",
        JwksLocation::Direct("https://login.example/keys".into()),
    );
    let config = |pairs: &[(&str, &str)]| {
        Config::from_map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    };
    assert!(
        ConsoleSettings::from_config(&config(&[]), &oidc, "https://mcp.example/")
            .unwrap()
            .is_none(),
        "no client id: not mounted"
    );
    let settings = ConsoleSettings::from_config(
        &config(&[("MCP_CONSOLE_CLIENT_ID", "console")]),
        &oidc,
        "https://mcp.example/",
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        settings.redirect_uri(),
        "https://mcp.example/console/callback"
    );
    assert_eq!(settings.scopes, "openid mcp:admin");
    assert_eq!(settings.issuer, "https://login.example/realms/acme");
    assert_eq!(settings.origin(), "https://mcp.example");
    assert_eq!(settings.profile, Profile::Keycloak);
    let custom = ConsoleSettings::from_config(
        &config(&[
            ("MCP_CONSOLE_CLIENT_ID", "console"),
            ("MCP_CONSOLE_REDIRECT_PATH", "/admin-ui/oidc"),
            ("MCP_CONSOLE_SCOPES", "api://mcp/mcp:admin openid"),
        ]),
        &oidc,
        "https://mcp.example:8443",
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        custom.redirect_uri(),
        "https://mcp.example:8443/admin-ui/oidc"
    );
    assert_eq!(custom.scopes, "api://mcp/mcp:admin openid");
    assert_eq!(custom.origin(), "https://mcp.example:8443");
    for bad in ["callback", "/cb?x=1", "/cb#f", "/{id}", "//cb"] {
        let error = ConsoleSettings::from_config(
            &config(&[
                ("MCP_CONSOLE_CLIENT_ID", "console"),
                ("MCP_CONSOLE_REDIRECT_PATH", bad),
            ]),
            &oidc,
            "https://mcp.example",
        )
        .unwrap_err();
        assert!(
            error.contains("MCP_CONSOLE_REDIRECT_PATH"),
            "{bad}: {error}"
        );
    }
}

#[tokio::test]
async fn login_redirects_with_pkce_and_binds_state_to_the_pre_session_cookie() {
    let f = fixture(Role::All).await;
    let start = f
        .client
        .get(format!("{}/console/login", f.url))
        .send()
        .await
        .unwrap();
    assert_eq!(start.status(), 303);
    let location = url::Url::parse(start.headers()["location"].to_str().unwrap()).unwrap();
    assert_eq!(
        format!(
            "{}://{}:{}{}",
            location.scheme(),
            location.host_str().unwrap(),
            location.port().unwrap(),
            location.path()
        ),
        format!("{}/authorize", f.idp.uri())
    );
    assert_eq!(query_param(&location, "response_type"), "code");
    assert_eq!(query_param(&location, "client_id"), "console-client");
    assert_eq!(
        query_param(&location, "redirect_uri"),
        "https://mcp.example/console/callback"
    );
    assert_eq!(query_param(&location, "scope"), "openid mcp:admin");
    assert_eq!(query_param(&location, "code_challenge_method"), "S256");
    assert_eq!(query_param(&location, "resource"), PUBLIC_URL);
    let state = query_param(&location, "state");
    let challenge = query_param(&location, "code_challenge");
    assert_eq!(state.len(), 43);
    assert_eq!(query_param(&location, "nonce").len(), 43);
    assert_eq!(challenge.len(), 43);
    let login_line = set_cookie(&start, "mcp_console_login").unwrap();
    for attribute in [
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Path=/console/callback",
        "Max-Age=300",
    ] {
        assert!(login_line.contains(attribute), "{login_line}");
    }
    let login_cookie = cookie_pair(&login_line);

    // The wrong state is refused; the login is consumed by the attempt.
    let wrong = f
        .client
        .get(format!(
            "{}/console/callback?code=authcode-1&state=not-the-state",
            f.url
        ))
        .header("cookie", &login_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 403);
    assert!(set_cookie(&wrong, "mcp_console_session").is_none());
    assert!(
        set_cookie(&wrong, "mcp_console_login")
            .unwrap()
            .contains("Max-Age=0")
    );
    let reused = f
        .client
        .get(format!(
            "{}/console/callback?code=authcode-1&state={state}",
            f.url
        ))
        .header("cookie", &login_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(reused.status(), 403, "a consumed login cannot be replayed");
    assert!(
        f.idp
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.url.path() != "/token")
    );
}

#[tokio::test]
async fn callback_redeems_the_code_with_the_verifier_and_starts_a_strict_session() {
    let f = fixture(Role::All).await;
    // A fresh start, completed: the verifier redeems the code.
    let start = f
        .client
        .get(format!("{}/console/login", f.url))
        .send()
        .await
        .unwrap();
    let location = url::Url::parse(start.headers()["location"].to_str().unwrap()).unwrap();
    let state = query_param(&location, "state");
    let challenge = query_param(&location, "code_challenge");
    let login_cookie = cookie_pair(&set_cookie(&start, "mcp_console_login").unwrap());
    let callback = f
        .client
        .get(format!(
            "{}/console/callback?code=authcode-1&state={state}",
            f.url
        ))
        .header("cookie", &login_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(callback.status(), 200);
    let session_line = set_cookie(&callback, "mcp_console_session").unwrap();
    for attribute in [
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        "Path=/console",
        "Max-Age=300",
    ] {
        assert!(session_line.contains(attribute), "{session_line}");
    }
    assert!(
        set_cookie(&callback, "mcp_console_login")
            .unwrap()
            .contains("Max-Age=0")
    );
    let body = callback.text().await.unwrap();
    assert!(body.contains("Signed in"));
    assert!(body.contains("url=/console/policy"));
    assert!(!body.contains(ADMIN_TOKEN));
    let exchange = f
        .idp
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.url.path() == "/token")
        .expect("the code was redeemed");
    let form: HashMap<String, String> = url::form_urlencoded::parse(&exchange.body)
        .into_owned()
        .collect();
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["code"], "authcode-1");
    assert_eq!(form["client_id"], "console-client");
    assert_eq!(form["redirect_uri"], "https://mcp.example/console/callback");
    assert_eq!(form["resource"], PUBLIC_URL);
    let verifier_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(form["code_verifier"].as_bytes()));
    assert_eq!(
        verifier_challenge, challenge,
        "S256 of the verifier is the challenge sent"
    );
    assert!(!form.contains_key("client_secret"));

    // No login in progress at all: refused, nothing exchanged.
    let cold = f
        .client
        .get(format!("{}/console/callback?code=x&state=y", f.url))
        .send()
        .await
        .unwrap();
    assert_eq!(cold.status(), 403);
}

#[tokio::test]
async fn a_token_the_admin_api_refuses_gets_no_session() {
    let f = fixture_with(
        Role::All,
        static_validator(),
        json!({"access_token": "tools", "token_type": "Bearer", "expires_in": 300}),
        false,
        None,
    )
    .await;
    let start = f
        .client
        .get(format!("{}/console/login", f.url))
        .send()
        .await
        .unwrap();
    let location = url::Url::parse(start.headers()["location"].to_str().unwrap()).unwrap();
    let state = query_param(&location, "state");
    let login_cookie = cookie_pair(&set_cookie(&start, "mcp_console_login").unwrap());
    let callback = f
        .client
        .get(format!("{}/console/callback?code=c&state={state}", f.url))
        .header("cookie", &login_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(callback.status(), 403);
    assert!(set_cookie(&callback, "mcp_console_session").is_none());
    assert!(callback.text().await.unwrap().contains("mcp:admin"));
}

#[tokio::test]
async fn every_route_carries_the_security_headers() {
    let f = fixture(Role::All).await;
    let session = sign_in(&f).await;
    let csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
    let assert_headers = |route: &str, response: &reqwest::Response, cache: &str| {
        let headers = response.headers();
        assert_eq!(headers["content-security-policy"], csp, "{route}");
        assert_eq!(headers["referrer-policy"], "no-referrer", "{route}");
        assert_eq!(headers["x-content-type-options"], "nosniff", "{route}");
        assert_eq!(headers["x-frame-options"], "DENY", "{route}");
        assert_eq!(headers["cache-control"], cache, "{route}");
        assert!(
            headers.get("access-control-allow-origin").is_none(),
            "{route}: the console never reflects an origin"
        );
    };
    for route in [
        "/console",
        "/console?reason=expired",
        "/console/login",
        "/console/callback?code=x&state=y",
        "/console/policy",
        "/console/activity",
        "/console/activity?since=2026-01-01T00:00:00Z",
        "/console/access-review",
        "/console/usage",
        "/console/usage?report=timeline&bucket=hour",
        "/console/sessions",
        "/console/artifacts",
        "/console/proposals",
        "/console/health",
        "/console/static/missing.js",
    ] {
        let response = page(&f, &session, route).await;
        assert_headers(route, &response, "no-store");
        let response = f
            .client
            .get(format!("{}{route}", f.url))
            .send()
            .await
            .unwrap();
        assert_headers(route, &response, "no-store");
    }
    for route in ["/console/static/htmx.min.js", "/console/static/console.css"] {
        let response = page(&f, &session, route).await;
        assert_eq!(response.status(), 200);
        assert_headers(route, &response, "private, max-age=86400");
    }
    for (route, form) in [
        ("/console/logout", vec![]),
        (
            "/console/policy/explain",
            vec![("tool", "grafana_query_logs")],
        ),
        (
            "/console/access-review",
            vec![("tenant", "tenant"), ("groups", "{}")],
        ),
    ] {
        for origin in [Some("https://evil.example"), Some(PUBLIC_URL), None] {
            let mut request = f
                .client
                .post(format!("{}{route}", f.url))
                .header("cookie", &session)
                .form(&form);
            if let Some(origin) = origin {
                request = request.header("origin", origin);
            }
            let response = request.send().await.unwrap();
            assert_headers(route, &response, "no-store");
        }
    }
    // The page markup itself carries no inline script or style, and loads
    // exactly the embedded assets. (The logout above ended the session.)
    let session = sign_in(&f).await;
    let html = page(&f, &session, "/console/policy")
        .await
        .text()
        .await
        .unwrap();
    assert!(
        html.contains(r#"<script src="/console/static/htmx.min.js" defer></script>"#),
        "{html}"
    );
    assert!(html.contains(r#"<link rel="stylesheet" href="/console/static/console.css">"#));
    assert!(html.contains(
        r#"<meta name="htmx-config" content='{"includeIndicatorCSS":false,"history":false}'>"#
    ));
    assert!(!html.contains("<style"));
    assert!(!html.contains(" style="));
    assert!(!html.contains("onclick"));
    assert!(!html.contains("hx-on"));
    assert_eq!(html.matches("<script").count(), 1);
}

#[tokio::test]
async fn non_get_requests_need_the_public_origin() {
    let f = fixture(Role::All).await;
    let session = sign_in(&f).await;
    let post = |origin: Option<&str>, fetch_site: Option<&str>| {
        let mut request = f
            .client
            .post(format!("{}/console/policy/explain", f.url))
            .header("cookie", &session)
            .form(&[("tool", "grafana_query_logs")]);
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        if let Some(site) = fetch_site {
            request = request.header("sec-fetch-site", site);
        }
        async move { request.send().await.unwrap() }
    };
    for (origin, site) in [
        (None, None),
        (None, Some("cross-site")),
        (None, Some("same-site")),
        (None, Some("none")),
        (Some("https://evil.example"), None),
        (Some("https://evil.example"), Some("same-origin")),
        (Some("null"), None),
        (Some("https://mcp.example.evil"), None),
        (Some("http://mcp.example"), None),
    ] {
        let response = post(origin, site).await;
        assert_eq!(response.status(), 403, "{origin:?} {site:?}");
        assert_eq!(
            response.text().await.unwrap(),
            "Forbidden: cross-site request"
        );
    }
    for (origin, site) in [
        (Some(PUBLIC_URL), None),
        (Some("HTTPS://MCP.EXAMPLE"), Some("cross-site")),
        (None, Some("same-origin")),
    ] {
        let response = post(origin, site).await;
        assert_eq!(response.status(), 200, "{origin:?} {site:?}");
    }
    // The same guard on logout: a cross-site POST cannot end a session.
    let response = f
        .client
        .post(format!("{}/console/logout", f.url))
        .header("cookie", &session)
        .header("origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(page(&f, &session, "/console/policy").await.status(), 200);
    let response = f
        .client
        .post(format!("{}/console/logout", f.url))
        .header("cookie", &session)
        .header("origin", PUBLIC_URL)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 303);
    assert_eq!(response.headers()["location"], "/console?reason=signed-out");
    assert_eq!(
        response.headers()["hx-redirect"],
        "/console?reason=signed-out"
    );
    assert!(
        set_cookie(&response, "mcp_console_session")
            .unwrap()
            .contains("Max-Age=0")
    );
    let after = page(&f, &session, "/console/policy").await;
    assert_eq!(after.status(), 303);
    assert_eq!(after.headers()["location"], "/console?reason=expired");
}

#[tokio::test]
async fn pages_render_the_api_answers_and_never_the_token() {
    let f = fixture(Role::All).await;
    // Anonymous: the sign-in page, and every page redirects to it.
    let index = f
        .client
        .get(format!("{}/console", f.url))
        .send()
        .await
        .unwrap();
    assert_eq!(index.status(), 200);
    let html = index.text().await.unwrap();
    assert!(html.contains("Sign in with your identity provider"));
    assert!(html.contains(r#"href="/console/login""#));
    assert!(!html.contains("Sign out"));
    for route in ["/console/policy", "/console/activity", "/console/health"] {
        let response = f
            .client
            .get(format!("{}{route}", f.url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 303, "{route}");
        assert_eq!(response.headers()["location"], "/console");
    }
    let session = sign_in(&f).await;
    let index = page(&f, &session, "/console").await;
    assert_eq!(index.status(), 303);
    assert_eq!(index.headers()["location"], "/console/policy");

    // Policy: the document, its version, the explain form.
    let policy = page(&f, &session, "/console/policy").await;
    assert_eq!(policy.status(), 200);
    assert_eq!(policy.headers()["content-type"], "text/html; charset=utf-8");
    let html = policy.text().await.unwrap();
    assert!(html.contains("sre-read-qa-loki"));
    assert!(html.contains("Policy in force"));
    assert!(html.contains(r#"aria-current="page">Policy"#));
    assert!(html.contains("Sign out"));
    assert!(!html.contains(ADMIN_TOKEN));

    // Explain: the API's decision in the CLI's words, escaped.
    let explain = f
        .client
        .post(format!("{}/console/policy/explain", f.url))
        .header("cookie", &session)
        .header("origin", PUBLIC_URL)
        .form(&[
            ("tool", "grafana_query_logs"),
            (
                "arguments",
                r#"{"datasourceUid":"loki-qa","query":"{app=\"<b>\"}","limit":10}"#,
            ),
            ("groups", "SRE"),
            ("environment", "qa"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(explain.status(), 200);
    let html = explain.text().await.unwrap();
    assert!(
        html.contains(r#"<span class="verdict allow">ALLOW</span>"#),
        "{html}"
    );
    assert!(html.contains("<code>sre-read-qa-loki</code> (allow) — decisive"));
    assert!(html.contains("environment=qa"));
    assert!(html.contains("configuration says unclassified"));
    assert!(html.contains("subject=someone@example"));
    assert!(
        html.contains("&#60;b&#62;") || html.contains("&lt;b&gt;"),
        "arguments are escaped: {html}"
    );
    assert!(!html.contains("<b>"));
    let denied = f
        .client
        .post(format!("{}/console/policy/explain", f.url))
        .header("cookie", &session)
        .header("origin", PUBLIC_URL)
        .form(&[("tool", "grafana_query_logs"), ("arguments", "{}")])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(denied.contains(r#"<span class="verdict deny">DENY</span>"#));
    assert!(denied.contains("fails on `"));
    let bad = f
        .client
        .post(format!("{}/console/policy/explain", f.url))
        .header("cookie", &session)
        .header("origin", PUBLIC_URL)
        .form(&[("tool", "no_such_tool"), ("arguments", "[1]")])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(bad.contains("Arguments must be a JSON object."));
}

#[tokio::test]
async fn report_and_inventory_pages_render_honestly() {
    let f = fixture(Role::All).await;
    let session = sign_in(&f).await;
    // Activity without a journal: the backend's refusal, rendered honestly.
    let activity = page(&f, &session, "/console/activity")
        .await
        .text()
        .await
        .unwrap();
    assert!(activity.contains("admin_backend_unavailable"));
    let invalid = page(&f, &session, "/console/activity?since=yesterday")
        .await
        .text()
        .await
        .unwrap();
    assert!(invalid.contains("admin_backend_unavailable") || invalid.contains("RFC 3339"));

    // Access review: the SRE rule's row.
    let review = f
        .client
        .post(format!("{}/console/access-review", f.url))
        .header("cookie", &session)
        .header("origin", PUBLIC_URL)
        .form(&[
            ("tenant", "tenant"),
            ("groups", r#"{"SRE":["alice@example"]}"#),
        ])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(review.contains("alice@example"), "{review}");
    assert!(review.contains("<code>sre-read-qa-loki</code>"));
    assert!(review.contains("vendor=grafana"));
    let malformed = f
        .client
        .post(format!("{}/console/access-review", f.url))
        .header("cookie", &session)
        .header("origin", PUBLIC_URL)
        .form(&[("tenant", "tenant"), ("groups", "not json")])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(malformed.contains("not a JSON object"));

    // Usage over the in-memory store: totals, a grouping, a timeline.
    let usage = page(&f, &session, "/console/usage")
        .await
        .text()
        .await
        .unwrap();
    assert!(usage.contains("<dt>Rows</dt><dd>0</dd>"), "{usage}");
    let by_vendor = page(&f, &session, "/console/usage?report=by_vendor")
        .await
        .text()
        .await
        .unwrap();
    assert!(by_vendor.contains(r#"<option value="by_vendor" selected>"#));
    let timeline = page(&f, &session, "/console/usage?report=timeline&bucket=hour")
        .await
        .text()
        .await
        .unwrap();
    assert!(timeline.contains(r#"<option value="hour" selected>"#));
    assert!(timeline.contains("<th>Bucket</th>"));

    // Sessions and artifacts: scope:process, from the co-located process.
    let sessions = page(&f, &session, "/console/sessions")
        .await
        .text()
        .await
        .unwrap();
    assert!(sessions.contains("Scope: <code>process</code>"));
    let artifacts = page(&f, &session, "/console/artifacts")
        .await
        .text()
        .await
        .unwrap();
    assert!(artifacts.contains("<th>Content type</th>"));

    // Proposals with approvals off: said so, no rows.
    let proposals = page(&f, &session, "/console/proposals")
        .await
        .text()
        .await
        .unwrap();
    assert!(proposals.contains("Two-person approval is off"));
    assert!(proposals.contains(r#"hx-trigger="every 30s""#));

    // Health: the banner the public route answers.
    let health = page(&f, &session, "/console/health")
        .await
        .text()
        .await
        .unwrap();
    assert!(html_contains_banner(&health));

    // Nothing rendered so far carried the bearer.
    for text in [
        &activity, &review, &usage, &sessions, &artifacts, &proposals, &health,
    ] {
        assert!(!text.contains(ADMIN_TOKEN));
    }
}

fn html_contains_banner(html: &str) -> bool {
    html.contains("mcp-server-devtools v") && html.contains("is running")
}

#[tokio::test]
async fn activity_page_renders_journal_rows_and_the_stopped_banner_shape() {
    let f = fixture_with(
        Role::All,
        static_validator(),
        json!({"access_token": ADMIN_TOKEN, "token_type": "Bearer", "expires_in": 300}),
        true,
        None,
    )
    .await;
    let session = sign_in(&f).await;
    // The projection ingests the startup records in the background.
    let html = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let html = page(&f, &session, "/console/activity")
                .await
                .text()
                .await
                .unwrap();
            if html.contains("policy_loaded") {
                break html;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the activity page shows journal rows once the projection catches up");
    assert!(html.contains("<td>policy_loaded</td>"), "{html}");
    assert!(html.contains("records read"));
    assert!(!html.contains("Incomplete: the report stopped"));
    let filtered = page(&f, &session, "/console/activity?vendor=nope")
        .await
        .text()
        .await
        .unwrap();
    assert!(filtered.contains("0 rows shown"), "{filtered}");
    assert!(filtered.contains(r#"value="nope""#));
}

#[tokio::test]
async fn an_api_401_ends_the_session() {
    let f = fixture(Role::All).await;
    let session = sign_in(&f).await;
    assert_eq!(page(&f, &session, "/console/policy").await.status(), 200);
    // Revoke the administrator through the API itself: the deny-list
    // replacement the runbook describes, signed with the policy key.
    let document = "version: 2\nsubjects:\n- subject: alice\n  revoked_at: 2026-09-05T00:00:00Z\ntoken_ids: []\n";
    let response = reqwest::Client::new()
        .put(format!("{}/admin/deny-list", f.url))
        .bearer_auth(ADMIN_TOKEN)
        .json(&json!({"document": document, "signature": f.key.sign(Domain::RevocationList, document.as_bytes()).to_base64()}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let ended = page(&f, &session, "/console/policy").await;
    assert_eq!(ended.status(), 303);
    assert_eq!(ended.headers()["location"], "/console?reason=ended");
    assert_eq!(ended.headers()["hx-redirect"], "/console?reason=ended");
    assert!(
        set_cookie(&ended, "mcp_console_session")
            .unwrap()
            .contains("Max-Age=0")
    );
    // The session is gone server-side too: the cookie now finds nothing.
    let again = page(&f, &session, "/console/policy").await;
    assert_eq!(again.headers()["location"], "/console?reason=expired");
    let login = f
        .client
        .get(format!("{}/console?reason=ended", f.url))
        .send()
        .await
        .unwrap();
    assert!(
        login
            .text()
            .await
            .unwrap()
            .contains("no longer accepts your token")
    );
}

#[tokio::test]
async fn control_role_renders_process_scope_unavailability_honestly() {
    let f = fixture(Role::Control).await;
    let session = sign_in(&f).await;
    for route in ["/console/sessions", "/console/artifacts"] {
        let html = page(&f, &session, route).await.text().await.unwrap();
        assert!(
            html.contains("admin_backend_unavailable"),
            "{route}: {html}"
        );
        assert!(html.contains("co-located"), "{route}");
    }
    assert_eq!(page(&f, &session, "/console/policy").await.status(), 200);
    assert_eq!(page(&f, &session, "/console/health").await.status(), 200);
    // The control role has no data plane: /mcp is not there, the console is.
    let mcp = f
        .client
        .post(format!("{}/mcp", f.url))
        .bearer_auth(ADMIN_TOKEN)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(mcp.status(), 404);
    // The console's cross-site guard is its own: an unknown path elsewhere
    // is the server's 404, never a 403 from a layer that leaked into the
    // fallback.
    let elsewhere = f
        .client
        .post(format!("{}/nowhere", f.url))
        .send()
        .await
        .unwrap();
    assert_eq!(elsewhere.status(), 404);
    assert!(elsewhere.headers().get("content-security-policy").is_none());
}

/// The whole path with a real bearer: an RS256 token signed with the test
/// key, published as a JWKS on the provider, validated by the production
/// validator behind the admin API the console renders from.
#[tokio::test]
async fn signs_in_with_a_real_bearer_from_a_wiremock_jwks() {
    const PRIVATE_KEY_DER: &[u8] = include_bytes!("fixtures/okta_test_rsa_pkcs1.der");
    const PUBLIC_JWK: &str = include_str!("fixtures/okta_test_jwk.json");
    let idp = MockServer::start().await;
    let issuer = idp.uri();
    let mut jwk: Value = serde_json::from_str(PUBLIC_JWK).unwrap();
    jwk["kid"] = json!("test-key-1");
    Mock::given(method("GET"))
        .and(path("/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys": [jwk]})))
        .mount(&idp)
        .await;
    let now = get_current_timestamp();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".to_owned());
    let token = encode(
        &header,
        &json!({
            "sub": "alice@acme.example", "iss": issuer, "aud": PUBLIC_URL,
            "iat": now, "exp": now + 300, "scp": ["mcp:admin"], "groups": ["SRE"],
        }),
        &EncodingKey::from_rsa_der(PRIVATE_KEY_DER),
    )
    .unwrap();
    let validator: Arc<dyn TokenValidator> = Arc::new(Arc::new(OidcJwksValidator::new(
        OidcSettings::new(
            Profile::Okta,
            &issuer,
            PUBLIC_URL,
            JwksLocation::Direct(format!("{issuer}/keys")),
        )
        .with_tenant("acme"),
        reqwest::Client::new(),
    )));
    // The fixture mounts discovery and the token endpoint on this same
    // provider, so the issuer the token names is the one the console
    // discovers from and the one the validator trusts.
    let f = fixture_with(
        Role::All,
        validator,
        json!({"access_token": token, "token_type": "bearer", "expires_in": 120}),
        false,
        Some(idp),
    )
    .await;
    let session = sign_in(&f).await;
    let policy = page(&f, &session, "/console/policy").await;
    assert_eq!(policy.status(), 200);
    let html = policy.text().await.unwrap();
    assert!(html.contains("sre-read-qa-loki"));
    assert!(!html.contains(&token));
    let health = page(&f, &session, "/console/health")
        .await
        .text()
        .await
        .unwrap();
    assert!(html_contains_banner(&health));
    assert!(
        f.idp
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|r| r.url.path() == "/keys"),
        "the production validator fetched the JWKS"
    );
}

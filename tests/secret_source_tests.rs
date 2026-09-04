//! C.2a (`docs/enterprise-product-plan.md` §3.8): secret references.
//!
//! What is locked here, in the order the plan lists it:
//!
//! - the adapter **conformance suite** — the same assertions against the
//!   `file://` adapter and the in-memory one, which is how a later adapter
//!   (Vault, AWS, Azure) is proven;
//! - the **rotation lock**: write v1, start, assert the upstream header;
//!   write v2, assert the header changed with no restart and the audit
//!   record carries the new `version`. Fails on the env-only code, where
//!   `file:///…` would go upstream as if it were the token;
//! - **fail-closed startup** for a missing file, a missing key, and a
//!   scheme with no adapter compiled in;
//! - **last good at runtime**: a vanished file keeps the last value in
//!   force and degrades the health banner; a restored file recovers;
//! - **atomic multi-part**: Atlassian email and token from one document
//!   swap together;
//! - the community path: no references, no snapshot, no `_meta`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use mcp_server_devtools::auth::keychain::{InMemoryKeychain, KeychainBackend, SecretKind};
use mcp_server_devtools::bootstrap::secrets::REFRESH_INTERVAL_KEY;
use mcp_server_devtools::bootstrap::{ServerBuilder, Vendors, refuse_unresolved_references};
use mcp_server_devtools::config::{Config, VENDOR_GRAFANA, VENDOR_JIRA};
use mcp_server_devtools::policy::{Principal, PrincipalAuthority};
use mcp_server_devtools::ports::{
    InMemoryAuditSink, InMemorySecretSource, Scheme, SecretLocator, SecretSource,
    SecretSourceError, StaticValidator,
};
use mcp_server_devtools::secrets::FileSecretSource;
use mcp_server_devtools::server::auth::{InboundAuth, InboundAuthSettings};
use mcp_server_devtools::server::http::{build_app_with_server, build_app_with_server_and_auth};
use mcp_server_devtools::tools::{DevtoolsServer, UPSTREAM_META_KEY};
use mcp_server_devtools::vendor::grafana::GrafanaVendor;
use mcp_server_devtools::vendor::jira::JiraVendor;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "alice-bearer-token";
const LOKI_PATH: &str = "/api/datasources/proxy/uid/loki-qa/loki/api/v1/query_range";

// ---------------------------------------------------------------------------
// Conformance suite: every adapter, the same assertions
// ---------------------------------------------------------------------------

/// How a test writes a document behind an adapter.
trait Fixture {
    fn source(&self) -> Arc<dyn SecretSource>;
    fn put(&self, target: &str, document: &str);
    fn remove(&self, target: &str);
    fn target(&self, name: &str) -> String;
}

struct FileFixture {
    dir: tempfile::TempDir,
}

impl Fixture for FileFixture {
    fn source(&self) -> Arc<dyn SecretSource> {
        Arc::new(FileSecretSource)
    }
    fn put(&self, target: &str, document: &str) {
        write_atomically(Path::new(target), document);
    }
    fn remove(&self, target: &str) {
        std::fs::remove_file(target).unwrap();
    }
    fn target(&self, name: &str) -> String {
        file_target(&self.dir.path().join(name))
    }
}

struct MemoryFixture {
    source: Arc<InMemorySecretSource>,
}

impl Fixture for MemoryFixture {
    fn source(&self) -> Arc<dyn SecretSource> {
        Arc::clone(&self.source) as Arc<dyn SecretSource>
    }
    fn put(&self, target: &str, document: &str) {
        self.source.put(target, document);
    }
    fn remove(&self, target: &str) {
        self.source.remove(target);
    }
    fn target(&self, name: &str) -> String {
        format!("/memory/{name}")
    }
}

/// The locator target for a filesystem path: `/abs/path` on Unix,
/// `/C:/abs/path` on Windows, as `file:///` spells it.
fn file_target(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    if text.starts_with('/') {
        text
    } else {
        format!("/{text}")
    }
}

/// Write the way a kubelet or a careful operator does: whole file, then
/// rename, so a reader never sees a partial document.
fn write_atomically(path: &Path, document: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, document).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

async fn conformance(fixture: &dyn Fixture) {
    let source = fixture.source();
    let target = fixture.target("token");
    let locator = SecretLocator::new(Scheme::File, target.clone());

    // Absent → NotFound, naming the locator, never anything else.
    let missing = source.fetch(&locator).await.unwrap_err();
    assert!(
        matches!(missing, SecretSourceError::NotFound { .. }),
        "{missing:?}"
    );
    assert!(missing.to_string().contains(&locator.to_string()));

    // Present → the document, with a version.
    fixture.put(&target, "secret-v1\n");
    let first = source.fetch(&locator).await.unwrap();
    assert_eq!(first.document(), "secret-v1\n");
    assert!(!first.version().is_empty());
    assert!(
        !format!("{first:?}").contains("secret-v1"),
        "Debug leaks the document"
    );

    // Same bytes → same version; new bytes → new version.
    let again = source.fetch(&locator).await.unwrap();
    assert_eq!(again.version(), first.version());
    fixture.put(&target, "secret-v2\n");
    let second = source.fetch(&locator).await.unwrap();
    assert_eq!(second.document(), "secret-v2\n");
    assert_ne!(second.version(), first.version());

    // Removed → NotFound again (a rotation that deleted the file is a
    // refresh failure, not a value of "").
    fixture.remove(&target);
    assert!(matches!(
        source.fetch(&locator).await.unwrap_err(),
        SecretSourceError::NotFound { .. }
    ));
}

#[tokio::test]
async fn file_adapter_conforms() {
    conformance(&FileFixture {
        dir: tempfile::tempdir().unwrap(),
    })
    .await;
}

#[tokio::test]
async fn in_memory_adapter_conforms() {
    conformance(&MemoryFixture {
        source: Arc::new(InMemorySecretSource::new(Scheme::File)),
    })
    .await;
}

#[tokio::test]
async fn file_adapter_refuses_a_host_part_and_a_huge_file() {
    let dir = tempfile::tempdir().unwrap();
    let host = SecretLocator::new(Scheme::File, "host/etc/x");
    assert!(matches!(
        FileSecretSource.fetch(&host).await.unwrap_err(),
        SecretSourceError::Malformed { .. }
    ));
    let big = dir.path().join("big");
    let file = std::fs::File::create(&big).unwrap();
    file.set_len(mcp_server_devtools::secrets::file::MAX_SECRET_FILE_BYTES + 1)
        .unwrap();
    let locator = SecretLocator::new(Scheme::File, file_target(&big));
    assert!(matches!(
        FileSecretSource.fetch(&locator).await.unwrap_err(),
        SecretSourceError::Malformed { .. }
    ));
}

// ---------------------------------------------------------------------------
// The running gateway
// ---------------------------------------------------------------------------

fn principal() -> Principal {
    Principal {
        tenant: "acme".to_owned(),
        subject: "alice@acme.example".to_owned(),
        groups: vec!["SRE".to_owned()],
        scopes: vec!["mcp:tools".to_owned()],
        authority: PrincipalAuthority::oidc("https://acme.okta.com/oauth2/default"),
    }
}

fn inbound_auth() -> Arc<InboundAuth> {
    let validator = StaticValidator::new().with(TOKEN, principal());
    let settings = InboundAuthSettings::from_config(
        &Config::from_map(HashMap::from([(
            "MCP_PUBLIC_URL".to_owned(),
            "https://mcp.acme.example".to_owned(),
        )])),
        "okta",
        vec!["https://acme.okta.com/oauth2/default".to_owned()],
    )
    .unwrap();
    Arc::new(InboundAuth::new(Arc::new(validator), settings))
}

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    )
}

struct Gateway {
    base: String,
    server: DevtoolsServer,
    sink: Arc<InMemoryAuditSink>,
    upstream: MockServer,
    dir: tempfile::TempDir,
}

async fn spawn(app: axum::Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// A protected gateway whose vendor credentials are references into files
/// under a temp dir, refreshing every second. `build` returns a
/// `DevtoolsServer` that has resolved its references (or the startup
/// error).
async fn gateway(
    dir: tempfile::TempDir,
    extra: &[(&str, &str)],
    vendors: impl FnOnce(&MockServer) -> Vendors,
) -> Result<Gateway, mcp_server_devtools::error::McpError> {
    let upstream = MockServer::start().await;
    let sink = Arc::new(InMemoryAuditSink::new());
    let mut pairs = vec![
        (REFRESH_INTERVAL_KEY, "1"),
        ("MCP_VENDOR_ENVIRONMENT", "qa"),
    ];
    pairs.extend_from_slice(extra);
    let server = ServerBuilder::new()
        .config(config(&pairs))
        .vendors(vendors(&upstream))
        .audit_sink(Arc::<InMemoryAuditSink>::clone(&sink))
        .require_inbound_auth(true)
        .build()
        .expect("build server");
    server.resolve_secrets().await?;
    let base = spawn(build_app_with_server_and_auth(
        server.clone(),
        inbound_auth(),
        Duration::from_mins(5),
        Duration::from_mins(5),
        CancellationToken::new(),
    ))
    .await;
    Ok(Gateway {
        base,
        server,
        sink,
        upstream,
        dir,
    })
}

fn grafana_vendors(upstream: &MockServer) -> Vendors {
    Vendors {
        grafana: GrafanaVendor::with_base_url(upstream.uri()),
        ..Vendors::default()
    }
}

async fn call(base: &str, tool: &str, arguments: Value) -> Value {
    let response = reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", tool)
        .header("authorization", format!("Bearer {TOKEN}"))
        .json(&json!({
            "jsonrpc": "2.0", "id": "req-1", "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": { "name": "secret-test", "version": "0" }
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    serde_json::from_str(&body).unwrap_or_else(|_| {
        body.lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .find_map(|data| serde_json::from_str(data.trim()).ok())
            .unwrap_or_else(|| panic!("unparseable: {body}"))
    })
}

async fn query_logs(base: &str) -> Value {
    call(
        base,
        "grafana_query_logs",
        json!({ "datasourceUid": "loki-qa", "query": "{app=\"api\"}", "limit": 10 }),
    )
    .await
}

/// The `Authorization` header of the most recent upstream request.
async fn last_authorization(upstream: &MockServer) -> String {
    let requests = upstream.received_requests().await.unwrap();
    let last = requests.last().expect("an upstream request");
    last.headers
        .get("authorization")
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default()
}

/// Call until the upstream sees `expected` as the bearer, within a bound
/// comfortably past the 1 s refresh interval. Returns the last response.
async fn call_until_bearer(gateway: &Gateway, expected: &str) -> Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let response = query_logs(&gateway.base).await;
        if last_authorization(&gateway.upstream).await == format!("Bearer {expected}") {
            return response;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "upstream never saw Bearer {expected}; last: {}",
            last_authorization(&gateway.upstream).await
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn mount_loki(upstream: &MockServer) -> impl std::future::Future<Output = ()> + '_ {
    Mock::given(method("GET"))
        .and(path(LOKI_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "success",
            "data": { "resultType": "streams", "result": [] }
        })))
        .mount(upstream)
}

fn grafana_file(dir: &Path) -> PathBuf {
    dir.join("grafana.json")
}

fn grafana_reference(dir: &Path) -> String {
    format!("file://{}#token", file_target(&grafana_file(dir)))
}

async fn health(base: &str) -> String {
    reqwest::get(format!("{base}/"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}

/// The `upstream_identity` of the last intent record.
fn last_intent_identity(sink: &InMemoryAuditSink) -> Value {
    sink.events()
        .into_iter()
        .rfind(|event| event["kind"] == "tool_call_intent")
        .expect("an intent record")["upstream_identity"]
        .clone()
}

#[tokio::test]
async fn rotation_lock_a_rewritten_file_changes_the_upstream_header_without_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    write_atomically(&grafana_file(dir.path()), r#"{"token":"glsa_v1"}"#);
    let reference = grafana_reference(dir.path());
    let gateway = gateway(dir, &[("GRAFANA_TOKEN", &reference)], grafana_vendors)
        .await
        .expect("references resolve at startup");
    mount_loki(&gateway.upstream).await;

    // v1 is what goes upstream — not the reference text.
    let response = query_logs(&gateway.base).await;
    assert_eq!(
        last_authorization(&gateway.upstream).await,
        "Bearer glsa_v1",
        "{response}"
    );
    let meta_v1 = response["result"]["_meta"][UPSTREAM_META_KEY].clone();
    assert_eq!(meta_v1["label"], "grafana/GRAFANA_TOKEN");
    assert_eq!(meta_v1["source"], "file");
    let version_v1 = meta_v1["version"].as_str().expect("version").to_owned();
    assert!(version_v1.starts_with("sha256:"), "{meta_v1}");
    let intent_v1 = last_intent_identity(&gateway.sink);
    assert_eq!(intent_v1["source"], "file");
    assert_eq!(intent_v1["version"], version_v1);

    // Rotate. No restart, no signal: the refresher picks it up.
    write_atomically(&grafana_file(gateway.dir.path()), r#"{"token":"glsa_v2"}"#);
    let response = call_until_bearer(&gateway, "glsa_v2").await;
    let meta_v2 = response["result"]["_meta"][UPSTREAM_META_KEY].clone();
    assert_eq!(
        meta_v2["label"], "grafana/GRAFANA_TOKEN",
        "the slot did not move"
    );
    assert_ne!(
        meta_v2["version"], version_v1,
        "the version is the rotation evidence"
    );
    let intent_v2 = last_intent_identity(&gateway.sink);
    assert_eq!(intent_v2["version"], meta_v2["version"]);
    assert_eq!(gateway.server.secrets_degraded(), None);

    // Nothing that was ever a secret is in the journal or the response.
    let journal = serde_json::to_string(&gateway.sink.events()).unwrap();
    for secret in ["glsa_v1", "glsa_v2"] {
        assert!(!journal.contains(secret), "journal leaked {secret}");
        assert!(
            !response.to_string().contains(secret),
            "response leaked {secret}"
        );
    }
}

#[tokio::test]
async fn startup_fails_closed_on_every_unresolvable_reference() {
    let dir = tempfile::tempdir().unwrap();
    write_atomically(&grafana_file(dir.path()), r#"{"token":"glsa_v1"}"#);
    let present = grafana_reference(dir.path());
    let missing_file = format!("file://{}", file_target(&dir.path().join("absent")));
    let missing_key = present.replace("#token", "#nope");
    let cases: [(&str, &str, &str); 3] = [
        (&missing_file, "secret_source_not_found", "does not exist"),
        (
            &missing_key,
            "cannot resolve secret reference",
            "no `nope` key",
        ),
        (
            "vault://secret/mcp#token",
            "vault://",
            "compiled into this binary",
        ),
    ];
    for (reference, needle_a, needle_b) in cases {
        let dir = tempfile::tempdir().unwrap();
        let error = gateway(dir, &[("GRAFANA_TOKEN", reference)], grafana_vendors)
            .await
            .err()
            .unwrap_or_else(|| panic!("{reference} must refuse startup"));
        let text = error.to_string();
        assert!(text.contains(needle_a), "{reference}: {text}");
        assert!(text.contains(needle_b), "{reference}: {text}");
        assert!(text.contains("refusing to start"), "{text}");
        assert!(!text.contains("glsa_v1"), "{text}");
    }
}

#[tokio::test]
async fn a_vanished_file_keeps_the_last_good_value_and_degrades_health() {
    let dir = tempfile::tempdir().unwrap();
    write_atomically(&grafana_file(dir.path()), r#"{"token":"glsa_v1"}"#);
    let reference = grafana_reference(dir.path());
    let gateway = gateway(dir, &[("GRAFANA_TOKEN", &reference)], grafana_vendors)
        .await
        .unwrap();
    mount_loki(&gateway.upstream).await;
    assert!(!health(&gateway.base).await.contains("secret refresh"));

    std::fs::remove_file(grafana_file(gateway.dir.path())).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while gateway.server.secrets_degraded().is_none() {
        assert!(std::time::Instant::now() < deadline, "never degraded");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        gateway.server.secrets_degraded(),
        Some("secret_source_not_found")
    );
    let banner = health(&gateway.base).await;
    assert!(
        banner.contains("; secret refresh is failing; last good values in force"),
        "{banner}"
    );
    assert!(
        !banner.contains("grafana"),
        "the banner names no reference: {banner}"
    );

    // Still serving with v1.
    query_logs(&gateway.base).await;
    assert_eq!(
        last_authorization(&gateway.upstream).await,
        "Bearer glsa_v1"
    );

    // Restored with v3 → recovered, and v3 in force.
    write_atomically(&grafana_file(gateway.dir.path()), r#"{"token":"glsa_v3"}"#);
    call_until_bearer(&gateway, "glsa_v3").await;
    assert_eq!(gateway.server.secrets_degraded(), None);
    assert!(!health(&gateway.base).await.contains("secret refresh"));
}

#[tokio::test]
async fn multi_part_credentials_rotate_together_from_one_document() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("atlassian.json");
    write_atomically(&file, r#"{"email":"svc-1@acme.example","token":"tok-1"}"#);
    let base_ref = format!("file://{}", file_target(&file));
    let email_ref = format!("{base_ref}#email");
    let token_ref = format!("{base_ref}#token");
    let gateway = gateway(
        dir,
        &[
            ("ATLASSIAN_USER_EMAIL", &email_ref),
            ("ATLASSIAN_API_TOKEN", &token_ref),
        ],
        |upstream| Vendors {
            jira: JiraVendor::with_base_url(upstream.uri()),
            ..Vendors::default()
        },
    )
    .await
    .unwrap();
    Mock::given(method("GET"))
        .and(path("/rest/api/3/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accountId": "1"})))
        .mount(&gateway.upstream)
        .await;

    let basic = |email: &str, token: &str| {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{email}:{token}"))
        )
    };
    call(
        &gateway.base,
        "jira_get",
        json!({ "path": "/rest/api/3/myself" }),
    )
    .await;
    assert_eq!(
        last_authorization(&gateway.upstream).await,
        basic("svc-1@acme.example", "tok-1")
    );
    let identity = last_intent_identity(&gateway.sink);
    assert_eq!(
        identity["label"],
        "jira/ATLASSIAN_API_TOKEN/svc-1@acme.example"
    );
    assert_eq!(identity["source"], "file");

    write_atomically(&file, r#"{"email":"svc-2@acme.example","token":"tok-2"}"#);
    let expected = basic("svc-2@acme.example", "tok-2");
    let mixed = [
        basic("svc-1@acme.example", "tok-2"),
        basic("svc-2@acme.example", "tok-1"),
    ];
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        call(
            &gateway.base,
            "jira_get",
            json!({ "path": "/rest/api/3/myself" }),
        )
        .await;
        let seen = last_authorization(&gateway.upstream).await;
        assert!(!mixed.contains(&seen), "a torn credential went upstream");
        if seen == expected {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "never rotated: {seen}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // The label moved with the account; that is the audit trail of a
    // principal change, distinct from a rotation under the same account.
    assert_eq!(
        last_intent_identity(&gateway.sink)["label"],
        "jira/ATLASSIAN_API_TOKEN/svc-2@acme.example"
    );
}

#[tokio::test]
async fn a_reloaded_config_with_a_reference_is_resolved_before_it_is_swapped_in() {
    // `resolve_reloaded` is what the config watcher calls; the watcher
    // itself is exercised by `bootstrap::watcher` tests on a temp file.
    let dir = tempfile::tempdir().unwrap();
    write_atomically(&grafana_file(dir.path()), r#"{"token":"glsa_v1"}"#);
    let resolver = mcp_server_devtools::secrets::SecretResolver::with_defaults();
    let reloaded = mcp_server_devtools::bootstrap::secrets::resolve_reloaded(
        &resolver,
        config(&[("GRAFANA_TOKEN", &grafana_reference(dir.path()))]),
    )
    .await
    .unwrap();
    assert_eq!(
        reloaded.get_for(VENDOR_GRAFANA, "GRAFANA_TOKEN"),
        Some("glsa_v1")
    );
    let provenance = reloaded
        .secret_provenance(VENDOR_GRAFANA, "GRAFANA_TOKEN")
        .unwrap();
    assert_eq!(provenance.source, "file");

    std::fs::remove_file(grafana_file(dir.path())).unwrap();
    let refused = mcp_server_devtools::bootstrap::secrets::resolve_reloaded(
        &resolver,
        config(&[("GRAFANA_TOKEN", &grafana_reference(dir.path()))]),
    )
    .await
    .unwrap_err();
    assert_eq!(refused.cause.category(), "secret_source_not_found");
}

// ---------------------------------------------------------------------------
// The community path, and the guards around an unresolved reference
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_references_means_no_snapshot_no_refresher_and_no_meta() {
    let upstream = MockServer::start().await;
    mount_loki(&upstream).await;
    let config = config(&[("GRAFANA_TOKEN", "glsa_literal")]);
    assert_eq!(config.secret_references().count(), 0);
    assert!(config.secrets().is_empty());
    assert_eq!(
        config.secret_provenance(VENDOR_GRAFANA, "GRAFANA_TOKEN"),
        None
    );

    let server = ServerBuilder::new()
        .config(config)
        .vendors(grafana_vendors(&upstream))
        .build()
        .unwrap();
    server.resolve_secrets().await.unwrap();
    assert_eq!(server.secrets_degraded(), None);
    let base = spawn(build_app_with_server(
        server,
        Duration::from_mins(5),
        Duration::from_mins(5),
        CancellationToken::new(),
    ))
    .await;
    let response = call(
        &base,
        "grafana_query_logs",
        json!({
            "datasourceUid": "loki-qa", "query": "{app=\"api\"}", "limit": 10
        }),
    )
    .await;
    assert_eq!(last_authorization(&upstream).await, "Bearer glsa_literal");
    assert!(
        response["result"].get("_meta").is_none(),
        "local mode carries no _meta: {response}"
    );
}

#[tokio::test]
async fn an_unresolved_reference_is_refused_by_name_never_sent_upstream() {
    // A server assembled without `resolve_secrets` (or the one-shot CLI):
    // the cascade refuses the credential and names the reference.
    let unresolved = config(&[("GRAFANA_TOKEN", "file:///run/secrets/grafana#token")]);
    let error =
        mcp_server_devtools::auth::vendor_secret(&unresolved, VENDOR_GRAFANA, "GRAFANA_TOKEN")
            .await
            .unwrap_err();
    let text = error.to_string();
    assert!(text.contains("file:///run/secrets/grafana#token"), "{text}");
    assert!(text.contains("not resolved"), "{text}");

    // Same for a principal that is a reference.
    let unresolved = config(&[
        (
            "ATLASSIAN_USER_EMAIL",
            "file:///run/secrets/atlassian#email",
        ),
        ("ATLASSIAN_API_TOKEN", "literal"),
    ]);
    let error = mcp_server_devtools::auth::Credentials::require_for_async(&unresolved, VENDOR_JIRA)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("#email"), "{error}");

    // And the CLI refuses up front.
    let refused = refuse_unresolved_references(&unresolved).unwrap_err();
    assert!(refused.to_string().contains("#email"), "{refused}");
    assert!(refuse_unresolved_references(&config(&[("X", "literal")])).is_ok());
}

#[test]
fn keychain_uri_is_an_alias_of_the_sentinel() {
    let keychain = InMemoryKeychain::new();
    keychain
        .set(
            SecretKind::Token,
            VENDOR_GRAFANA,
            "GRAFANA_TOKEN",
            "from-keychain",
        )
        .unwrap();
    for spelling in ["keychain", "keychain://"] {
        let config = config(&[("GRAFANA_TOKEN", spelling)]);
        let value = mcp_server_devtools::auth::vendor_secret_with(
            &config,
            &keychain,
            VENDOR_GRAFANA,
            "GRAFANA_TOKEN",
        )
        .unwrap();
        assert_eq!(value.as_deref(), Some("from-keychain"), "{spelling}");
    }
}

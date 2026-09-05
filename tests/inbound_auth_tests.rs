//! WPs A.2 / A.3 and CF-6 over the real HTTP router: bearer challenges,
//! `insufficient_scope`, the RFC 9728 metadata document, the validated
//! principal reaching the audit journal, health reflecting journal
//! availability — and nothing about the token in the logs.
//!
//! The validator here is the `StaticValidator` (the port's second
//! implementation); the Okta validator's own behaviour is covered by
//! `tests/token_validator_tests.rs`. What is under test is the transport's
//! use of the port.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use mcp_server_devtools::bootstrap::{ServerBuilder, Vendors};
use mcp_server_devtools::config::Config;
use mcp_server_devtools::policy::{Principal, PrincipalAuthority};
use mcp_server_devtools::ports::{InMemoryAuditSink, StaticValidator};
use mcp_server_devtools::server::auth::{InboundAuth, InboundAuthSettings};
use mcp_server_devtools::server::http::{build_app_with_server, build_app_with_server_and_auth};
use mcp_server_devtools::tools::DevtoolsServer;
use mcp_server_devtools::vendor::jira::JiraVendor;
use reqwest::StatusCode;
use serde_json::json;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PUBLIC_URL: &str = "https://mcp.acme.example";
const ISSUER: &str = "https://acme.okta.com/oauth2/default";
const ALICE_TOKEN: &str = "static-token-for-alice-with-scope-0123456789";
const BOB_TOKEN: &str = "static-token-for-bob-without-scope-9876543210";
const FORGED_TOKEN: &str = "definitely-not-a-known-token-abcdef";

/// Everything `tracing` emits during this test binary, so a test can assert
/// that a rejected token never reached a log line.
fn captured_logs() -> &'static Arc<Mutex<Vec<u8>>> {
    static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    LOGS.get_or_init(|| {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturingWriter(Arc::clone(&buffer));
        let _ = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .try_init();
        buffer
    })
}

#[derive(Clone)]
struct CapturingWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write_all(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn principal(subject: &str, scopes: &[&str]) -> Principal {
    Principal {
        tenant: "acme".to_owned(),
        subject: subject.to_owned(),
        groups: vec!["SRE".to_owned()],
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        authority: PrincipalAuthority::oidc("https://acme.okta.com/oauth2/default"),
    }
}

fn inbound_auth() -> Arc<InboundAuth> {
    let validator = StaticValidator::new()
        .with(ALICE_TOKEN, principal("alice@acme.example", &["mcp:tools"]))
        .with(BOB_TOKEN, principal("bob@acme.example", &["openid"]));
    let settings = InboundAuthSettings::from_config(
        &Config::from_map(HashMap::from([(
            "MCP_PUBLIC_URL".to_owned(),
            PUBLIC_URL.to_owned(),
        )])),
        "okta",
        vec![ISSUER.to_owned()],
    )
    .unwrap();
    Arc::new(InboundAuth::new(Arc::new(validator), settings))
}

fn server(mock_uri: &str, sink: &Arc<InMemoryAuditSink>, auth_required: bool) -> DevtoolsServer {
    ServerBuilder::new()
        .config(Config::from_map(HashMap::from([
            (
                "ATLASSIAN_USER_EMAIL".to_owned(),
                "svc@acme.example".to_owned(),
            ),
            ("ATLASSIAN_API_TOKEN".to_owned(), "svc-token".to_owned()),
        ])))
        .vendors(Vendors {
            jira: JiraVendor::with_base_url(mock_uri),
            ..Vendors::default()
        })
        .audit_sink(Arc::<InMemoryAuditSink>::clone(sink))
        .require_inbound_auth(auth_required)
        .build()
        .expect("build server")
}

async fn spawn(app: axum::Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum::serve");
    });
    format!("http://{addr}")
}

async fn spawn_protected(mock_uri: &str, sink: &Arc<InMemoryAuditSink>) -> String {
    spawn(build_app_with_server_and_auth(
        server(mock_uri, sink, true),
        inbound_auth(),
        Duration::from_mins(5),
        Duration::from_mins(5),
        CancellationToken::new(),
    ))
    .await
}

fn tools_list_request(client: &reqwest::Client, base: &str) -> reqwest::RequestBuilder {
    client
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/list")
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": { "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": { "name": "auth-test", "version": "0" }
            } }
        }))
}

fn www_authenticate(response: &reqwest::Response) -> String {
    response
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn missing_bearer_is_401_with_a_resource_metadata_challenge() {
    let _ = captured_logs();
    let sink = Arc::new(InMemoryAuditSink::new());
    let base = spawn_protected("http://127.0.0.1:1", &sink).await;
    let client = reqwest::Client::new();

    for request in [
        tools_list_request(&client, &base),
        tools_list_request(&client, &base).header("authorization", "Basic dXNlcjpwYXNz"),
        tools_list_request(&client, &base).header("authorization", "Bearer "),
        client.get(format!("{base}/artifacts/some-id")),
    ] {
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenge = www_authenticate(&response);
        assert!(
            challenge.starts_with("Bearer realm=\"mcp-devtools\""),
            "{challenge}"
        );
        assert!(
            challenge.contains(&format!(
                "resource_metadata=\"{PUBLIC_URL}/.well-known/oauth-protected-resource\""
            )),
            "{challenge}"
        );
        assert!(
            !challenge.contains("error="),
            "no error code without a token: {challenge}"
        );
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["error"], "unauthorized");
    }
    assert!(sink.events().is_empty(), "nothing reached dispatch");
}

#[tokio::test]
async fn rejected_token_is_401_invalid_token_and_never_logged() {
    let logs = captured_logs();
    let sink = Arc::new(InMemoryAuditSink::new());
    let base = spawn_protected("http://127.0.0.1:1", &sink).await;

    let response = tools_list_request(&reqwest::Client::new(), &base)
        .header("authorization", format!("Bearer {FORGED_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = www_authenticate(&response);
    assert!(challenge.contains("error=\"invalid_token\""), "{challenge}");
    assert!(
        challenge.contains("error_description=\"unknown_token\""),
        "{challenge}"
    );
    let body = response.text().await.unwrap();
    assert!(
        !body.contains(FORGED_TOKEN),
        "body echoes the token: {body}"
    );

    let logged = String::from_utf8_lossy(&logs.lock().unwrap()).into_owned();
    assert!(
        logged.contains("rejected bearer token"),
        "the rejection is logged as a category: {logged}"
    );
    assert!(
        !logged.contains(FORGED_TOKEN),
        "the token itself must never reach a log line"
    );
    assert!(sink.events().is_empty());
}

#[tokio::test]
async fn token_without_the_required_scope_is_403_insufficient_scope() {
    let logs = captured_logs();
    let sink = Arc::new(InMemoryAuditSink::new());
    let base = spawn_protected("http://127.0.0.1:1", &sink).await;

    let response = tools_list_request(&reqwest::Client::new(), &base)
        .header("authorization", format!("Bearer {BOB_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let challenge = www_authenticate(&response);
    assert!(
        challenge.contains("error=\"insufficient_scope\""),
        "{challenge}"
    );
    assert!(challenge.contains("scope=\"mcp:tools\""), "{challenge}");
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"], "insufficient_scope");
    assert!(sink.events().is_empty());

    // The rejection is logged as a category. The validated subject is a
    // claim value: it belongs in the audit journal, not the operator log,
    // and the token itself belongs nowhere.
    let logged = String::from_utf8_lossy(&logs.lock().unwrap()).into_owned();
    assert!(
        logged.contains("insufficient_scope"),
        "the 403 is logged as a category: {logged}"
    );
    assert!(
        !logged.contains("bob@acme.example"),
        "a claim value reached the operator log"
    );
    assert!(!logged.contains(BOB_TOKEN));
}

#[tokio::test]
async fn valid_token_reaches_the_tool_and_its_principal_reaches_the_journal() {
    let _ = captured_logs();
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "svc"})))
        .expect(1)
        .mount(&mock)
        .await;
    let sink = Arc::new(InMemoryAuditSink::new());
    let base = spawn_protected(&mock.uri(), &sink).await;
    let client = reqwest::Client::new();

    let listed = tools_list_request(&client, &base)
        .header("authorization", format!("Bearer {ALICE_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);

    let called = client
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "jira_get")
        .header("authorization", format!("Bearer {ALICE_TOKEN}"))
        .json(&json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {
                "name": "jira_get",
                "arguments": { "path": "/rest/api/3/myself" },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": { "name": "auth-test", "version": "0" }
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(called.status(), StatusCode::OK);
    let body = called.text().await.unwrap();
    assert!(!body.contains("isError\":true"), "{body}");

    // CF-6: the validated principal, not `local`, is in both records.
    let events = sink.events();
    assert_eq!(events.len(), 2, "{events:?}");
    for event in &events {
        assert_eq!(event["principal"]["subject"], "alice@acme.example");
        assert_eq!(event["principal"]["tenant"], "acme");
        // C.1b: the authority records the issuer, not the vendor.
        assert_eq!(event["principal"]["authority"], ISSUER);
        assert_eq!(event["principal"]["groups"], json!(["SRE"]));
        assert_eq!(event["principal"]["scopes"], json!(["mcp:tools"]));
    }
}

#[tokio::test]
async fn protected_resource_metadata_is_public_and_points_at_the_issuer() {
    let _ = captured_logs();
    let sink = Arc::new(InMemoryAuditSink::new());
    let base = spawn_protected("http://127.0.0.1:1", &sink).await;

    let response = reqwest::get(format!("{base}/.well-known/oauth-protected-resource"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json"))
    );
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["resource"], PUBLIC_URL);
    assert_eq!(body["authorization_servers"], json!([ISSUER]));
    assert_eq!(body["scopes_supported"], json!(["mcp:tools"]));
    assert_eq!(body["bearer_methods_supported"], json!(["header"]));

    // The health banner stays reachable without a token: probes need it.
    let health = reqwest::get(format!("{base}/")).await.unwrap();
    assert_eq!(health.status(), StatusCode::OK);
}

#[tokio::test]
async fn local_mode_router_has_no_metadata_route_and_no_challenge() {
    let _ = captured_logs();
    let sink = Arc::new(InMemoryAuditSink::new());
    let base = spawn(build_app_with_server(
        server("http://127.0.0.1:1", &sink, false),
        Duration::from_mins(5),
        Duration::from_mins(5),
        CancellationToken::new(),
    ))
    .await;
    let metadata = reqwest::get(format!("{base}/.well-known/oauth-protected-resource"))
        .await
        .unwrap();
    assert_eq!(metadata.status(), StatusCode::NOT_FOUND);
    let listed = tools_list_request(&reqwest::Client::new(), &base)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    assert!(www_authenticate(&listed).is_empty());
}

#[tokio::test]
async fn health_reports_an_unavailable_journal_as_503() {
    let _ = captured_logs();
    let sink = Arc::new(InMemoryAuditSink::new());
    let base = spawn_protected("http://127.0.0.1:1", &sink).await;

    let healthy = reqwest::get(format!("{base}/")).await.unwrap();
    assert_eq!(healthy.status(), StatusCode::OK);
    assert!(healthy.text().await.unwrap().ends_with(" is running"));

    sink.set_failing(true);
    let degraded = reqwest::get(format!("{base}/")).await.unwrap();
    assert_eq!(degraded.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        degraded
            .text()
            .await
            .unwrap()
            .contains("audit journal is unavailable")
    );
}

/// The belt under the braces: if a server built with `require_inbound_auth`
/// is ever served without the middleware, calls are refused, not run as
/// `local`.
#[tokio::test]
async fn auth_required_without_a_principal_refuses_rather_than_running_as_local() {
    let _ = captured_logs();
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(0)
        .mount(&mock)
        .await;
    let sink = Arc::new(InMemoryAuditSink::new());
    // Deliberately the plain router: no middleware, but auth required.
    let base = spawn(build_app_with_server(
        server(&mock.uri(), &sink, true),
        Duration::from_mins(5),
        Duration::from_mins(5),
        CancellationToken::new(),
    ))
    .await;
    let response = reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "jira_get")
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "jira_get",
                "arguments": { "path": "/rest/api/3/myself" },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": { "name": "t", "version": "0" }
                }
            }
        }))
        .send()
        .await
        .unwrap();
    let body = response.text().await.unwrap();
    assert!(body.contains("Unauthenticated"), "{body}");
    assert!(sink.events().is_empty(), "no intent for a refused call");
}

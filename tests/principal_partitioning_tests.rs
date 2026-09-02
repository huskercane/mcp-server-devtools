//! WPs A.4 and A.5 over the real router: artifacts are owned by the
//! principal that created them and a cross-owner request is a 404 on both
//! the download route and the `artifact_read` tool; sessions are bound to
//! the principal that initialized them; the HTTP response cache never
//! serves one principal's response to another.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mcp_server_devtools::bootstrap::{ServerBuilder, Vendors};
use mcp_server_devtools::config::Config;
use mcp_server_devtools::policy::{CallScope, ClientIdentity, Principal, PrincipalAuthority};
use mcp_server_devtools::ports::{InMemoryAuditSink, StaticValidator};
use mcp_server_devtools::server::auth::{InboundAuth, InboundAuthSettings};
use mcp_server_devtools::server::http::build_app_with_server_and_auth;
use mcp_server_devtools::transport::raw_response;
use mcp_server_devtools::vendor::jira::JiraVendor;
use reqwest::StatusCode;
use serde_json::json;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ALICE_TOKEN: &str = "partition-token-alice-0123456789abcdef";
const BOB_TOKEN: &str = "partition-token-bob-fedcba9876543210";

fn principal(subject: &str) -> Principal {
    Principal {
        tenant: "acme".to_owned(),
        subject: subject.to_owned(),
        groups: Vec::new(),
        scopes: vec!["mcp:tools".to_owned()],
        authority: PrincipalAuthority::Okta,
    }
}

fn alice() -> Principal {
    principal("alice@acme.example")
}

fn bob() -> Principal {
    principal("bob@acme.example")
}

fn inbound_auth() -> Arc<InboundAuth> {
    let validator = StaticValidator::new()
        .with(ALICE_TOKEN, alice())
        .with(BOB_TOKEN, bob());
    let settings = InboundAuthSettings::from_config(
        &Config::from_map(HashMap::from([(
            "MCP_PUBLIC_URL".to_owned(),
            "https://mcp.acme.example".to_owned(),
        )])),
        vec!["https://acme.okta.com/oauth2/default".to_owned()],
    )
    .unwrap();
    Arc::new(InboundAuth::new(Arc::new(validator), settings))
}

async fn spawn(mock_uri: &str, extra_config: &[(&str, &str)]) -> String {
    let mut values = HashMap::from([
        (
            "ATLASSIAN_USER_EMAIL".to_owned(),
            "svc@acme.example".to_owned(),
        ),
        ("ATLASSIAN_API_TOKEN".to_owned(), "svc-token".to_owned()),
    ]);
    for (key, value) in extra_config {
        values.insert((*key).to_owned(), (*value).to_owned());
    }
    let server = ServerBuilder::new()
        .config(Config::from_map(values))
        .vendors(Vendors {
            jira: JiraVendor::with_base_url(mock_uri),
            ..Vendors::default()
        })
        .audit_sink(Arc::new(InMemoryAuditSink::new()))
        .require_inbound_auth(true)
        .build()
        .expect("build server");
    let app = build_app_with_server_and_auth(
        server,
        inbound_auth(),
        Duration::from_mins(5),
        Duration::from_mins(5),
        CancellationToken::new(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum::serve");
    });
    format!("http://{addr}")
}

/// Create an artifact the way a tool call by `owner` would: inside that
/// principal's call scope.
async fn artifact_owned_by(owner: Principal, content: &str) -> String {
    let scope = Arc::new(CallScope::new(
        owner,
        ClientIdentity::default(),
        "some_tool",
        "sha256:req",
    ));
    let path = CallScope::enter(scope, raw_response::save_artifact("owned", content))
        .await
        .expect("artifact saved");
    raw_response::artifact_for_path(&path)
        .expect("registered")
        .id
}

fn stateless_call(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    tool: &str,
    arguments: &serde_json::Value,
) -> reqwest::RequestBuilder {
    client
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", tool)
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": { "name": "partition-test", "version": "0" }
                }
            }
        }))
}

async fn tool_text(response: reqwest::Response) -> String {
    let body = response.text().await.unwrap();
    let value: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|_| {
        body.lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .find_map(|data| serde_json::from_str(data.trim()).ok())
            .unwrap_or_else(|| panic!("unparseable: {body}"))
    });
    value["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn artifact_download_is_owner_only_and_cross_owner_is_404() {
    let base = spawn("http://127.0.0.1:1", &[]).await;
    let id = artifact_owned_by(alice(), "alice's private result").await;
    let client = reqwest::Client::new();

    let own = client
        .get(format!("{base}/artifacts/{id}"))
        .header("authorization", format!("Bearer {ALICE_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(own.status(), StatusCode::OK);
    assert_eq!(own.text().await.unwrap(), "alice's private result");

    let other = client
        .get(format!("{base}/artifacts/{id}"))
        .header("authorization", format!("Bearer {BOB_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), StatusCode::NOT_FOUND);
    // Indistinguishable from an unknown id.
    let unknown = client
        .get(format!("{base}/artifacts/does-not-exist"))
        .header("authorization", format!("Bearer {BOB_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        other.text().await.unwrap(),
        unknown.text().await.unwrap(),
        "a cross-owner 404 must not differ from a missing-artifact 404"
    );

    // No token at all is a 401, not a 404: authentication comes first.
    let anonymous = client
        .get(format!("{base}/artifacts/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn artifact_read_tool_is_owner_only() {
    let base = spawn("http://127.0.0.1:1", &[]).await;
    let id = artifact_owned_by(alice(), "chunked-secret").await;
    let client = reqwest::Client::new();

    let own = tool_text(
        stateless_call(
            &client,
            &base,
            ALICE_TOKEN,
            "artifact_read",
            &json!({ "artifactId": id, "offset": 0 }),
        )
        .send()
        .await
        .unwrap(),
    )
    .await;
    assert!(own.contains("\"eof\":true"), "{own}");

    let other = tool_text(
        stateless_call(
            &client,
            &base,
            BOB_TOKEN,
            "artifact_read",
            &json!({ "artifactId": id, "offset": 0 }),
        )
        .send()
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(other, "Artifact not found or expired");
}

#[tokio::test]
async fn a_session_is_bound_to_the_principal_that_initialized_it() {
    let base = spawn("http://127.0.0.1:1", &[]).await;
    let client = reqwest::Client::new();
    let initialize = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "partition-test", "version": "0" }
        }
    });

    let created = client
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {ALICE_TOKEN}"))
        .json(&initialize)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let session = created
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .expect("session id")
        .to_owned();

    let ping = json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" });
    let by_bob = client
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-session-id", &session)
        .header("authorization", format!("Bearer {BOB_TOKEN}"))
        .json(&ping)
        .send()
        .await
        .unwrap();
    assert_eq!(
        by_bob.status(),
        StatusCode::NOT_FOUND,
        "another principal must not be able to use the session"
    );

    let bob_deletes = client
        .delete(format!("{base}/mcp"))
        .header("mcp-session-id", &session)
        .header("authorization", format!("Bearer {BOB_TOKEN}"))
        .send()
        .await
        .unwrap();
    assert_eq!(bob_deletes.status(), StatusCode::NOT_FOUND);

    let by_alice = client
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("mcp-session-id", &session)
        .header("authorization", format!("Bearer {ALICE_TOKEN}"))
        .json(&ping)
        .send()
        .await
        .unwrap();
    assert!(
        by_alice.status().is_success(),
        "owner keeps using the session: {}",
        by_alice.status()
    );
}

#[tokio::test]
async fn the_response_cache_is_partitioned_by_principal() {
    let mock = MockServer::start().await;
    // alice twice (second is a cache hit) + bob once = two upstream calls.
    // Were the cache shared, bob would be served alice's response and the
    // upstream would see one call.
    Mock::given(method("GET"))
        .and(path("/rest/api/3/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(2)
        .mount(&mock)
        .await;
    let base = spawn(&mock.uri(), &[("HTTP_CACHE_ENABLED", "true")]).await;
    let client = reqwest::Client::new();

    for token in [ALICE_TOKEN, ALICE_TOKEN, BOB_TOKEN] {
        let text = tool_text(
            stateless_call(
                &client,
                &base,
                token,
                "jira_get",
                &json!({ "path": "/rest/api/3/myself" }),
            )
            .send()
            .await
            .unwrap(),
        )
        .await;
        assert!(text.contains("ok"), "{text}");
    }
    // `expect(2)` is verified when `mock` drops.
}

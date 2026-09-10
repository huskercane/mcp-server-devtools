//! Runnable proof for spike WP 0.5 (`docs/spikes/rmcp-extensions.md`):
//! rmcp 3.1.2 propagates axum request extensions into
//! `RequestContext::extensions` in `call_tool`, on both the stateless
//! (MCP 2026-07-28) and legacy session dispatch paths.
//!
//! Deliberately uses a purpose-built spike handler, not `DevtoolsServer`:
//! the production tool surface is golden-locked and must not grow a probe
//! tool. What is under test here is rmcp's transport behaviour, which is
//! what Phase A's design depends on.

use std::sync::Arc;
use std::time::Duration;

use axum::http::request::Parts;
use axum::routing::any_service;
use axum::{Extension, Router};
use reqwest::StatusCode;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock as Content,
    Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities,
    ServerInfo, Tool,
};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, ServerHandler};
use serde_json::json;
use tokio::net::TcpListener;

/// The marker a Phase A bearer middleware would insert after validating the
/// inbound token. Cloneable, request-scoped, never the raw token.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SpikePrincipal {
    subject: String,
}

#[derive(Clone, Default)]
struct SpikeServer;

impl ServerHandler for SpikeServer {
    fn call_tool(
        &self,
        _request: CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<CallToolResponse, ErrorData>> + Send {
        // The exact production lookup: RequestContext extensions carry the
        // HTTP request's Parts; the Parts extensions carry middleware state.
        let principal = context
            .extensions
            .get::<Parts>()
            .and_then(|parts| parts.extensions.get::<SpikePrincipal>())
            .cloned();
        let text = match principal {
            Some(principal) => format!("principal:{}", principal.subject),
            None => "principal:absent".to_owned(),
        };
        std::future::ready(Ok(CallToolResponse::Complete(CallToolResult::success(
            vec![Content::text(text)],
        ))))
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + Send {
        let tool = Tool::new(
            "spike_probe",
            "Echoes the principal observed in request extensions.",
            Arc::new(
                serde_json::from_value(json!({"type": "object", "properties": {}}))
                    .expect("static schema"),
            ),
        );
        std::future::ready(Ok(ListToolsResult::with_all_items(vec![tool])))
    }

    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::LATEST;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        let mut implementation = Implementation::default();
        "rmcp-extensions-spike".clone_into(&mut implementation.name);
        info.server_info = implementation;
        info
    }
}

/// Spawn the spike app: a production-shaped `StreamableHttpService` behind
/// an axum `Extension` layer standing in for the Phase A bearer middleware.
async fn spawn_spike_app() -> String {
    let service = StreamableHttpService::new(
        || Ok(SpikeServer),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().with_stateless_protocol_metadata_required(true),
    );
    let app = Router::new()
        .route("/mcp", any_service(service))
        .layer(Extension(SpikePrincipal {
            subject: "spike-user@example.test".to_owned(),
        }));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum::serve");
    });
    format!("http://{addr}")
}

fn mcp_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/json, text/event-stream"),
    );
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers
}

async fn response_json(response: reqwest::Response) -> serde_json::Value {
    let body = response.text().await.expect("response body");
    if let Ok(value) = serde_json::from_str(&body) {
        return value;
    }
    body.lines()
        .filter_map(|line| {
            line.strip_prefix("data: ")
                .or_else(|| line.strip_prefix("data:"))
        })
        // Skip empty priming events; take the first data payload that parses.
        .find_map(|data| serde_json::from_str(data.trim()).ok())
        .unwrap_or_else(|| panic!("response was neither JSON nor JSON-framed SSE:\n{body}"))
}

fn tool_text(body: &serde_json::Value) -> &str {
    body["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no tool text in {body}"))
}

#[tokio::test]
async fn stateless_call_tool_sees_the_axum_extension_principal() {
    let base = spawn_spike_app().await;
    let response = reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .headers(mcp_headers())
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "spike_probe")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "spike_probe",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "spike-test", "version": "0.0.0"
                    }
                }
            }
        }))
        .send()
        .await
        .expect("stateless tools/call");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(
        tool_text(&body),
        "principal:spike-user@example.test",
        "stateless dispatch dropped the request extension: {body}"
    );
}

#[tokio::test]
async fn session_call_tool_sees_the_axum_extension_principal() {
    let base = spawn_spike_app().await;
    let client = reqwest::Client::new();

    let init = client
        .post(format!("{base}/mcp"))
        .headers(mcp_headers())
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "spike-test", "version": "0.0.0" }
            }
        }))
        .send()
        .await
        .expect("initialize");
    assert_eq!(init.status(), StatusCode::OK);
    let session_id = init
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .expect("session id")
        .to_owned();

    let initialized = client
        .post(format!("{base}/mcp"))
        .headers(mcp_headers())
        .header("mcp-session-id", &session_id)
        .json(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .send()
        .await
        .expect("initialized notification");
    assert!(
        initialized.status().is_success(),
        "initialized: {}",
        initialized.status()
    );

    let call = client
        .post(format!("{base}/mcp"))
        .headers(mcp_headers())
        .header("mcp-session-id", &session_id)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "spike_probe", "arguments": {} }
        }))
        .send()
        .await
        .expect("session tools/call");
    assert_eq!(call.status(), StatusCode::OK);
    let body = tokio::time::timeout(Duration::from_secs(10), response_json(call))
        .await
        .expect("session response arrived");
    assert_eq!(
        tool_text(&body),
        "principal:spike-user@example.test",
        "session dispatch dropped the request extension: {body}"
    );
}

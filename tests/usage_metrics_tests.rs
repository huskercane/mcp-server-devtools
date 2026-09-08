//! WP C.6 in composition: the per-principal rate limit through the real
//! bearer middleware, `GET /metrics` after real tool calls, usage rows
//! reaching a `SQLite` rollup store from a real tool call (allowed and
//! denied), the role gate on the rollup channel, and the startup refusals.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mcp_server_devtools::bootstrap::{ServerBuilder, Vendors};
use mcp_server_devtools::config::Config;
use mcp_server_devtools::policy::{FilePolicy, Principal, PrincipalAuthority};
use mcp_server_devtools::ports::{InMemoryAuditSink, Report, ReportQuery, StaticValidator, Window};
use mcp_server_devtools::server::auth::{InboundAuth, InboundAuthSettings};
use mcp_server_devtools::server::http::{build_app_with_server, build_app_with_server_and_auth};
use mcp_server_devtools::server::rate_limit::{RateLimitSettings, RateLimiter};
use mcp_server_devtools::tools::DevtoolsServer;
use mcp_server_devtools::vendor::grafana::GrafanaVendor;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ALICE: &str = "alice-token-fixture";
const PUBLIC_URL: &str = "https://mcp.acme.example";
const ISSUER: &str = "https://acme.okta.com/oauth2/default";

fn principal(subject: &str) -> Principal {
    Principal {
        tenant: "acme".to_owned(),
        subject: subject.to_owned(),
        groups: vec!["SRE".to_owned()],
        scopes: vec!["mcp:tools".to_owned()],
        authority: PrincipalAuthority::oidc(ISSUER),
    }
}

fn auth(rate: Option<RateLimitSettings>) -> Arc<InboundAuth> {
    let validator = StaticValidator::new().with(ALICE, principal("alice@acme.example"));
    let settings = InboundAuthSettings::from_config(
        &Config::from_map(HashMap::from([(
            "MCP_PUBLIC_URL".to_owned(),
            PUBLIC_URL.to_owned(),
        )])),
        "okta",
        vec![ISSUER.to_owned()],
    )
    .unwrap();
    let mut auth = InboundAuth::new(Arc::new(validator), settings);
    if let Some(rate) = rate {
        auth = auth.with_rate_limit(Arc::new(RateLimiter::new(rate)));
    }
    Arc::new(auth)
}

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<HashMap<_, _>>(),
    )
}

const POLICY: &str = include_str!("fixtures/policy/phase-a.yaml");

fn server(grafana_uri: &str, extra: &[(&str, &str)], serves_control: bool) -> DevtoolsServer {
    let mut pairs = vec![
        ("GRAFANA_TOKEN", "glsa_qa_service_token"),
        ("MCP_VENDOR_ENVIRONMENT", "qa"),
    ];
    pairs.extend_from_slice(extra);
    ServerBuilder::new()
        .config(config(&pairs))
        .vendors(Vendors {
            grafana: GrafanaVendor::with_base_url(grafana_uri),
            ..Vendors::default()
        })
        .audit_sink(Arc::new(InMemoryAuditSink::new()))
        .policy(Arc::new(FilePolicy::from_bytes(POLICY.as_bytes()).unwrap()))
        .require_inbound_auth(true)
        .serves_control(serves_control)
        .build()
        .unwrap()
}

async fn spawn(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

async fn call(base: &str, token: &str, tool: &str, arguments: Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .bearer_auth(token)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", tool)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": { "name": "usage-test", "version": "0.0.0" }
                }
            }
        }))
        .send()
        .await
        .expect("tools/call")
}

async fn grafana_mock() -> MockServer {
    let grafana = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(
            "/api/datasources/proxy/uid/loki-qa/loki/api/v1/query_range",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "success",
            "data": { "resultType": "streams", "result": [] }
        })))
        .mount(&grafana)
        .await;
    grafana
}

fn query_logs(uid: &str) -> Value {
    json!({"datasourceUid": uid, "query": "{app=\"api\"}", "limit": 10})
}

#[tokio::test]
async fn a_principal_over_its_rate_limit_gets_429_with_retry_after_and_the_metric_counts_it() {
    let grafana = grafana_mock().await;
    let auth = auth(Some(RateLimitSettings {
        per_second: 1.0,
        burst: 2.0,
    }));
    let server = server(&grafana.uri(), &[("MCP_METRICS", "on")], true);
    let base = spawn(build_app_with_server_and_auth(
        server,
        Arc::clone(&auth),
        Duration::from_mins(5),
        Duration::from_mins(5),
        CancellationToken::new(),
    ))
    .await;

    let first = call(&base, ALICE, "grafana_query_logs", query_logs("loki-qa")).await;
    assert_eq!(first.status(), 200);
    let second = call(&base, ALICE, "grafana_query_logs", query_logs("loki-qa")).await;
    assert_eq!(second.status(), 200);
    let third = call(&base, ALICE, "grafana_query_logs", query_logs("loki-qa")).await;
    assert_eq!(third.status(), 429);
    assert_eq!(third.headers().get("retry-after").unwrap(), "1");
    let body: Value = third.json().await.unwrap();
    assert_eq!(body["error"], "rate_limited");
    assert_eq!(auth.rate_limiter().unwrap().refused(), 1);

    // Unauthenticated requests never reach the limiter (no principal to
    // key on), so an attacker cannot spend a principal's budget.
    let anonymous = call(
        &base,
        "not-a-token",
        "grafana_query_logs",
        query_logs("loki-qa"),
    )
    .await;
    assert_eq!(anonymous.status(), 401);
    assert_eq!(auth.rate_limiter().unwrap().refused(), 1);

    let page = reqwest::get(format!("{base}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("mcp_rate_limited_total 1\n"), "{page}");
    assert!(page.contains("mcp_tool_calls_total{vendor=\"grafana\",tool=\"grafana_query_logs\",decision=\"allow\",outcome=\"success\"} 2\n"), "{page}");
    assert!(!page.contains("alice"), "no subject on the metrics page");
}

#[tokio::test]
async fn usage_rows_reach_the_sqlite_rollups_for_allowed_and_denied_calls() {
    let grafana = grafana_mock().await;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("usage.db");
    let store_uri = format!("sqlite://{}", db.display());
    let server = server(
        &grafana.uri(),
        &[("MCP_ROLLUP_STORE", &store_uri), ("MCP_METRICS", "on")],
        true,
    );
    let cancel = CancellationToken::new();
    assert_eq!(
        server.start_rollups(cancel.clone()).unwrap(),
        Some("sqlite")
    );
    let store = server.rollup_store().expect("store configured");
    let health = server.rollup_health();
    let base = spawn(build_app_with_server_and_auth(
        server,
        auth(None),
        Duration::from_mins(5),
        Duration::from_mins(5),
        cancel.clone(),
    ))
    .await;

    assert_eq!(
        call(&base, ALICE, "grafana_query_logs", query_logs("loki-qa"))
            .await
            .status(),
        200
    );
    // A datasource outside the policy's QA allowlist is denied: a usage row with
    // decision=deny, no upstream request.
    let denied = call(&base, ALICE, "grafana_query_logs", query_logs("loki-prod")).await;
    assert_eq!(denied.status(), 200);

    tokio::time::timeout(Duration::from_secs(10), async {
        while health.appended() < 2 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("two usage rows appended");
    let Report::Groups { rows } = store
        .report(&ReportQuery::ByTool {
            window: Window::all(),
        })
        .await
        .unwrap()
    else {
        panic!("shape");
    };
    assert_eq!(
        rows.iter()
            .map(|r| (r.key.as_str(), r.allowed, r.denied))
            .collect::<Vec<_>>(),
        [("grafana_query_logs", 1, 1)]
    );
    let Report::Groups { rows } = store
        .report(&ReportQuery::ByPrincipal {
            window: Window::all(),
        })
        .await
        .unwrap()
    else {
        panic!("shape");
    };
    assert_eq!(rows[0].key, "alice@acme.example");
    let Report::Groups { rows } = store
        .report(&ReportQuery::DenialsByEnvironment {
            window: Window::all(),
        })
        .await
        .unwrap()
    else {
        panic!("shape");
    };
    assert_eq!(
        rows.iter()
            .map(|r| (r.key.as_str(), r.denied))
            .collect::<Vec<_>>(),
        [("qa", 1)]
    );

    // Both are on the metrics page too, and the rollup gauges are present.
    let page = reqwest::get(format!("{base}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("mcp_tool_calls_total{vendor=\"grafana\",tool=\"grafana_query_logs\",decision=\"deny\",outcome=\"policy_denied\"} 1\n"), "{page}");
    assert!(page.contains("mcp_rollups_degraded 0\n"), "{page}");
    assert!(page.contains("mcp_rollups_appended_total 2\n"), "{page}");
    assert!(page.contains("mcp_audit_journal_available 1\n"), "{page}");
    cancel.cancel();
}

#[tokio::test]
async fn a_gateway_replica_attaches_no_rollup_channel_and_metrics_are_off_by_default() {
    let grafana = grafana_mock().await;
    let dir = tempfile::tempdir().unwrap();
    let store_uri = format!("sqlite://{}", dir.path().join("usage.db").display());
    let server = server(&grafana.uri(), &[("MCP_ROLLUP_STORE", &store_uri)], false);
    assert!(
        server.rollup_store().is_none(),
        "a pure gateway has no consumer, so no store"
    );
    assert_eq!(
        server.start_rollups(CancellationToken::new()).unwrap(),
        None
    );
    let base = spawn(build_app_with_server(
        server,
        Duration::from_mins(5),
        Duration::from_mins(5),
        CancellationToken::new(),
    ))
    .await;
    assert_eq!(
        reqwest::get(format!("{base}/metrics"))
            .await
            .unwrap()
            .status(),
        404
    );
}

#[tokio::test]
async fn rollup_and_rate_limit_misconfiguration_refuses_startup() {
    for (pairs, expected) in [
        (
            vec![("MCP_ROLLUP_STORE", "postgres://control/usage")],
            "no `postgres://` rollup store is compiled",
        ),
        (
            vec![("MCP_ROLLUP_STORE", "kafka://x")],
            "no rollup store for `kafka://`",
        ),
        (
            vec![("MCP_ROLLUP_STORE", "sqlite://relative/usage.db")],
            "three slashes",
        ),
        (vec![("MCP_ROLLUP_STORE", "usage.db")], "is not a URI"),
        (
            vec![
                ("MCP_ROLLUP_STORE", "memory://"),
                ("MCP_ROLLUP_RETENTION_DAYS", "soon"),
            ],
            "MCP_ROLLUP_RETENTION_DAYS must be",
        ),
    ] {
        let error = ServerBuilder::new()
            .config(config(&pairs))
            .build()
            .err()
            .map(|e| e.to_string());
        let error = error.unwrap_or_else(|| panic!("{pairs:?} must refuse"));
        assert!(error.contains(expected), "{expected:?} not in {error}");
        assert!(error.contains("refusing to start"), "{error}");
    }
    assert!(
        RateLimitSettings::from_config(&config(&[("MCP_RATE_LIMIT_PER_PRINCIPAL", "lots")]))
            .is_err()
    );
    let server = ServerBuilder::new()
        .config(config(&[("MCP_ROLLUP_STORE", "memory://")]))
        .build()
        .unwrap();
    assert_eq!(
        server.rollup_store().map(|store| store.name()),
        Some("memory")
    );
}

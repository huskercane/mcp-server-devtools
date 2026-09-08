//! WP 0.7 integration tests: durable audit is written **before** dispatch,
//! carries the upstream identity (WP 0.6), and fails closed.
//!
//! These drive the real HTTP transport (`build_app_with_server`) against a
//! `DevtoolsServer` whose Jira vendor points at wiremock, so the property
//! under test is the actual `call_tool` path, not a mock of it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mcp_server_devtools::bootstrap::{ServerBuilder, Vendors};
use mcp_server_devtools::config::Config;
use mcp_server_devtools::ports::InMemoryAuditSink;
use mcp_server_devtools::server::http::build_app_with_server;
use mcp_server_devtools::tools::DevtoolsServer;
use mcp_server_devtools::vendor::jira::JiraVendor;
use reqwest::StatusCode;
use serde_json::json;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn jira_config() -> Config {
    Config::from_map(HashMap::from([
        (
            "ATLASSIAN_USER_EMAIL".to_owned(),
            "alice@example.com".to_owned(),
        ),
        ("ATLASSIAN_API_TOKEN".to_owned(), "test-token".to_owned()),
        ("MCP_VENDOR_ENVIRONMENT".to_owned(), "qa".to_owned()),
    ]))
}

fn server_against(mock_uri: &str, sink: &Arc<InMemoryAuditSink>) -> DevtoolsServer {
    ServerBuilder::new()
        .config(jira_config())
        .vendors(Vendors {
            jira: JiraVendor::with_base_url(mock_uri),
            ..Vendors::default()
        })
        .audit_sink(Arc::<InMemoryAuditSink>::clone(sink))
        .build()
        .expect("build server")
}

async fn spawn(server: DevtoolsServer) -> String {
    let app = build_app_with_server(
        server,
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

/// Stateless MCP 2026-07-28 `tools/call` of `jira_get /rest/api/3/myself`.
async fn call_jira_get(base: &str) -> serde_json::Value {
    let response = reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "jira_get")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "jira_get",
                "arguments": { "path": "/rest/api/3/myself" },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "audit-test", "version": "0.0.0"
                    }
                }
            }
        }))
        .send()
        .await
        .expect("tools/call");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");
    if let Ok(value) = serde_json::from_str(&body) {
        return value;
    }
    body.lines()
        .filter_map(|line| {
            line.strip_prefix("data: ")
                .or_else(|| line.strip_prefix("data:"))
        })
        .find_map(|data| serde_json::from_str(data.trim()).ok())
        .unwrap_or_else(|| panic!("unparseable response:\n{body}"))
}

#[tokio::test]
async fn failed_journal_write_refuses_the_call_and_never_contacts_the_vendor() {
    let mock = MockServer::start().await;
    // The property under test: zero upstream requests when the journal is
    // unwritable. `.expect(0)` is verified when `mock` drops.
    Mock::given(method("GET"))
        .and(path("/rest/api/3/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(0)
        .mount(&mock)
        .await;

    let sink = Arc::new(InMemoryAuditSink::new());
    sink.set_failing(true);
    let base = spawn(server_against(&mock.uri(), &sink)).await;

    let body = call_jira_get(&base).await;
    assert_eq!(
        body["result"]["isError"], true,
        "call must be refused: {body}"
    );
    let text = body["result"]["content"][0]["text"]
        .as_str()
        .expect("error text");
    assert!(
        text.contains("Audit journal unavailable"),
        "unexpected refusal text: {text}"
    );
    assert!(
        sink.events().is_empty(),
        "no partial evidence should be recorded by the failing sink"
    );
    // The sink's own error goes to the operator log, never to the model. A
    // sink is free to be an HTTP client, and its errors can quote request
    // headers; this response is rendered into a transcript.
    assert!(
        !text.contains("test switch"),
        "the sink's raw error must not be echoed to the caller: {text}"
    );
}

#[tokio::test]
async fn intent_with_upstream_identity_is_journaled_before_dispatch_and_outcome_after() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "alice"})))
        .expect(1)
        .mount(&mock)
        .await;

    let sink = Arc::new(InMemoryAuditSink::new());
    let base = spawn(server_against(&mock.uri(), &sink)).await;

    let body = call_jira_get(&base).await;
    assert_ne!(
        body["result"]["isError"], true,
        "call should succeed: {body}"
    );

    let events = sink.events();
    assert_eq!(events.len(), 2, "intent + outcome: {events:?}");

    let intent = &events[0];
    assert_eq!(intent["seq"], 1);
    assert_eq!(intent["kind"], "tool_call_intent");
    assert_eq!(intent["tool_name"], "jira_get");
    assert_eq!(intent["vendor"], "jira");
    assert_eq!(intent["decision"]["effect"], "allow");
    assert_eq!(intent["principal"]["subject"], "local");
    // Client name/version are self-reported and never kept verbatim — see
    // `policy::ClientIdentity` — so the journal holds a correlation digest,
    // not the reported text. `correlation_id` shares the same digest
    // implementation, so it doubles as the expected-value oracle here.
    assert_eq!(
        intent["client"]["name"].as_str().unwrap(),
        mcp_server_devtools::policy::correlation_id("audit-test")
    );
    assert_eq!(
        intent["client"]["version"].as_str().unwrap(),
        mcp_server_devtools::policy::correlation_id("0.0.0")
    );
    // WP 0.6: the upstream identity appears in every event, with the
    // config-derived label and environment classification.
    assert_eq!(
        intent["upstream_identity"]["label"],
        "jira/ATLASSIAN_API_TOKEN/alice@example.com"
    );
    assert_eq!(intent["upstream_identity"]["environment"], "qa");
    assert_eq!(intent["upstream_identity"]["authority"], "shared");
    assert!(intent["outcome"].is_null(), "intent carries no outcome yet");

    let outcome = &events[1];
    assert_eq!(outcome["seq"], 2);
    assert_eq!(outcome["kind"], "tool_call_outcome");
    assert_eq!(outcome["outcome"], "success");
    assert_eq!(
        outcome["upstream_identity"]["label"],
        intent["upstream_identity"]["label"]
    );
    assert!(outcome["duration_ms"].is_u64());
}

/// A sink whose outcome appends wait on a gate the test holds. Intents go
/// straight through, so the dispatch happens; the outcome is what stalls.
struct StallingSink {
    inner: InMemoryAuditSink,
    released: tokio::sync::watch::Receiver<bool>,
}

impl mcp_server_devtools::ports::AuditSink for StallingSink {
    fn append<'a>(
        &'a self,
        event: &'a mcp_server_devtools::ports::AuditEvent,
    ) -> mcp_server_devtools::ports::audit_sink::AppendFuture<'a> {
        Box::pin(async move {
            if event.kind == mcp_server_devtools::ports::AuditEventKind::ToolCallOutcome {
                let mut released = self.released.clone();
                released
                    .wait_for(|released| *released)
                    .await
                    .map_err(|_| std::io::Error::other("gate dropped"))?;
            }
            self.inner.append_now(event)
        })
    }

    fn append_control<'a>(
        &'a self,
        event: &'a mcp_server_devtools::ports::ControlEvent,
    ) -> mcp_server_devtools::ports::audit_sink::AppendFuture<'a> {
        self.inner.append_control(event)
    }
}

/// CF-14, the post-dispatch half: the outcome append is bounded in how long
/// the *caller* waits, but the record is never abandoned. A journal that
/// stalls past the bound after the vendor was contacted must still end up
/// holding the outcome once it recovers — otherwise a dispatched call reads
/// as "requested, not dispatched" forever.
#[tokio::test]
async fn a_stalled_outcome_append_is_not_cancelled_by_the_bound() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "alice"})))
        .expect(1)
        .mount(&mock)
        .await;

    let (release, released) = tokio::sync::watch::channel(false);
    let sink = Arc::new(StallingSink {
        inner: InMemoryAuditSink::new(),
        released,
    });
    let config = Config::from_map(HashMap::from([
        (
            "ATLASSIAN_USER_EMAIL".to_owned(),
            "alice@example.com".to_owned(),
        ),
        ("ATLASSIAN_API_TOKEN".to_owned(), "test-token".to_owned()),
        ("MCP_AUDIT_APPEND_TIMEOUT_MS".to_owned(), "100".to_owned()),
    ]));
    let server = ServerBuilder::new()
        .config(config)
        .vendors(Vendors {
            jira: JiraVendor::with_base_url(mock.uri()),
            ..Vendors::default()
        })
        .audit_sink(Arc::<StallingSink>::clone(&sink))
        .build()
        .expect("build server");
    let base = spawn(server).await;

    // The call completes: the caller waits for the bound, not for the disk.
    let started = std::time::Instant::now();
    let body = call_jira_get(&base).await;
    assert_ne!(body["result"]["isError"], true, "{body}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the caller must not be parked behind a stalled outcome append"
    );
    let kinds = |events: &[serde_json::Value]| {
        events
            .iter()
            .map(|event| event["kind"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        kinds(&sink.inner.events()),
        ["tool_call_intent"],
        "the outcome is still waiting on the journal"
    );

    // The journal recovers. The outcome that was pending lands — it was
    // never cancelled.
    release.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while sink.inner.events().len() < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the stalled outcome must be written once the journal recovers");
    let events = sink.inner.events();
    assert_eq!(kinds(&events), ["tool_call_intent", "tool_call_outcome"]);
    assert_eq!(events[1]["outcome"], "success");
    assert_eq!(events[1]["request_id"], events[0]["request_id"]);
}

/// The other half of the outcome guarantee: an append that outlived its
/// caller is tracked, and a shutdown drains it instead of dropping it with
/// the runtime. `pending_audit()` is what the transports drain.
#[tokio::test]
async fn pending_outcome_appends_are_tracked_for_shutdown_to_drain() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "alice"})))
        .mount(&mock)
        .await;

    let (release, released) = tokio::sync::watch::channel(false);
    let sink = Arc::new(StallingSink {
        inner: InMemoryAuditSink::new(),
        released,
    });
    let server = ServerBuilder::new()
        .config(Config::from_map(HashMap::from([
            (
                "ATLASSIAN_USER_EMAIL".to_owned(),
                "alice@example.com".to_owned(),
            ),
            ("ATLASSIAN_API_TOKEN".to_owned(), "test-token".to_owned()),
            ("MCP_AUDIT_APPEND_TIMEOUT_MS".to_owned(), "100".to_owned()),
        ])))
        .vendors(Vendors {
            jira: JiraVendor::with_base_url(mock.uri()),
            ..Vendors::default()
        })
        .audit_sink(Arc::<StallingSink>::clone(&sink))
        .build()
        .expect("build server");
    let pending = server.pending_audit();
    let base = spawn(server).await;

    let body = call_jira_get(&base).await;
    assert_ne!(body["result"]["isError"], true, "{body}");
    assert_eq!(sink.inner.events().len(), 1, "outcome still pending");

    // A drain that starts now must wait: the append is in flight.
    pending.close();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), pending.wait())
            .await
            .is_err(),
        "the tracker must hold the pending append"
    );
    // The journal recovers; the drain completes and the outcome is there.
    release.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), pending.wait())
        .await
        .expect("drain completes once the journal acknowledges");
    let events = sink.inner.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["kind"], "tool_call_outcome");
}

#[tokio::test]
async fn journal_configured_via_config_is_written_through_and_fails_startup_when_unusable() {
    // End-to-end through MCP_AUDIT_JOURNAL_DIR (the production wiring, no
    // injected sink): events land in the JSONL journal on disk.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&mock)
        .await;

    let journal_dir = tempfile::tempdir().expect("tempdir");
    // On Windows the journal adapter refuses to auto-create the journal
    // file: it can never durably sync a newly created directory entry
    // there, so the operator must pre-create it. A no-op elsewhere, where
    // `JournalAuditSink::open` creates it itself.
    if cfg!(windows) {
        std::fs::File::create(
            journal_dir
                .path()
                .join(mcp_server_devtools::audit::journal::JOURNAL_FILE_NAME),
        )
        .expect("pre-create journal file for the Windows preflight check");
    }
    let mut values = HashMap::from([
        (
            "ATLASSIAN_USER_EMAIL".to_owned(),
            "alice@example.com".to_owned(),
        ),
        ("ATLASSIAN_API_TOKEN".to_owned(), "test-token".to_owned()),
    ]);
    values.insert(
        "MCP_AUDIT_JOURNAL_DIR".to_owned(),
        journal_dir.path().to_string_lossy().into_owned(),
    );
    let server = ServerBuilder::new()
        .config(Config::from_map(values.clone()))
        .vendors(Vendors {
            jira: JiraVendor::with_base_url(mock.uri()),
            ..Vendors::default()
        })
        .build()
        .expect("build server with journal");
    let base = spawn(server).await;
    let body = call_jira_get(&base).await;
    assert_ne!(body["result"]["isError"], true, "{body}");

    let journal = std::fs::read_to_string(
        journal_dir
            .path()
            .join(mcp_server_devtools::audit::journal::JOURNAL_FILE_NAME),
    )
    .expect("journal file exists");
    let lines: Vec<serde_json::Value> = journal
        .lines()
        .map(|line| serde_json::from_str(line).expect("journal line is JSON"))
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["seq"], 1);
    assert_eq!(lines[0]["kind"], "tool_call_intent");
    assert_eq!(
        lines[0]["upstream_identity"]["label"],
        "jira/ATLASSIAN_API_TOKEN/alice@example.com"
    );
    // Secrets hygiene: the configured token value never reaches the journal.
    assert!(
        !journal.contains("test-token"),
        "journal leaked a credential value"
    );

    // Fail-closed startup: a journal path that cannot be a directory.
    let blocking_file = journal_dir.path().join("not-a-dir");
    std::fs::write(&blocking_file, b"x").expect("write blocker");
    values.insert(
        "MCP_AUDIT_JOURNAL_DIR".to_owned(),
        blocking_file.to_string_lossy().into_owned(),
    );
    let Err(error) = ServerBuilder::new()
        .config(Config::from_map(values))
        .build()
    else {
        panic!("unusable journal dir must fail startup");
    };
    assert!(
        error.message.contains("audit journal"),
        "unexpected startup error: {}",
        error.message
    );
}

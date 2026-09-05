//! Phase B's second vendor, end to end (WP B.1): the shipped Slack read-only
//! profile decides, the purpose-built tools dispatch through the real
//! router, the journal holds intent, egress, and outcome.
//!
//! - An SRE reads the incident channel's history and a thread in it: both
//!   allowed by the channel-id rule, both reach Slack, and the outcome
//!   record's egress list classifies each request as a channel-scoped read.
//! - The same SRE reads another channel: denied by default before Slack is
//!   contacted; the denial names the profile's version.
//! - Search is unscoped and denied for SRE; `slack_get` against a method
//!   the extractor does not know is denied at the tool level *and* would be
//!   at egress.
//! - A malformed channel id is refused by the controller and unclassified
//!   by the extractor: neither the journal nor Slack ever sees it.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mcp_server_devtools::bootstrap::{ServerBuilder, Vendors};
use mcp_server_devtools::config::Config;
use mcp_server_devtools::policy::{FilePolicy, Principal, PrincipalAuthority};
use mcp_server_devtools::ports::{AuditSink, InMemoryAuditSink, StaticValidator};
use mcp_server_devtools::server::auth::{InboundAuth, InboundAuthSettings};
use mcp_server_devtools::server::http::build_app_with_server_and_auth;
use mcp_server_devtools::vendor::slack::SlackVendor;
use pretty_assertions::assert_eq;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SRE_TOKEN: &str = "sre-token";
const IC_TOKEN: &str = "ic-token";

fn principal(subject: &str, groups: &[&str]) -> Principal {
    Principal {
        tenant: "acme".to_owned(),
        subject: subject.to_owned(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
        scopes: vec!["mcp:tools".to_owned()],
        authority: PrincipalAuthority::oidc("https://acme.okta.com/oauth2/default"),
    }
}

fn shipped_profile() -> Arc<FilePolicy> {
    let profile = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/policies/incident-investigation.yaml"),
    )
    .expect("shipped profile");
    FilePolicy::from_bytes(profile.as_bytes()).expect("shipped profile compiles")
}

struct Slice {
    base: String,
    slack: MockServer,
    sink: Arc<InMemoryAuditSink>,
}

async fn spawn_slice() -> Slice {
    let slack = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/conversations.history"))
        .and(query_param("channel", "C0INCIDENTS"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "messages": [
                { "ts": "1700000000.000100", "user": "U1", "text": "api is down", "thread_ts": "1700000000.000100", "reply_count": 2 },
                { "ts": "1700000010.000200", "user": "U2", "text": "on it" }
            ],
            "has_more": false
        })))
        .mount(&slack)
        .await;
    Mock::given(method("GET"))
        .and(path("/conversations.replies"))
        .and(query_param("channel", "C0INCIDENTS"))
        .and(query_param("ts", "1700000000.000100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "messages": [
                { "ts": "1700000000.000100", "user": "U1", "text": "api is down" },
                { "ts": "1700000005.000300", "user": "U3", "text": "seeing 502s in loki" }
            ]
        })))
        .mount(&slack)
        .await;
    Mock::given(method("GET"))
        .and(path("/search.messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "messages": { "matches": [ { "channel": { "name": "incidents" }, "ts": "1", "text": "outage" } ] }
        })))
        .mount(&slack)
        .await;

    let sink = Arc::new(InMemoryAuditSink::new());
    let config = Config::from_map(HashMap::from([
        ("SLACK_TOKEN".to_owned(), "xoxb-qa-bot".to_owned()),
        ("MCP_VENDOR_ENVIRONMENT".to_owned(), "qa".to_owned()),
    ]));
    let server = ServerBuilder::new()
        .config(config)
        .vendors(Vendors {
            slack: SlackVendor::with_base_url(slack.uri()),
            ..Vendors::default()
        })
        .audit_sink(Arc::clone(&sink) as Arc<dyn AuditSink>)
        .policy(shipped_profile())
        .require_inbound_auth(true)
        .build()
        .expect("build server");
    let validator = StaticValidator::new()
        .with(SRE_TOKEN, principal("sre@acme.example", &["SRE"]))
        .with(
            IC_TOKEN,
            principal("ic@acme.example", &["IncidentCommanders"]),
        );
    let auth = Arc::new(InboundAuth::new(
        Arc::new(validator),
        InboundAuthSettings::from_config(
            &Config::from_map(HashMap::from([(
                "MCP_PUBLIC_URL".to_owned(),
                "https://mcp.acme.example".to_owned(),
            )])),
            "okta",
            vec!["https://acme.okta.com/oauth2/default".to_owned()],
        )
        .unwrap(),
    ));
    let app = build_app_with_server_and_auth(
        server,
        auth,
        Duration::from_mins(5),
        Duration::from_mins(5),
        CancellationToken::new(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Slice {
        base: format!("http://{addr}"),
        slack,
        sink,
    }
}

async fn call(base: &str, token: &str, tool: &str, arguments: Value) -> Value {
    let response = reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", tool)
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "jsonrpc": "2.0", "id": "req-1", "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": { "name": "slice-test", "version": "0" }
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

fn text_of(result: &Value) -> &str {
    result["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("")
}

fn intents(sink: &InMemoryAuditSink) -> Vec<Value> {
    sink.events()
        .into_iter()
        .filter(|event| event["kind"] == "tool_call_intent")
        .collect()
}

fn outcomes(sink: &InMemoryAuditSink) -> Vec<Value> {
    sink.events()
        .into_iter()
        .filter(|event| event["kind"] == "tool_call_outcome")
        .collect()
}

// One walk through the workflow; the sequence is the point.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn the_incident_channel_is_readable_other_channels_and_search_are_not() {
    let slice = spawn_slice().await;

    // History and a thread in the incident channel: allowed, dispatched.
    let history = call(
        &slice.base,
        SRE_TOKEN,
        "slack_channel_history",
        json!({ "channelId": "C0INCIDENTS", "limit": 50, "outputFormat": "json" }),
    )
    .await;
    assert_ne!(history["result"]["isError"], true, "{history}");
    assert!(text_of(&history).contains("api is down"), "{history}");
    let thread = call(
        &slice.base,
        SRE_TOKEN,
        "slack_thread_replies",
        json!({ "channelId": "C0INCIDENTS", "threadTs": "1700000000.000100" }),
    )
    .await;
    assert_ne!(thread["result"]["isError"], true, "{thread}");
    assert!(text_of(&thread).contains("502s in loki"), "{thread}");

    // Another channel: denied by default, Slack never contacted for it.
    let secret = call(
        &slice.base,
        SRE_TOKEN,
        "slack_channel_history",
        json!({ "channelId": "C0SECRET" }),
    )
    .await;
    assert_eq!(secret["result"]["isError"], true, "{secret}");
    assert!(text_of(&secret).contains("Policy denied"), "{secret}");
    assert!(text_of(&secret).contains("default deny"), "{secret}");
    assert!(text_of(&secret).contains("(policy v1+sha256:"), "{secret}");

    // Search: unscoped; SRE has no rule, the incident commander does.
    let denied_search = call(
        &slice.base,
        SRE_TOKEN,
        "slack_search_messages",
        json!({ "query": "outage in:#incidents" }),
    )
    .await;
    assert_eq!(denied_search["result"]["isError"], true, "{denied_search}");
    let allowed_search = call(
        &slice.base,
        IC_TOKEN,
        "slack_search_messages",
        json!({ "query": "outage in:#incidents" }),
    )
    .await;
    assert_ne!(
        allowed_search["result"]["isError"], true,
        "{allowed_search}"
    );

    // Slack saw exactly the three authorized requests.
    let requests = slice.slack.received_requests().await.unwrap();
    let paths: Vec<String> = requests
        .iter()
        .map(|request| request.url.path().to_owned())
        .collect();
    assert_eq!(
        paths,
        vec![
            "/conversations.history",
            "/conversations.replies",
            "/search.messages"
        ]
    );
    assert!(
        requests.iter().all(|request| request
            .url
            .query()
            .is_none_or(|query| !query.contains("C0SECRET"))),
        "the denied channel never reached Slack"
    );

    // The journal: five intents (3 allow, 2 deny) with the canonical action,
    // and three outcomes whose egress lists classify the wire request the
    // same way the tool level did.
    let intents = intents(&slice.sink);
    assert_eq!(intents.len(), 5);
    assert_eq!(
        intents[0]["decision"]["rule_id"],
        "sre-read-incident-channels"
    );
    assert_eq!(
        intents[0]["action"]["normalized_action"],
        "read_channel_history"
    );
    assert_eq!(intents[0]["action"]["resource_type"], "channel");
    assert_eq!(
        intents[0]["action"]["resource_scope"]["ids"],
        json!(["C0INCIDENTS"])
    );
    assert_eq!(intents[0]["action"]["environment"], "qa");
    assert_eq!(
        intents[0]["action"]["canonical_path"],
        "/conversations.history"
    );
    assert!(
        intents[0]["action"]["query_attributes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|pair| pair[0] == "limit"),
        "{}",
        intents[0]["action"]
    );
    assert_eq!(intents[1]["action"]["normalized_action"], "read_thread");
    assert_eq!(intents[2]["decision"]["effect"], "deny");
    assert_eq!(
        intents[2]["action"]["resource_scope"]["ids"],
        json!(["C0SECRET"])
    );
    assert_eq!(intents[3]["decision"]["effect"], "deny");
    assert_eq!(intents[3]["action"]["resource_scope"]["kind"], "unscoped");
    assert_eq!(
        intents[4]["decision"]["rule_id"],
        "incident-commanders-search"
    );
    let query_attribute = &intents[4]["action"]["query_attributes"][0];
    assert_eq!(query_attribute[0], "query");
    assert!(
        query_attribute[1].as_str().unwrap().starts_with("sha256:"),
        "the search text is a digest in the journal: {query_attribute}"
    );

    let outcomes = outcomes(&slice.sink);
    assert_eq!(outcomes.len(), 3);
    let egress = &outcomes[0]["egress"]["requests"];
    assert_eq!(egress.as_array().unwrap().len(), 1);
    assert_eq!(egress[0]["effect"], "allow");
    assert_eq!(egress[0]["rule_id"], "sre-read-incident-channels");
    assert_eq!(egress[0]["dispatch"]["state"], "attempted");
    assert_eq!(egress[0]["dispatch"]["last_status"], 200);
    assert!(
        egress[0]["canonical_target"]
            .as_str()
            .unwrap()
            .starts_with("/conversations.history?channel=C0INCIDENTS"),
        "{}",
        egress[0]
    );
}

#[tokio::test]
async fn unknown_methods_and_malformed_ids_never_reach_slack() {
    let slice = spawn_slice().await;

    // A read method the extractor does not map: unclassified, denied.
    let users = call(
        &slice.base,
        SRE_TOKEN,
        "slack_get",
        json!({ "path": "/users.list" }),
    )
    .await;
    assert_eq!(users["result"]["isError"], true, "{users}");
    assert!(
        text_of(&users).contains("could not be classified"),
        "{users}"
    );

    // The mapped method through the passthrough: the same decision as the
    // purpose-built tool.
    let via_get = call(
        &slice.base,
        SRE_TOKEN,
        "slack_get",
        json!({ "path": "/conversations.history", "queryParams": { "channel": "C0INCIDENTS" } }),
    )
    .await;
    assert_ne!(via_get["result"]["isError"], true, "{via_get}");

    // The allowed channel in the path and another in `queryParams`: the
    // wire request would carry both, so it is not classified — the tool
    // decision denies and Slack never sees the second value.
    let two_channels = call(
        &slice.base,
        SRE_TOKEN,
        "slack_get",
        json!({
            "path": "/conversations.history?channel=C0INCIDENTS",
            "queryParams": { "channel": "C0SECRET" }
        }),
    )
    .await;
    assert_eq!(two_channels["result"]["isError"], true, "{two_channels}");
    assert!(
        text_of(&two_channels).contains("could not be classified"),
        "{two_channels}"
    );

    // A malformed channel id: the extractor declines to classify it, so
    // policy denies before the controller's own check even runs.
    let hostile = call(
        &slice.base,
        SRE_TOKEN,
        "slack_channel_history",
        json!({ "channelId": "C0INCIDENTS/../admin" }),
    )
    .await;
    assert_eq!(hostile["result"]["isError"], true, "{hostile}");
    assert!(
        text_of(&hostile).contains("could not be classified"),
        "{hostile}"
    );
    let intents = intents(&slice.sink);
    let hostile_intent = intents.last().unwrap();
    assert_eq!(hostile_intent["action"]["resource_type"], "unknown");
    assert!(
        !hostile_intent["action"]["canonical_path"]
            .as_str()
            .unwrap()
            .contains("admin"),
        "the hostile value never enters the record: {}",
        hostile_intent["action"]
    );

    let requests = slice.slack.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        1,
        "only the passthrough history read reached Slack"
    );
    assert_eq!(requests[0].url.path(), "/conversations.history");
    assert!(
        !requests[0]
            .url
            .query()
            .unwrap_or_default()
            .contains("C0SECRET"),
        "the second channel value never left the gateway: {}",
        requests[0].url
    );
}

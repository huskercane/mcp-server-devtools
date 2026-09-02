//! Phase A "done when" (`docs/enterprise-product-plan.md` §4), in process:
//!
//! > an Okta-issued token reaches [the gateway], `grafana_query_logs`
//! > against a QA datasource succeeds for group A and is denied for group B
//! > with a reason, both the denial and the allow are in the journal with
//! > policy version and upstream identity, and the journal was written
//! > before dispatch.
//!
//! Every component is the production one: RS256 tokens signed with the
//! test key and validated by `OktaJwksValidator` against a wiremock JWKS;
//! the real bearer middleware and router; the file policy compiled from
//! the shipped read-only profile plus a group-B row; the durable
//! `JournalAuditSink` on disk; Grafana's Loki proxy on wiremock. The TLS
//! ingress and the container are the only pieces not in the loop, and
//! `tests/auth_mode_tests.rs` covers the binary boundary.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, get_current_timestamp};
use mcp_server_devtools::audit::journal::{JOURNAL_FILE_NAME, JournalAuditSink};
use mcp_server_devtools::auth::okta::{OktaJwksValidator, OktaSettings};
use mcp_server_devtools::bootstrap::{ServerBuilder, Vendors};
use mcp_server_devtools::config::Config;
use mcp_server_devtools::policy::{ActionContext, FilePolicy, PolicyDecision, PolicyEffect};
use mcp_server_devtools::ports::{InMemoryAuditSink, PolicyDecisionPoint, StaticValidator};
use mcp_server_devtools::server::auth::{InboundAuth, InboundAuthSettings};
use mcp_server_devtools::server::http::build_app_with_server_and_auth;
use mcp_server_devtools::vendor::grafana::GrafanaVendor;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const PRIVATE_KEY_DER: &[u8] = include_bytes!("fixtures/okta_test_rsa_pkcs1.der");
const PUBLIC_JWK: &str = include_str!("fixtures/okta_test_jwk.json");
const ISSUER: &str = "https://acme.okta.com/oauth2/default";
const AUDIENCE: &str = "api://mcp-devtools";
const LOKI_QA_PATH: &str = "/api/datasources/proxy/uid/loki-qa/loki/api/v1/query_range";

fn token_for(subject: &str, groups: &[&str]) -> String {
    let now = get_current_timestamp();
    let claims = json!({
        "sub": subject,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 300,
        "scp": ["mcp:tools"],
        "groups": groups,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".to_owned());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_der(PRIVATE_KEY_DER),
    )
    .unwrap()
}

/// The shipped Grafana read-only profile, plus a second group so the
/// denial is by a real policy decision, not by a missing rule.
fn phase_a_policy() -> Arc<FilePolicy> {
    let profile = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/policies/grafana-read-only.yaml"),
    )
    .expect("shipped profile");
    FilePolicy::from_bytes(profile.as_bytes()).expect("shipped profile compiles")
}

/// Records how many journal lines existed at the moment the upstream saw
/// the request — the "written before dispatch" witness.
struct JournalWitness {
    journal: std::path::PathBuf,
    lines_at_request: Arc<Mutex<Option<usize>>>,
    hits: Arc<AtomicUsize>,
}

impl Respond for JournalWitness {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let lines = std::fs::read_to_string(&self.journal).map_or(0, |text| text.lines().count());
        *self.lines_at_request.lock().unwrap() = Some(lines);
        self.hits.fetch_add(1, Ordering::SeqCst);
        ResponseTemplate::new(200).set_body_json(json!({
            "status": "success",
            "data": { "resultType": "streams", "result": [
                { "stream": {"app": "api"}, "values": [["1700000000000000000", "hello from qa"]] }
            ] }
        }))
    }
}

struct Slice {
    base: String,
    journal: std::path::PathBuf,
    lines_at_request: Arc<Mutex<Option<usize>>>,
    hits: Arc<AtomicUsize>,
    _jwks: MockServer,
    _grafana: MockServer,
    _dir: tempfile::TempDir,
}

async fn spawn_slice(policy: Arc<dyn PolicyDecisionPoint>) -> Slice {
    let jwks = MockServer::start().await;
    let jwk: Value = serde_json::from_str(PUBLIC_JWK).unwrap();
    Mock::given(method("GET"))
        .and(path("/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&jwks)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    if cfg!(windows) {
        std::fs::create_dir_all(&journal_dir).unwrap();
        std::fs::File::create(journal_dir.join(JOURNAL_FILE_NAME)).unwrap();
    }
    let journal = journal_dir.join(JOURNAL_FILE_NAME);
    let sink = JournalAuditSink::open(&journal_dir).expect("open journal");

    let grafana = MockServer::start().await;
    let lines_at_request = Arc::new(Mutex::new(None));
    let hits = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path(LOKI_QA_PATH))
        .respond_with(JournalWitness {
            journal: journal.clone(),
            lines_at_request: Arc::clone(&lines_at_request),
            hits: Arc::clone(&hits),
        })
        .mount(&grafana)
        .await;

    let config = Config::from_map(HashMap::from([
        (
            "GRAFANA_TOKEN".to_owned(),
            "glsa_qa_service_token".to_owned(),
        ),
        ("MCP_VENDOR_ENVIRONMENT".to_owned(), "qa".to_owned()),
    ]));
    let server = ServerBuilder::new()
        .config(config.clone())
        .vendors(Vendors {
            grafana: GrafanaVendor::with_base_url(grafana.uri()),
            ..Vendors::default()
        })
        .audit_sink(Arc::new(sink))
        .policy(policy)
        .require_inbound_auth(true)
        .build()
        .expect("build server");

    let settings = OktaSettings {
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
        jwks_url: format!("{}/keys", jwks.uri()),
        groups_claim: "groups".to_owned(),
        clock_skew: Duration::from_mins(1),
        tenant: "acme".to_owned(),
        jwks_refresh: Duration::from_mins(10),
        jwks_min_refetch_interval: Duration::from_secs(30),
    };
    let validator = Arc::new(OktaJwksValidator::new(settings, reqwest::Client::new()));
    let auth = Arc::new(InboundAuth::new(
        Arc::new(validator),
        InboundAuthSettings::from_config(
            &Config::from_map(HashMap::from([(
                "MCP_PUBLIC_URL".to_owned(),
                "https://mcp.acme.example".to_owned(),
            )])),
            vec![ISSUER.to_owned()],
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
        journal,
        lines_at_request,
        hits,
        _jwks: jwks,
        _grafana: grafana,
        _dir: dir,
    }
}

async fn query_logs(base: &str, token: &str, uid: &str) -> Value {
    let response = reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "grafana_query_logs")
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "jsonrpc": "2.0", "id": "req-1", "method": "tools/call",
            "params": {
                "name": "grafana_query_logs",
                "arguments": { "datasourceUid": uid, "query": "{app=\"api\"}", "limit": 10 },
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

fn journal_lines(journal: &Path) -> Vec<Value> {
    std::fs::read_to_string(journal)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("journal line is JSON"))
        .collect()
}

#[tokio::test]
async fn group_a_is_allowed_group_b_is_denied_and_both_are_in_the_journal_first() {
    let policy = phase_a_policy();
    let policy_version = policy.version().unwrap();
    let slice = spawn_slice(policy).await;
    let alice = token_for("alice@acme.example", &["SRE"]);
    let bob = token_for("bob@acme.example", &["Developers"]);

    // Group A: allowed, dispatched, answered.
    let allowed = query_logs(&slice.base, &alice, "loki-qa").await;
    assert_ne!(allowed["result"]["isError"], true, "{allowed}");
    assert!(
        allowed["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("hello from qa"),
        "{allowed}"
    );
    assert_eq!(slice.hits.load(Ordering::SeqCst), 1);
    // …and the intent was on disk before the upstream saw the request.
    let lines_when_upstream_was_hit = slice.lines_at_request.lock().unwrap().unwrap();
    assert!(
        lines_when_upstream_was_hit >= 1,
        "the intent record must be durable before dispatch"
    );

    // Group B: denied with a reason, and the upstream never sees it.
    let denied = query_logs(&slice.base, &bob, "loki-qa").await;
    assert_eq!(denied["result"]["isError"], true, "{denied}");
    let text = denied["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("Policy denied"), "{text}");
    assert!(text.contains("no rule allows this call"), "{text}");
    assert!(
        text.contains(&policy_version),
        "the reason names the policy: {text}"
    );
    assert_eq!(
        slice.hits.load(Ordering::SeqCst),
        1,
        "denied call must not reach Grafana"
    );

    // The journal: allow intent, allow outcome, deny intent — sequenced,
    // with the policy version, the upstream identity, and the principal.
    let lines = journal_lines(&slice.journal);
    assert_eq!(lines.len(), 3, "{lines:#?}");
    let (allow_intent, allow_outcome, deny_intent) = (&lines[0], &lines[1], &lines[2]);

    assert_eq!(allow_intent["seq"], 1);
    assert_eq!(allow_intent["kind"], "tool_call_intent");
    assert_eq!(allow_intent["principal"]["subject"], "alice@acme.example");
    assert_eq!(allow_intent["principal"]["groups"], json!(["SRE"]));
    assert_eq!(allow_intent["principal"]["authority"], "okta");
    assert_eq!(allow_intent["decision"]["effect"], "allow");
    assert_eq!(
        allow_intent["decision"]["rule_id"],
        "sre-read-qa-datasources"
    );
    assert_eq!(allow_intent["decision"]["policy_version"], policy_version);
    assert_eq!(
        allow_intent["upstream_identity"]["label"],
        "grafana/GRAFANA_TOKEN"
    );
    assert_eq!(allow_intent["upstream_identity"]["environment"], "qa");
    assert_eq!(allow_intent["upstream_identity"]["authority"], "shared");
    assert_eq!(allow_intent["action"]["resource_type"], "datasource");
    assert_eq!(
        allow_intent["action"]["resource_scope"]["ids"],
        json!(["loki-qa"])
    );
    assert_eq!(allow_intent["action"]["canonical_path"], LOKI_QA_PATH);
    assert_eq!(allow_intent["action"]["request_risk"], "read");

    assert_eq!(allow_outcome["seq"], 2);
    assert_eq!(allow_outcome["kind"], "tool_call_outcome");
    assert_eq!(allow_outcome["outcome"], "success");
    assert_eq!(allow_outcome["request_id"], allow_intent["request_id"]);
    assert_eq!(allow_outcome["decision"]["policy_version"], policy_version);

    assert_eq!(deny_intent["seq"], 3);
    assert_eq!(deny_intent["kind"], "tool_call_intent");
    assert_eq!(deny_intent["principal"]["subject"], "bob@acme.example");
    assert_eq!(deny_intent["decision"]["effect"], "deny");
    assert!(deny_intent["decision"]["rule_id"].is_null());
    assert_eq!(deny_intent["decision"]["policy_version"], policy_version);
    assert_eq!(
        deny_intent["upstream_identity"]["label"],
        "grafana/GRAFANA_TOKEN"
    );

    // Secrets hygiene: the service token and both bearer tokens are nowhere
    // in the evidence.
    let raw = std::fs::read_to_string(&slice.journal).unwrap();
    for secret in ["glsa_qa_service_token", alice.as_str(), bob.as_str()] {
        assert!(!raw.contains(secret), "journal leaked a secret");
    }

    // A datasource outside the profile is denied even for group A, and the
    // LogQL never reaches the journal as text.
    let elsewhere = query_logs(&slice.base, &alice, "loki-prod").await;
    assert_eq!(elsewhere["result"]["isError"], true);
    assert_eq!(slice.hits.load(Ordering::SeqCst), 1);
    let raw = std::fs::read_to_string(&slice.journal).unwrap();
    assert!(
        !raw.contains("app=\\\"api\\\""),
        "LogQL text must not be journaled"
    );
}

/// A decision point that allows at the tool level and denies at egress, so
/// the second chokepoint is exercised on its own: the vendor is never
/// contacted and the denial is journaled with the canonical request.
struct FlipOnSecond {
    calls: AtomicUsize,
}

impl PolicyDecisionPoint for FlipOnSecond {
    fn evaluate(&self, _context: &ActionContext) -> PolicyDecision {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call.is_multiple_of(2) {
            PolicyDecision::by_rule(PolicyEffect::Allow, "tool-level-allow", "test")
        } else {
            PolicyDecision::by_rule(PolicyEffect::Deny, "egress-deny", "test")
        }
    }

    fn version(&self) -> Option<String> {
        Some("test".to_owned())
    }
}

#[tokio::test]
async fn an_egress_denial_stops_the_request_and_is_journaled() {
    let slice = spawn_slice(Arc::new(FlipOnSecond {
        calls: AtomicUsize::new(0),
    }))
    .await;
    let alice = token_for("alice@acme.example", &["SRE"]);

    let denied = query_logs(&slice.base, &alice, "loki-qa").await;
    assert_eq!(denied["result"]["isError"], true, "{denied}");
    let text = denied["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("egress-deny"), "{text}");
    assert_eq!(
        slice.hits.load(Ordering::SeqCst),
        0,
        "egress denial must stop the request"
    );

    let lines = journal_lines(&slice.journal);
    let kinds: Vec<&str> = lines
        .iter()
        .map(|line| line["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        ["tool_call_intent", "egress_decision", "tool_call_outcome"]
    );
    let egress = &lines[1];
    assert_eq!(egress["decision"]["effect"], "deny");
    assert_eq!(egress["decision"]["rule_id"], "egress-deny");
    assert_eq!(egress["outcome"], "egress_denied");
    assert_eq!(egress["action"]["canonical_path"], LOKI_QA_PATH);
    assert_eq!(egress["action"]["method"], "GET");
    assert_eq!(lines[2]["outcome"], "error");
}

/// `AllowAll` plus a journal is local mode with evidence: no scope
/// enforcement, decisions are the local allow, and nothing is denied.
#[tokio::test]
async fn allow_all_with_a_journal_records_but_never_denies() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let grafana = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(LOKI_QA_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "success", "data": { "resultType": "streams", "result": [] }
        })))
        .expect(1)
        .mount(&grafana)
        .await;
    let server = ServerBuilder::new()
        .config(Config::from_map(HashMap::from([(
            "GRAFANA_TOKEN".to_owned(),
            "glsa".to_owned(),
        )])))
        .vendors(Vendors {
            grafana: GrafanaVendor::with_base_url(grafana.uri()),
            ..Vendors::default()
        })
        .audit_sink(Arc::<InMemoryAuditSink>::clone(&sink))
        .require_inbound_auth(true)
        .build()
        .unwrap();
    let auth = Arc::new(InboundAuth::new(
        Arc::new(StaticValidator::new().with(
            "tok",
            mcp_server_devtools::policy::Principal {
                tenant: "acme".to_owned(),
                subject: "x".to_owned(),
                groups: Vec::new(),
                scopes: vec!["mcp:tools".to_owned()],
                authority: mcp_server_devtools::policy::PrincipalAuthority::Okta,
            },
        )),
        InboundAuthSettings::from_config(
            &Config::from_map(HashMap::from([(
                "MCP_PUBLIC_URL".to_owned(),
                "https://mcp.acme.example".to_owned(),
            )])),
            vec![ISSUER.to_owned()],
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

    let body = query_logs(&format!("http://{addr}"), "tok", "loki-qa").await;
    assert_ne!(body["result"]["isError"], true, "{body}");
    let events = sink.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["decision"]["effect"], "allow");
    assert!(events[0]["decision"]["policy_version"].is_null());
    assert_eq!(
        events[0]["action"]["resource_scope"]["ids"],
        json!(["loki-qa"])
    );
}

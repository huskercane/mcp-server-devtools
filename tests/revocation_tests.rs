//! WP B.4: revocation (plan §3.6) over the real HTTP router.
//!
//! - A subject named by the signed revocation list is refused at the next
//!   request once the list is reloaded — cached validation or not — with a
//!   `revoked` challenge, and the refusal is a control record in the journal.
//! - `revoke all` (a `not_before` cut-off) refuses every token issued before
//!   it and closes the sessions those tokens opened.
//! - A non-read call needs a token issued within `MCP_WRITE_MAX_TOKEN_AGE_SECONDS`.
//! - The group-removal window: a token minted before a group change keeps
//!   its groups until it expires or its subject is revoked (measured).
//! - `mcp-devtools revoke …` round-trips at the binary boundary and refuses
//!   to re-sign a list its key did not sign.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use assert_cmd::cargo::cargo_bin;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, get_current_timestamp};
use mcp_server_devtools::auth::okta::{OktaJwksValidator, OktaSettings};
use mcp_server_devtools::auth::revocation::{
    NotBefore, RevocationFile, RevocationList, RevokedSubject,
};
use mcp_server_devtools::bootstrap::{ServerBuilder, Vendors};
use mcp_server_devtools::config::Config;
use mcp_server_devtools::policy::signing::{Domain, SigningKey, write_detached};
use mcp_server_devtools::policy::{BundleAudit, FilePolicy, Principal, PrincipalAuthority};
use mcp_server_devtools::ports::{
    AllowAll, AuditSink, InMemoryAuditSink, StaticValidator, TokenFacts,
};
use mcp_server_devtools::server::auth::{InboundAuth, InboundAuthSettings};
use mcp_server_devtools::server::http::build_app_with_server_and_auth;
use mcp_server_devtools::tools::DevtoolsServer;
use mcp_server_devtools::vendor::grafana::GrafanaVendor;
use mcp_server_devtools::vendor::jira::JiraVendor;
use pretty_assertions::assert_eq;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BIN: &str = "mcp-devtools";
const ALICE: &str = "alice-token";
const BOB: &str = "bob-token";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn principal(subject: &str, groups: &[&str]) -> Principal {
    Principal {
        tenant: "acme".to_owned(),
        subject: subject.to_owned(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
        scopes: vec!["mcp:tools".to_owned()],
        authority: PrincipalAuthority::Okta,
    }
}

fn facts(issued_at: u64, jti: &str) -> TokenFacts {
    TokenFacts {
        issued_at: Some(issued_at),
        token_id: Some(jti.to_owned()),
    }
}

/// A signed revocation list on disk, plus the key that signs it.
struct Signed {
    _dir: tempfile::TempDir,
    file: PathBuf,
    key: SigningKey,
}

impl Signed {
    fn empty() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("revocations.yaml");
        let (key, _) = SigningKey::generate().unwrap();
        let signed = Self {
            _dir: dir,
            file,
            key,
        };
        signed.write(&RevocationFile::empty());
        signed
    }

    fn write(&self, list: &RevocationFile) {
        let yaml = list.to_yaml().unwrap();
        std::fs::write(&self.file, &yaml).unwrap();
        write_detached(
            &self.file,
            &self.key.sign(Domain::RevocationList, yaml.as_bytes()),
        )
        .unwrap();
    }

    fn load(&self) -> Arc<RevocationList> {
        RevocationList::load_verified(&self.file, self.key.verifying_key()).unwrap()
    }

    fn revoke_subject(&self, subject: &str) {
        let mut list = RevocationFile::parse(&std::fs::read(&self.file).unwrap()).unwrap();
        list.subjects.push(RevokedSubject {
            subject: subject.to_owned(),
            revoked_at: "2026-09-03T10:00:00Z".to_owned(),
            reason: Some("test".to_owned()),
        });
        self.write(&list);
    }

    fn revoke_all_at(&self, at: &str) {
        let mut list = RevocationFile::parse(&std::fs::read(&self.file).unwrap()).unwrap();
        list.not_before = Some(NotBefore {
            at: at.to_owned(),
            reason: None,
        });
        self.write(&list);
    }
}

fn rfc3339(epoch: u64) -> String {
    chrono::DateTime::from_timestamp(i64::try_from(epoch).unwrap(), 0)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn settings() -> InboundAuthSettings {
    InboundAuthSettings::from_config(
        &Config::from_map(HashMap::from([(
            "MCP_PUBLIC_URL".to_owned(),
            "https://mcp.acme.example".to_owned(),
        )])),
        vec!["https://acme.okta.com/oauth2/default".to_owned()],
    )
    .unwrap()
}

fn server(sink: &Arc<InMemoryAuditSink>, config: Config, vendors: Vendors) -> DevtoolsServer {
    ServerBuilder::new()
        .config(config)
        .vendors(vendors)
        .audit_sink(Arc::clone(sink) as Arc<dyn AuditSink>)
        .policy(Arc::new(AllowAll))
        .require_inbound_auth(true)
        .build()
        .unwrap()
}

async fn spawn(app: axum::Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn spawn_with(
    server: DevtoolsServer,
    validator: Arc<dyn mcp_server_devtools::ports::TokenValidator>,
    list: Arc<RevocationList>,
    sink: &Arc<InMemoryAuditSink>,
) -> String {
    let auth = InboundAuth::new(validator, settings())
        .with_revocations(list)
        .with_audit(BundleAudit {
            sink: Arc::clone(sink) as Arc<dyn AuditSink>,
            append_timeout: Duration::from_secs(5),
        });
    spawn(build_app_with_server_and_auth(
        server,
        Arc::new(auth),
        Duration::from_mins(5),
        Duration::from_mins(5),
        CancellationToken::new(),
    ))
    .await
}

#[allow(clippy::needless_pass_by_value)] // `json!` literals at every call site
fn stateless(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    body: Value,
) -> reqwest::RequestBuilder {
    client
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("authorization", format!("Bearer {token}"))
        .json(&body)
}

fn tools_list(client: &reqwest::Client, base: &str, token: &str) -> reqwest::RequestBuilder {
    stateless(
        client,
        base,
        token,
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": { "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": { "name": "revocation-test", "version": "0" }
            } }
        }),
    )
    .header("Mcp-Method", "tools/list")
}

#[allow(clippy::needless_pass_by_value)] // `json!` literals at every call site
fn tool_call(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    tool: &str,
    arguments: Value,
) -> reqwest::RequestBuilder {
    stateless(
        client,
        base,
        token,
        json!({
            "jsonrpc": "2.0", "id": "req-1", "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": { "name": "revocation-test", "version": "0" }
                }
            }
        }),
    )
    .header("Mcp-Method", "tools/call")
    .header("Mcp-Name", tool)
}

async fn rpc_result(response: reqwest::Response) -> Value {
    let body = response.text().await.unwrap();
    serde_json::from_str(&body).unwrap_or_else(|_| {
        body.lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .find_map(|data| serde_json::from_str(data.trim()).ok())
            .unwrap_or_else(|| panic!("unparseable: {body}"))
    })
}

fn www_authenticate(response: &reqwest::Response) -> String {
    response
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn events(sink: &InMemoryAuditSink, kind: &str) -> Vec<Value> {
    sink.events()
        .into_iter()
        .filter(|event| event["kind"] == kind)
        .collect()
}

/// Poll until `request` answers `status`, returning how long it took.
async fn wait_for_status(
    request: impl Fn() -> reqwest::RequestBuilder,
    status: StatusCode,
    bound: Duration,
) -> Duration {
    let started = Instant::now();
    loop {
        let response = request().send().await.unwrap();
        if response.status() == status {
            return started.elapsed();
        }
        assert!(
            started.elapsed() < bound,
            "still {} after {:?}; wanted {status}",
            response.status(),
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_subject_is_refused_within_a_poll_and_the_refusal_is_journaled() {
    let signed = Signed::empty();
    let list = signed.load();
    let sink = Arc::new(InMemoryAuditSink::new());
    let validator = StaticValidator::new()
        .with_facts(ALICE, principal("alice", &[]), facts(now(), "jti-alice"))
        .with_facts(BOB, principal("bob", &[]), facts(now(), "jti-bob"));
    let base = spawn_with(
        server(&sink, Config::from_map(HashMap::new()), Vendors::default()),
        Arc::new(validator),
        list,
        &sink,
    )
    .await;
    let client = reqwest::Client::new();

    assert_eq!(
        tools_list(&client, &base, ALICE)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    signed.revoke_subject("alice");
    let window = wait_for_status(
        || tools_list(&client, &base, ALICE),
        StatusCode::UNAUTHORIZED,
        Duration::from_secs(3),
    )
    .await;
    println!("revocation by subject took effect after {window:?}");
    assert!(window < Duration::from_secs(2), "{window:?}");

    let refused = tools_list(&client, &base, ALICE).send().await.unwrap();
    let challenge = www_authenticate(&refused);
    assert!(challenge.contains("error=\"invalid_token\""), "{challenge}");
    assert!(
        challenge.contains("error_description=\"revoked\""),
        "{challenge}"
    );
    let body: Value = refused.json().await.unwrap();
    assert_eq!(body["error_description"], "the token has been revoked");

    // Bob is untouched.
    assert_eq!(
        tools_list(&client, &base, BOB)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    // The change and every refusal are in the journal, in order.
    let changed = events(&sink, "revocation_changed");
    assert_eq!(changed.len(), 1, "{changed:?}");
    assert_eq!(changed[0]["revoked_subjects"], 1);
    assert_eq!(changed[0]["revoked_tokens"], 0);
    assert_eq!(changed[0]["signature"]["verified"], true);
    let loaded = events(&sink, "revocation_loaded");
    assert_eq!(loaded.len(), 1);
    assert!(loaded[0]["seq"].as_u64() < changed[0]["seq"].as_u64());
    let rejected = events(&sink, "revoked_token_rejected");
    assert!(!rejected.is_empty());
    assert_eq!(rejected[0]["principal"]["subject"], "alice");
    assert_eq!(rejected[0]["reason"], "subject");
    assert_eq!(rejected[0]["version"], changed[0]["version"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_all_refuses_tokens_issued_before_the_cutoff_and_closes_their_sessions() {
    let signed = Signed::empty();
    let list = signed.load();
    let sink = Arc::new(InMemoryAuditSink::new());
    let issued = now() - 100;
    let validator = StaticValidator::new()
        .with_facts(ALICE, principal("alice", &[]), facts(issued, "jti-old"))
        .with_facts(
            "alice-fresh",
            principal("alice", &[]),
            facts(now() + 3600, "jti-new"),
        );
    let base = spawn_with(
        server(&sink, Config::from_map(HashMap::new()), Vendors::default()),
        Arc::new(validator),
        list,
        &sink,
    )
    .await;
    let client = reqwest::Client::new();

    // A legacy session, opened with the old token.
    let created = client
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {ALICE}"))
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "revocation-test", "version": "0" }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let session = created
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_owned();
    let ping = |token: &str| {
        client
            .post(format!("{base}/mcp"))
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .header("mcp-session-id", &session)
            .header("authorization", format!("Bearer {token}"))
            .json(&json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" }))
    };
    assert_eq!(ping(ALICE).send().await.unwrap().status(), StatusCode::OK);

    signed.revoke_all_at(&rfc3339(now()));
    let window = wait_for_status(
        || tools_list(&client, &base, ALICE),
        StatusCode::UNAUTHORIZED,
        Duration::from_secs(3),
    )
    .await;
    println!("revoke-all took effect after {window:?}");

    // The fresh token (issued after the cut-off) still works stateless…
    assert_eq!(
        tools_list(&client, &base, "alice-fresh")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    // …but the session the old token opened is gone, even for the same
    // subject: a session cannot say which token created it.
    let closed = wait_for_status(
        || ping("alice-fresh"),
        StatusCode::NOT_FOUND,
        Duration::from_secs(3),
    )
    .await;
    println!("session closed after {closed:?}");

    let changed = events(&sink, "revocation_changed");
    assert_eq!(changed.len(), 1);
    assert!(changed[0]["not_before"].is_string());
    let rejected = events(&sink, "revoked_token_rejected");
    assert_eq!(rejected[0]["reason"], "not_before");
}

// One scenario per token kind, in sequence; splitting would hide the contrast.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_read_calls_need_a_fresh_token_reads_do_not() {
    let jira = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "alice"})))
        .mount(&jira)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/issue"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"key": "PLAT-1"})))
        .mount(&jira)
        .await;
    let signed = Signed::empty();
    let sink = Arc::new(InMemoryAuditSink::new());
    let validator = StaticValidator::new()
        .with_facts(
            "stale",
            principal("alice", &[]),
            facts(now() - 600, "jti-stale"),
        )
        .with_facts(
            "fresh",
            principal("alice", &[]),
            facts(now() - 10, "jti-fresh"),
        )
        .with_facts("undated", principal("alice", &[]), TokenFacts::default());
    let config = Config::from_map(HashMap::from([
        ("ATLASSIAN_SITE_NAME".to_owned(), "acme".to_owned()),
        (
            "ATLASSIAN_USER_EMAIL".to_owned(),
            "alice@acme.example".to_owned(),
        ),
        ("ATLASSIAN_API_TOKEN".to_owned(), "token".to_owned()),
    ]));
    let base = spawn_with(
        server(
            &sink,
            config,
            Vendors {
                jira: JiraVendor::with_base_url(jira.uri()),
                ..Vendors::default()
            },
        ),
        Arc::new(validator),
        signed.load(),
        &sink,
    )
    .await;
    let client = reqwest::Client::new();
    let post = json!({ "path": "/rest/api/3/issue", "body": { "fields": {} } });

    for token in ["stale", "undated"] {
        let response = tool_call(&client, &base, token, "jira_post", post.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let result = rpc_result(response).await;
        assert_eq!(result["result"]["isError"], true, "{token}: {result}");
        let text = result["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("fresh token"), "{token}: {text}");
        // A read with the same token is fine.
        let read = rpc_result(
            tool_call(
                &client,
                &base,
                token,
                "jira_get",
                json!({ "path": "/rest/api/3/myself" }),
            )
            .send()
            .await
            .unwrap(),
        )
        .await;
        assert_ne!(read["result"]["isError"], true, "{token}: {read}");
    }
    let result = rpc_result(
        tool_call(&client, &base, "fresh", "jira_post", post)
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_ne!(result["result"]["isError"], true, "{result}");
    assert_eq!(
        jira.received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method == "POST")
            .count(),
        1,
        "only the fresh token's write reached the vendor"
    );

    // The refusals are denials in the journal, under the policy in force.
    let denied: Vec<Value> = events(&sink, "tool_call_intent")
        .into_iter()
        .filter(|event| event["decision"]["effect"] == "deny")
        .collect();
    assert_eq!(denied.len(), 2, "{denied:?}");
    assert!(
        denied[0]["decision"]["reason"]
            .as_str()
            .unwrap()
            .contains("no older than 300s"),
        "{:?}",
        denied[0]
    );
}

// --- the group-removal window, with the real Okta validator ----------------

const PRIVATE_KEY_DER: &[u8] = include_bytes!("fixtures/okta_test_rsa_pkcs1.der");
const PUBLIC_JWK: &str = include_str!("fixtures/okta_test_jwk.json");
const ISSUER: &str = "https://acme.okta.com/oauth2/default";
const AUDIENCE: &str = "api://mcp-devtools";

fn okta_token(subject: &str, groups: &[&str], jti: &str, ttl: u64) -> String {
    let now = get_current_timestamp();
    let claims = json!({
        "sub": subject, "iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + ttl,
        "jti": jti, "scp": ["mcp:tools"], "groups": groups,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_removal_waits_for_the_token_but_revocation_does_not() {
    let jwks = MockServer::start().await;
    let jwk: Value = serde_json::from_str(PUBLIC_JWK).unwrap();
    Mock::given(method("GET"))
        .and(path("/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(&jwks)
        .await;
    let grafana = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/datasources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "uid": "loki-qa" }])))
        .mount(&grafana)
        .await;

    let policy = FilePolicy::from_bytes(
        b"version: 1\nrules:\n  - id: sre-list\n    effect: allow\n    subjects: { groups: [SRE] }\n    match: { vendor: grafana, normalized_action: list_datasources }\n",
    )
    .unwrap();
    let sink = Arc::new(InMemoryAuditSink::new());
    let server = ServerBuilder::new()
        .config(Config::from_map(HashMap::from([
            ("GRAFANA_TOKEN".to_owned(), "glsa".to_owned()),
            ("MCP_VENDOR_ENVIRONMENT".to_owned(), "qa".to_owned()),
        ])))
        .vendors(Vendors {
            grafana: GrafanaVendor::with_base_url(grafana.uri()),
            ..Vendors::default()
        })
        .audit_sink(Arc::clone(&sink) as Arc<dyn AuditSink>)
        .policy(policy)
        .require_inbound_auth(true)
        .build()
        .unwrap();
    let validator = Arc::new(OktaJwksValidator::new(
        OktaSettings {
            issuer: ISSUER.to_owned(),
            audience: AUDIENCE.to_owned(),
            jwks_url: format!("{}/keys", jwks.uri()),
            groups_claim: "groups".to_owned(),
            clock_skew: Duration::from_mins(1),
            tenant: "acme".to_owned(),
            jwks_refresh: Duration::from_mins(10),
            jwks_min_refetch_interval: Duration::from_secs(30),
        },
        reqwest::Client::new(),
    ));
    let signed = Signed::empty();
    let base = spawn_with(server, Arc::new(validator), signed.load(), &sink).await;
    let client = reqwest::Client::new();
    let list_datasources =
        |token: &str| tool_call(&client, &base, token, "grafana_list_datasources", json!({}));

    // The token minted while alice was in SRE is allowed…
    let with_group = okta_token("alice", &["SRE"], "jti-1", 300);
    let allowed = rpc_result(list_datasources(&with_group).send().await.unwrap()).await;
    assert_ne!(allowed["result"]["isError"], true, "{allowed}");

    // …the identity provider removes the group: the *next* token is denied…
    let without_group = okta_token("alice", &[], "jti-2", 300);
    let denied = rpc_result(list_datasources(&without_group).send().await.unwrap()).await;
    assert_eq!(denied["result"]["isError"], true, "{denied}");
    assert!(
        denied["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Policy denied"),
    );

    // …but the old token still carries the group until it expires or its
    // cache entry does: that is the §3.6 window (≤ token TTL + 5 min),
    // and it is what the revocation list exists to cut short.
    let still_allowed = rpc_result(list_datasources(&with_group).send().await.unwrap()).await;
    assert_ne!(still_allowed["result"]["isError"], true, "{still_allowed}");

    signed.revoke_subject("alice");
    let window = wait_for_status(
        || list_datasources(&with_group),
        StatusCode::UNAUTHORIZED,
        Duration::from_secs(3),
    )
    .await;
    println!(
        "group removal alone: bounded by token TTL (300s here) + cache TTL; \
         revocation by subject took effect after {window:?}"
    );
    assert!(window < Duration::from_secs(2), "{window:?}");
    // Both facts are in the journal: the denial by policy and the refusal
    // by revocation, in that order.
    let denials = events(&sink, "tool_call_intent")
        .into_iter()
        .filter(|event| event["decision"]["effect"] == "deny")
        .count();
    assert_eq!(denials, 1);
    let rejected = events(&sink, "revoked_token_rejected");
    assert_eq!(rejected[0]["principal"]["subject"], "alice");
    assert_eq!(rejected[0]["principal"]["groups"], json!(["SRE"]));
}

// --- the CLI --------------------------------------------------------------

fn run(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(cargo_bin(BIN))
        .args(args)
        .env_remove("MCP_AUDIT_JOURNAL_DIR")
        .output()
        .expect("spawn binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn arg(path: &Path) -> String {
    path.display().to_string()
}

// The whole operator workflow, start to finish, at the binary boundary.
#[allow(clippy::too_many_lines)]
#[test]
fn revoke_cli_edits_and_resigns_the_list_and_refuses_a_list_it_did_not_sign() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("signing.key");
    let file = dir.path().join("revocations.yaml");
    let (ok, stdout, stderr) = run(&["policy", "keygen", "--out", &arg(&key), "--json"]);
    assert!(ok, "{stderr}");
    let public_key = serde_json::from_str::<Value>(stdout.trim()).unwrap()["public_key"]
        .as_str()
        .unwrap()
        .to_owned();
    let verifier = mcp_server_devtools::policy::VerifyingKey::from_base64(&public_key).unwrap();

    let (ok, _, stderr) = run(&["revoke", "init", "--file", &arg(&file), "--key", &arg(&key)]);
    assert!(ok, "{stderr}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "version: 1\n");
    let list = RevocationList::load_verified(&file, verifier.clone()).unwrap();
    assert_eq!(list.snapshot().document.subject_count(), 0);
    let (ok, _, stderr) = run(&["revoke", "init", "--file", &arg(&file), "--key", &arg(&key)]);
    assert!(!ok, "init must not clobber an existing list");
    assert!(stderr.contains("already exists"), "{stderr}");

    let (ok, _, stderr) = run(&[
        "revoke",
        "subject",
        "alice@acme.example",
        "--reason",
        "offboarded",
        "--file",
        &arg(&file),
        "--key",
        &arg(&key),
    ]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = run(&[
        "revoke",
        "token",
        "AT.leaked",
        "--file",
        &arg(&file),
        "--key",
        &arg(&key),
    ]);
    assert!(ok, "{stderr}");
    let (ok, stdout, stderr) = run(&[
        "revoke",
        "all",
        "--reason",
        "key rotated",
        "--file",
        &arg(&file),
        "--key",
        &arg(&key),
        "--json",
    ]);
    assert!(ok, "{stderr}");
    let summary: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(summary["subjects"], 1);
    assert_eq!(summary["token_ids"], 1);
    assert!(summary["not_before"].is_string());

    let list = RevocationList::load_verified(&file, verifier.clone()).unwrap();
    let document = &list.snapshot().document;
    assert!(document.revokes_subject("alice@acme.example"));
    assert_eq!(document.token_count(), 1);
    assert!(document.not_before_epoch().is_some());

    let (ok, stdout, stderr) = run(&[
        "revoke",
        "show",
        "--file",
        &arg(&file),
        "--public-key",
        &public_key,
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("signature verified"), "{stdout}");
    assert!(stdout.contains("alice@acme.example"), "{stdout}");
    assert!(stdout.contains("reason: offboarded"), "{stdout}");

    let (ok, _, stderr) = run(&[
        "revoke",
        "remove",
        "subject",
        "alice@acme.example",
        "--file",
        &arg(&file),
        "--key",
        &arg(&key),
    ]);
    assert!(ok, "{stderr}");
    let (ok, _, stderr) = run(&[
        "revoke",
        "remove",
        "subject",
        "nobody",
        "--file",
        &arg(&file),
        "--key",
        &arg(&key),
    ]);
    assert!(!ok);
    assert!(stderr.contains("no subject entry"), "{stderr}");
    let (ok, _, stderr) = run(&[
        "revoke",
        "clear-all",
        "--file",
        &arg(&file),
        "--key",
        &arg(&key),
    ]);
    assert!(ok, "{stderr}");
    let list = RevocationList::load_verified(&file, verifier).unwrap();
    assert!(
        !list
            .snapshot()
            .document
            .revokes_subject("alice@acme.example")
    );
    assert!(list.snapshot().document.not_before_epoch().is_none());

    // A list edited by hand without re-signing is not laundered into a
    // signed one by the next edit.
    std::fs::write(
        &file,
        "version: 1\nsubjects:\n  - subject: mallory\n    revoked_at: x\n",
    )
    .unwrap();
    let (ok, _, stderr) = run(&[
        "revoke",
        "token",
        "AT.x",
        "--file",
        &arg(&file),
        "--key",
        &arg(&key),
    ]);
    assert!(!ok);
    assert!(stderr.contains("does not verify"), "{stderr}");
}

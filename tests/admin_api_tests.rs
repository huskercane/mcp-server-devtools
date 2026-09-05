//! C.4 contracts over real HTTP, real signed files and `SQLite`.
use mcp_server_devtools::{
    bootstrap::ServerBuilder,
    config::Config,
    policy::{
        Principal, PrincipalAuthority,
        signing::{Domain, SigningKey, write_detached},
    },
    ports::{InMemoryAuditSink, StaticValidator},
    server::{
        auth::{InboundAuth, InboundAuthSettings},
        http::{Role, build_app_for_role},
        rate_limit::{RateLimitSettings, RateLimiter},
    },
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

struct Fixture {
    dir: tempfile::TempDir,
    url: String,
    sink: Arc<InMemoryAuditSink>,
    policy: std::path::PathBuf,
    key: SigningKey,
    cancel: CancellationToken,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
async fn fixture(role: Role) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.yaml");
    let (key, _) = SigningKey::generate().unwrap();
    let document = b"version: 1\nrules: []\n";
    std::fs::write(&policy, document).unwrap();
    write_detached(&policy, &key.sign(Domain::PolicyBundle, document)).unwrap();
    let revocation_path = dir.path().join("revocations.yaml");
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
    let sink = Arc::new(InMemoryAuditSink::new());
    let config = Config::from_map(HashMap::from([
        ("MCP_POLICY_FILE".into(), policy.display().to_string()),
        (
            "MCP_POLICY_PUBLIC_KEY".into(),
            key.verifying_key().to_base64(),
        ),
        (
            "MCP_ROLLUP_STORE".into(),
            format!("sqlite://{}", dir.path().join("rollups.sqlite").display()),
        ),
    ]));
    let server = ServerBuilder::new()
        .config(config)
        .serves_control(true)
        .audit_sink(sink.clone())
        .build()
        .unwrap();
    let principal = |scopes: &[&str]| Principal {
        tenant: "tenant".into(),
        subject: "alice".into(),
        groups: vec![],
        scopes: scopes.iter().map(|s| (*s).into()).collect(),
        authority: PrincipalAuthority::oidc("https://issuer.example"),
    };
    let auth = Arc::new(
        InboundAuth::new(
            Arc::new(
                StaticValidator::new()
                    .with("admin", principal(&["mcp:admin"]))
                    .with("tools", principal(&["mcp:tools"]))
                    .with("both", principal(&["mcp:tools", "mcp:admin"])),
            ),
            InboundAuthSettings {
                public_url: "https://mcp.example".into(),
                authorization_servers: vec!["https://issuer.example".into()],
                required_scope: "mcp:tools".into(),
            },
        )
        .with_revocations(revocations)
        .with_rate_limit(Arc::new(RateLimiter::new(RateLimitSettings {
            per_second: 0.01,
            burst: 1.0,
        }))),
    );
    let cancel = CancellationToken::new();
    let app = build_app_for_role(
        role,
        server,
        Some(auth),
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
        dir,
        url,
        sink,
        policy,
        key,
        cancel,
    }
}
async fn post(f: &Fixture, op: &str, body: Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}/admin/{op}", f.url))
        .bearer_auth("admin")
        .json(&body)
        .send()
        .await
        .unwrap()
}
#[tokio::test]
async fn auth_role_and_json_contracts() {
    let f = fixture(Role::Control).await;
    let client = reqwest::Client::new();
    for (token, status) in [("", 401), ("tools", 403), ("admin", 200)] {
        let response = client
            .get(format!("{}/admin/policy", f.url))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        let body: Value = response.json().await.unwrap();
        if status == 200 {
            assert_eq!(body["data"]["document"], "version: 1\nrules: []\n");
            assert_eq!(body["data"]["signature"]["verified"], true);
            assert_eq!(body["data"].as_object().unwrap().len(), 3);
        } else {
            assert!(body["error"].is_string());
        }
    }
    assert_eq!(
        client
            .post(format!("{}/mcp", f.url))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .get(format!("{}/admin/sessions", f.url))
            .bearer_auth("admin")
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap(),
        json!({"error":"admin_backend_unavailable", "error_description":"admin_backend_unavailable"})
    );
    let f = fixture(Role::Gateway).await;
    assert_eq!(
        client
            .get(format!("{}/admin/policy", f.url))
            .bearer_auth("admin")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}
#[tokio::test]
async fn reload_is_fail_closed_and_candidate_shapes_are_locked() {
    let f = fixture(Role::All).await;
    let candidate = "version: 1\nrules: []\n# new revision\n";
    let body = post(&f, "policy/validate", json!({"document":candidate}))
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(body["data"]["valid"], true);
    assert_eq!(body["data"]["signature_verified"], false);
    assert_eq!(body["data"].as_object().unwrap().len(), 4);
    let diff = post(&f, "policy/diff", json!({"document":candidate}))
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(diff["data"].as_object().unwrap().len(), 4);
    assert_ne!(
        diff["data"]["current_version"],
        diff["data"]["candidate_version"]
    );
    std::fs::write(&f.policy, candidate).unwrap();
    assert_eq!(post(&f, "policy/reload", json!({})).await.status(), 400);
    write_detached(
        &f.policy,
        &f.key.sign(Domain::PolicyBundle, candidate.as_bytes()),
    )
    .unwrap();
    f.sink.set_failing(true);
    assert_eq!(
        post(&f, "policy/reload", json!({}))
            .await
            .json::<Value>()
            .await
            .unwrap(),
        json!({"error":"audit_unavailable", "error_description":"audit_unavailable"})
    );
    f.sink.set_failing(false);
    let result = post(&f, "policy/reload", json!({}))
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(result["data"]["changed"], true);
    assert_eq!(result["data"]["version"], diff["data"]["candidate_version"]);
    let records = f.sink.events();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["kind"], "admin_mutation");
    assert_eq!(records[0]["principal"]["subject"], "alice");
    assert_eq!(result["data"]["audit_seq"], records[0]["seq"]);
}
#[tokio::test]
async fn reports_sqlite_and_inventory_are_live() {
    let f = fixture(Role::All).await;
    let usage = post(&f, "usage", json!({"report":"totals","window":{}}))
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(usage["data"]["shape"], "totals");
    assert_eq!(usage["data"]["rows"], 0);
    let access = post(
        &f,
        "reports/access-review",
        json!({"groups":{},"tenant":"tenant"}),
    )
    .await
    .json::<Value>()
    .await
    .unwrap();
    assert_eq!(access, json!({"data":{"rows":[]}}));
    let lookup = post(
        &f,
        "principals/lookup",
        json!({"subject":"alice","tenant":"tenant"}),
    )
    .await
    .json::<Value>()
    .await
    .unwrap();
    assert_eq!(
        lookup,
        json!({"data":{"subject":"alice","tenant":"tenant","scope":"process","principal":{"tenant":"tenant","subject":"alice","groups":[],"scopes":["mcp:admin"],"authority":"https://issuer.example"},"sessions":[],"subject_denied":false}})
    );
    assert_eq!(
        post(&f, "sessions/revoke", json!({"id":"unknown"}))
            .await
            .status(),
        404
    );
    assert_eq!(
        f.sink.events().len(),
        1,
        "attempt durably recorded even when target disappeared"
    );
    assert_eq!(
        post(
            &f,
            "policy/validate",
            json!({"document":"bad","unexpected":true})
        )
        .await
        .json::<Value>()
        .await
        .unwrap(),
        json!({"error":"invalid_request","error_description":"invalid_request"})
    );
}
#[tokio::test]
async fn admin_limiter_is_independent_of_mcp() {
    let f = fixture(Role::All).await;
    let client = reqwest::Client::new();
    for _ in 0..2 {
        client
            .post(format!("{}/mcp", f.url))
            .bearer_auth("both")
            .body("{}")
            .send()
            .await
            .unwrap();
    }
    let response = client
        .get(format!("{}/admin/policy", f.url))
        .bearer_auth("both")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let mut limited = false;
    for _ in 0..20 {
        if client
            .get(format!("{}/admin/policy", f.url))
            .bearer_auth("both")
            .send()
            .await
            .unwrap()
            .status()
            == 429
        {
            limited = true;
            break;
        }
    }
    assert!(limited);
}

#[tokio::test]
async fn signed_deny_list_replace_is_audited_persistent_and_enforced() {
    let f = fixture(Role::All).await;
    let client = reqwest::Client::new();
    let document = "version: 1\nsubjects:\n- subject: alice\n  revoked_at: 2026-09-04T00:00:00Z\ntoken_ids: []\n";
    let request = json!({"document": document, "signature": f.key.sign(Domain::RevocationList, document.as_bytes()).to_base64()});
    f.sink.set_failing(true);
    let response = client
        .put(format!("{}/admin/deny-list", f.url))
        .bearer_auth("admin")
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    let path = f.dir.path().join("revocations.yaml");
    assert!(!std::fs::read_to_string(&path).unwrap().contains("alice"));
    f.sink.set_failing(false);
    let response = client
        .put(format!("{}/admin/deny-list", f.url))
        .bearer_auth("admin")
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["data"].as_object().unwrap().len(), 2);
    assert_eq!(f.sink.events()[0]["source"], "deny-list/replace");
    let reloaded = mcp_server_devtools::auth::revocation::RevocationList::load_verified(
        &path,
        f.key.verifying_key(),
    )
    .unwrap();
    assert!(reloaded.snapshot().document.revokes_subject("alice"));
    assert_eq!(
        client
            .get(format!("{}/admin/policy", f.url))
            .bearer_auth("admin")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
}

#[tokio::test]
async fn artifact_purge_uses_real_pin_aware_backend_and_fails_closed() {
    use mcp_server_devtools::transport::raw_response;
    let f = fixture(Role::All).await;
    let path = raw_response::save_artifact("admin-test", "fixture body")
        .await
        .unwrap();
    let artifact = raw_response::artifact_for_path(&path).unwrap();
    let pin =
        raw_response::pin_artifact(&artifact.id, &mcp_server_devtools::policy::OwnerKey::Local)
            .unwrap();
    let response = reqwest::Client::new()
        .get(format!("{}/admin/artifacts", f.url))
        .bearer_auth("admin")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let row = response["data"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == artifact.id)
        .unwrap();
    assert_eq!(row.as_object().unwrap().len(), 4);
    assert!(row.get("path").is_none());
    f.sink.set_failing(true);
    assert_eq!(
        post(&f, "artifacts/purge", json!({"id":artifact.id}))
            .await
            .status(),
        503
    );
    assert!(raw_response::artifact(&artifact.id).is_some());
    f.sink.set_failing(false);
    let response = post(&f, "artifacts/purge", json!({"id":artifact.id}))
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        response,
        json!({"data":{"audit_seq":1,"id":artifact.id,"scope":"process"}})
    );
    assert!(raw_response::artifact(&artifact.id).is_none());
    assert!(path.exists(), "existing read pin delays physical deletion");
    drop(pin);
}

#[tokio::test]
async fn durable_journal_activity_adapter_reads_control_evidence() {
    use mcp_server_devtools::{
        audit::{
            export::{ActivityFilter, JournalActivityReports},
            journal::{JOURNAL_FILE_NAME, JournalAuditSink},
        },
        ports::{AuditSink, ControlEvent, ControlEventKind, activity_reports::ActivityReports},
    };
    let directory = tempfile::tempdir().unwrap();
    let sink = JournalAuditSink::open(directory.path()).unwrap();
    let event = ControlEvent::now(ControlEventKind::AdminMutation);
    let seq = sink.append_control(&event).await.unwrap();
    let reports = JournalActivityReports::new(directory.path().join(JOURNAL_FILE_NAME));
    let result = reports.activity(&ActivityFilter::default()).await.unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].seq, seq);
    assert_eq!(result.rows[0].kind, "admin_mutation");
    assert!(result.stopped.is_none());
}

#[tokio::test]
async fn activity_projection_matches_file_adapter_without_querying_journal() {
    use mcp_server_devtools::{
        audit::{
            activity_sqlite::SqliteActivityReports,
            export::{ActivityFilter, JournalActivityReports},
            journal::{JOURNAL_FILE_NAME, JournalAuditSink},
        },
        ports::{AuditSink, ControlEvent, ControlEventKind, activity_reports::ActivityReports},
    };
    let directory = tempfile::tempdir().unwrap();
    let sink = JournalAuditSink::open(directory.path()).unwrap();
    let mut event = ControlEvent::now(ControlEventKind::AdminMutation);
    event.source = Some("policy/reload".into());
    sink.append_control(&event).await.unwrap();
    let source = directory.path().join(JOURNAL_FILE_NAME);
    let file = JournalActivityReports::new(source.clone());
    let store = SqliteActivityReports::open(&directory.path().join("reports.sqlite")).unwrap();
    let cancel = CancellationToken::new();
    store.spawn(source, cancel.clone());
    let filter = ActivityFilter::default();
    let projected = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(result) = store.activity(&filter).await {
                break result;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let direct = file.activity(&filter).await.unwrap();
    assert_eq!(
        serde_json::to_value(projected.rows).unwrap(),
        serde_json::to_value(direct.rows).unwrap()
    );
    cancel.cancel();
    drop(sink);
    std::fs::remove_file(directory.path().join(JOURNAL_FILE_NAME)).unwrap();
    assert_eq!(
        store.activity(&filter).await.unwrap().rows.len(),
        1,
        "query reads the projection"
    );
}

#[tokio::test]
async fn session_inventory_lists_and_closes_real_rmcp_sessions() {
    use mcp_server_devtools::{
        ports::admin_inventory::SessionStore, server::session::ReapingSessionManager,
    };
    use rmcp::transport::streamable_http_server::SessionManager;
    let manager = ReapingSessionManager::new(Duration::from_mins(10));
    let (id, _transport) = manager.create_session().await.unwrap();
    let owner = mcp_server_devtools::policy::OwnerKey::Local;
    manager.bind_owner(&id, owner.clone()).await;
    let rows = manager.list().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, id.as_ref());
    assert_eq!(rows[0].owner, Some(owner));
    manager.revoke(id.as_ref()).await.unwrap();
    assert!(manager.list().await.unwrap().is_empty());
    assert!(manager.revoke(id.as_ref()).await.is_err());
}

#[tokio::test]
async fn admin_cli_uses_the_audited_http_boundary_and_json_errors() {
    let f = fixture(Role::All).await;
    let token = f.dir.path().join("admin-token");
    std::fs::write(&token, "admin\n").unwrap();
    let run = |args: &[&str]| {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-devtools"));
        command
            .env("MCP_AUTH_MODE", "oidc")
            .env("GRAFANA_TOKEN", "vault://unconfigured/vendor#token");
        command
            .args(["admin", "--url", &f.url, "--token-file"])
            .arg(&token)
            .args(args);
        async move { command.output().await.unwrap() }
    };
    let output = run(&["policy", "read", "--json"]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["data"]["document"], "version: 1\nrules: []\n");
    let output = run(&["policy", "reload", "--json"]).await;
    assert!(output.status.success());
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["data"]["audit_seq"], f.sink.events()[0]["seq"]);
    assert_eq!(f.sink.events()[0]["source"], "policy/reload");
    f.sink.set_failing(true);
    let output = run(&["policy", "reload", "--json"]).await;
    assert!(!output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({"error":"audit_unavailable","error_description":"audit_unavailable"})
    );
}

#[test]
fn every_admin_command_accepts_json() {
    use clap::Parser as _;
    let commands: &[&[&str]] = &[
        &["policy", "read"],
        &["policy", "validate", "policy.yaml"],
        &["policy", "diff", "policy.yaml"],
        &["policy", "reload"],
        &["principals", "--tenant", "t", "--subject", "s"],
        &["sessions", "list"],
        &["sessions", "remove", "s"],
        &["artifacts", "list"],
        &["artifacts", "remove", "a"],
        &["deny-list", "read"],
        &[
            "deny-list",
            "replace",
            "list.yaml",
            "--signature",
            "list.sig",
        ],
        &["report", "activity", "--request", "q.json"],
        &["report", "access-review", "--request", "q.json"],
        &["usage", "--request", "q.json"],
    ];
    for command in commands {
        let mut args = vec![
            "mcp-devtools",
            "admin",
            "--url",
            "https://mcp.example",
            "--token-file",
            "token",
        ];
        args.extend_from_slice(command);
        args.push("--json");
        assert!(
            mcp_server_devtools::cli::Cli::try_parse_from(args).is_ok(),
            "{command:?}"
        );
    }
}

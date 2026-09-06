//! WP D.2: two-person approval over real HTTP, real signed files, and the
//! real on-disk journal (the production wiring, no injected sink).
use mcp_server_devtools::{
    bootstrap::{ServerBuilder, approvals::APPROVALS_KEY},
    config::Config,
    policy::{
        FilePolicy, Principal, PrincipalAuthority,
        signing::{Domain, SigningKey, write_detached},
    },
    ports::{StaticValidator, TokenFacts},
    server::{
        auth::{InboundAuth, InboundAuthSettings},
        http::{Role, build_app_for_role},
        rate_limit::{RateLimitSettings, RateLimiter},
    },
};
use serde_json::{Value, json};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

struct Fixture {
    dir: tempfile::TempDir,
    url: String,
    key: SigningKey,
    policy: PathBuf,
    revocations: PathBuf,
    cancel: CancellationToken,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Sign and write a policy and a revocation list into `dir`; returns the key.
fn sign_files(dir: &std::path::Path) -> (SigningKey, PathBuf, PathBuf) {
    let policy = dir.join("policy.yaml");
    let (key, _) = SigningKey::generate().unwrap();
    let document = b"version: 1\nrules: []\n";
    std::fs::write(&policy, document).unwrap();
    write_detached(&policy, &key.sign(Domain::PolicyBundle, document)).unwrap();
    let revocations = dir.join("revocations.yaml");
    let bytes = b"version: 1\nsubjects: []\ntoken_ids: []\n";
    std::fs::write(&revocations, bytes).unwrap();
    write_detached(&revocations, &key.sign(Domain::RevocationList, bytes)).unwrap();
    (key, policy, revocations)
}

/// Bearers: `alice` and `bob` are fresh administrators, `carol` carries no
/// issue time, `dave` an old one.
fn auth_stack(
    list: Arc<mcp_server_devtools::auth::revocation::RevocationList>,
) -> Arc<InboundAuth> {
    let principal = |subject: &str| Principal {
        tenant: "tenant".into(),
        subject: subject.into(),
        groups: vec![],
        scopes: vec!["mcp:admin".into()],
        authority: PrincipalAuthority::oidc("https://issuer.example"),
    };
    let fresh = || TokenFacts {
        issued_at: Some(now()),
        ..TokenFacts::default()
    };
    Arc::new(
        InboundAuth::new(
            Arc::new(
                StaticValidator::new()
                    .with_facts("alice", principal("alice"), fresh())
                    .with_facts("bob", principal("bob"), fresh())
                    .with("carol", principal("carol"))
                    .with_facts(
                        "dave",
                        principal("dave"),
                        TokenFacts {
                            issued_at: Some(now() - 3600),
                            ..TokenFacts::default()
                        },
                    ),
            ),
            InboundAuthSettings {
                public_url: "https://mcp.example".into(),
                authorization_servers: vec!["https://issuer.example".into()],
                required_scope: "mcp:tools".into(),
            },
        )
        .with_revocations(list)
        .with_rate_limit(Arc::new(RateLimiter::new(RateLimitSettings {
            per_second: 0.01,
            burst: 1.0,
        }))),
    )
}

/// `dir` holds the signed files and the journal; `approvals` is the
/// `MCP_ADMIN_APPROVALS` value (None leaves it unset), `extra` any other
/// settings. Bearers: `alice` and `bob` are fresh administrators, `carol`
/// carries no issue time, `dave` an old one.
async fn start(
    dir: tempfile::TempDir,
    key: SigningKey,
    approvals: Option<&str>,
    extra: &[(&str, &str)],
) -> Fixture {
    let policy = dir.path().join("policy.yaml");
    let revocations = dir.path().join("revocations.yaml");
    if cfg!(windows) {
        let _ = std::fs::File::create_new(
            dir.path()
                .join(mcp_server_devtools::audit::journal::JOURNAL_FILE_NAME),
        );
    }
    let mut map = HashMap::from([
        ("MCP_POLICY_FILE".to_owned(), policy.display().to_string()),
        (
            "MCP_POLICY_PUBLIC_KEY".to_owned(),
            key.verifying_key().to_base64(),
        ),
        (
            "MCP_AUDIT_JOURNAL_DIR".to_owned(),
            dir.path().display().to_string(),
        ),
    ]);
    if let Some(value) = approvals {
        map.insert(APPROVALS_KEY.to_owned(), value.to_owned());
    }
    for (name, value) in extra {
        map.insert((*name).to_owned(), (*value).to_owned());
    }
    // A server that was just stopped releases its journal lock when its
    // writer thread exits, shortly after the router drops.
    let mut attempts = 0;
    let server = loop {
        match ServerBuilder::new()
            .config(Config::from_map(map.clone()))
            .serves_control(true)
            .build()
        {
            Ok(server) => break server,
            Err(error) if attempts < 100 && error.to_string().contains("already held") => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("{error}"),
        }
    };
    let list = mcp_server_devtools::auth::revocation::RevocationList::load_verified(
        &revocations,
        key.verifying_key(),
    )
    .unwrap();
    let auth = auth_stack(list);
    let cancel = CancellationToken::new();
    let app = build_app_for_role(
        Role::All,
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
        key,
        policy,
        revocations,
        cancel,
    }
}

async fn fixture(approvals: Option<&str>, extra: &[(&str, &str)]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (key, _, _) = sign_files(dir.path());
    start(dir, key, approvals, extra).await
}

/// Stop the server, keeping the directory, so another can start on it.
fn stop(f: Fixture) -> (tempfile::TempDir, SigningKey) {
    let mut f = f;
    f.cancel.cancel();
    let dir = std::mem::replace(&mut f.dir, tempfile::tempdir().unwrap());
    let (key, _) = SigningKey::generate().unwrap();
    let key = std::mem::replace(&mut f.key, key);
    (dir, key)
}

async fn call(
    f: &Fixture,
    bearer: &str,
    method: &str,
    op: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let client = reqwest::Client::new();
    let url = format!("{}/admin/{op}", f.url);
    let request = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        _ => client.post(url),
    }
    .bearer_auth(bearer);
    let request = match body {
        Some(body) => request.json(&body),
        None => request,
    };
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap())
}

/// Every non-checkpoint record in the on-disk journal, in order.
fn journal(f: &Fixture) -> Vec<Value> {
    let path = f
        .dir
        .path()
        .join(mcp_server_devtools::audit::journal::JOURNAL_FILE_NAME);
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|record| record["kind"] != "checkpoint")
        .collect()
}

fn signed_policy(f: &Fixture, document: &str) -> Value {
    json!({"document": document, "signature": f.key.sign(Domain::PolicyBundle, document.as_bytes()).to_base64()})
}

/// The locked JSON shape of a pending proposal, agreeing with its record.
fn assert_pending_shape(proposal: &Value, id: &str, record: &Value) {
    let records = [record.clone()];
    assert_eq!(proposal["id"], id);
    assert_eq!(proposal["state"], "pending");
    assert_eq!(proposal["operation"], "policy/install");
    assert_eq!(
        proposal["proposer"],
        json!({"tenant": "tenant", "subject": "alice"})
    );
    assert_eq!(
        proposal["candidate_digest"],
        records[0]["proposal"]["candidate_digest"]
    );
    assert_eq!(proposal["expires"], records[0]["proposal"]["expires"]);
    assert_eq!(
        proposal
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "id",
            "operation",
            "target",
            "candidate_digest",
            "proposer",
            "created",
            "expires",
            "state"
        ]
    );
}

#[tokio::test]
async fn required_defers_a_policy_install_until_a_second_administrator_approves() {
    let f = fixture(Some("required"), &[]).await;
    let candidate = "version: 2\nrules: []\n";
    let request = signed_policy(&f, candidate);
    let (status, body) = call(&f, "alice", "PUT", "policy", Some(request.clone())).await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["data"]["state"], "pending");
    assert_eq!(body["data"]["operation"], "policy/install");
    let id = body["data"]["proposal"].as_str().unwrap().to_owned();
    assert!(id.starts_with("p-") && id.len() == 18, "{id}");
    // Nothing applied; the proposal is the only record, and it carries the
    // candidate so a restart can apply it.
    assert_eq!(
        std::fs::read_to_string(&f.policy).unwrap(),
        "version: 1\nrules: []\n"
    );
    let records = journal(&f);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["kind"], "admin_proposal");
    assert_eq!(records[0]["principal"]["subject"], "alice");
    assert_eq!(records[0]["source"], "policy/install");
    assert_eq!(records[0]["proposal"]["id"], id);
    assert_eq!(records[0]["proposal"]["document"], candidate);
    assert_eq!(records[0]["proposal"]["signature"], request["signature"]);
    assert!(
        records[0]["proposal"]["candidate_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    // Listed, pending, with the locked shape.
    let (status, list) = call(&f, "bob", "GET", "proposals", None).await;
    assert_eq!(status, 200);
    let rows = list["data"]["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    let proposal = &rows[0];
    assert_pending_shape(proposal, &id, &records[0]);
    let (status, shown) = call(&f, "bob", "GET", &format!("proposals/{id}"), None).await;
    assert_eq!(status, 200);
    assert_eq!(&shown["data"]["proposal"], proposal);
    // A second administrator with a fresh token approves: approval, then
    // the ordinary install intent, then the effect.
    let (status, body) = call(
        &f,
        "bob",
        "POST",
        &format!("proposals/{id}/approve"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let approved = &body["data"]["proposal"];
    assert_eq!(approved["state"], "approved");
    assert_eq!(
        approved["decided_by"],
        json!({"tenant": "tenant", "subject": "bob"})
    );
    assert!(approved["decided"].is_string());
    let records = journal(&f);
    assert_eq!(records.len(), 4, "{records:?}");
    assert_eq!(records[1]["kind"], "admin_approval");
    assert_eq!(records[1]["principal"]["subject"], "bob");
    assert_eq!(records[1]["proposal"]["id"], id);
    assert_eq!(
        records[1]["proposal"]["candidate_digest"],
        proposal["candidate_digest"]
    );
    assert!(records[1]["proposal"].get("document").is_none());
    assert_eq!(records[2]["kind"], "admin_mutation");
    assert_eq!(records[2]["source"], "policy/install");
    assert_eq!(records[2]["principal"]["subject"], "bob");
    assert_eq!(records[2]["version"], proposal["target"]);
    assert_eq!(approved["applied_seq"], records[2]["seq"]);
    assert_eq!(std::fs::read_to_string(&f.policy).unwrap(), candidate);
    FilePolicy::load_verified(&f.policy, f.key.verifying_key()).unwrap();
    let (_, read) = call(&f, "alice", "GET", "policy", None).await;
    assert_eq!(read["data"]["document"], candidate);
    // A second approval is idempotent: same answer, no new record, no
    // second apply. A rejection of a decided proposal is refused.
    let (status, again) = call(
        &f,
        "bob",
        "POST",
        &format!("proposals/{id}/approve"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(again["data"]["proposal"], *approved);
    assert_eq!(journal(&f).len(), 4);
    let (status, body) = call(
        &f,
        "bob",
        "POST",
        &format!("proposals/{id}/reject"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(body["error"], "proposal_decided");
}

#[tokio::test]
async fn refusals_record_nothing_and_shapes_are_checked() {
    let f = fixture(Some("required"), &[]).await;
    let (_, body) = call(
        &f,
        "alice",
        "PUT",
        "policy",
        Some(signed_policy(&f, "version: 2\nrules: []\n")),
    )
    .await;
    let id = body["data"]["proposal"].as_str().unwrap().to_owned();
    // Refusals that record nothing: self-approval, a token without an issue
    // time, a token past the write bound, an unknown id.
    for (bearer, path, status, error) in [
        (
            "alice",
            format!("proposals/{id}/approve"),
            409,
            "approval_self",
        ),
        (
            "carol",
            format!("proposals/{id}/approve"),
            403,
            "stale_token",
        ),
        (
            "dave",
            format!("proposals/{id}/approve"),
            403,
            "stale_token",
        ),
        (
            "bob",
            "proposals/p-0000000000000000/approve".to_owned(),
            404,
            "not_found",
        ),
        (
            "bob",
            "proposals/not-an-id/approve".to_owned(),
            404,
            "not_found",
        ),
    ] {
        let (got, body) = call(&f, bearer, "POST", &path, Some(json!({}))).await;
        assert_eq!(got, status, "{bearer} {path}: {body}");
        assert_eq!(body["error"], error, "{bearer} {path}");
    }
    assert_eq!(journal(&f).len(), 1);
    // Wrong methods and bodies.
    let (status, _) = call(&f, "bob", "PUT", "proposals", None).await;
    assert_eq!(status, 405);
    let (status, _) = call(
        &f,
        "bob",
        "POST",
        &format!("proposals/{id}/approve"),
        Some(json!({"x": 1})),
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = call(&f, "bob", "GET", &format!("proposals/{id}/nonsense"), None).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn reject_and_expiry_journal_their_own_records() {
    let f = fixture(Some("required"), &[("MCP_ADMIN_APPROVAL_TTL_SECONDS", "1")]).await;
    let (_, first) = call(
        &f,
        "alice",
        "PUT",
        "policy",
        Some(signed_policy(&f, "version: 2\nrules: []\n")),
    )
    .await;
    let first = first["data"]["proposal"].as_str().unwrap().to_owned();
    // The proposer withdraws their own proposal; the reason is bounded and
    // journaled.
    let (status, body) = call(
        &f,
        "alice",
        "POST",
        &format!("proposals/{first}/reject"),
        Some(json!({"reason": "wrong file"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["proposal"]["state"], "rejected");
    assert_eq!(body["data"]["proposal"]["reason"], "wrong file");
    assert_eq!(body["data"]["proposal"]["decided_by"]["subject"], "alice");
    let records = journal(&f);
    assert_eq!(records[1]["kind"], "admin_rejection");
    assert_eq!(records[1]["reason"], "wrong file");
    assert_eq!(records[1]["proposal"]["id"], first);
    let (status, body) = call(
        &f,
        "bob",
        "POST",
        &format!("proposals/{first}/approve"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(body["error"], "proposal_decided");
    let (status, _) = call(
        &f,
        "bob",
        "POST",
        &format!("proposals/{first}/reject"),
        Some(json!({"reason": "x".repeat(600)})),
    )
    .await;
    assert_eq!(status, 400);
    // A proposal past its TTL reads as expired before anyone decides, and
    // the first decision asked of it journals the expiry exactly once.
    let (_, second) = call(
        &f,
        "alice",
        "PUT",
        "policy",
        Some(signed_policy(&f, "version: 3\nrules: []\n")),
    )
    .await;
    let second = second["data"]["proposal"].as_str().unwrap().to_owned();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let (_, list) = call(&f, "bob", "GET", "proposals", None).await;
    let row = list["data"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == second)
        .unwrap();
    assert_eq!(row["state"], "expired");
    assert_eq!(journal(&f).len(), 3);
    for _ in 0..2 {
        let (status, body) = call(
            &f,
            "bob",
            "POST",
            &format!("proposals/{second}/approve"),
            Some(json!({})),
        )
        .await;
        assert_eq!(status, 409, "{body}");
        assert_eq!(body["error"], "approval_expired");
    }
    let records = journal(&f);
    assert_eq!(records.len(), 4, "{records:?}");
    assert_eq!(records[3]["kind"], "admin_rejection");
    assert_eq!(records[3]["reason"], "expired");
    assert_eq!(records[3]["proposal"]["id"], second);
    assert!(records[3].get("principal").is_none());
    assert_eq!(
        std::fs::read_to_string(&f.policy).unwrap(),
        "version: 1\nrules: []\n"
    );
}

#[tokio::test]
async fn pending_proposals_survive_a_restart_and_a_tampered_journal_is_refused() {
    let f = fixture(Some("required"), &[]).await;
    let candidate = "version: 2\nrules: []\n";
    let (_, body) = call(
        &f,
        "alice",
        "PUT",
        "policy",
        Some(signed_policy(&f, candidate)),
    )
    .await;
    let id = body["data"]["proposal"].as_str().unwrap().to_owned();
    let (_, before) = call(&f, "bob", "GET", &format!("proposals/{id}"), None).await;
    let (dir, key) = stop(f);
    // The projection is rebuilt from the journal alone.
    let f = start(dir, key, Some("required"), &[]).await;
    let (status, after) = call(&f, "bob", "GET", &format!("proposals/{id}"), None).await;
    assert_eq!(status, 200, "{after}");
    assert_eq!(after["data"]["proposal"], before["data"]["proposal"]);
    let (status, body) = call(
        &f,
        "bob",
        "POST",
        &format!("proposals/{id}/approve"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(std::fs::read_to_string(&f.policy).unwrap(), candidate);
    let applied_seq = body["data"]["proposal"]["applied_seq"].as_u64().unwrap();
    // After another restart the approval and its apply are both projected.
    let (dir, key) = stop(f);
    let f = start(dir, key, Some("required"), &[]).await;
    let (_, again) = call(&f, "bob", "GET", &format!("proposals/{id}"), None).await;
    assert_eq!(again["data"]["proposal"]["state"], "approved");
    assert_eq!(again["data"]["proposal"]["applied_seq"], applied_seq);
    assert_eq!(again["data"]["proposal"]["decided_by"]["subject"], "bob");
    // A proposal whose journaled candidate no longer matches its digest is
    // never applied.
    let tampered = "version: 9\nrules: []\n";
    let (_, body) = call(
        &f,
        "alice",
        "PUT",
        "policy",
        Some(signed_policy(&f, tampered)),
    )
    .await;
    let victim = body["data"]["proposal"].as_str().unwrap().to_owned();
    let (dir, key) = stop(f);
    let path = dir
        .path()
        .join(mcp_server_devtools::audit::journal::JOURNAL_FILE_NAME);
    let edited: String = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| {
            if line.contains(&victim) && line.contains("admin_proposal") {
                line.replace("version: 9", "version: 8")
            } else {
                line.to_owned()
            }
        })
        .map(|line| line + "\n")
        .collect();
    std::fs::write(&path, edited).unwrap();
    let f = start(dir, key, Some("required"), &[]).await;
    let (status, body) = call(
        &f,
        "bob",
        "POST",
        &format!("proposals/{victim}/approve"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"], "proposal_digest_mismatch");
    assert_eq!(std::fs::read_to_string(&f.policy).unwrap(), candidate);
}

#[tokio::test]
async fn deny_list_is_gated_and_the_rest_stays_direct_under_required() {
    let f = fixture(Some("required"), &[]).await;
    // Reload is one-person by decision (§3.10.3): applied, with its intent.
    let (status, body) = call(&f, "alice", "POST", "policy/reload", Some(json!({}))).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(journal(&f)[0]["kind"], "admin_mutation");
    // A deny-list replacement waits for the second administrator and is
    // applied as proposed: sessions closed, the proposer's subject denied.
    let list = "version: 2\nsubjects:\n- subject: alice\n  revoked_at: 2026-09-05T00:00:00Z\ntoken_ids: []\n";
    let request = json!({"document": list, "signature": f.key.sign(Domain::RevocationList, list.as_bytes()).to_base64()});
    let (status, body) = call(&f, "alice", "PUT", "deny-list", Some(request)).await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["data"]["operation"], "deny-list/replace");
    let id = body["data"]["proposal"].as_str().unwrap().to_owned();
    assert!(
        !std::fs::read_to_string(&f.revocations)
            .unwrap()
            .contains("alice")
    );
    let (status, body) = call(
        &f,
        "bob",
        "POST",
        &format!("proposals/{id}/approve"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["proposal"]["operation"], "deny-list/replace");
    assert!(
        std::fs::read_to_string(&f.revocations)
            .unwrap()
            .contains("alice")
    );
    let records = journal(&f);
    assert_eq!(records.last().unwrap()["kind"], "admin_application");
    assert_eq!(records.last().unwrap()["source"], "deny-list/replace");
    assert_eq!(
        body["data"]["proposal"]["applied_seq"],
        records.last().unwrap()["applied_seq"]
    );
    let (status, _) = call(&f, "alice", "GET", "policy", None).await;
    assert_eq!(status, 401, "the approved list denies alice");
}

#[tokio::test]
async fn proposals_are_off_under_the_direct_gate_and_the_setting_is_validated() {
    let f = fixture(None, &[]).await;
    let (status, body) = call(&f, "alice", "GET", "proposals", None).await;
    assert_eq!(status, 503);
    assert_eq!(body["error"], "approvals_off");
    let (status, body) = call(
        &f,
        "alice",
        "PUT",
        "policy",
        Some(signed_policy(&f, "version: 2\nrules: []\n")),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    // The TTL must be whole seconds within its bound.
    for ttl in ["0", "x", "2592001"] {
        let dir = tempfile::tempdir().unwrap();
        let (key, policy, _) = sign_files(dir.path());
        let error = ServerBuilder::new()
            .config(Config::from_map(HashMap::from([
                ("MCP_POLICY_FILE".to_owned(), policy.display().to_string()),
                (
                    "MCP_POLICY_PUBLIC_KEY".to_owned(),
                    key.verifying_key().to_base64(),
                ),
                (
                    "MCP_AUDIT_JOURNAL_DIR".to_owned(),
                    dir.path().display().to_string(),
                ),
                (APPROVALS_KEY.to_owned(), "required".to_owned()),
                ("MCP_ADMIN_APPROVAL_TTL_SECONDS".to_owned(), ttl.to_owned()),
            ])))
            .build()
            .err()
            .expect("refused")
            .to_string();
        assert!(
            error.contains("MCP_ADMIN_APPROVAL_TTL_SECONDS"),
            "{ttl}: {error}"
        );
    }
}

#[tokio::test]
async fn cli_proposes_lists_and_approves_with_json() {
    let f = fixture(Some("required"), &[]).await;
    let token = |name: &str| {
        let path = f.dir.path().join(format!("{name}-token"));
        std::fs::write(&path, format!("{name}\n")).unwrap();
        path
    };
    let (alice, bob) = (token("alice"), token("bob"));
    let run = |token: PathBuf, args: Vec<String>| {
        let url = f.url.clone();
        async move {
            let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-devtools"));
            command
                .env("MCP_AUTH_MODE", "oidc")
                .env("GRAFANA_TOKEN", "vault://unconfigured/vendor#token")
                .args(["admin", "--url", &url, "--token-file"])
                .arg(&token)
                .args(&args)
                .arg("--json");
            let output = command.output().await.unwrap();
            (
                output.status.success(),
                serde_json::from_slice::<Value>(&output.stdout).unwrap_or(Value::Null),
            )
        }
    };
    let candidate = f.dir.path().join("candidate.yaml");
    std::fs::write(&candidate, "version: 2\nrules: []\n").unwrap();
    let signature = write_detached(
        &candidate,
        &f.key.sign(Domain::PolicyBundle, b"version: 2\nrules: []\n"),
    )
    .unwrap();
    let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let (ok, body) = run(
        alice.clone(),
        args(&[
            "policy",
            "install",
            candidate.to_str().unwrap(),
            "--signature",
            signature.to_str().unwrap(),
        ]),
    )
    .await;
    assert!(ok, "{body}");
    assert_eq!(body["data"]["state"], "pending");
    let id = body["data"]["proposal"].as_str().unwrap().to_owned();
    let (ok, body) = run(bob.clone(), args(&["proposals", "list"])).await;
    assert!(ok, "{body}");
    assert_eq!(body["data"]["rows"][0]["id"], id);
    let (ok, body) = run(bob.clone(), args(&["proposals", "show", &id])).await;
    assert!(ok, "{body}");
    assert_eq!(body["data"]["proposal"]["state"], "pending");
    let (ok, body) = run(bob.clone(), args(&["proposals", "show", "../policy"])).await;
    assert!(!ok);
    assert_eq!(body["error"], "invalid_id");
    let (ok, body) = run(alice, args(&["proposals", "approve", &id])).await;
    assert!(!ok);
    assert_eq!(body["error"], "approval_self");
    let (ok, body) = run(bob, args(&["proposals", "approve", &id])).await;
    assert!(ok, "{body}");
    assert_eq!(body["data"]["proposal"]["state"], "approved");
    assert_eq!(
        std::fs::read_to_string(&f.policy).unwrap(),
        "version: 2\nrules: []\n"
    );
}

#[tokio::test]
async fn concurrent_http_approvals_install_once_and_remain_idempotent_after_restart() {
    let f = fixture(Some("required"), &[]).await;
    let candidate = "version: 2\nrules: []\n";
    let (_, proposed) = call(
        &f,
        "alice",
        "PUT",
        "policy",
        Some(signed_policy(&f, candidate)),
    )
    .await;
    let id = proposed["data"]["proposal"].as_str().unwrap().to_owned();
    let path = format!("proposals/{id}/approve");
    let (a, b) = tokio::join!(
        call(&f, "bob", "POST", &path, Some(json!({}))),
        call(&f, "bob", "POST", &path, Some(json!({})))
    );
    assert!(a.0 == 200 || b.0 == 200, "{a:?} {b:?}");
    for (status, body) in [a, b] {
        assert!(
            status == 200 || (status == 409 && body["error"] == "proposal_incomplete"),
            "{status}: {body}"
        );
    }
    let records = journal(&f);
    assert_eq!(
        records
            .iter()
            .filter(|r| r["kind"] == "admin_mutation")
            .count(),
        1
    );
    assert_eq!(records.len(), 4);
    assert_eq!(records[3]["proposal"]["id"], id);
    assert_eq!(records[3]["applied_seq"], records[2]["seq"]);
    let (dir, key) = stop(f);
    let f = start(dir, key, Some("required"), &[]).await;
    assert_eq!(call(&f, "bob", "POST", &path, Some(json!({}))).await.0, 200);
    assert_eq!(journal(&f).len(), 4);
    assert_eq!(std::fs::read_to_string(&f.policy).unwrap(), candidate);
}

#[tokio::test]
async fn failed_file_install_after_intent_is_not_retried_or_recovered_as_complete() {
    let f = fixture(Some("required"), &[]).await;
    let (_, proposed) = call(
        &f,
        "alice",
        "PUT",
        "policy",
        Some(signed_policy(&f, "version: 2\nrules: []\n")),
    )
    .await;
    let id = proposed["data"]["proposal"].as_str().unwrap().to_owned();
    let path = format!("proposals/{id}/approve");
    // Force the document replacement to fail after the detached signature write.
    std::fs::remove_file(&f.policy).unwrap();
    std::fs::create_dir(&f.policy).unwrap();
    let (status, body) = call(&f, "bob", "POST", &path, Some(json!({}))).await;
    assert_eq!(status, 503, "{body}");
    assert_eq!(journal(&f).len(), 3);
    assert_eq!(journal(&f)[2]["kind"], "admin_mutation");
    assert_eq!(
        call(&f, "bob", "POST", &path, Some(json!({}))).await.1["error"],
        "proposal_incomplete"
    );
    // Restore a known-good signed pair, as the operating procedure requires.
    std::fs::remove_dir(&f.policy).unwrap();
    let initial = b"version: 1\nrules: []\n";
    std::fs::write(&f.policy, initial).unwrap();
    write_detached(&f.policy, &f.key.sign(Domain::PolicyBundle, initial)).unwrap();
    let (dir, key) = stop(f);
    let f = start(dir, key, Some("required"), &[]).await;
    let (_, shown) = call(&f, "bob", "GET", &format!("proposals/{id}"), None).await;
    assert!(shown["data"]["proposal"].get("applied_seq").is_none());
    assert_eq!(
        call(&f, "bob", "POST", &path, Some(json!({}))).await.1["error"],
        "proposal_incomplete"
    );
    assert_eq!(journal(&f).len(), 3);
    assert_eq!(std::fs::read(&f.policy).unwrap(), initial);
}

//! WP D.0: the `AdminClient` port across both adapters, and the
//! `MutationGate` port in front of every durable admin intent.
mod support;

use mcp_server_devtools::{
    admin::{HttpAdminClient, LocalAdminClient},
    bootstrap::{ServerBuilder, approvals::APPROVALS_KEY},
    config::Config,
    policy::{
        Principal, PrincipalAuthority,
        signing::{Domain, SigningKey, write_detached},
    },
    ports::{
        AdminClient, AdminClientError, AdminMethod, AdminRequest, Admission, AdmissionFuture,
        InMemoryAuditSink, MutationGate, MutationIntent, MutationKind, StaticValidator,
    },
    server::{
        auth::{InboundAuth, InboundAuthSettings},
        http::{Role, build_app_for_role},
    },
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

struct Fixture {
    _dir: tempfile::TempDir,
    key: SigningKey,
    policy: std::path::PathBuf,
    url: String,
    app: axum::Router,
    sink: Arc<InMemoryAuditSink>,
    cancel: CancellationToken,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// A signed policy on disk, a static validator with `admin` / `tools`
/// bearers, the `all` role served on loopback and the same router kept
/// for the in-process adapter.
async fn fixture(gate: Option<Arc<dyn MutationGate>>, settings: &[(&str, &str)]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.yaml");
    let (key, _) = SigningKey::generate().unwrap();
    let document = b"version: 1\nrules: []\n";
    std::fs::write(&policy, document).unwrap();
    write_detached(&policy, &key.sign(Domain::PolicyBundle, document)).unwrap();
    let mut map = HashMap::from([
        ("MCP_POLICY_FILE".to_owned(), policy.display().to_string()),
        (
            "MCP_POLICY_PUBLIC_KEY".to_owned(),
            key.verifying_key().to_base64(),
        ),
    ]);
    for (key, value) in settings {
        map.insert((*key).to_owned(), (*value).to_owned());
    }
    let sink = Arc::new(InMemoryAuditSink::new());
    let mut builder = ServerBuilder::new()
        .config(Config::from_map(map))
        .audit_sink(sink.clone());
    if let Some(gate) = gate {
        builder = builder.mutation_gate(gate);
    }
    let server = builder.build().unwrap();
    let principal = |subject: &str, scopes: &[&str]| Principal {
        tenant: "tenant".into(),
        subject: subject.into(),
        groups: vec![],
        scopes: scopes.iter().map(|s| (*s).into()).collect(),
        authority: PrincipalAuthority::oidc("https://issuer.example"),
    };
    // Two administrators: the admin limiter is per subject, and the
    // conformance suite runs once per adapter.
    let auth = Arc::new(InboundAuth::new(
        Arc::new(
            StaticValidator::new()
                .with("admin", principal("alice", &["mcp:admin"]))
                .with("admin-b", principal("bob", &["mcp:admin"]))
                .with("tools", principal("alice", &["mcp:tools"])),
        ),
        InboundAuthSettings {
            public_url: "https://mcp.example".into(),
            authorization_servers: vec!["https://issuer.example".into()],
            required_scope: "mcp:tools".into(),
        },
    ));
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
    let routes = app.clone();
    let stop = cancel.clone();
    tokio::spawn(async move {
        axum::serve(listener, routes)
            .with_graceful_shutdown(stop.cancelled_owned())
            .await
            .unwrap();
    });
    Fixture {
        _dir: dir,
        key,
        policy,
        url,
        app,
        sink,
        cancel,
    }
}

#[tokio::test]
async fn both_adapters_pass_the_conformance_suite_and_agree() {
    let f = fixture(None, &[]).await;
    let remote = HttpAdminClient::new(&f.url).unwrap();
    let local = LocalAdminClient::new(f.app.clone());
    let over_http = support::admin_client_conformance::conformance(&remote, "admin", "tools").await;
    let in_process =
        support::admin_client_conformance::conformance(&local, "admin-b", "tools").await;
    assert_eq!(over_http, in_process);
}

#[test]
fn http_adapter_refuses_urls_a_bearer_must_not_travel_to() {
    for url in [
        "http://mcp.example/",
        "https://user:pw@mcp.example/",
        "https://mcp.example/admin",
        "https://mcp.example/?x=1",
        "https://mcp.example/#f",
        "not a url",
    ] {
        assert_eq!(
            HttpAdminClient::new(url).err(),
            Some(AdminClientError::InvalidUrl),
            "{url}"
        );
    }
    assert!(HttpAdminClient::new("http://127.0.0.1:1/").is_ok());
    assert!(HttpAdminClient::new("http://localhost:1/").is_ok());
    assert!(HttpAdminClient::new("https://mcp.example/").is_ok());
}

#[tokio::test]
async fn http_adapter_reports_transport_failures_as_typed_errors() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    drop(listener);
    let client = HttpAdminClient::new(&url).unwrap();
    let request = AdminRequest {
        method: AdminMethod::Get,
        operation: "policy",
        body: None,
    };
    assert_eq!(
        client.call("admin", request).await.err(),
        Some(AdminClientError::Unreachable)
    );
    // A boundary that does not answer JSON is an invalid response, not a
    // panic and not an empty success.
    let mock = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("<html>"))
        .mount(&mock)
        .await;
    let client = HttpAdminClient::new(&format!("{}/", mock.uri())).unwrap();
    assert_eq!(
        client.call("admin", request).await.err(),
        Some(AdminClientError::InvalidResponse)
    );
}

/// The gate an approval adapter will be: it sees the intent, answers, and
/// the boundary does the rest. Records every intent it was shown.
/// One intent as the gate saw it: kind, subject, target, candidate bytes.
type SeenIntent = (MutationKind, String, Option<String>, Option<Vec<u8>>);
struct ScriptedGate {
    answer: Admission,
    seen: Mutex<Vec<SeenIntent>>,
}
impl ScriptedGate {
    fn new(answer: Admission) -> Arc<Self> {
        Arc::new(Self {
            answer,
            seen: Mutex::new(Vec::new()),
        })
    }
}
impl MutationGate for ScriptedGate {
    fn admit<'a>(&'a self, intent: &'a MutationIntent<'a>) -> AdmissionFuture<'a> {
        self.seen.lock().unwrap().push((
            intent.kind,
            intent.principal.subject.clone(),
            intent.target.map(str::to_owned),
            intent.candidate.map(<[u8]>::to_vec),
        ));
        Box::pin(std::future::ready(self.answer.clone()))
    }
    fn name(&self) -> &'static str {
        "scripted"
    }
}

async fn mutate(f: &Fixture, method: AdminMethod, operation: &str, body: Value) -> (u16, Value) {
    let response = LocalAdminClient::new(f.app.clone())
        .call(
            "admin",
            AdminRequest {
                method,
                operation,
                body: Some(&body),
            },
        )
        .await
        .unwrap();
    (response.status, response.body)
}

#[tokio::test]
async fn direct_gate_is_the_default_and_every_mutation_still_journals_its_intent() {
    let f = fixture(None, &[]).await;
    let (status, body) = mutate(&f, AdminMethod::Post, "policy/reload", json!({})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["audit_seq"], f.sink.events()[0]["seq"]);
    assert_eq!(f.sink.events()[0]["kind"], "admin_mutation");
    assert_eq!(f.sink.events()[0]["source"], "policy/reload");
    // An unknown session under the direct gate: the intent is durable
    // before the backend says not found — the C.4 ordering, unchanged.
    let (status, body) = mutate(&f, AdminMethod::Post, "sessions/revoke", json!({"id": "s"})).await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(f.sink.events().len(), 2);
    assert_eq!(f.sink.events()[1]["source"], "sessions/revoke");
    assert_eq!(f.sink.events()[1]["version"], "s");
}

#[tokio::test]
async fn deferred_admission_answers_202_and_appends_no_intent() {
    let gate = ScriptedGate::new(Admission::Deferred {
        proposal: "p-1".into(),
    });
    let f = fixture(Some(gate.clone()), &[]).await;
    for (method, operation, body, kind, target) in [
        (
            AdminMethod::Post,
            "policy/reload",
            json!({}),
            MutationKind::PolicyReload,
            None,
        ),
        (
            AdminMethod::Post,
            "sessions/revoke",
            json!({"id": "s-1"}),
            MutationKind::SessionRevoke,
            Some("s-1"),
        ),
        (
            AdminMethod::Post,
            "artifacts/purge",
            json!({"id": "a-1"}),
            MutationKind::ArtifactPurge,
            Some("a-1"),
        ),
    ] {
        let (status, response) = mutate(&f, method, operation, body).await;
        assert_eq!(status, 202, "{operation}: {response}");
        assert_eq!(
            response,
            json!({"data": {"proposal": "p-1", "state": "pending", "operation": operation}})
        );
        let seen = gate.seen.lock().unwrap();
        let last = seen.last().unwrap();
        assert_eq!(last.0, kind);
        assert_eq!(last.1, "alice");
        assert_eq!(last.2.as_deref(), target);
        assert_eq!(last.3, None);
    }
    assert!(
        f.sink.events().is_empty(),
        "a deferred mutation must not be journaled as admitted: {:?}",
        f.sink.events()
    );
    // Reads are not mutations and never consult the gate.
    let (status, _) = {
        let response = LocalAdminClient::new(f.app.clone())
            .call(
                "admin",
                AdminRequest {
                    method: AdminMethod::Get,
                    operation: "policy",
                    body: None,
                },
            )
            .await
            .unwrap();
        (response.status, response.body)
    };
    assert_eq!(status, 200);
    assert_eq!(gate.seen.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn deny_list_replacement_is_admitted_on_the_verified_candidate() {
    let gate = ScriptedGate::new(Admission::Deferred {
        proposal: "p-2".into(),
    });
    // The deny-list needs a revocation list on the auth stack; build one
    // the way the C.4 tests do, signed with the policy key.
    let dir = tempfile::tempdir().unwrap();
    let (key, _) = SigningKey::generate().unwrap();
    let policy = dir.path().join("policy.yaml");
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
    let server = ServerBuilder::new()
        .config(Config::from_map(HashMap::from([
            ("MCP_POLICY_FILE".into(), policy.display().to_string()),
            (
                "MCP_POLICY_PUBLIC_KEY".into(),
                key.verifying_key().to_base64(),
            ),
        ])))
        .audit_sink(sink.clone())
        .mutation_gate(gate.clone())
        .build()
        .unwrap();
    let auth = InboundAuth::new(
        Arc::new(StaticValidator::new().with(
            "admin",
            Principal {
                tenant: "tenant".into(),
                subject: "alice".into(),
                groups: vec![],
                scopes: vec!["mcp:admin".into()],
                authority: PrincipalAuthority::oidc("https://issuer.example"),
            },
        )),
        InboundAuthSettings {
            public_url: "https://mcp.example".into(),
            authorization_servers: vec!["https://issuer.example".into()],
            required_scope: "mcp:tools".into(),
        },
    )
    .with_revocations(revocations);
    let app = mcp_server_devtools::server::admin::router(server, &auth, None, None, None);
    let client = LocalAdminClient::new(app);
    let candidate = "version: 2\nsubjects:\n- subject: mallory\n  revoked_at: 2026-09-05T00:00:00Z\ntoken_ids: []\n";
    let signature = key
        .sign(Domain::RevocationList, candidate.as_bytes())
        .to_base64();
    let response = client
        .call(
            "admin",
            AdminRequest {
                method: AdminMethod::Put,
                operation: "deny-list",
                body: Some(&json!({"document": candidate, "signature": signature})),
            },
        )
        .await
        .unwrap();
    assert_eq!(response.status, 202, "{}", response.body);
    assert_eq!(response.body["data"]["operation"], "deny-list/replace");
    {
        let seen = gate.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, MutationKind::DenyListReplace);
        assert!(seen[0].2.is_some(), "the verified candidate's version");
        assert_eq!(seen[0].3.as_deref(), Some(candidate.as_bytes()));
    }
    assert!(sink.events().is_empty());
    // Nothing was installed: the file on disk is the original list.
    assert_eq!(
        std::fs::read(&revocation_path).unwrap(),
        revocation_bytes.to_vec()
    );
    // An unverifiable candidate never reaches the gate at all.
    let response = client
        .call(
            "admin",
            AdminRequest {
                method: AdminMethod::Put,
                operation: "deny-list",
                body: Some(&json!({"document": candidate, "signature": "AAAA"})),
            },
        )
        .await
        .unwrap();
    assert_eq!(response.status, 400);
    assert_eq!(gate.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn policy_install_is_admitted_on_the_verified_candidate() {
    let gate = ScriptedGate::new(Admission::Deferred {
        proposal: "p-3".into(),
    });
    let f = fixture(Some(gate.clone()), &[]).await;
    let candidate = "version: 2\nrules: []\n";
    let signature = f
        .key
        .sign(Domain::PolicyBundle, candidate.as_bytes())
        .to_base64();
    let (status, body) = mutate(
        &f,
        AdminMethod::Put,
        "policy",
        json!({"document": candidate, "signature": signature}),
    )
    .await;
    assert_eq!(status, 202, "{body}");
    assert_eq!(
        body,
        json!({"data": {"proposal": "p-3", "state": "pending", "operation": "policy/install"}})
    );
    {
        let seen = gate.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, MutationKind::PolicyInstall);
        assert_eq!(seen[0].1, "alice");
        assert!(seen[0].2.is_some(), "the verified candidate's version");
        assert_eq!(seen[0].3.as_deref(), Some(candidate.as_bytes()));
    }
    assert!(f.sink.events().is_empty());
    assert_eq!(
        std::fs::read(&f.policy).unwrap(),
        b"version: 1\nrules: []\n".to_vec()
    );
    // An unverifiable candidate never reaches the gate at all.
    let (status, _) = mutate(
        &f,
        AdminMethod::Put,
        "policy",
        json!({"document": candidate, "signature": "AAAA"}),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(gate.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn refused_admission_answers_409_with_the_cause_and_appends_nothing() {
    let gate = ScriptedGate::new(Admission::Refused("approval_self"));
    let f = fixture(Some(gate), &[]).await;
    let (status, body) = mutate(&f, AdminMethod::Post, "policy/reload", json!({})).await;
    assert_eq!(status, 409);
    assert_eq!(
        body,
        json!({"error": "approval_self", "error_description": "approval_self"})
    );
    assert!(f.sink.events().is_empty());
}

#[test]
fn approvals_setting_selects_direct_or_refuses_startup_by_name() {
    let build = |value: Option<&str>| {
        let mut map = HashMap::new();
        if let Some(value) = value {
            map.insert(APPROVALS_KEY.to_owned(), value.to_owned());
        }
        ServerBuilder::new().config(Config::from_map(map)).build()
    };
    for value in [None, Some("off"), Some(" OFF "), Some("")] {
        let server = build(value).unwrap_or_else(|error| panic!("{value:?}: {error}"));
        assert_eq!(server.mutation_gate().name(), "direct", "{value:?}");
    }
    let refused = build(Some("required")).err().expect("refused").to_string();
    assert!(refused.contains(APPROVALS_KEY), "{refused}");
    assert!(refused.contains("D.2"), "{refused}");
    assert!(refused.contains("refusing to start"), "{refused}");
    let unknown = build(Some("maybe")).err().expect("refused").to_string();
    assert!(unknown.contains("maybe"), "{unknown}");
}

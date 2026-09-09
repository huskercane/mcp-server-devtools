//! CF-42 / AE-1: who the administrative boundary admits, over the real
//! HTTP path with real RS256 tokens against a wiremock JWKS.
//!
//! The four-eyes rule refuses self-approval on subject equality, which two
//! service accounts satisfy. The control that closes that is here: a
//! machine principal — decided on a validated claim, never on its subject
//! name — is refused at `/admin/*` while the same token still reaches
//! `/mcp`, where its policy applies as before.
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, get_current_timestamp};
use mcp_server_devtools::transport::build_client;
use mcp_server_devtools::{
    auth::oidc::{JwksLocation, OidcJwksValidator, OidcSettings, Profile},
    bootstrap::ServerBuilder,
    config::Config,
    policy::signing::{Domain, SigningKey, write_detached},
    ports::InMemoryAuditSink,
    server::{
        auth::{AdminPrincipals, InboundAuth, InboundAuthSettings},
        http::{Role, build_app_for_role},
    },
};
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PRIVATE_KEY_DER: &[u8] = include_bytes!("fixtures/okta_test_rsa_pkcs1.der");
const PUBLIC_JWK: &str = include_str!("fixtures/okta_test_jwk.json");
const ISSUER: &str = "https://acme.okta.com/oauth2/default";
const AUDIENCE: &str = "api://mcp-devtools";

struct Fixture {
    _dir: tempfile::TempDir,
    url: String,
    cancel: CancellationToken,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn fixture(jwks: &MockServer, policy: AdminPrincipals) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let policy_file = dir.path().join("policy.yaml");
    let (key, _) = SigningKey::generate().unwrap();
    let document = b"version: 1\nrules: []\n";
    std::fs::write(&policy_file, document).unwrap();
    write_detached(&policy_file, &key.sign(Domain::PolicyBundle, document)).unwrap();
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
    let server = ServerBuilder::new()
        .config(Config::from_map(HashMap::from([
            ("MCP_POLICY_FILE".into(), policy_file.display().to_string()),
            (
                "MCP_POLICY_PUBLIC_KEY".into(),
                key.verifying_key().to_base64(),
            ),
        ])))
        .serves_control(true)
        .audit_sink(Arc::new(InMemoryAuditSink::new()))
        .build()
        .unwrap();
    let validator = Arc::new(OidcJwksValidator::new(
        OidcSettings::new(
            Profile::Okta,
            ISSUER,
            AUDIENCE,
            JwksLocation::Direct(format!("{}/keys", jwks.uri())),
        )
        .with_tenant("acme"),
        build_client().unwrap(),
    ));
    let auth = Arc::new(
        InboundAuth::new(
            Arc::new(validator),
            InboundAuthSettings {
                public_url: "https://mcp.example".into(),
                authorization_servers: vec![ISSUER.into()],
                required_scope: "mcp:tools".into(),
            },
        )
        .with_revocations(revocations)
        .with_admin_principals(policy),
    );
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
        _dir: dir,
        url,
        cancel,
    }
}

async fn mount_jwks(server: &MockServer) {
    let mut jwk: Value = serde_json::from_str(PUBLIC_JWK).unwrap();
    jwk["kid"] = json!("test-key-1");
    Mock::given(method("GET"))
        .and(path("/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
        .mount(server)
        .await;
}

fn sign(claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".to_owned());
    encode(&header, claims, &EncodingKey::from_rsa_der(PRIVATE_KEY_DER)).unwrap()
}

fn base(subject: &str) -> Value {
    let now = get_current_timestamp();
    json!({
        "sub": subject,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 300,
        "scp": ["mcp:tools", "mcp:admin"],
    })
}

/// An Okta token with a user bound (`uid`).
fn human_token() -> String {
    let mut claims = base("alice@acme.example");
    claims["uid"] = json!("00u1alice");
    claims["cid"] = json!("0oa-console");
    sign(&claims)
}

/// An Okta client-credentials token: `sub` is the client, `cid` names it,
/// and no `uid` because no user is bound. Named to look like a person on
/// purpose — the name must not matter.
fn machine_token() -> String {
    machine_token_for("alice@acme.example")
}

fn machine_token_for(subject: &str) -> String {
    let mut claims = base(subject);
    claims["cid"] = json!("0oa-ci-pipeline");
    sign(&claims)
}

/// Neither marker: the profile cannot say.
fn unknown_token() -> String {
    sign(&base("someone@acme.example"))
}

async fn admin_get(f: &Fixture, token: &str) -> reqwest::Response {
    reqwest::Client::new()
        .get(format!("{}/admin/policy", f.url))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}

async fn admin_lookup(f: &Fixture, token: &str, subject: &str) -> Value {
    reqwest::Client::new()
        .post(format!("{}/admin/principals/lookup", f.url))
        .bearer_auth(token)
        .json(&json!({"subject": subject, "tenant": "acme"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn tools_list(f: &Fixture, token: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}/mcp", f.url))
        .bearer_auth(token)
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/list")
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": { "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": { "name": "kind-test", "version": "0" }
            } }
        }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn default_policy_refuses_machines_at_admin_and_nowhere_else() {
    let jwks = MockServer::start().await;
    mount_jwks(&jwks).await;
    let f = fixture(&jwks, AdminPrincipals::default()).await;

    // A person with mcp:admin administers.
    assert_eq!(admin_get(&f, &human_token()).await.status(), 200);

    // A client-credentials token with the same scope, and the same subject
    // string, does not: refused on the validated `uid`-less shape.
    let refused = admin_get(&f, &machine_token()).await;
    assert_eq!(refused.status(), 403);
    let challenge = refused
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(challenge.starts_with("Bearer realm="), "{challenge}");
    assert!(!challenge.contains("insufficient_scope"), "{challenge}");
    let body: Value = refused.json().await.unwrap();
    assert_eq!(body["error"], "machine_principal");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("MCP_ADMIN_PRINCIPALS")
    );
    // Category only: no claim value in the envelope.
    assert!(!body.to_string().contains("0oa-ci-pipeline"));

    // The MCP boundary is untouched: the machine calls tools under policy.
    assert_eq!(tools_list(&f, &machine_token()).await.status(), 200);

    // A token the profile cannot classify is admitted under the default.
    assert_eq!(admin_get(&f, &unknown_token()).await.status(), 200);
}

const PIPELINE: &str = "ci-pipeline@acme.example";

#[tokio::test]
async fn refused_machine_never_appears_as_an_observed_administrator() {
    let jwks = MockServer::start().await;
    mount_jwks(&jwks).await;
    let f = fixture(&jwks, AdminPrincipals::default()).await;
    // A pipeline with its own subject is refused at the boundary...
    assert_eq!(
        admin_get(&f, &machine_token_for(PIPELINE)).await.status(),
        403
    );
    // ...and a different person, looking up that exact subject, finds no
    // observation of it: refusal happened before the inventory was written.
    // The person's own visit is what the lookup itself records, so their
    // entry is the control that the inventory is live at all.
    let pipeline = admin_lookup(&f, &human_token(), PIPELINE).await;
    assert_eq!(pipeline["data"]["subject"], PIPELINE);
    assert!(
        pipeline["data"]["principal"].is_null(),
        "a refused machine must not be observed: {pipeline}"
    );
    let person = admin_lookup(&f, &human_token(), "alice@acme.example").await;
    assert!(
        person["data"]["principal"]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|scope| scope == "mcp:admin")
    );
}

#[tokio::test]
async fn human_only_policy_refuses_unknown_and_any_admits_machines() {
    let jwks = MockServer::start().await;
    mount_jwks(&jwks).await;

    let strict = fixture(&jwks, AdminPrincipals::Human).await;
    assert_eq!(admin_get(&strict, &human_token()).await.status(), 200);
    let refused = admin_get(&strict, &unknown_token()).await;
    assert_eq!(refused.status(), 403);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["error"],
        "unverified_principal_kind"
    );
    assert_eq!(admin_get(&strict, &machine_token()).await.status(), 403);
    drop(strict);

    let open = fixture(&jwks, AdminPrincipals::Any).await;
    assert_eq!(admin_get(&open, &machine_token()).await.status(), 200);
    assert_eq!(admin_get(&open, &unknown_token()).await.status(), 200);
}

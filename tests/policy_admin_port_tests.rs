//! The HTTP adapter can operate without a local policy file and maps port
//! failures without leaking backend details into its error envelope.
use mcp_server_devtools::{
    audit::export::AccessRow,
    bootstrap::ServerBuilder,
    config::Config,
    policy::{Principal, PrincipalAuthority},
    ports::{
        StaticValidator,
        policy_admin::{
            AdminFuture, PolicyAdmin, PolicyAdminError, PolicyDiff, PolicyDocument,
            PolicyExplanation, PolicyInstall, PolicyReload, PolicyValidation,
        },
    },
    server::{
        admin,
        auth::{InboundAuth, InboundAuthSettings},
    },
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

struct RemotePolicy;
impl PolicyAdmin for RemotePolicy {
    fn read(&self) -> AdminFuture<'_, PolicyDocument> {
        Box::pin(std::future::ready(Ok(PolicyDocument {
            version: "remote-v7".into(),
            document: "remote policy".into(),
            signature: None,
        })))
    }
    fn validate(&self, _: String) -> AdminFuture<'_, PolicyValidation> {
        Box::pin(std::future::ready(Err(PolicyAdminError::Invalid)))
    }
    fn diff(&self, _: String) -> AdminFuture<'_, PolicyDiff> {
        Box::pin(std::future::ready(Err(PolicyAdminError::Unavailable)))
    }
    fn reload<'a>(&'a self, principal: &'a Principal) -> AdminFuture<'a, PolicyReload> {
        assert_eq!(principal.subject, "operator");
        Box::pin(std::future::ready(Err(PolicyAdminError::AuditUnavailable)))
    }
    fn verify<'a>(&'a self, _: &'a str, _: &'a str) -> AdminFuture<'a, PolicyValidation> {
        Box::pin(std::future::ready(Err(PolicyAdminError::Invalid)))
    }
    fn install<'a>(
        &'a self,
        _: &'a Principal,
        _: String,
        _: String,
    ) -> AdminFuture<'a, PolicyInstall> {
        Box::pin(std::future::ready(Err(PolicyAdminError::Unavailable)))
    }
    fn access_review(
        &self,
        _: BTreeMap<String, Vec<String>>,
        _: String,
    ) -> AdminFuture<'_, Vec<AccessRow>> {
        Box::pin(std::future::ready(Ok(vec![])))
    }
    fn explain(
        &self,
        _: mcp_server_devtools::policy::ActionContext,
    ) -> AdminFuture<'_, PolicyExplanation> {
        Box::pin(std::future::ready(Err(PolicyAdminError::Unavailable)))
    }
}

#[tokio::test]
async fn http_uses_injected_policy_port_and_preserves_error_envelopes() {
    let server = ServerBuilder::new()
        .config(Config::default())
        .build()
        .unwrap();
    assert!(server.policy_file().is_none());
    let principal = Principal {
        tenant: "tenant".into(),
        subject: "operator".into(),
        groups: vec![],
        scopes: vec!["mcp:admin".into()],
        authority: PrincipalAuthority::oidc("https://issuer.example"),
    };
    let auth = InboundAuth::new(
        Arc::new(StaticValidator::new().with("admin", principal)),
        InboundAuthSettings {
            public_url: "https://mcp.example".into(),
            authorization_servers: vec!["https://issuer.example".into()],
            required_scope: "mcp:tools".into(),
        },
    );
    let app = admin::router_with_policy(
        server,
        &auth,
        None,
        None,
        None,
        Some(Arc::new(RemotePolicy)),
        Arc::new(mcp_server_devtools::ports::DirectGate),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let response: Value = client
        .get(format!("http://{address}/admin/policy"))
        .bearer_auth("admin")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        response,
        json!({"data": {"version": "remote-v7", "document": "remote policy", "signature": null}})
    );
    for (op, body, status, error) in [
        (
            "policy/validate",
            json!({"document":"candidate"}),
            400,
            "invalid_request",
        ),
        (
            "policy/diff",
            json!({"document":"candidate"}),
            503,
            "admin_backend_unavailable",
        ),
        ("policy/reload", json!({}), 503, "audit_unavailable"),
    ] {
        let response = client
            .post(format!("http://{address}/admin/{op}"))
            .bearer_auth("admin")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(
            response.json::<Value>().await.unwrap(),
            json!({"error":error,"error_description":error})
        );
    }
    let response: Value = client
        .post(format!("http://{address}/admin/reports/access-review"))
        .bearer_auth("admin")
        .json(&json!({"groups":{},"tenant":"tenant"}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response, json!({"data":{"rows":[]}}));
    tasks.shutdown().await;
}

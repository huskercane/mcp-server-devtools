//! Community remains independently operable and refuses absent paid adapters.
use axum::{body::Body, http::Request};
use mcp_server_devtools::{
    bootstrap::ServerBuilder,
    config::Config,
    policy::{Principal, PrincipalAuthority},
    ports::StaticValidator,
    server::{
        auth::{InboundAuth, InboundAuthSettings},
        http::{CommunityEdition, HttpEdition, Role, build_app_for_role},
    },
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

#[test]
fn paid_configuration_cannot_silently_fall_back_to_direct_administration() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::from_map(HashMap::from([
        ("MCP_ADMIN_APPROVALS".into(), "required".into()),
        (
            "MCP_AUDIT_JOURNAL_DIR".into(),
            dir.path().display().to_string(),
        ),
    ]));
    let error = ServerBuilder::new()
        .config(config)
        .build()
        .err()
        .expect("Community must refuse approvals");
    assert!(error.to_string().contains("Enterprise approval adapter"));
    let config = Config::from_map(HashMap::from([(
        "MCP_CONSOLE_CLIENT_ID".into(),
        "console".into(),
    )]));
    assert!(
        CommunityEdition
            .setup(&config, Role::All, None, None)
            .is_err()
    );
}

#[tokio::test]
async fn community_has_no_proposal_or_console_routes_and_preserves_admin_authentication() {
    let server = ServerBuilder::new()
        .config(Config::from_map(HashMap::new()))
        .build()
        .unwrap();
    let auth = Arc::new(InboundAuth::new(
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
    ));
    let cancel = CancellationToken::new();
    let app = build_app_for_role(
        Role::All,
        server,
        Some(auth),
        Duration::from_mins(1),
        Duration::from_mins(1),
        cancel.clone(),
    );
    for (path, bearer, expected) in [
        ("/console", None, 404),
        ("/admin/proposals", None, 401),
        ("/admin/proposals", Some("admin"), 404),
    ] {
        let mut request = Request::builder().uri(path);
        if let Some(bearer) = bearer {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), expected, "{path}");
    }
    cancel.cancel();
}

//! Controller-pipeline tests for the Vercel vendor. Exercises the full path a
//! `vercel_*` tool takes: read the static `VERCEL_TOKEN` from config → resolve
//! the team scope (argument → `VERCEL_TEAM_ID` → none) → dispatch through the
//! shared transport with an `Authorization: Bearer <token>` header → classify
//! Vercel's `{"error": {"code", "message"}}` envelope.
//!
//! Vercel's REST API is stood up on a wiremock instance, so these tests need no
//! network and no global state — the base-URL override is what makes that
//! possible.

use std::collections::HashMap;

use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::vercel::{
    VercelContext, get_deployment, get_deployment_logs, list_deployments, list_projects,
};
use mcp_server_devtools::error::ErrorKind;
use mcp_server_devtools::tools::args::{
    VercelGetDeploymentArgs, VercelGetDeploymentLogsArgs, VercelListDeploymentsArgs,
    VercelListProjectsArgs,
};
use mcp_server_devtools::transport::build_client;
use mcp_server_devtools::vendor::vercel::{
    DEFAULT_API_BASE, VercelVendor, deployment_events_path, deployment_path,
};
use mcp_server_devtools::vendor::{Vendor, vercel::error::parse_error_body};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "vc-secret-token";

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
    )
}

fn token_only() -> Config {
    config(&[("VERCEL_TOKEN", TOKEN)])
}

/// The query string of the single request wiremock received, as a sorted
/// `key=value` list — used to assert a parameter is *absent*, which the
/// positive matchers cannot express.
async fn only_request_query(server: &MockServer) -> Vec<String> {
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "expected exactly one upstream request");
    let mut pairs: Vec<String> = requests[0]
        .url
        .query_pairs()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    pairs.sort();
    pairs
}

fn cleanup(resp: &mcp_server_devtools::controllers::ControllerResponse) {
    if let Some(p) = &resp.raw_response_path {
        let _ = std::fs::remove_file(p);
    }
}

#[tokio::test]
async fn configuration_base_url_team_scope_and_tool_routing() {
    let vendor = VercelVendor::new();
    assert_eq!(vendor.name(), "vercel");

    // Missing / blank token → AuthMissing at call time.
    for value in [None, Some(""), Some("   ")] {
        let cfg = value.map_or_else(
            || Config::from_map(HashMap::new()),
            |v| config(&[("VERCEL_TOKEN", v)]),
        );
        assert_eq!(
            vendor.token(&cfg).await.unwrap_err().kind,
            ErrorKind::AuthMissing
        );
        // The base URL is fixed and never depends on config.
        assert_eq!(vendor.base_url(&cfg).unwrap(), DEFAULT_API_BASE);
    }

    let cfg = config(&[("VERCEL_TOKEN", TOKEN), ("VERCEL_TEAM_ID", " team_abc ")]);
    assert_eq!(vendor.token(&cfg).await.unwrap(), TOKEN);
    assert_eq!(vendor.default_team_id(&cfg), Some("team_abc"));
    assert_eq!(VercelVendor::new().default_team_id(&token_only()), None);
    assert_eq!(
        VercelVendor::new().default_team_id(&config(&[("VERCEL_TEAM_ID", "  ")])),
        None
    );
    assert_eq!(
        VercelVendor::with_base_url("http://localhost:1234/")
            .base_url(&cfg)
            .unwrap(),
        "http://localhost:1234"
    );
    assert_eq!(vendor.normalize_path("v9/projects"), "/v9/projects");
    assert_eq!(vendor.normalize_path("/v9/projects"), "/v9/projects");
    assert_eq!(deployment_path("dpl_1"), "/v13/deployments/dpl_1");
    assert_eq!(
        deployment_events_path("dpl_1"),
        "/v3/deployments/dpl_1/events"
    );

    for tool in [
        "vercel_list_projects",
        "vercel_list_deployments",
        "vercel_get_deployment",
        "vercel_get_deployment_logs",
    ] {
        assert_eq!(
            mcp_server_devtools::tools::vendor_for_tool(tool),
            Some("vercel")
        );
    }
}

#[tokio::test]
async fn list_projects_sends_bearer_filters_and_config_team_scope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v9/projects"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .and(header("accept", "application/json"))
        .and(query_param("teamId", "team_cfg"))
        .and(query_param("search", "storefront"))
        .and(query_param("limit", "5"))
        .and(query_param("from", "1718000000000"))
        .and(query_param("until", "1719000000000"))
        .and(query_param("repoUrl", "https://github.com/acme/storefront"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projects": [{"id": "prj_1", "name": "storefront", "framework": "nextjs"}],
            "pagination": {"count": 1, "next": 1_717_000_000_000_i64, "prev": null}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = config(&[("VERCEL_TOKEN", TOKEN), ("VERCEL_TEAM_ID", "team_cfg")]);
    let client = build_client().unwrap();
    let vendor = VercelVendor::with_base_url(server.uri());
    let ctx = VercelContext::new(&client, &cfg, &vendor);
    let args: VercelListProjectsArgs = serde_json::from_value(json!({
        "search": "storefront", "limit": 5, "from": "1718000000000",
        "until": "1719000000000", "repoUrl": "https://github.com/acme/storefront",
        "jq": "projects[0].name", "outputFormat": "json"
    }))
    .unwrap();
    let resp = list_projects(&ctx, &args).await.unwrap();
    assert!(resp.content.contains("storefront"));
    assert!(
        !resp.content.contains("prj_1"),
        "jq should have narrowed the body"
    );
    cleanup(&resp);
}

#[tokio::test]
async fn list_projects_defaults_limit_and_omits_team_when_unscoped() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v9/projects"))
        .and(query_param("limit", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"projects": []})))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = token_only();
    let client = build_client().unwrap();
    let vendor = VercelVendor::with_base_url(server.uri());
    let ctx = VercelContext::new(&client, &cfg, &vendor);
    let resp = list_projects(&ctx, &VercelListProjectsArgs::default())
        .await
        .unwrap();
    cleanup(&resp);
    assert_eq!(only_request_query(&server).await, vec!["limit=20"]);
}

#[tokio::test]
async fn list_deployments_argument_team_overrides_config_and_normalizes_filters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v6/deployments"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .and(query_param("teamId", "team_arg"))
        .and(query_param("projectId", "prj_1"))
        .and(query_param("app", "storefront"))
        .and(query_param("state", "ERROR,CANCELED"))
        .and(query_param("target", "production"))
        .and(query_param("limit", "100"))
        .and(query_param("since", "1718000000000"))
        .and(query_param("until", "1719000000000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "deployments": [{"uid": "dpl_9", "state": "ERROR", "url": "x.vercel.app"}],
            "pagination": {"count": 1, "next": null, "prev": null}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = config(&[("VERCEL_TOKEN", TOKEN), ("VERCEL_TEAM_ID", "team_cfg")]);
    let client = build_client().unwrap();
    let vendor = VercelVendor::with_base_url(server.uri());
    let ctx = VercelContext::new(&client, &cfg, &vendor);
    let args: VercelListDeploymentsArgs = serde_json::from_value(json!({
        "teamId": " team_arg ", "projectId": "prj_1", "app": "storefront",
        "state": "error, canceled", "target": "Production", "limit": 100,
        "since": "1718000000000", "until": "1719000000000", "outputFormat": "json"
    }))
    .unwrap();
    let resp = list_deployments(&ctx, &args).await.unwrap();
    assert!(resp.content.contains("dpl_9"));
    cleanup(&resp);
    let query = only_request_query(&server).await;
    assert_eq!(
        query.iter().filter(|p| p.starts_with("teamId=")).count(),
        1,
        "the argument replaces, not augments, the configured team"
    );
}

#[tokio::test]
async fn get_deployment_hits_v13_path_by_id_or_hostname() {
    let server = MockServer::start().await;
    for deployment in ["dpl_abc123", "storefront-abc123-acme.vercel.app"] {
        Mock::given(method("GET"))
            .and(path(format!("/v13/deployments/{deployment}")))
            .and(header("authorization", &format!("Bearer {TOKEN}")))
            .and(query_param("teamId", "team_cfg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "dpl_abc123", "readyState": "ERROR", "errorMessage": "Build failed"
            })))
            .expect(1)
            .mount(&server)
            .await;
    }

    let cfg = config(&[("VERCEL_TOKEN", TOKEN), ("VERCEL_TEAM_ID", "team_cfg")]);
    let client = build_client().unwrap();
    let vendor = VercelVendor::with_base_url(server.uri());
    let ctx = VercelContext::new(&client, &cfg, &vendor);
    for deployment in ["dpl_abc123", "storefront-abc123-acme.vercel.app"] {
        let args = VercelGetDeploymentArgs {
            deployment: deployment.to_owned(),
            jq: Some("errorMessage".into()),
            ..Default::default()
        };
        let resp = get_deployment(&ctx, &args).await.unwrap();
        assert!(resp.content.contains("Build failed"));
        cleanup(&resp);
    }
}

#[tokio::test]
async fn deployment_logs_are_bounded_never_followed_and_builds_toggle() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v3/deployments/dpl_abc/events"))
        .and(header("authorization", &format!("Bearer {TOKEN}")))
        .and(query_param("limit", "100"))
        .and(query_param("direction", "forward"))
        .and(query_param("builds", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"type": "stdout", "created": 1_718_000_000_000_i64, "payload": {"text": "Installing"}},
            {"type": "stderr", "created": 1_718_000_001_000_i64, "payload": {"text": "Type error"}}
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = token_only();
    let client = build_client().unwrap();
    let vendor = VercelVendor::with_base_url(server.uri());
    let ctx = VercelContext::new(&client, &cfg, &vendor);
    let args = VercelGetDeploymentLogsArgs {
        deployment: "dpl_abc".into(),
        jq: Some("[?type=='stderr'].payload.text".into()),
        ..Default::default()
    };
    let resp = get_deployment_logs(&ctx, &args).await.unwrap();
    assert!(resp.content.contains("Type error"));
    assert!(!resp.content.contains("Installing"));
    cleanup(&resp);
    assert_eq!(
        only_request_query(&server).await,
        vec!["builds=1", "direction=forward", "limit=100"]
    );

    // Explicit filters, backward read, and builds=false (parameter omitted).
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/v3/deployments/dpl_abc/events"))
        .and(query_param("teamId", "team_arg"))
        .and(query_param("limit", "1000"))
        .and(query_param("direction", "backward"))
        .and(query_param("since", "1718000000000"))
        .and(query_param("until", "1719000000000"))
        .and(query_param("statusCode", "5xx"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;
    let args: VercelGetDeploymentLogsArgs = serde_json::from_value(json!({
        "deployment": "dpl_abc", "teamId": "team_arg", "limit": 1000,
        "direction": "BACKWARD", "builds": false, "since": "1718000000000",
        "until": "1719000000000", "statusCode": "5xx"
    }))
    .unwrap();
    let resp = get_deployment_logs(&ctx, &args).await.unwrap();
    cleanup(&resp);
    let query = only_request_query(&server).await;
    assert!(!query.iter().any(|p| p.starts_with("follow=")));
    assert!(!query.iter().any(|p| p.starts_with("builds=")));
}

#[tokio::test]
async fn identifier_and_argument_validation_rejects_before_any_request() {
    let server = MockServer::start().await;
    let cfg = token_only();
    let client = build_client().unwrap();
    let vendor = VercelVendor::with_base_url(server.uri());
    let ctx = VercelContext::new(&client, &cfg, &vendor);

    for bad in ["", "  ", "..", "a/b", "dpl?x", "a%2Fb", "a b"] {
        let err = get_deployment(
            &ctx,
            &VercelGetDeploymentArgs {
                deployment: bad.to_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code, Some(400), "deployment {bad:?}");
        let err = get_deployment_logs(
            &ctx,
            &VercelGetDeploymentLogsArgs {
                deployment: bad.to_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code, Some(400), "logs deployment {bad:?}");
    }

    // teamId is validated the same way, from the argument and from config.
    for bad in ["team/x", "..", "team?x"] {
        let err = list_projects(
            &ctx,
            &VercelListProjectsArgs {
                team_id: Some(bad.to_owned()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code, Some(400), "teamId {bad:?}");
        assert!(err.message.contains("teamId"));
    }
    let bad_cfg = config(&[("VERCEL_TOKEN", TOKEN), ("VERCEL_TEAM_ID", "team/x")]);
    let bad_ctx = VercelContext::new(&client, &bad_cfg, &vendor);
    assert_eq!(
        list_projects(&bad_ctx, &VercelListProjectsArgs::default())
            .await
            .unwrap_err()
            .status_code,
        Some(400)
    );

    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn pagination_and_enum_validation_rejects_before_any_request() {
    let server = MockServer::start().await;
    let cfg = token_only();
    let client = build_client().unwrap();
    let vendor = VercelVendor::with_base_url(server.uri());
    let ctx = VercelContext::new(&client, &cfg, &vendor);

    // Page bounds and enumerations.
    for limit in [0, 101] {
        let err = list_projects(
            &ctx,
            &VercelListProjectsArgs {
                limit: Some(limit),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code, Some(400), "projects limit {limit}");
        let err = list_deployments(
            &ctx,
            &VercelListDeploymentsArgs {
                limit: Some(limit),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code, Some(400), "deployments limit {limit}");
    }
    for limit in [0, 1001] {
        let err = get_deployment_logs(
            &ctx,
            &VercelGetDeploymentLogsArgs {
                deployment: "dpl_1".into(),
                limit: Some(limit),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code, Some(400), "logs limit {limit}");
    }
    let err = list_deployments(
        &ctx,
        &VercelListDeploymentsArgs {
            state: Some("READY,BROKEN".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(400));
    assert!(err.message.contains("`state`"));
    let err = list_deployments(
        &ctx,
        &VercelListDeploymentsArgs {
            target: Some("staging".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(400));
    let err = get_deployment_logs(
        &ctx,
        &VercelGetDeploymentLogsArgs {
            deployment: "dpl_1".into(),
            direction: Some("sideways".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(400));

    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "validation must fail before any upstream request"
    );
}

#[tokio::test]
async fn missing_token_surfaces_auth_missing_at_call_time() {
    let server = MockServer::start().await;
    let cfg = Config::from_map(HashMap::new());
    let client = build_client().unwrap();
    let vendor = VercelVendor::with_base_url(server.uri());
    let ctx = VercelContext::new(&client, &cfg, &vendor);
    let err = list_projects(&ctx, &VercelListProjectsArgs::default())
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthMissing);
    assert!(err.message.contains("VERCEL_TOKEN"));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn vercel_error_envelope_is_classified_and_preserved() {
    let server = MockServer::start().await;
    let cfg = token_only();
    let client = build_client().unwrap();
    let vendor = VercelVendor::with_base_url(server.uri());
    let ctx = VercelContext::new(&client, &cfg, &vendor);

    for (status, code, message) in [
        (401, "unauthorized", "Not authorized"),
        (
            403,
            "forbidden",
            "Not authorized: Trying to access a resource of a team",
        ),
        (404, "not_found", "Deployment not found"),
        (429, "rate_limited", "Too many requests"),
        (
            500,
            "internal_server_error",
            "An unexpected internal error occurred",
        ),
    ] {
        let deployment = format!("dpl_{status}");
        Mock::given(method("GET"))
            .and(path(format!("/v13/deployments/{deployment}")))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(json!({"error": {"code": code, "message": message}})),
            )
            .mount(&server)
            .await;
        let err = get_deployment(
            &ctx,
            &VercelGetDeploymentArgs {
                deployment,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code, Some(status));
        assert!(err.message.contains(message), "{status}: {}", err.message);
        assert!(err.message.contains(code), "{status}: {}", err.message);
        assert!(err.original.is_some());
        match status {
            401 | 403 => {
                assert_eq!(err.kind, ErrorKind::AuthInvalid);
                assert!(err.message.contains("teamId"), "{status}: {}", err.message);
            }
            404 => {
                assert_eq!(err.kind, ErrorKind::ApiError);
                assert!(err.message.contains("teamId"));
            }
            429 => assert!(err.message.contains("Rate limit")),
            _ => assert!(err.message.contains("server error")),
        }
    }

    // A non-JSON body is passed through verbatim.
    Mock::given(method("GET"))
        .and(path("/v13/deployments/dpl_text"))
        .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway from edge"))
        .mount(&server)
        .await;
    let err = get_deployment(
        &ctx,
        &VercelGetDeploymentArgs {
            deployment: "dpl_text".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(502));
    assert!(err.message.contains("Bad Gateway from edge"));
}

#[test]
fn error_body_parsing_handles_every_envelope_shape() {
    assert!(parse_error_body("   ").message.is_none());
    assert_eq!(
        parse_error_body(r#"{"error":{"code":"forbidden","message":"Nope"}}"#)
            .message
            .as_deref(),
        Some("Nope (code: forbidden)")
    );
    assert_eq!(
        parse_error_body(r#"{"error":{"code":"forbidden"}}"#)
            .message
            .as_deref(),
        Some("forbidden")
    );
    assert_eq!(
        parse_error_body(r#"{"message":"top level"}"#)
            .message
            .as_deref(),
        Some("top level")
    );
    assert!(parse_error_body(r#"{"unrelated": true}"#).message.is_none());
    assert_eq!(
        parse_error_body("{not json").message.as_deref(),
        Some("{not json")
    );
}

#[tokio::test]
async fn vendor_sections_aliases_and_secret_registration() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("configs.json");
    for alias in ["vercel", "mcp-server-vercel"] {
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({alias: {"environments": {
                "VERCEL_TOKEN": "scoped-token", "VERCEL_TEAM_ID": "team_from_file"
            }}}))
            .unwrap(),
        )
        .unwrap();
        let cfg = Config::load_from_sources(Some(&file), None, &HashMap::new());
        let vendor = VercelVendor::new();
        assert_eq!(vendor.token(&cfg).await.unwrap(), "scoped-token");
        assert_eq!(vendor.default_team_id(&cfg), Some("team_from_file"));
    }
    assert!(mcp_server_devtools::auth::secrets::lookup("vercel", "VERCEL_TOKEN").is_some());
}

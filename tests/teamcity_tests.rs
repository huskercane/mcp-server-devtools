use std::collections::HashMap;

use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::teamcity::{TeamcityContext, handle_read, handle_write};
use mcp_server_devtools::error::ErrorKind;
use mcp_server_devtools::tools::args::{TeamcityReadArgs, TeamcityWriteArgs};
use mcp_server_devtools::transport::{HttpMethod, build_client};
use mcp_server_devtools::vendor::{Vendor, teamcity::TeamcityVendor};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
    )
}

#[tokio::test]
async fn required_configuration_and_path_normalization() {
    let vendor = TeamcityVendor::new();
    assert_eq!(vendor.name(), "teamcity");
    for value in [None, Some(""), Some("   ")] {
        let cfg = value.map_or_else(
            || Config::from_map(HashMap::new()),
            |v| config(&[("TEAMCITY_URL", v), ("TEAMCITY_TOKEN", v)]),
        );
        assert_eq!(
            vendor.base_url(&cfg).unwrap_err().kind,
            ErrorKind::AuthMissing
        );
        assert_eq!(
            vendor.token(&cfg).await.unwrap_err().kind,
            ErrorKind::AuthMissing
        );
    }
    let cfg = config(&[
        ("TEAMCITY_URL", " https://ci.example/teamcity/ "),
        ("TEAMCITY_TOKEN", "token"),
    ]);
    assert_eq!(
        vendor.base_url(&cfg).unwrap(),
        "https://ci.example/teamcity"
    );
    assert_eq!(vendor.token(&cfg).await.unwrap(), "token");
    assert_eq!(
        TeamcityVendor::with_base_url("http://localhost/")
            .base_url(&cfg)
            .unwrap(),
        "http://localhost"
    );
    for input in ["builds", "/builds", "app/rest/builds", "/app/rest/builds"] {
        assert_eq!(vendor.normalize_path(input), "/app/rest/builds");
    }
    assert_eq!(vendor.normalize_path(""), "/app/rest");
    assert_eq!(
        vendor.normalize_path("/app/rest?fields=server"),
        "/app/rest?fields=server"
    );
    for tool in [
        "teamcity_get",
        "teamcity_post",
        "teamcity_put",
        "teamcity_delete",
    ] {
        assert_eq!(
            mcp_server_devtools::tools::vendor_for_tool(tool),
            Some("teamcity")
        );
    }
}

#[tokio::test]
async fn read_sends_bearer_json_accept_locator_and_context_path() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/teamcity/app/rest/builds"))
        .and(header("authorization", "Bearer tc-secret"))
        .and(header("accept", "application/json"))
        .and(query_param("locator", "buildType:MyBuild,count:20"))
        .and(query_param("fields", "build(id,status),nextHref"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"build":[{"id":42,"status":"SUCCESS"}]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[
        ("TEAMCITY_TOKEN", "tc-secret"),
        ("TEAMCITY_URL", &format!("{}/teamcity/", server.uri())),
    ]);
    let client = build_client().unwrap();
    let vendor = TeamcityVendor::new();
    let ctx = TeamcityContext::new(&client, &cfg, &vendor);
    let args: TeamcityReadArgs = serde_json::from_value(json!({"path":"builds","queryParams":{"locator":"buildType:MyBuild,count:20","fields":"build(id,status),nextHref"},"jq":"build[0].status","outputFormat":"json"})).unwrap();
    let response = handle_read(&ctx, HttpMethod::Get, &args).await.unwrap();
    assert!(response.content.contains("SUCCESS"));
    assert!(!response.content.contains("42"));
}

#[tokio::test]
async fn mutations_send_json_and_delete_handles_empty_response() {
    let server = MockServer::start().await;
    let cfg = config(&[("TEAMCITY_TOKEN", "tc-secret")]);
    let client = build_client().unwrap();
    let vendor = TeamcityVendor::with_base_url(server.uri());
    let ctx = TeamcityContext::new(&client, &cfg, &vendor);
    for (verb, http_method, endpoint, body) in [
        (
            "POST",
            HttpMethod::Post,
            "/app/rest/buildQueue",
            json!({"buildType":{"id":"MyBuild"}}),
        ),
        (
            "PUT",
            HttpMethod::Put,
            "/app/rest/buildQueue/pausedState",
            json!({"paused":true,"reason":"Maintenance"}),
        ),
    ] {
        Mock::given(method(verb))
            .and(path(endpoint))
            .and(header("authorization", "Bearer tc-secret"))
            .and(header("content-type", "application/json"))
            .and(body_json(&body))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":42})))
            .expect(1)
            .mount(&server)
            .await;
        let args: TeamcityWriteArgs =
            serde_json::from_value(json!({"path":endpoint,"body":body})).unwrap();
        assert!(
            handle_write(&ctx, http_method, &args)
                .await
                .unwrap()
                .content
                .contains("42")
        );
    }
    Mock::given(method("DELETE"))
        .and(path("/app/rest/builds/id:42"))
        .and(header("authorization", "Bearer tc-secret"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let args: TeamcityReadArgs = serde_json::from_value(json!({"path":"builds/id:42"})).unwrap();
    handle_read(&ctx, HttpMethod::Delete, &args).await.unwrap();
}

#[tokio::test]
async fn upstream_plain_text_errors_preserve_status_and_details() {
    let server = MockServer::start().await;
    let cfg = config(&[("TEAMCITY_TOKEN", "tc-secret")]);
    let client = build_client().unwrap();
    let vendor = TeamcityVendor::with_base_url(server.uri());
    let ctx = TeamcityContext::new(&client, &cfg, &vendor);
    for status in [400, 401, 403, 404, 429, 500] {
        let endpoint = format!("/app/rest/builds/id:{status}");
        Mock::given(method("GET"))
            .and(path(&endpoint))
            .respond_with(ResponseTemplate::new(status).set_body_string("TeamCity request failed"))
            .mount(&server)
            .await;
        let args: TeamcityReadArgs = serde_json::from_value(json!({"path":endpoint})).unwrap();
        let error = handle_read(&ctx, HttpMethod::Get, &args).await.unwrap_err();
        assert_eq!(error.status_code, Some(status));
        assert!(error.message.contains("TeamCity request failed"));
        assert!(error.original.is_some());
        if matches!(status, 401 | 403) {
            assert_eq!(error.kind, ErrorKind::AuthInvalid);
        }
    }
}

#[tokio::test]
async fn vendor_sections_aliases_and_secret_registration() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("configs.json");
    for alias in ["teamcity", "team-city", "mcp-server-teamcity"] {
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({alias: {"environments": {
                "TEAMCITY_URL": "https://ci.example", "TEAMCITY_TOKEN": "scoped-token"
            }}}))
            .unwrap(),
        )
        .unwrap();
        let cfg = Config::load_from_sources(Some(&file), None, &HashMap::new());
        assert_eq!(
            TeamcityVendor::new().token(&cfg).await.unwrap(),
            "scoped-token"
        );
        assert_eq!(
            TeamcityVendor::new().base_url(&cfg).unwrap(),
            "https://ci.example"
        );
    }
    assert!(mcp_server_devtools::auth::secrets::lookup("teamcity", "TEAMCITY_TOKEN").is_some());
}

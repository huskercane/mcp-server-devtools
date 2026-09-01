use std::collections::HashMap;

use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::ninjaone::{NinjaOneContext, handle_read, handle_write};
use mcp_server_devtools::tools::args::{NinjaOneReadArgs, NinjaOneWriteArgs, OutputFormatArg};
use mcp_server_devtools::transport::{HttpMethod, build_client};
use mcp_server_devtools::vendor::ninjaone::NinjaOneVendor;
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn read_args() -> NinjaOneReadArgs {
    NinjaOneReadArgs {
        server: None,
        path: "/v2/devices".to_owned(),
        query_params: None,
        jq: None,
        output_format: Some(OutputFormatArg::Json),
    }
}

#[tokio::test]
async fn get_uses_bearer_and_query_parameters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/devices"))
        .and(header("authorization", "Bearer secret-token"))
        .and(query_param("pageSize", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"id": 42}])))
        .mount(&server)
        .await;

    let config = Config::from_map(HashMap::from([(
        "NINJAONE_ACCESS_TOKEN".to_owned(),
        "secret-token".to_owned(),
    )]));
    let client = build_client().unwrap();
    let vendor = NinjaOneVendor::with_base_url(server.uri());
    let context = NinjaOneContext::new(&client, &config, &vendor);
    let mut args = read_args();
    args.query_params = Some([("pageSize".to_owned(), "10".to_owned())].into());

    let response = handle_read(&context, HttpMethod::Get, &args).await.unwrap();
    assert!(response.content.contains("42"));
    if let Some(path) = response.raw_response_path {
        let _ = std::fs::remove_file(path);
    }
}

#[tokio::test]
async fn post_supports_the_sample_search_shape_with_cookie_auth() {
    let server = MockServer::start().await;
    let body = json!({
        "searchCriteria": [{"type": "all-devices", "customFields": "{}"}]
    });
    Mock::given(method("POST"))
        .and(path("/ws/search/runner"))
        .and(header("cookie", "sessionKey=abc123"))
        .and(body_json(body.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"cacheKey": "key-1"})))
        .mount(&server)
        .await;

    let config = Config::from_map(HashMap::from([(
        "NINJAONE_SESSION_COOKIE".to_owned(),
        "sessionKey=abc123".to_owned(),
    )]));
    let client = build_client().unwrap();
    let vendor = NinjaOneVendor::with_base_url(server.uri());
    let context = NinjaOneContext::new(&client, &config, &vendor);
    let args = NinjaOneWriteArgs {
        server: None,
        path: "/ws/search/runner".to_owned(),
        body,
        query_params: None,
        jq: Some("cacheKey".to_owned()),
        output_format: Some(OutputFormatArg::Json),
    };

    let response = handle_write(&context, HttpMethod::Post, &args)
        .await
        .unwrap();
    assert!(response.content.contains("key-1"));
    if let Some(path) = response.raw_response_path {
        let _ = std::fs::remove_file(path);
    }
}

#[tokio::test]
async fn post_forwards_an_empty_object_as_an_object_not_a_json_string() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/backup/lockhart/scheduled-deletion"))
        .and(header("cookie", "sessionKey=abc123"))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let config = Config::from_map(HashMap::from([(
        "NINJAONE_SESSION_COOKIE".to_owned(),
        "sessionKey=abc123".to_owned(),
    )]));
    let client = build_client().unwrap();
    let vendor = NinjaOneVendor::with_base_url(server.uri());
    let context = NinjaOneContext::new(&client, &config, &vendor);
    let args: NinjaOneWriteArgs = serde_json::from_value(json!({
        "path": "/backup/lockhart/scheduled-deletion",
        "body": {},
        "outputFormat": "json"
    }))
    .unwrap();

    let response = handle_write(&context, HttpMethod::Post, &args)
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();

    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, b"{}");
    if let Some(path) = response.raw_response_path {
        let _ = std::fs::remove_file(path);
    }
}

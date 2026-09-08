use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use mcp_server_devtools::{
    config::Config,
    controllers::{api::HandleContext, jira::get_attachment},
    transport::{build_client, image::MAX_IMAGE_BYTES},
    vendor::jira::JiraVendor,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path, query_param},
};

async fn download(
    template: ResponseTemplate,
) -> Result<serde_json::Value, mcp_server_devtools::error::McpError> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/attachment/content/493334"))
        .and(query_param("redirect", "false"))
        .and(header("accept", "*/*"))
        .and(header(
            "authorization",
            "Basic YWxpY2VAZXhhbXBsZS5jb206dG9r",
        ))
        .respond_with(template)
        .expect(1)
        .mount(&server)
        .await;
    let config = Config::from_map(HashMap::from([
        ("ATLASSIAN_USER_EMAIL".into(), "alice@example.com".into()),
        ("ATLASSIAN_API_TOKEN".into(), "tok".into()),
    ]));
    let client = build_client().unwrap();
    let vendor = JiraVendor::with_base_url(server.uri());
    let result = get_attachment(&HandleContext::new(&client, &config, &vendor), "493334").await?;
    Ok(serde_json::to_value(result).unwrap())
}

#[tokio::test]
async fn png_bytes_survive_mcp_json_round_trip() {
    // A PNG signature followed by every byte value catches lossy UTF-8 decoding.
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    bytes.extend(0..=255);
    let result = download(
        ResponseTemplate::new(200)
            .set_body_bytes(bytes.clone())
            .insert_header("Content-Type", "image/png"),
    )
    .await
    .unwrap();
    assert_eq!(result["type"], "image");
    assert_eq!(result["mimeType"], "image/png");
    assert_eq!(
        STANDARD.decode(result["data"].as_str().unwrap()).unwrap(),
        bytes
    );
}

#[tokio::test]
async fn rejects_non_images_and_empty_images() {
    let err = download(
        ResponseTemplate::new(200)
            .set_body_string("<html>login</html>")
            .insert_header("Content-Type", "text/html"),
    )
    .await
    .unwrap_err();
    assert!(err.message.contains("not a supported image"));
    let err = download(ResponseTemplate::new(200).insert_header("Content-Type", "image/png"))
        .await
        .unwrap_err();
    assert!(err.message.contains("empty"));
}

#[tokio::test]
async fn preserves_jira_authentication_error() {
    let err = download(
        ResponseTemplate::new(401).set_body_json(serde_json::json!({"message":"Unauthorized"})),
    )
    .await
    .unwrap_err();
    assert_eq!(err.message, "Authentication failed. Jira API: Unauthorized");
}

#[tokio::test]
async fn rejects_oversized_images() {
    let err = download(
        ResponseTemplate::new(200)
            .set_body_bytes(vec![0; MAX_IMAGE_BYTES + 1])
            .insert_header("Content-Type", "image/png"),
    )
    .await
    .unwrap_err();
    assert!(err.message.contains("5 MiB"));
}

#[tokio::test]
async fn rejects_media_urls_and_path_injection_before_authentication() {
    let config = Config::from_map(HashMap::new());
    let client = build_client().unwrap();
    let vendor = JiraVendor::with_base_url("http://127.0.0.1:1");
    let ctx = HandleContext::new(&client, &config, &vendor);
    for id in [
        "",
        "../myself",
        "123?redirect=true",
        "blob:https://media.example/id",
        "6a0cbebb-80e0-417f-84d5-c8d646f4d310",
    ] {
        assert!(
            get_attachment(&ctx, id)
                .await
                .unwrap_err()
                .message
                .contains("numeric Jira attachment ID")
        );
    }
}

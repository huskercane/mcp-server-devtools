use base64::Engine as _;
use std::collections::HashMap;

use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::{artifactory, figma, github};
use mcp_server_devtools::transport::{
    StreamingPolicy, build_client, fetch_streamed_url, raw_response,
};
use mcp_server_devtools::vendor::{
    artifactory::ArtifactoryVendor, figma::FigmaVendor, github::GithubVendor,
};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(entries: &[(&str, &str)]) -> Config {
    Config::from_map(
        entries
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect(),
    )
}

#[tokio::test]
async fn github_log_redirect_strips_credentials_and_returns_artifact() {
    let api = MockServer::start().await;
    let download = MockServer::start().await;
    Mock::given(path("/repos/acme/repo/actions/jobs/42/logs"))
        .and(header("authorization", "Bearer secret"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "location",
            format!("{}/log?signature=private", download.uri()),
        ))
        .expect(1)
        .mount(&api)
        .await;
    Mock::given(path("/log"))
        .respond_with(ResponseTemplate::new(200).set_body_string("build failed\n"))
        .expect(1)
        .mount(&download)
        .await;
    let config = config(&[
        ("GITHUB_TOKEN", "secret"),
        ("MCP_DOWNLOAD_ALLOWED_ORIGINS", &download.uri()),
    ]);
    let client = build_client().unwrap();
    let vendor = GithubVendor::with_base_url(api.uri());
    let result = github::get_job_logs(
        &github::GithubContext::new(&client, &config, &vendor),
        &serde_json::from_value(json!({"owner":"acme","repo":"repo","jobId":42})).unwrap(),
    )
    .await
    .unwrap();
    let metadata: Value = serde_json::from_str(&result.content).unwrap();
    assert_eq!(metadata["bytes"], 13);
    assert_eq!(metadata["complete"], true);
    assert!(!result.content.contains("build failed"));
    let requests = download.received_requests().await.unwrap();
    for key in ["authorization", "x-github-api-version", "cookie"] {
        assert!(!requests[0].headers.contains_key(key));
    }
    let artifact = raw_response::artifact(metadata["artifactId"].as_str().unwrap()).unwrap();
    raw_response::remove_artifact(&artifact.path).await.unwrap();
}

#[tokio::test]
async fn direct_unconfigured_download_is_denied_without_a_request() {
    let server = MockServer::start().await;
    let error = fetch_streamed_url(
        "figma",
        &Config::from_map(HashMap::new()),
        &server.uri(),
        "denied",
        "bin",
        "application/octet-stream",
        StreamingPolicy::new(1024, 1024),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status_code, Some(403));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn custom_token_redirect_is_stripped_and_relative_loops_are_bounded() {
    use mcp_server_devtools::auth::Credentials;
    use mcp_server_devtools::transport::{RequestOptions, fetch};
    let api = MockServer::start().await;
    let other = MockServer::start().await;
    Mock::given(path("/v1/files/key"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", format!("{}/image", other.uri())),
        )
        .expect(1)
        .mount(&api)
        .await;
    Mock::given(path("/image"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&other)
        .await;
    let client = build_client().unwrap();
    let vendor = FigmaVendor::with_base_url(api.uri());
    let creds = Credentials::ApiKeyHeader {
        header_name: "X-Figma-Token".into(),
        key: "secret".into(),
    };
    fetch(
        &client,
        &vendor,
        &creds,
        &config(&[("MCP_DOWNLOAD_ALLOWED_ORIGINS", &other.uri())]),
        "/v1/files/key",
        RequestOptions::default(),
    )
    .await
    .unwrap();
    assert!(
        !other.received_requests().await.unwrap()[0]
            .headers
            .contains_key("x-figma-token")
    );
    Mock::given(path("/loop"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/loop"))
        .expect(1)
        .mount(&api)
        .await;
    let error = fetch(
        &client,
        &vendor,
        &creds,
        &config(&[]),
        "/loop",
        RequestOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(error.message.contains("loop"));
}

#[tokio::test]
async fn artifactory_download_checks_sha256_and_limits() {
    let api = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/artifactory/repo/file.zip"))
        .and(header("authorization", "Bearer secret"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "x-checksum-sha256",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .set_body_bytes([0, 1, 2, 255]),
        )
        .expect(1)
        .mount(&api)
        .await;
    let config = config(&[("ARTIFACTORY_TOKEN", "secret")]);
    let client = build_client().unwrap();
    let vendor = ArtifactoryVendor::with_base_url(format!("{}/artifactory", api.uri()));
    let error = artifactory::download(
        &artifactory::ArtifactoryContext::new(&client, &config, &vendor),
        &serde_json::from_value(json!({"repo":"repo","path":"file.zip","maxBytes":100})).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(error.message.contains("checksum mismatch"));
}

#[tokio::test]
async fn figma_exports_png_and_marks_missing_nodes_without_exposing_signed_urls() {
    let api = MockServer::start().await;
    let files = MockServer::start().await;
    Mock::given(path("/v1/images/abc123"))
        .and(query_param("format", "png"))
        .and(query_param("ids", "1:2,3:4"))
        .and(header("x-figma-token", "secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"images":{"1:2":format!("{}/image?signature=private", files.uri()),"3:4":null}}),
        ))
        .expect(1)
        .mount(&api)
        .await;
    let png = base64::engine::general_purpose::STANDARD.decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=").unwrap();
    Mock::given(path("/image"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(png))
        .expect(1)
        .mount(&files)
        .await;
    let config = config(&[
        ("FIGMA_TOKEN", "secret"),
        ("MCP_DOWNLOAD_ALLOWED_ORIGINS", &files.uri()),
    ]);
    let client = build_client().unwrap();
    let vendor = FigmaVendor::with_base_url(api.uri());
    let result = figma::export_images(
        &figma::FigmaContext::new(&client, &config, &vendor),
        &serde_json::from_value(json!({"file":"abc123","ids":"1:2,3:4"})).unwrap(),
    )
    .await
    .unwrap();
    assert!(!result.content.contains("signature"));
    let value: Value = serde_json::from_str(&result.content).unwrap();
    assert_eq!(value["images"][0]["complete"], true);
    assert_eq!(value["images"][1]["complete"], false);
    assert!(
        !files.received_requests().await.unwrap()[0]
            .headers
            .contains_key("x-figma-token")
    );
    let artifact =
        raw_response::artifact(value["images"][0]["artifactId"].as_str().unwrap()).unwrap();
    raw_response::remove_artifact(&artifact.path).await.unwrap();
}

#[tokio::test]
async fn redirects_are_authorized_by_origin_and_path_before_dispatch() {
    use mcp_server_devtools::auth::Credentials;
    use mcp_server_devtools::policy::{
        CallScope, ClientIdentity, CredentialLabel, Enforcement, EnvironmentClass, FilePolicy,
        Principal, UpstreamAuthority, UpstreamIdentity,
    };
    use mcp_server_devtools::ports::InMemoryAuditSink;
    use mcp_server_devtools::transport::{RequestOptions, fetch};
    use std::sync::Arc;
    use std::time::Duration;
    let server = MockServer::start().await;
    Mock::given(path("/v1/files/key"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "/forbidden?signature=secret"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let policy = FilePolicy::from_bytes(format!("version: 1\nrules:\n  - id: allow-start\n    effect: allow\n    subjects: {{everyone: true}}\n    match:\n      canonical_path: /v1/files/key\n      destination_origin: '{}'\n", server.uri()).as_bytes()).unwrap();
    let slot = mcp_server_devtools::auth::secrets::for_vendor("figma")
        .next()
        .unwrap();
    let scope = Arc::new(
        CallScope::new(
            Principal::local(),
            ClientIdentity::default(),
            "figma_get_file",
            "test",
        )
        .with_enforcement(Enforcement {
            policy,
            audit: Arc::new(InMemoryAuditSink::new()),
            upstream: UpstreamIdentity {
                label: CredentialLabel::slot(slot),
                vendor: "figma".into(),
                environment: EnvironmentClass::Qa,
                authority: UpstreamAuthority::Shared,
                provenance: None,
            },
            append_timeout: Duration::from_secs(1),
        }),
    );
    let client = build_client().unwrap();
    let vendor = FigmaVendor::with_base_url(server.uri());
    let credentials = Credentials::ApiKeyHeader {
        header_name: "X-Figma-Token".into(),
        key: "secret".into(),
    };
    let config = config(&[]);
    let error = CallScope::enter(
        Arc::clone(&scope),
        fetch(
            &client,
            &vendor,
            &credentials,
            &config,
            "/v1/files/key",
            RequestOptions::default(),
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status_code, Some(403));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    let audit = serde_json::to_string(&scope.take_egress().unwrap()).unwrap();
    assert!(audit.contains("destination_origin"));
    assert!(audit.contains("302"));
    assert!(audit.contains("forbidden"));
    assert!(!audit.contains("signature"));
}

#[tokio::test]
async fn retry_after_does_not_squeeze_an_attempt_into_an_insufficient_budget() {
    use std::time::Duration;
    let server = MockServer::start().await;
    Mock::given(path("/throttle"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "10"))
        .expect(1)
        .mount(&server)
        .await;
    let config = config(&[("MCP_DOWNLOAD_ALLOWED_ORIGINS", &server.uri())]);
    let mut policy = StreamingPolicy::new(1024, 1024);
    policy.total_deadline = Duration::from_millis(200);
    let error = fetch_streamed_url(
        "github",
        &config,
        &format!("{}/throttle", server.uri()),
        "retry",
        "log",
        "text/plain",
        policy,
    )
    .await
    .unwrap_err();
    assert_eq!(error.status_code, Some(408));
    assert!(error.original.unwrap().render().unwrap().contains("10000"));
}

#[tokio::test]
async fn compressed_error_expansion_is_bounded_on_streaming_and_shared_paths() {
    use mcp_server_devtools::auth::Credentials;
    use mcp_server_devtools::transport::{RequestOptions, fetch};
    let server = MockServer::start().await;
    let compressed =
        zstd::stream::encode_all(std::io::Cursor::new(vec![b'x'; 11 * 1024 * 1024]), 1).unwrap();
    Mock::given(path("/error"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-encoding", "zstd")
                .set_body_bytes(compressed),
        )
        .expect(2)
        .mount(&server)
        .await;
    let config = config(&[("MCP_DOWNLOAD_ALLOWED_ORIGINS", &server.uri())]);
    let error = fetch_streamed_url(
        "github",
        &config,
        &format!("{}/error", server.uri()),
        "error",
        "log",
        "text/plain",
        StreamingPolicy::new(1024 * 1024, 1024),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status_code, Some(413));
    let client = build_client().unwrap();
    let vendor = GithubVendor::with_base_url(server.uri());
    let error = fetch(
        &client,
        &vendor,
        &Credentials::Bearer {
            token: "test".into(),
        },
        &config,
        "/error",
        RequestOptions::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status_code, Some(413));
}

#[tokio::test]
async fn github_pagination_retains_continuation_and_missing_patch_metadata() {
    let server = MockServer::start().await;
    Mock::given(path("/repos/acme/repo/pulls/1/files"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "link",
                    format!(
                        "<{}/repos/acme/repo/pulls/1/files?page=2>; rel=\"next\"",
                        server.uri()
                    ),
                )
                .set_body_json(json!([{"filename":"binary.png"}])),
        )
        .expect(2)
        .mount(&server)
        .await;
    let config = config(&[("GITHUB_TOKEN", "secret"), ("HTTP_CACHE_ENABLED", "true")]);
    let client = build_client().unwrap();
    let vendor = GithubVendor::with_base_url(server.uri());
    for _ in 0..2 {
        let result = github::get_pull_request_diff(
            &github::GithubContext::new(&client, &config, &vendor),
            &serde_json::from_value(
                json!({"owner":"acme","repo":"repo","number":1,"outputFormat":"json"}),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let output: Value = serde_json::from_str(&result.content).unwrap();
        assert_eq!(output["nextPage"], 2);
        assert_eq!(output["patchesUnavailable"], true);
        assert_eq!(output["data"][0]["filename"], "binary.png");
    }
}

#[tokio::test]
async fn binary_artifacts_never_collect_text_previews() {
    let mut writer =
        raw_response::begin_artifact("binary-preview", "bin", "application/octet-stream", 100_000)
            .await
            .unwrap();
    let bytes = vec![0xff; 80_000];
    writer.write_chunk(&bytes).await.unwrap();
    let artifact = writer.commit().await.unwrap();
    assert!(artifact.head.is_empty());
    assert!(artifact.tail.is_empty());
    assert_eq!(artifact.artifact.size, 80_000);
    raw_response::remove_artifact(&artifact.artifact.path)
        .await
        .unwrap();
}

#[tokio::test]
async fn redirected_error_bodies_do_not_echo_signed_urls() {
    use mcp_server_devtools::auth::Credentials;
    use mcp_server_devtools::transport::{
        RequestOptions, fetch, fetch_streamed_artifact_with_policy,
    };
    let server = MockServer::start().await;
    Mock::given(path("/start"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "/error?signature=secret"),
        )
        .mount(&server)
        .await;
    Mock::given(path("/error"))
        .respond_with(ResponseTemplate::new(403).set_body_string("signature=secret"))
        .mount(&server)
        .await;
    let client = build_client().unwrap();
    let vendor = GithubVendor::with_base_url(server.uri());
    let credentials = Credentials::Bearer {
        token: "token".into(),
    };
    let config = config(&[]);
    let shared = fetch(
        &client,
        &vendor,
        &credentials,
        &config,
        "/start",
        RequestOptions::default(),
    )
    .await
    .unwrap_err();
    let streamed = fetch_streamed_artifact_with_policy(
        &vendor,
        &credentials,
        &config,
        "/start",
        RequestOptions::default(),
        "redacted",
        "log",
        "text/plain",
        StreamingPolicy::new(1024, 1024),
    )
    .await
    .unwrap_err();
    for error in [shared, streamed] {
        assert_eq!(error.status_code, Some(403));
        assert!(!error.message.contains("secret"));
        assert!(error.original.is_none());
    }
}

#[tokio::test]
async fn figma_rejects_excessive_png_dimensions_without_returning_a_handle() {
    let server = MockServer::start().await;
    Mock::given(path("/v1/images/abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "images": {"1:2": format!("{}/image", server.uri())}
        })))
        .mount(&server)
        .await;
    let mut png = base64::engine::general_purpose::STANDARD.decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=").unwrap();
    png[16..20].copy_from_slice(&100_000_u32.to_be_bytes());
    Mock::given(path("/image"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(png))
        .mount(&server)
        .await;
    let config = config(&[
        ("FIGMA_TOKEN", "secret"),
        ("MCP_DOWNLOAD_ALLOWED_ORIGINS", &server.uri()),
    ]);
    let client = build_client().unwrap();
    let vendor = FigmaVendor::with_base_url(server.uri());
    let error = figma::export_images(
        &figma::FigmaContext::new(&client, &config, &vendor),
        &serde_json::from_value(json!({"file":"abc123","ids":"1:2"})).unwrap(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status_code, Some(413));
    assert!(error.message.contains("dimensions"));
}

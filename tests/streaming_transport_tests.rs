use std::io::Cursor;

use mcp_server_devtools::transport::{StreamingPolicy, fetch_streamed_url};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn explicitly_decodes_and_accounts_for_zstd_without_content_length_assumptions() {
    let server = MockServer::start().await;
    let decoded = b"streamed log payload\n".repeat(100);
    let encoded = zstd::stream::encode_all(Cursor::new(&decoded), 1).unwrap();
    Mock::given(method("GET"))
        .and(path("/logs"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "zstd")
                .set_body_bytes(encoded.clone()),
        )
        .mount(&server)
        .await;

    let artifact = fetch_streamed_url(
        "circleci",
        &mcp_server_devtools::config::Config::from_map(std::collections::HashMap::from([(
            "MCP_DOWNLOAD_ALLOWED_ORIGINS".into(),
            server.uri(),
        )])),
        &format!("{}/logs", server.uri()),
        "compressed-accounting-test",
        "log",
        "text/plain",
        StreamingPolicy::new(encoded.len() as u64, decoded.len() as u64),
    )
    .await
    .unwrap();

    assert_eq!(artifact.encoded_bytes, encoded.len() as u64);
    assert_eq!(artifact.decoded_bytes, decoded.len() as u64);
    assert_eq!(
        tokio::fs::read(&artifact.artifact.path).await.unwrap(),
        decoded
    );
    let _ = tokio::fs::remove_file(artifact.artifact.path).await;
}

#[tokio::test]
async fn transient_request_send_errors_are_retried() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/transient"))
        .respond_with_err(|_: &wiremock::Request| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "injected transient request failure",
            )
        })
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/transient"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"recovered"))
        .with_priority(2)
        .expect(1)
        .mount(&server)
        .await;

    let mut policy = StreamingPolicy::new(64, 64);
    policy.max_attempts = 2;
    let artifact = fetch_streamed_url(
        "circleci",
        &mcp_server_devtools::config::Config::from_map(std::collections::HashMap::from([(
            "MCP_DOWNLOAD_ALLOWED_ORIGINS".into(),
            server.uri(),
        )])),
        &format!("{}/transient", server.uri()),
        "transient-request-retry",
        "log",
        "text/plain",
        policy,
    )
    .await
    .unwrap();

    assert_eq!(
        tokio::fs::read(&artifact.artifact.path).await.unwrap(),
        b"recovered"
    );
    let _ = mcp_server_devtools::transport::raw_response::remove_artifact(&artifact.artifact.path)
        .await;
}

#[tokio::test]
async fn decoded_quota_is_enforced_during_decompression() {
    let server = MockServer::start().await;
    let decoded = vec![b'x'; 32 * 1024];
    let encoded = zstd::stream::encode_all(Cursor::new(&decoded), 1).unwrap();
    Mock::given(method("GET"))
        .and(path("/bomb"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "zstd")
                .set_body_bytes(encoded.clone()),
        )
        .mount(&server)
        .await;

    let error = fetch_streamed_url(
        "circleci",
        &mcp_server_devtools::config::Config::from_map(std::collections::HashMap::from([(
            "MCP_DOWNLOAD_ALLOWED_ORIGINS".into(),
            server.uri(),
        )])),
        &format!("{}/bomb", server.uri()),
        "decoded-limit-test",
        "log",
        "text/plain",
        StreamingPolicy::new(encoded.len() as u64, 1024),
    )
    .await
    .unwrap_err();

    assert_eq!(error.status_code, Some(413));
}

#[tokio::test]
async fn encoded_quota_is_enforced_and_partial_artifact_is_cleaned() {
    let server = MockServer::start().await;
    let encoded = vec![b'x'; 4096];
    Mock::given(method("GET"))
        .and(path("/encoded-limit"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(encoded))
        .mount(&server)
        .await;
    let directory = mcp_server_devtools::transport::raw_response::init();
    let before = std::fs::read_dir(&directory)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains("encoded-limit-test"))
        })
        .collect::<std::collections::HashSet<_>>();

    let error = fetch_streamed_url(
        "circleci",
        &mcp_server_devtools::config::Config::from_map(std::collections::HashMap::from([(
            "MCP_DOWNLOAD_ALLOWED_ORIGINS".into(),
            server.uri(),
        )])),
        &format!("{}/encoded-limit", server.uri()),
        "encoded-limit-test",
        "log",
        "text/plain",
        StreamingPolicy::new(1024, 8192),
    )
    .await
    .unwrap_err();

    assert_eq!(error.status_code, Some(413));
    let after = std::fs::read_dir(directory)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains("encoded-limit-test"))
        })
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(after, before, "quota failure must not leave a part file");
}

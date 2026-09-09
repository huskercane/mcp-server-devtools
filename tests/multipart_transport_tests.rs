//! The vendor-neutral multipart transport: exact wire bytes of the encoder,
//! and `post_multipart` driven against a real loopback server with a vendor
//! other than Bitbucket, so the reuse the Jira/Confluence attachment work
//! will rely on is proven here rather than assumed.

use std::collections::HashMap;
use std::time::Duration;

use mcp_server_devtools::auth::Credentials;
use mcp_server_devtools::config::Config;
use mcp_server_devtools::transport::multipart::{
    FilePart, MultipartBody, MultipartRequest, post_multipart,
};
use mcp_server_devtools::transport::{ResponseBody, build_client};
use mcp_server_devtools::vendor::bitbucket::BitbucketVendor;
use mcp_server_devtools::vendor::jira::JiraVendor;
use pretty_assertions::assert_eq;
use reqwest::header::{HeaderName, HeaderValue};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn creds() -> Credentials {
    Credentials::AtlassianApiToken {
        email: "alice@example.com".to_owned(),
        token: "tok".to_owned(),
    }
}

fn config(extra: &[(&str, &str)]) -> Config {
    let mut values: HashMap<String, String> = HashMap::from([
        (
            "ATLASSIAN_USER_EMAIL".to_owned(),
            "alice@example.com".to_owned(),
        ),
        ("ATLASSIAN_API_TOKEN".to_owned(), "tok".to_owned()),
    ]);
    for (key, value) in extra {
        values.insert((*key).to_owned(), (*value).to_owned());
    }
    Config::from_map(values)
}

#[test]
fn encoder_produces_exact_rfc7578_bytes() {
    let parts = [
        FilePart {
            field: "files",
            filename: "hello.txt",
            content_type: "text/plain",
            bytes: b"Hello World\n",
        },
        FilePart {
            field: "files",
            filename: "bin\"ary\r\n.dat",
            content_type: "application/octet-stream",
            bytes: &[0x00, 0xFF, 0x0D, 0x0A, 0x2D, 0x2D],
        },
    ];
    let body = MultipartBody::encode_with_boundary("XyZ-boundary".to_owned(), &parts);

    let mut expected: Vec<u8> = Vec::new();
    expected.extend_from_slice(
        b"--XyZ-boundary\r\n\
          Content-Disposition: form-data; name=\"files\"; filename=\"hello.txt\"\r\n\
          Content-Type: text/plain\r\n\
          \r\n\
          Hello World\n\r\n\
          --XyZ-boundary\r\n\
          Content-Disposition: form-data; name=\"files\"; filename=\"bin%22ary%0D%0A.dat\"\r\n\
          Content-Type: application/octet-stream\r\n\
          \r\n",
    );
    expected.extend_from_slice(&[0x00, 0xFF, 0x0D, 0x0A, 0x2D, 0x2D]);
    expected.extend_from_slice(b"\r\n--XyZ-boundary--\r\n");

    assert_eq!(body.as_bytes(), expected.as_slice());
    assert_eq!(body.len(), expected.len());
    assert_eq!(body.boundary(), "XyZ-boundary");
    assert_eq!(
        body.content_type(),
        "multipart/form-data; boundary=XyZ-boundary"
    );
    assert_eq!(body.into_bytes(), expected);
}

#[test]
fn encoder_with_no_parts_is_just_the_closing_delimiter() {
    let body = MultipartBody::encode_with_boundary("b".to_owned(), &[]);
    assert_eq!(body.as_bytes(), b"--b--\r\n");
    assert!(!body.is_empty());
}

#[test]
fn random_boundary_is_unique_per_body_and_absent_from_content() {
    let part = [FilePart {
        field: "f",
        filename: "f",
        content_type: "text/plain",
        bytes: b"x",
    }];
    let first = MultipartBody::encode(&part);
    let second = MultipartBody::encode(&part);
    assert_ne!(first.boundary(), second.boundary());
    assert!(first.boundary().starts_with("----mcp-devtools-"));
    assert_eq!(first.boundary().len(), 49);
}

#[tokio::test]
async fn posts_the_body_with_vendor_auth_and_caller_headers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/3/issue/PROJ-1/attachments"))
        .and(header(
            "authorization",
            "Basic YWxpY2VAZXhhbXBsZS5jb206dG9r",
        ))
        .and(header("x-atlassian-token", "no-check"))
        .and(header("accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"id": "10001"}])))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let config = config(&[]);
    let vendor = JiraVendor::with_base_url(server.uri());
    let body = MultipartBody::encode(&[FilePart {
        field: "file",
        filename: "trace.log",
        content_type: "text/plain",
        bytes: b"line 1\nline 2\n",
    }]);
    let expected_bytes = body.as_bytes().to_vec();
    let expected_content_type = body.content_type();
    let headers = [(
        HeaderName::from_static("x-atlassian-token"),
        HeaderValue::from_static("no-check"),
    )];

    let response = post_multipart(
        &client,
        &vendor,
        &creds(),
        &config,
        MultipartRequest {
            path: "/rest/api/3/issue/PROJ-1/attachments",
            body,
            headers: &headers,
            manifest: None,
        },
    )
    .await
    .unwrap();

    assert_eq!(response.data.as_json().unwrap(), &json!([{"id": "10001"}]));
    assert!(!response.cache.hit);

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let request = &received[0];
    assert_eq!(
        request
            .headers
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        expected_content_type
    );
    assert_eq!(
        request
            .headers
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        expected_bytes.len().to_string()
    );
    assert_eq!(request.body, expected_bytes);
}

#[tokio::test]
async fn empty_created_response_is_the_empty_body_variant() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;
    let client = build_client().unwrap();
    let config = config(&[]);
    let vendor = BitbucketVendor::with_base_url(server.uri());
    let response = post_multipart(
        &client,
        &vendor,
        &creds(),
        &config,
        MultipartRequest {
            path: "/2.0/repositories/ws/repo/downloads",
            body: MultipartBody::encode(&[]),
            headers: &[],
            manifest: None,
        },
    )
    .await
    .unwrap();
    assert!(matches!(response.data, ResponseBody::Empty));
    assert!(response.raw_response_path.is_none());
}

#[tokio::test]
async fn non_success_goes_through_the_vendor_classifier() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "type": "error",
            "error": {"message": "You do not have write access"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let client = build_client().unwrap();
    let config = config(&[]);
    let vendor = BitbucketVendor::with_base_url(server.uri());
    let err = post_multipart(
        &client,
        &vendor,
        &creds(),
        &config,
        MultipartRequest {
            path: "/2.0/repositories/ws/repo/downloads",
            body: MultipartBody::encode(&[]),
            headers: &[],
            manifest: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(403));
    assert_eq!(
        err.message,
        "Bitbucket API: Permission denied - You do not have write access"
    );
}

#[tokio::test]
async fn a_timeout_is_one_attempt_and_no_retry() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_delay(Duration::from_secs(3)))
        .mount(&server)
        .await;
    let client = build_client().unwrap();
    let config = config(&[("ATLASSIAN_REQUEST_TIMEOUT", "250")]);
    let vendor = BitbucketVendor::with_base_url(server.uri());
    let err = post_multipart(
        &client,
        &vendor,
        &creds(),
        &config,
        MultipartRequest {
            path: "/2.0/repositories/ws/repo/downloads",
            body: MultipartBody::encode(&[]),
            headers: &[],
            manifest: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(408), "{}", err.message);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn an_absolute_url_path_is_refused_before_any_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201))
        .expect(0)
        .mount(&server)
        .await;
    let client = build_client().unwrap();
    let config = config(&[]);
    let vendor = BitbucketVendor::with_base_url(server.uri());
    let err = post_multipart(
        &client,
        &vendor,
        &creds(),
        &config,
        MultipartRequest {
            path: "https://evil.example/2.0/repositories/ws/repo/downloads",
            body: MultipartBody::encode(&[]),
            headers: &[],
            manifest: None,
        },
    )
    .await
    .unwrap_err();
    assert!(
        err.message.contains("Invalid request path"),
        "{}",
        err.message
    );
}

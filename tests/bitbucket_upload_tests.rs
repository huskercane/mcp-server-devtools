//! `bb_upload` against a loopback Bitbucket: the controller end to end, and
//! the tool through the real `tools/call` path over streamable HTTP.
//!
//! Every test that expects a refusal also asserts that the mock saw no
//! `POST`: the contract is that a rejected call has uploaded nothing.

use std::collections::HashMap;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use mcp_server_devtools::bootstrap::{ServerBuilder, Vendors};
use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::api::BitbucketContext;
use mcp_server_devtools::controllers::upload_downloads;
use mcp_server_devtools::error::McpError;
use mcp_server_devtools::server::http::build_app_with_server;
use mcp_server_devtools::tools::DevtoolsServer;
use mcp_server_devtools::tools::args::{
    ConflictPolicy, OutputFormatArg, UploadArgs, UploadFileArg,
};
use mcp_server_devtools::transport::build_client;
use mcp_server_devtools::transport::raw_response::{artifact_for_path, save_artifact};
use mcp_server_devtools::vendor::bitbucket::BitbucketVendor;
use mcp_server_devtools::workspace::WorkspaceCache;
use pretty_assertions::assert_eq;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const DOWNLOADS: &str = "/2.0/repositories/myteam/project-api/downloads";
const BASIC: &str = "Basic YWxpY2VAZXhhbXBsZS5jb206dG9r";

fn config(extra: &[(&str, &str)]) -> Config {
    let mut values: HashMap<String, String> = HashMap::from([
        (
            "ATLASSIAN_USER_EMAIL".to_owned(),
            "alice@example.com".to_owned(),
        ),
        ("ATLASSIAN_API_TOKEN".to_owned(), "tok".to_owned()),
        (
            "BITBUCKET_DEFAULT_WORKSPACE".to_owned(),
            "myteam".to_owned(),
        ),
    ]);
    for (key, value) in extra {
        values.insert((*key).to_owned(), (*value).to_owned());
    }
    Config::from_map(values)
}

fn file(name: &str, mime: Option<&str>, bytes: &[u8]) -> UploadFileArg {
    UploadFileArg {
        filename: name.to_owned(),
        mime_type: mime.map(str::to_owned),
        content_base64: Some(STANDARD.encode(bytes)),
        artifact_id: None,
    }
}

fn args(files: Vec<UploadFileArg>) -> UploadArgs {
    UploadArgs {
        workspace_slug: None,
        repo_slug: "project-api".to_owned(),
        files,
        on_conflict: None,
        output_format: Some(OutputFormatArg::Json),
    }
}

/// A listing page. `next` is set when more pages follow.
fn listing(names: &[&str], next: bool) -> ResponseTemplate {
    let values: Vec<Value> = names
        .iter()
        .map(|name| json!({"name": name, "size": 12, "links": {"self": {"href": format!("https://api.bitbucket.org{DOWNLOADS}/{name}")}}}))
        .collect();
    let mut body = json!({"values": values, "pagelen": 100});
    if next {
        body["next"] = json!(format!("https://api.bitbucket.org{DOWNLOADS}?page=2"));
    }
    ResponseTemplate::new(200).set_body_json(body)
}

async fn mount_listing(server: &MockServer, names: &[&str]) {
    Mock::given(method("GET"))
        .and(path(DOWNLOADS))
        .and(query_param("pagelen", "100"))
        .and(query_param("page", "1"))
        .and(header("authorization", BASIC))
        .respond_with(listing(names, false))
        .mount(server)
        .await;
}

async fn mount_upload(server: &MockServer, template: ResponseTemplate, expected: u64) {
    Mock::given(method("POST"))
        .and(path(DOWNLOADS))
        .and(header("authorization", BASIC))
        .respond_with(template)
        .expect(expected)
        .mount(server)
        .await;
}

async fn run(server: &MockServer, config: &Config, args: &UploadArgs) -> Result<Value, McpError> {
    let client = build_client().unwrap();
    let vendor = BitbucketVendor::with_base_url(server.uri());
    let cache = WorkspaceCache::new();
    let ctx = BitbucketContext::new(&client, config, &vendor, &cache);
    let response = upload_downloads(&ctx, args).await?;
    assert!(response.raw_response_path.is_none());
    Ok(serde_json::from_str(&response.content).expect("JSON output"))
}

async fn posts(server: &MockServer) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|request| request.method == "POST")
        .collect()
}

/// One decoded part of a received multipart body.
#[derive(Debug, PartialEq, Eq)]
struct Part {
    headers: String,
    bytes: Vec<u8>,
}

/// Split a `multipart/form-data` body on its boundary. Strict about the
/// delimiters so a malformed body fails the test instead of parsing.
fn parse_multipart(request: &Request) -> Vec<Part> {
    let content_type = request
        .headers
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    let boundary = content_type
        .strip_prefix("multipart/form-data; boundary=")
        .unwrap_or_else(|| panic!("unexpected content type {content_type:?}"));
    let delimiter = format!("--{boundary}");
    let body = &request.body;
    assert!(body.starts_with(delimiter.as_bytes()));
    let closing = format!("\r\n--{boundary}--\r\n");
    assert!(
        body.ends_with(closing.as_bytes()),
        "body must end with the closing delimiter"
    );
    let inner = &body[delimiter.len()..body.len() - closing.len()];

    let separator = format!("\r\n--{boundary}");
    let mut parts = Vec::new();
    let mut rest = inner;
    loop {
        let end = find(rest, separator.as_bytes()).unwrap_or(rest.len());
        let raw = &rest[..end];
        let raw = raw.strip_prefix(b"\r\n").expect("CRLF after delimiter");
        let split = find(raw, b"\r\n\r\n").expect("header/body separator");
        parts.push(Part {
            headers: String::from_utf8(raw[..split].to_vec()).unwrap(),
            bytes: raw[split + 4..].to_vec(),
        });
        if end == rest.len() {
            break;
        }
        rest = &rest[end + separator.len()..];
    }
    parts
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[tokio::test]
async fn uploads_multiple_files_in_one_multipart_post() {
    let server = MockServer::start().await;
    mount_listing(&server, &["unrelated.zip"]).await;
    mount_upload(&server, ResponseTemplate::new(201), 1).await;

    let mut binary = b"\x89PNG\r\n\x1a\n".to_vec();
    binary.extend(0..=255u8);
    let collection = br#"{"info":{"name":"project-api"},"item":[]}"#;
    let result = run(
        &server,
        &config(&[]),
        &args(vec![
            file(
                "project-api.postman_collection.json",
                Some("application/json"),
                collection,
            ),
            file("screen shot.png", None, &binary),
        ]),
    )
    .await
    .unwrap();

    assert_eq!(result["workspace"], "myteam");
    assert_eq!(result["repoSlug"], "project-api");
    assert_eq!(
        result["downloadsUrl"],
        "https://bitbucket.org/myteam/project-api/downloads"
    );
    let files = result["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(
        files[0],
        json!({
            "name": "project-api.postman_collection.json",
            "size": collection.len(),
            "mimeType": "application/json",
            "downloadUrl": format!("{}{DOWNLOADS}/project-api.postman_collection.json", server.uri()),
            "browserUrl": "https://bitbucket.org/myteam/project-api/downloads/project-api.postman_collection.json",
            "replaced": false,
        })
    );
    assert_eq!(files[1]["name"], "screen shot.png");
    assert_eq!(files[1]["size"], binary.len());
    assert_eq!(files[1]["mimeType"], "application/octet-stream");
    assert_eq!(
        files[1]["browserUrl"],
        "https://bitbucket.org/myteam/project-api/downloads/screen%20shot.png"
    );

    let posts = posts(&server).await;
    assert_eq!(posts.len(), 1);
    assert_eq!(
        posts[0].headers.get("accept").unwrap().to_str().unwrap(),
        "application/json"
    );
    let parts = parse_multipart(&posts[0]);
    assert_eq!(parts.len(), 2);
    assert_eq!(
        parts[0].headers,
        "Content-Disposition: form-data; name=\"files\"; filename=\"project-api.postman_collection.json\"\r\nContent-Type: application/json"
    );
    assert_eq!(parts[0].bytes, collection.to_vec());
    assert_eq!(
        parts[1].headers,
        "Content-Disposition: form-data; name=\"files\"; filename=\"screen shot.png\"\r\nContent-Type: application/octet-stream"
    );
    assert_eq!(
        parts[1].bytes, binary,
        "binary bytes must survive untouched"
    );
}

#[tokio::test]
async fn toon_is_the_default_output_format() {
    let server = MockServer::start().await;
    mount_listing(&server, &[]).await;
    mount_upload(&server, ResponseTemplate::new(201), 1).await;
    let client = build_client().unwrap();
    let vendor = BitbucketVendor::with_base_url(server.uri());
    let cache = WorkspaceCache::new();
    let config = config(&[]);
    let ctx = BitbucketContext::new(&client, &config, &vendor, &cache);
    let mut args = args(vec![file("a.txt", Some("text/plain"), b"a")]);
    args.output_format = None;
    let response = upload_downloads(&ctx, &args).await.unwrap();
    assert!(
        response.content.contains("browserUrl")
            && response
                .content
                .contains("https://bitbucket.org/myteam/project-api/downloads/a.txt"),
        "{}",
        response.content
    );
    assert!(
        serde_json::from_str::<Value>(&response.content).is_err(),
        "TOON, not JSON: {}",
        response.content
    );
}

#[tokio::test]
async fn explicit_workspace_overrides_the_default() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2.0/repositories/other-team/project-api/downloads"))
        .respond_with(listing(&[], false))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/2.0/repositories/other-team/project-api/downloads"))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;
    let mut args = args(vec![file("a.txt", None, b"a")]);
    args.workspace_slug = Some("other-team".to_owned());
    let result = run(&server, &config(&[]), &args).await.unwrap();
    assert_eq!(result["workspace"], "other-team");
}

#[tokio::test]
async fn refuses_a_name_collision_before_sending_anything() {
    let server = MockServer::start().await;
    mount_listing(&server, &["postman.json", "other.bin"]).await;
    mount_upload(&server, ResponseTemplate::new(201), 0).await;

    let err = run(
        &server,
        &config(&[]),
        &args(vec![
            file("new.txt", None, b"new"),
            file("postman.json", Some("application/json"), b"{}"),
        ]),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(409));
    assert!(
        err.message.contains("\"postman.json\" already exist"),
        "{}",
        err.message
    );
    assert!(!err.message.contains("new.txt"));
    assert!(err.message.contains("onConflict: \"replace\""));
    assert!(err.message.contains("Nothing was uploaded"));
    assert!(posts(&server).await.is_empty());
}

#[tokio::test]
async fn collision_names_are_matched_exactly() {
    let server = MockServer::start().await;
    mount_listing(&server, &["Postman.json"]).await;
    mount_upload(&server, ResponseTemplate::new(201), 1).await;
    let result = run(
        &server,
        &config(&[]),
        &args(vec![file("postman.json", None, b"{}")]),
    )
    .await
    .unwrap();
    assert_eq!(result["files"][0]["replaced"], false);
}

#[tokio::test]
async fn replace_policy_uploads_and_reports_which_artifacts_were_replaced() {
    let server = MockServer::start().await;
    mount_listing(&server, &["postman.json"]).await;
    mount_upload(&server, ResponseTemplate::new(201), 1).await;

    let mut args = args(vec![
        file("postman.json", Some("application/json"), b"{}"),
        file("fresh.txt", None, b"x"),
    ]);
    args.on_conflict = Some(ConflictPolicy::Replace);
    let result = run(&server, &config(&[]), &args).await.unwrap();
    assert_eq!(result["files"][0]["replaced"], true);
    assert_eq!(result["files"][1]["replaced"], false);
    assert_eq!(parse_multipart(&posts(&server).await[0]).len(), 2);
}

#[tokio::test]
async fn collision_check_walks_every_listing_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(DOWNLOADS))
        .and(query_param("page", "1"))
        .respond_with(listing(&["a.txt"], true))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(DOWNLOADS))
        .and(query_param("page", "2"))
        .respond_with(listing(&["postman.json"], false))
        .expect(1)
        .mount(&server)
        .await;
    mount_upload(&server, ResponseTemplate::new(201), 0).await;

    let err = run(
        &server,
        &config(&[]),
        &args(vec![file("postman.json", None, b"{}")]),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(409));
    assert!(posts(&server).await.is_empty());
}

#[tokio::test]
async fn collision_listing_bypasses_the_response_cache() {
    let server = MockServer::start().await;
    // First listing is empty and cacheable for ten minutes; the second
    // shows the artifact the first upload created. A cached listing would
    // let the second call overwrite it silently.
    Mock::given(method("GET"))
        .and(path(DOWNLOADS))
        .respond_with(listing(&[], false).insert_header("Cache-Control", "max-age=600"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(DOWNLOADS))
        .respond_with(listing(&["report.pdf"], false))
        .mount(&server)
        .await;
    mount_upload(&server, ResponseTemplate::new(201), 1).await;

    let config = config(&[("HTTP_CACHE_ENABLED", "true")]);
    let upload = args(vec![file("report.pdf", Some("application/pdf"), b"%PDF")]);
    run(&server, &config, &upload).await.unwrap();
    let err = run(&server, &config, &upload).await.unwrap_err();
    assert_eq!(err.status_code, Some(409), "{}", err.message);
}

#[tokio::test]
async fn listing_failures_are_reported_and_upload_nothing() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(DOWNLOADS))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "type": "error", "error": {"message": "Repository myteam/project-api not found"}
        })))
        .mount(&server)
        .await;
    mount_upload(&server, ResponseTemplate::new(201), 0).await;
    let err = run(
        &server,
        &config(&[]),
        &args(vec![file("a.txt", None, b"a")]),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(404));
    assert!(
        err.message.contains("Resource not found"),
        "{}",
        err.message
    );
    assert!(
        err.message.contains("nothing was uploaded"),
        "{}",
        err.message
    );
}

/// A file argument with a raw `contentBase64` value and no other source.
fn raw(name: &str, content_base64: Option<&str>) -> UploadFileArg {
    UploadFileArg {
        filename: name.to_owned(),
        mime_type: None,
        content_base64: content_base64.map(str::to_owned),
        artifact_id: None,
    }
}

/// Every malformed call and the error text it must produce. Built by a
/// helper so the test itself stays under the line limit.
fn invalid_cases() -> Vec<(&'static str, UploadArgs, u16, &'static str)> {
    let mut both = file("both.txt", None, b"x");
    both.artifact_id = Some("abc".to_owned());
    let mut unknown_artifact = raw("log.txt", None);
    unknown_artifact.artifact_id = Some("00000000-0000-0000-0000-000000000000".to_owned());
    let too_many: Vec<UploadFileArg> = (0..21)
        .map(|index| file(&format!("f{index}.txt"), None, b"x"))
        .collect();
    let mut bad_repo = args(vec![file("a.txt", None, b"a")]);
    "project/../other".clone_into(&mut bad_repo.repo_slug);
    let mut bad_workspace = args(vec![file("a.txt", None, b"a")]);
    bad_workspace.workspace_slug = Some("team?x=1".to_owned());
    let one = |file: UploadFileArg| args(vec![file]);

    vec![
        ("no files", args(vec![]), 400, "at least one file"),
        ("too many files", args(too_many), 400, "at most 20"),
        (
            "traversal filename",
            one(file("../etc/passwd", None, b"x")),
            400,
            "contains '/'",
        ),
        (
            "backslash filename",
            one(file("a\\b", None, b"x")),
            400,
            "contains '\\\\'",
        ),
        (
            "control char",
            one(file("a\nb", None, b"x")),
            400,
            "control",
        ),
        (
            "dot dot",
            one(file("..", None, b"x")),
            400,
            "not a file name",
        ),
        (
            "empty filename",
            one(file("", None, b"x")),
            400,
            "must not be empty",
        ),
        ("both sources", one(both), 400, "not both"),
        (
            "no source",
            one(raw("neither.txt", None)),
            400,
            "contentBase64 or artifactId is required",
        ),
        (
            "data url",
            one(raw("data.txt", Some("data:text/plain;base64,eA=="))),
            400,
            "not a data: URL",
        ),
        (
            "bad base64",
            one(raw("bad.txt", Some("not base64!!"))),
            400,
            "not valid standard base64",
        ),
        (
            "empty content",
            one(raw("empty.txt", Some(""))),
            400,
            "is empty",
        ),
        (
            "bad mime",
            one(file("a.txt", Some("json"), b"x")),
            400,
            "type/subtype",
        ),
        (
            "duplicate names",
            args(vec![
                file("Same.txt", None, b"x"),
                file("same.txt", None, b"y"),
            ]),
            400,
            "more than once",
        ),
        ("bad repo slug", bad_repo, 400, "repoSlug"),
        ("bad workspace", bad_workspace, 400, "workspaceSlug"),
        (
            "unknown artifact",
            one(unknown_artifact),
            404,
            "not found or expired",
        ),
    ]
}

#[tokio::test]
async fn invalid_inputs_never_reach_upstream() {
    let server = MockServer::start().await;
    mount_listing(&server, &[]).await;
    mount_upload(&server, ResponseTemplate::new(201), 0).await;
    for (label, case, status, needle) in invalid_cases() {
        let err = run(&server, &config(&[]), &case).await.expect_err(label);
        assert_eq!(err.status_code, Some(status), "{label}: {}", err.message);
        assert!(err.message.contains(needle), "{label}: {}", err.message);
    }

    assert_eq!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count(),
        0
    );
}

#[tokio::test]
async fn size_limits_are_enforced_on_decoded_bytes_before_any_request() {
    let server = MockServer::start().await;
    mount_listing(&server, &[]).await;
    mount_upload(&server, ResponseTemplate::new(201), 0).await;
    let tight = config(&[
        ("UPLOAD_MAX_FILE_BYTES", "16"),
        ("UPLOAD_MAX_TOTAL_BYTES", "24"),
    ]);

    // Size limits come from configuration and are enforced on decoded bytes.
    let err = run(
        &server,
        &tight,
        &args(vec![file("big.bin", None, &[0u8; 17])]),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(413));
    assert!(
        err.message.contains("16 bytes per-file limit"),
        "{}",
        err.message
    );
    let err = run(
        &server,
        &tight,
        &args(vec![
            file("a.bin", None, &[0u8; 16]),
            file("b.bin", None, &[0u8; 9]),
        ]),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(413));
    assert!(
        err.message.contains("total exceeds the 24 bytes limit"),
        "{}",
        err.message
    );
    assert!(posts(&server).await.is_empty());
}

#[tokio::test]
async fn wrapped_and_unpadded_base64_are_accepted() {
    let server = MockServer::start().await;
    mount_listing(&server, &[]).await;
    mount_upload(&server, ResponseTemplate::new(201), 1).await;
    let wrapped = UploadFileArg {
        filename: "wrapped.txt".to_owned(),
        mime_type: Some("Text/Plain".to_owned()),
        content_base64: Some("aGVs\nbG8g\r\nd29ybGQ".to_owned()),
        artifact_id: None,
    };
    run(&server, &config(&[]), &args(vec![wrapped]))
        .await
        .unwrap();
    let parts = parse_multipart(&posts(&server).await[0]);
    assert_eq!(parts[0].bytes, b"hello world".to_vec());
    assert!(parts[0].headers.ends_with("Content-Type: text/plain"));
}

#[tokio::test]
async fn upstream_refusals_are_classified_and_never_retried() {
    for (status, body, needle) in [
        (
            403,
            json!({"type": "error", "error": {"message": "Write access required"}}),
            "Permission denied - Write access required (nothing was uploaded)",
        ),
        (
            429,
            json!({"type": "error", "error": {"message": "Too many requests"}}),
            "Rate limit exceeded - Too many requests. This tool does not retry automatically",
        ),
        (
            406,
            json!({"type": "error", "error": {"message": "Unsupported Content-Type"}}),
            "Bitbucket API Error: Unsupported Content-Type (nothing was uploaded)",
        ),
        (
            401,
            json!({"type": "error", "error": {"message": "Bad token"}}),
            "Authentication failed - Bad token",
        ),
    ] {
        let server = MockServer::start().await;
        mount_listing(&server, &[]).await;
        mount_upload(
            &server,
            ResponseTemplate::new(status).set_body_json(body),
            1,
        )
        .await;
        let err = run(
            &server,
            &config(&[]),
            &args(vec![file("a.txt", None, b"a")]),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code, Some(status), "{}", err.message);
        assert!(err.message.contains(needle), "{status}: {}", err.message);
        assert_eq!(
            posts(&server).await.len(),
            1,
            "exactly one attempt for {status}"
        );
    }
}

#[tokio::test]
async fn failures_after_the_body_was_sent_report_an_unknown_outcome() {
    // A 5xx after the body was sent.
    let server = MockServer::start().await;
    mount_listing(&server, &[]).await;
    mount_upload(
        &server,
        ResponseTemplate::new(502).set_body_string("Bad Gateway"),
        1,
    )
    .await;
    let err = run(
        &server,
        &config(&[]),
        &args(vec![file("a.txt", None, b"a")]),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(502));
    assert!(
        err.message.starts_with("Upload outcome unknown:"),
        "{}",
        err.message
    );
    assert!(
        err.message.contains(&format!("bb_get on {DOWNLOADS}")),
        "{}",
        err.message
    );

    // A timeout: one attempt, no retry, same guidance.
    let server = MockServer::start().await;
    mount_listing(&server, &[]).await;
    mount_upload(
        &server,
        ResponseTemplate::new(201).set_delay(Duration::from_secs(3)),
        1,
    )
    .await;
    let err = run(
        &server,
        &config(&[("ATLASSIAN_REQUEST_TIMEOUT", "250")]),
        &args(vec![file("a.txt", None, b"a")]),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(408), "{}", err.message);
    assert!(
        err.message.starts_with("Upload outcome unknown:"),
        "{}",
        err.message
    );
    assert!(err.message.contains("a retry replaces"), "{}", err.message);
    assert_eq!(posts(&server).await.len(), 1);
}

#[tokio::test]
async fn a_server_side_artifact_can_be_uploaded_without_inline_content() {
    let server = MockServer::start().await;
    mount_listing(&server, &[]).await;
    mount_upload(&server, ResponseTemplate::new(201), 1).await;

    let path = save_artifact("upload-source", "line 1\nline 2\n")
        .await
        .expect("artifact saved");
    let artifact = artifact_for_path(&path).expect("artifact registered");

    let result = run(
        &server,
        &config(&[]),
        &args(vec![UploadFileArg {
            filename: "build.log".to_owned(),
            mime_type: None,
            content_base64: None,
            artifact_id: Some(artifact.id.clone()),
        }]),
    )
    .await
    .unwrap();
    assert_eq!(result["files"][0]["name"], "build.log");
    assert_eq!(result["files"][0]["size"], 14);
    assert_eq!(result["files"][0]["mimeType"], "text/plain");

    let parts = parse_multipart(&posts(&server).await[0]);
    assert_eq!(parts[0].bytes, b"line 1\nline 2\n".to_vec());
    assert!(parts[0].headers.contains("filename=\"build.log\""));

    // The artifact is still readable afterwards: uploading does not consume it.
    assert!(artifact_for_path(&path).is_some());
}

#[tokio::test]
async fn an_artifact_over_the_limit_is_refused_before_it_is_read() {
    let server = MockServer::start().await;
    mount_listing(&server, &[]).await;
    mount_upload(&server, ResponseTemplate::new(201), 0).await;
    let path = save_artifact("upload-large", &"x".repeat(64))
        .await
        .expect("artifact saved");
    let artifact = artifact_for_path(&path).expect("artifact registered");
    let err = run(
        &server,
        &config(&[("UPLOAD_MAX_FILE_BYTES", "63")]),
        &args(vec![UploadFileArg {
            filename: "large.log".to_owned(),
            mime_type: None,
            content_base64: None,
            artifact_id: Some(artifact.id),
        }]),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(413));
    assert!(posts(&server).await.is_empty());
}

// ---- The tool through the real `tools/call` path ----

async fn spawn(mock_uri: &str, extra: &[(&str, &str)]) -> String {
    let server: DevtoolsServer = ServerBuilder::new()
        .config(config(extra))
        .vendors(Vendors {
            bitbucket: BitbucketVendor::with_base_url(mock_uri),
            ..Vendors::default()
        })
        .build()
        .expect("build server");
    let app = build_app_with_server(
        server,
        Duration::from_mins(5),
        Duration::from_mins(5),
        CancellationToken::new(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum::serve");
    });
    format!("http://{addr}")
}

async fn call_bb_upload(base: &str, arguments: Value) -> Value {
    let response = send_bb_upload(base, arguments).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.expect("body");
    if let Ok(value) = serde_json::from_str(&body) {
        return value;
    }
    body.lines()
        .filter_map(|line| {
            line.strip_prefix("data: ")
                .or_else(|| line.strip_prefix("data:"))
        })
        .find_map(|data| serde_json::from_str(data.trim()).ok())
        .unwrap_or_else(|| panic!("unparseable response:\n{body}"))
}

async fn send_bb_upload(base: &str, arguments: Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "bb_upload")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "bb_upload",
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "upload-test", "version": "0.0.0"
                    }
                }
            }
        }))
        .send()
        .await
        .expect("tools/call")
}

#[tokio::test]
async fn bb_upload_tool_returns_links_over_the_mcp_transport() {
    let mock = MockServer::start().await;
    mount_listing(&mock, &[]).await;
    mount_upload(&mock, ResponseTemplate::new(201), 1).await;
    let base = spawn(&mock.uri(), &[]).await;

    let response = call_bb_upload(
        &base,
        json!({
            "repoSlug": "project-api",
            "outputFormat": "json",
            "files": [{
                "filename": "project-api.postman_collection.json",
                "mimeType": "application/json",
                "contentBase64": STANDARD.encode(b"{\"item\":[]}")
            }]
        }),
    )
    .await;
    let result = &response["result"];
    assert_ne!(result["isError"], true, "{response}");
    let text = result["content"][0]["text"].as_str().unwrap();
    let parsed: Value = serde_json::from_str(text).unwrap();
    assert_eq!(
        parsed["files"][0]["browserUrl"],
        "https://bitbucket.org/myteam/project-api/downloads/project-api.postman_collection.json"
    );
    assert_eq!(parsed["files"][0]["replaced"], false);
}

#[tokio::test]
async fn bb_upload_tool_surfaces_a_collision_as_a_tool_error() {
    let mock = MockServer::start().await;
    mount_listing(&mock, &["project-api.postman_collection.json"]).await;
    mount_upload(&mock, ResponseTemplate::new(201), 0).await;
    let base = spawn(&mock.uri(), &[]).await;

    let response = call_bb_upload(
        &base,
        json!({
            "repoSlug": "project-api",
            "files": [{
                "filename": "project-api.postman_collection.json",
                "contentBase64": STANDARD.encode(b"{}")
            }]
        }),
    )
    .await;
    let result = &response["result"];
    assert_eq!(result["isError"], true, "{response}");
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("already exist"), "{text}");
    assert!(text.contains("onConflict"), "{text}");
}

/// A 1.5 MiB file: its base64 form is over the default 1 MB `/mcp` body cap
/// and under a 4 MB one.
fn large_upload_arguments() -> Value {
    json!({
        "repoSlug": "project-api",
        "outputFormat": "json",
        "files": [{
            "filename": "big.bin",
            "contentBase64": STANDARD.encode(vec![7u8; 1_536 * 1024])
        }]
    })
}

#[tokio::test]
async fn the_default_mcp_body_cap_rejects_large_inline_uploads() {
    let mock = MockServer::start().await;
    mount_listing(&mock, &[]).await;
    mount_upload(&mock, ResponseTemplate::new(201), 0).await;
    let base = spawn(&mock.uri(), &[]).await;
    let response = send_bb_upload(&base, large_upload_arguments()).await;
    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_raised_mcp_body_cap_admits_large_inline_uploads() {
    let mock = MockServer::start().await;
    mount_listing(&mock, &[]).await;
    mount_upload(&mock, ResponseTemplate::new(201), 1).await;
    let base = spawn(&mock.uri(), &[("HTTP_REQUEST_BODY_LIMIT_BYTES", "4000000")]).await;
    let response = call_bb_upload(&base, large_upload_arguments()).await;
    let result = &response["result"];
    assert_ne!(result["isError"], true, "{response}");
    let parsed: Value =
        serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(parsed["files"][0]["size"], 1_536 * 1024);
    let parts = parse_multipart(&posts(&mock).await[0]);
    assert_eq!(parts[0].bytes.len(), 1_536 * 1024);
}

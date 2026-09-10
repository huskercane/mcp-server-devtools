//! Integration tests for the GitLab adapter: configuration, request shape per
//! tool (encoded identifiers, bearer auth, query params, page bounds), error
//! classification, and the base64 file-content transform.

use std::collections::HashMap;

use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::gitlab::{
    GitlabContext, get_file, get_issue, get_job_trace, get_merge_request, get_merge_request_diff,
    list_issues, list_merge_requests, list_pipeline_jobs, list_pipelines, list_projects,
};
use mcp_server_devtools::error::ErrorKind;
use mcp_server_devtools::tools::args::{
    GitlabGetFileArgs, GitlabGetIssueArgs, GitlabGetJobTraceArgs, GitlabGetMergeRequestArgs,
    GitlabGetMergeRequestDiffArgs, GitlabListIssuesArgs, GitlabListMergeRequestsArgs,
    GitlabListPipelineJobsArgs, GitlabListPipelinesArgs, GitlabListProjectsArgs,
};
use mcp_server_devtools::transport::{HttpClient, build_client};
use mcp_server_devtools::vendor::{Vendor, gitlab::GitlabVendor};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "glpat-secret";

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
    )
}

/// A wiremock-backed fixture: the vendor points at the mock server (which
/// therefore receives `/api/v4/...`), the token is set, and every request
/// must carry the bearer header.
struct Fixture {
    server: MockServer,
    cfg: Config,
    client: HttpClient,
    vendor: GitlabVendor,
}

impl Fixture {
    async fn new() -> Self {
        let server = MockServer::start().await;
        Self {
            vendor: GitlabVendor::with_base_url(server.uri()),
            server,
            cfg: config(&[("GITLAB_TOKEN", TOKEN)]),
            client: build_client().unwrap(),
        }
    }

    fn ctx(&self) -> GitlabContext<'_> {
        GitlabContext::new(&self.client, &self.cfg, &self.vendor)
    }

    async fn mount_json(&self, endpoint: &str, body: Value) {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(header("authorization", format!("Bearer {TOKEN}")))
            .and(header("accept", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&self.server)
            .await;
    }
}

fn parse<T: serde::de::DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

#[tokio::test]
async fn configuration_base_url_suffix_and_missing_token() {
    let vendor = GitlabVendor::new();
    assert_eq!(vendor.name(), "gitlab");
    assert_eq!(
        vendor.base_url(&Config::from_map(HashMap::new())).unwrap(),
        "https://gitlab.com/api/v4"
    );
    for (configured, expected) in [
        (
            "https://gitlab.example.com",
            "https://gitlab.example.com/api/v4",
        ),
        (
            " https://gitlab.example.com/ ",
            "https://gitlab.example.com/api/v4",
        ),
        (
            "https://gitlab.example.com/api/v4/",
            "https://gitlab.example.com/api/v4",
        ),
        ("   ", "https://gitlab.com/api/v4"),
    ] {
        let cfg = config(&[("GITLAB_API_BASE", configured)]);
        assert_eq!(vendor.base_url(&cfg).unwrap(), expected, "{configured:?}");
    }
    assert_eq!(
        GitlabVendor::with_base_url("http://localhost:9/")
            .base_url(&Config::from_map(HashMap::new()))
            .unwrap(),
        "http://localhost:9/api/v4"
    );

    for cfg in [
        Config::from_map(HashMap::new()),
        config(&[("GITLAB_TOKEN", "   ")]),
    ] {
        let err = vendor.token(&cfg).await.unwrap_err();
        assert_eq!(err.kind, ErrorKind::AuthMissing);
        assert!(err.message.contains("GITLAB_TOKEN"));
    }
    assert_eq!(
        vendor
            .token(&config(&[("GITLAB_TOKEN", TOKEN)]))
            .await
            .unwrap(),
        TOKEN
    );

    // Missing config surfaces at call time as AuthMissing, not as a panic.
    let fx = Fixture::new().await;
    let cfg = Config::from_map(HashMap::new());
    let ctx = GitlabContext::new(&fx.client, &cfg, &fx.vendor);
    let err = list_projects(&ctx, &GitlabListProjectsArgs::default())
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthMissing);
}

#[tokio::test]
async fn tool_names_aliases_and_secret_registration() {
    for tool in [
        "gitlab_list_projects",
        "gitlab_get_file",
        "gitlab_list_merge_requests",
        "gitlab_get_merge_request",
        "gitlab_get_merge_request_diff",
        "gitlab_list_issues",
        "gitlab_get_issue",
        "gitlab_list_pipelines",
        "gitlab_list_pipeline_jobs",
        "gitlab_get_job_trace",
    ] {
        assert_eq!(
            mcp_server_devtools::tools::vendor_for_tool(tool),
            Some("gitlab"),
            "{tool}"
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("configs.json");
    for alias in ["gitlab", "mcp-server-gitlab"] {
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({alias: {"environments": {
                "GITLAB_API_BASE": "https://gitlab.example.com", "GITLAB_TOKEN": "scoped-token"
            }}}))
            .unwrap(),
        )
        .unwrap();
        let cfg = Config::load_from_sources(Some(&file), None, &HashMap::new());
        assert_eq!(
            GitlabVendor::new().token(&cfg).await.unwrap(),
            "scoped-token"
        );
        assert_eq!(
            GitlabVendor::new().base_url(&cfg).unwrap(),
            "https://gitlab.example.com/api/v4"
        );
    }
    assert!(mcp_server_devtools::auth::secrets::lookup("gitlab", "GITLAB_TOKEN").is_some());
}

#[tokio::test]
async fn list_projects_defaults_membership_and_switches_to_group_listing() {
    let fx = Fixture::new().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .and(query_param("membership", "true"))
        .and(query_param("per_page", "20"))
        .and(query_param_is_missing("page"))
        .and(query_param_is_missing("owned"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 1, "path_with_namespace": "grp/one", "default_branch": "main"}
        ])))
        .expect(1)
        .mount(&fx.server)
        .await;
    let resp = list_projects(&fx.ctx(), &GitlabListProjectsArgs::default())
        .await
        .unwrap();
    assert!(resp.content.contains("grp/one"));

    Mock::given(method("GET"))
        .and(path("/api/v4/groups/my-org%2Fplatform/projects"))
        .and(query_param("search", "pay"))
        .and(query_param("owned", "true"))
        .and(query_param("order_by", "last_activity_at"))
        .and(query_param("sort", "desc"))
        .and(query_param("per_page", "5"))
        .and(query_param("page", "3"))
        .and(query_param_is_missing("membership"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 2, "path_with_namespace": "my-org/platform/payments"}
        ])))
        .expect(1)
        .mount(&fx.server)
        .await;
    let args: GitlabListProjectsArgs = parse(json!({
        "groupId": "my-org/platform", "search": "pay", "membership": false, "owned": true,
        "orderBy": "last_activity_at", "sort": "desc", "perPage": 5, "page": 3,
        "jq": "[0].path_with_namespace", "outputFormat": "json"
    }));
    let resp = list_projects(&fx.ctx(), &args).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&resp.content).unwrap()["data"],
        "my-org/platform/payments"
    );
}

#[tokio::test]
async fn get_file_decodes_utf8_content_and_encodes_identifiers() {
    let fx = Fixture::new().await;
    fx.mount_json(
        "/api/v4/projects/group%2Fsub%2Fproj/repository/files/src%2Fmain%20dir%2Fmain.rs",
        json!({
            "file_name": "main.rs", "file_path": "src/main dir/main.rs", "size": 12,
            "encoding": "base64", "content": "Zm4gbWFpbigpIHt9", "ref": "main",
            "blob_id": "abc", "commit_id": "def", "last_commit_id": "ghi"
        }),
    )
    .await;
    Mock::given(method("GET"))
        .and(query_param("ref", "main"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&fx.server)
        .await;
    let args: GitlabGetFileArgs = parse(json!({
        "project": "group/sub/proj", "path": "/src/main dir/main.rs", "ref": "main",
        "outputFormat": "json"
    }));
    let resp = get_file(&fx.ctx(), &args).await.unwrap();
    let body: Value = serde_json::from_str(&resp.content).unwrap();
    assert_eq!(body["content"], "fn main() {}");
    assert_eq!(body["encoding"], "utf-8");
    assert_eq!(body["size"], 12);
    assert!(body.get("contentOmitted").is_none());

    // Numeric project ids pass through verbatim; `jq` runs on the decoded body.
    fx.mount_json(
        "/api/v4/projects/42/repository/files/README.md",
        json!({"file_name": "README.md", "encoding": "base64", "content": "aGk="}),
    )
    .await;
    let args: GitlabGetFileArgs = parse(json!({
        "project": " 42 ", "path": "README.md", "ref": "v1.0", "jq": "content",
        "outputFormat": "json"
    }));
    let resp = get_file(&fx.ctx(), &args).await.unwrap();
    assert_eq!(resp.content.trim(), "\"hi\"");
}

#[tokio::test]
async fn get_file_omits_binary_content_and_requires_ref() {
    let fx = Fixture::new().await;
    fx.mount_json(
        "/api/v4/projects/42/repository/files/logo.png",
        json!({
            "file_name": "logo.png", "size": 4, "encoding": "base64",
            "content": "iVBOgA==", "blob_id": "abc"
        }),
    )
    .await;
    let args: GitlabGetFileArgs = parse(json!({
        "project": "42", "path": "logo.png", "ref": "main", "outputFormat": "json"
    }));
    let resp = get_file(&fx.ctx(), &args).await.unwrap();
    let body: Value = serde_json::from_str(&resp.content).unwrap();
    assert!(body.get("content").is_none());
    assert_eq!(
        body["contentOmitted"],
        "binary or non-UTF-8 content; only metadata is returned"
    );
    assert_eq!(body["file_name"], "logo.png");
    assert_eq!(body["size"], 4);

    let args: GitlabGetFileArgs = parse(json!({
        "project": "42", "path": "logo.png", "ref": "  "
    }));
    let err = get_file(&fx.ctx(), &args).await.unwrap_err();
    assert_eq!(err.status_code, Some(400));
    assert!(err.message.contains("`ref`"));
}

#[tokio::test]
async fn identifier_validation_rejects_structure_before_any_request() {
    let fx = Fixture::new().await;
    for bad_project in [
        "",
        "  ",
        "..",
        "a/../b",
        "a//b",
        "grp/ proj",
        "a%2Fb",
        "a?b",
    ] {
        let args: GitlabGetIssueArgs = parse(json!({"project": bad_project, "iid": 1}));
        let err = get_issue(&fx.ctx(), &args).await.unwrap_err();
        assert_eq!(err.status_code, Some(400), "{bad_project:?}");
        assert!(err.message.contains("`project`"), "{bad_project:?}");
    }
    for bad_path in ["", "/", "../secret", "a//b", "a/./b"] {
        let args: GitlabGetFileArgs =
            parse(json!({"project": "42", "path": bad_path, "ref": "main"}));
        let err = get_file(&fx.ctx(), &args).await.unwrap_err();
        assert_eq!(err.status_code, Some(400), "{bad_path:?}");
        assert!(err.message.contains("`path`"), "{bad_path:?}");
    }
    let args: GitlabListProjectsArgs = parse(json!({"groupId": "a/../b"}));
    let err = list_projects(&fx.ctx(), &args).await.unwrap_err();
    assert_eq!(err.status_code, Some(400));
    assert!(err.message.contains("`groupId`"));
    // Nothing above reached the wire (no mocks were mounted; an outbound
    // request would have produced a 404 from wiremock, not a 400).
    assert!(fx.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn page_bounds_and_enum_values_are_validated() {
    let fx = Fixture::new().await;
    for (per_page, page) in [(0, 1), (101, 1), (20, 0)] {
        let args: GitlabListIssuesArgs =
            parse(json!({"project": "42", "perPage": per_page, "page": page}));
        let err = list_issues(&fx.ctx(), &args).await.unwrap_err();
        assert_eq!(err.status_code, Some(400), "{per_page}/{page}");
    }
    let args: GitlabListIssuesArgs = parse(json!({"project": "42", "state": "merged"}));
    let err = list_issues(&fx.ctx(), &args).await.unwrap_err();
    assert_eq!(err.status_code, Some(400));
    assert!(err.message.contains("opened, closed, all"));

    let args: GitlabListMergeRequestsArgs = parse(json!({"project": "42", "sort": "up"}));
    let err = list_merge_requests(&fx.ctx(), &args).await.unwrap_err();
    assert_eq!(err.status_code, Some(400));
    assert!(err.message.contains("asc, desc"));

    let args: GitlabListPipelineJobsArgs =
        parse(json!({"project": "42", "pipelineId": 7, "scope": "failed,success"}));
    let err = list_pipeline_jobs(&fx.ctx(), &args).await.unwrap_err();
    assert_eq!(err.status_code, Some(400));
    assert!(err.message.contains("`scope`"));
    assert!(fx.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn merge_request_tools_send_filters_iid_and_diff_paging() {
    let fx = Fixture::new().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/grp%2Fproj/merge_requests"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .and(query_param("state", "opened"))
        .and(query_param("source_branch", "feature/x"))
        .and(query_param("target_branch", "main"))
        .and(query_param("labels", "bug,backend"))
        .and(query_param("author_username", "jdoe"))
        .and(query_param("order_by", "updated_at"))
        .and(query_param("sort", "asc"))
        .and(query_param("per_page", "10"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"iid": 12, "id": 9001, "title": "Fix login", "state": "opened"}
        ])))
        .expect(1)
        .mount(&fx.server)
        .await;
    let args: GitlabListMergeRequestsArgs = parse(json!({
        "project": "grp/proj", "state": "opened", "sourceBranch": "feature/x",
        "targetBranch": "main", "labels": "bug,backend", "authorUsername": "jdoe",
        "orderBy": "updated_at", "sort": "asc", "perPage": 10, "page": 2,
        "jq": "[0].iid", "outputFormat": "json"
    }));
    let resp = list_merge_requests(&fx.ctx(), &args).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&resp.content).unwrap()["data"],
        json!(12)
    );

    fx.mount_json(
        "/api/v4/projects/grp%2Fproj/merge_requests/12",
        json!({"iid": 12, "title": "Fix login", "head_pipeline": {"id": 555, "status": "failed"}}),
    )
    .await;
    let args: GitlabGetMergeRequestArgs = parse(json!({
        "project": "grp/proj", "iid": 12, "jq": "head_pipeline.id", "outputFormat": "json"
    }));
    let resp = get_merge_request(&fx.ctx(), &args).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&resp.content).unwrap(),
        json!(555)
    );

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/grp%2Fproj/merge_requests/12/diffs"))
        .and(query_param("per_page", "2"))
        .and(query_param("page", "4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"new_path": "a.rs", "diff": "@@ -1 +1 @@\n-a\n+b\n", "too_large": false},
            {"new_path": "big.bin", "diff": "", "too_large": true, "collapsed": true}
        ])))
        .expect(1)
        .mount(&fx.server)
        .await;
    let args: GitlabGetMergeRequestDiffArgs = parse(json!({
        "project": "grp/proj", "iid": 12, "perPage": 2, "page": 4,
        "jq": "[?too_large].new_path", "outputFormat": "json"
    }));
    let resp = get_merge_request_diff(&fx.ctx(), &args).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&resp.content).unwrap()["data"],
        json!(["big.bin"])
    );
}

#[tokio::test]
async fn issue_tools_send_filters_and_iid() {
    let fx = Fixture::new().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/issues"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .and(query_param("state", "opened"))
        .and(query_param("labels", "bug"))
        .and(query_param("assignee_username", "amy"))
        .and(query_param("author_username", "bob"))
        .and(query_param("search", "crash"))
        .and(query_param("order_by", "updated_at"))
        .and(query_param("sort", "desc"))
        .and(query_param("per_page", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"iid": 7, "id": 8008, "title": "Crash on start", "state": "opened"}
        ])))
        .expect(1)
        .mount(&fx.server)
        .await;
    let args: GitlabListIssuesArgs = parse(json!({
        "project": "42", "state": "opened", "labels": "bug", "assigneeUsername": "amy",
        "authorUsername": "bob", "search": "crash", "orderBy": "updated_at", "sort": "desc",
        "jq": "[0].title", "outputFormat": "json"
    }));
    let resp = list_issues(&fx.ctx(), &args).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&resp.content).unwrap()["data"],
        json!("Crash on start")
    );

    fx.mount_json(
        "/api/v4/projects/42/issues/7",
        json!({"iid": 7, "title": "Crash on start", "description": "stack trace"}),
    )
    .await;
    let args: GitlabGetIssueArgs = parse(json!({"project": "42", "iid": 7}));
    let resp = get_issue(&fx.ctx(), &args).await.unwrap();
    assert!(resp.content.contains("stack trace"));
}

#[tokio::test]
async fn pipeline_tools_send_filters_and_trace_passes_text_through() {
    let fx = Fixture::new().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/grp%2Fproj/pipelines"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .and(query_param("ref", "main"))
        .and(query_param("status", "failed"))
        .and(query_param("source", "push"))
        .and(query_param("sha", "abc123"))
        .and(query_param("order_by", "updated_at"))
        .and(query_param("sort", "desc"))
        .and(query_param("per_page", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 555, "status": "failed", "ref": "main", "sha": "abc123"}
        ])))
        .expect(1)
        .mount(&fx.server)
        .await;
    let args: GitlabListPipelinesArgs = parse(json!({
        "project": "grp/proj", "ref": "main", "status": "failed", "source": "push",
        "sha": "abc123", "orderBy": "updated_at", "sort": "desc", "jq": "[0].id",
        "outputFormat": "json"
    }));
    let resp = list_pipelines(&fx.ctx(), &args).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&resp.content).unwrap()["data"],
        json!(555)
    );

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/grp%2Fproj/pipelines/555/jobs"))
        .and(query_param("scope", "failed"))
        .and(query_param("include_retried", "true"))
        .and(query_param("per_page", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": 777, "name": "test", "stage": "test", "status": "failed"}
        ])))
        .expect(1)
        .mount(&fx.server)
        .await;
    let args: GitlabListPipelineJobsArgs = parse(json!({
        "project": "grp/proj", "pipelineId": 555, "scope": "failed", "includeRetried": true,
        "perPage": 50, "jq": "[0].id", "outputFormat": "json"
    }));
    let resp = list_pipeline_jobs(&fx.ctx(), &args).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&resp.content).unwrap()["data"],
        json!(777)
    );

    let trace = "Running with gitlab-runner\n\x1b[31mERROR: test failed\x1b[0m\n";
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/grp%2Fproj/jobs/777/trace"))
        .and(header("authorization", format!("Bearer {TOKEN}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain; charset=utf-8")
                .set_body_string(trace),
        )
        .expect(1)
        .mount(&fx.server)
        .await;
    let args: GitlabGetJobTraceArgs = parse(json!({"project": "grp/proj", "jobId": 777}));
    let resp = get_job_trace(&fx.ctx(), &args).await.unwrap();
    assert_eq!(resp.content, trace);
}

#[tokio::test]
async fn upstream_errors_are_classified_with_envelope_messages() {
    let fx = Fixture::new().await;
    let cases: [(u16, Value, &str); 6] = [
        (
            401,
            json!({"message": "401 Unauthorized"}),
            "401 Unauthorized",
        ),
        (403, json!({"message": "403 Forbidden"}), "403 Forbidden"),
        (
            404,
            json!({"message": "404 Project Not Found"}),
            "404 Project Not Found",
        ),
        (
            400,
            json!({"message": {"ref": ["is invalid"], "path": ["can't be blank"]}}),
            "ref: is invalid; path: can't be blank",
        ),
        (
            429,
            json!({"error": "rate_limited", "error_description": "slow down"}),
            "rate_limited: slow down",
        ),
        (500, json!({"message": "internal"}), "internal"),
    ];
    for (status, body, expected) in cases {
        let iid = u64::from(status);
        Mock::given(method("GET"))
            .and(path(format!("/api/v4/projects/42/issues/{iid}")))
            .respond_with(ResponseTemplate::new(status).set_body_json(body.clone()))
            .expect(1)
            .mount(&fx.server)
            .await;
        let args: GitlabGetIssueArgs = parse(json!({"project": "42", "iid": iid}));
        let err = get_issue(&fx.ctx(), &args).await.unwrap_err();
        assert_eq!(err.status_code, Some(status), "{status}");
        assert!(err.message.contains(expected), "{status}: {}", err.message);
        assert!(err.original.is_some(), "{status}");
        let expected_kind = if matches!(status, 401 | 403) {
            ErrorKind::AuthInvalid
        } else {
            ErrorKind::ApiError
        };
        assert_eq!(err.kind, expected_kind, "{status}");
    }

    // A non-JSON body (proxy page) is preserved verbatim.
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/issues/1"))
        .respond_with(ResponseTemplate::new(502).set_body_string("<html>bad gateway</html>"))
        .expect(1)
        .mount(&fx.server)
        .await;
    let args: GitlabGetIssueArgs = parse(json!({"project": "42", "iid": 1}));
    let err = get_issue(&fx.ctx(), &args).await.unwrap_err();
    assert_eq!(err.status_code, Some(502));
    assert!(err.message.contains("bad gateway"));
}

#[tokio::test]
async fn large_trace_returns_bounded_preview_and_complete_artifact() {
    let fx = Fixture::new().await;
    let trace = "x".repeat(100_000) + "failure at tail";
    Mock::given(path("/api/v4/projects/42/jobs/777/trace"))
        .respond_with(ResponseTemplate::new(200).set_body_string(trace.clone()))
        .mount(&fx.server)
        .await;
    let args = serde_json::from_value(json!({"project":"42","jobId":777})).unwrap();
    let result = get_job_trace(&fx.ctx(), &args).await.unwrap();
    let metadata: Value = serde_json::from_str(&result.content).unwrap();
    assert_eq!(metadata["bytes"], trace.len());
    assert_eq!(metadata["complete"], true);
    assert!(
        metadata["preview"]["tail"]
            .as_str()
            .unwrap()
            .ends_with("failure at tail")
    );
    assert!(result.content.len() < trace.len());
    let artifact = mcp_server_devtools::transport::raw_response::artifact(
        metadata["artifactId"].as_str().unwrap(),
    )
    .unwrap();
    mcp_server_devtools::transport::raw_response::remove_artifact(&artifact.path)
        .await
        .unwrap();
}

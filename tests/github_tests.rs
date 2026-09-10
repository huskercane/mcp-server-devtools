//! Integration tests for the GitHub REST adapter: configuration, request
//! shape per tool (paths, encoded identifiers, headers, query params, page
//! bounds), identifier validation, error classification, contents decoding,
//! and the config-alias / secret-registry wiring.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::github::{
    CONTENT_OMITTED_BINARY, CONTENT_OMITTED_TOO_LARGE, CONTENT_OMITTED_UNDECODABLE, GithubContext,
    decode_contents, get_file, get_issue, get_pull_request, get_pull_request_diff, list_issues,
    list_pull_requests, list_repositories, list_workflow_jobs, list_workflow_runs,
};
use mcp_server_devtools::error::ErrorKind;
use mcp_server_devtools::tools::args::GithubListRepositoriesArgs;
use mcp_server_devtools::transport::{HttpClient, build_client};
use mcp_server_devtools::vendor::{Vendor, github::GithubVendor};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOOLS: [&str; 9] = [
    "github_list_repositories",
    "github_get_file",
    "github_list_pull_requests",
    "github_get_pull_request",
    "github_get_pull_request_diff",
    "github_list_issues",
    "github_get_issue",
    "github_list_workflow_runs",
    "github_list_workflow_jobs",
];

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
    )
}

/// A wiremock-backed fixture: token `gh-secret`, base pointed at the server.
struct Fixture {
    server: MockServer,
    cfg: Config,
    client: HttpClient,
    vendor: GithubVendor,
}

impl Fixture {
    async fn new(extra: &[(&str, &str)]) -> Self {
        let server = MockServer::start().await;
        let mut pairs = vec![("GITHUB_TOKEN", "gh-secret")];
        pairs.extend_from_slice(extra);
        Self {
            vendor: GithubVendor::with_base_url(server.uri()),
            cfg: config(&pairs),
            client: build_client().unwrap(),
            server,
        }
    }

    fn ctx(&self) -> GithubContext<'_> {
        GithubContext::new(&self.client, &self.cfg, &self.vendor)
    }

    /// Mount a `GET` expectation that also asserts the bearer scheme and the
    /// pinned API version header.
    fn expect_get(
        endpoint: &str,
        version: &str,
        _body: Value,
    ) -> impl std::future::Future<Output = wiremock::MockBuilder> {
        std::future::ready(
            Mock::given(method("GET"))
                .and(path(endpoint))
                .and(header("authorization", "Bearer gh-secret"))
                .and(header("accept", "application/json"))
                .and(header("x-github-api-version", version)),
        )
    }
}

fn args<T: serde::de::DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

#[tokio::test]
async fn configuration_defaults_overrides_and_tool_prefixes() {
    let vendor = GithubVendor::new();
    assert_eq!(vendor.name(), "github");
    for value in [None, Some(""), Some("   ")] {
        let cfg = value.map_or_else(
            || Config::from_map(HashMap::new()),
            |v| config(&[("GITHUB_TOKEN", v)]),
        );
        assert_eq!(
            vendor.token(&cfg).await.unwrap_err().kind,
            ErrorKind::AuthMissing
        );
        // No base is required: the public API is the default.
        assert_eq!(vendor.base_url(&cfg).unwrap(), "https://api.github.com");
        assert_eq!(vendor.api_version(&cfg), "2022-11-28");
    }
    let cfg = config(&[
        ("GITHUB_TOKEN", "token"),
        ("GITHUB_API_BASE", " https://ghe.example.com/api/v3/ "),
        ("GITHUB_API_VERSION", " 2026-03-01 "),
    ]);
    assert_eq!(vendor.token(&cfg).await.unwrap(), "token");
    assert_eq!(
        vendor.base_url(&cfg).unwrap(),
        "https://ghe.example.com/api/v3"
    );
    assert_eq!(vendor.api_version(&cfg), "2026-03-01");
    assert_eq!(
        GithubVendor::with_base_url("http://localhost/")
            .base_url(&cfg)
            .unwrap(),
        "http://localhost"
    );
    assert_eq!(vendor.normalize_path("user/repos"), "/user/repos");
    assert_eq!(vendor.normalize_path("/user/repos"), "/user/repos");
    assert!(vendor.cache_reads("/repos/o/r/pulls/1"));
    assert!(!vendor.cache_reads("/repos/o/r/actions/runs?per_page=30"));
    for tool in TOOLS {
        assert_eq!(
            mcp_server_devtools::tools::vendor_for_tool(tool),
            Some("github")
        );
    }
}

#[tokio::test]
async fn missing_token_surfaces_at_call_time_without_a_request() {
    let server = MockServer::start().await;
    let cfg = Config::from_map(HashMap::new());
    let client = build_client().unwrap();
    let vendor = GithubVendor::with_base_url(server.uri());
    let ctx = GithubContext::new(&client, &cfg, &vendor);
    let error = list_repositories(&ctx, &GithubListRepositoriesArgs::default())
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::AuthMissing);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn list_repositories_routes_by_owner_and_bounds_pages() {
    let fx = Fixture::new(&[("GITHUB_API_VERSION", "2026-03-01")]).await;
    for (endpoint, args_json) in [
        (
            "/user/repos",
            json!({"visibility":"private","affiliation":"owner,collaborator","perPage":500}),
        ),
        (
            "/orgs/acme/repos",
            json!({"owner":"acme","type":"sources","sort":"pushed","direction":"desc","perPage":500,"page":2}),
        ),
        (
            "/users/octocat/repos",
            json!({"owner":" octocat ","ownerType":"user","perPage":500,"page":2}),
        ),
    ] {
        let mut mock = Fixture::expect_get(endpoint, "2026-03-01", json!([]))
            .await
            .and(query_param("per_page", "100"));
        if endpoint == "/user/repos" {
            mock = mock
                .and(query_param("visibility", "private"))
                .and(query_param("affiliation", "owner,collaborator"))
                .and(query_param_is_missing("page"));
        } else {
            mock = mock.and(query_param("page", "2"));
        }
        if endpoint == "/orgs/acme/repos" {
            mock = mock
                .and(query_param("type", "sources"))
                .and(query_param("sort", "pushed"))
                .and(query_param("direction", "desc"));
        }
        mock.respond_with(
            ResponseTemplate::new(200).set_body_json(json!([{"full_name":"acme/widgets"}])),
        )
        .expect(1)
        .mount(&fx.server)
        .await;
        let response = list_repositories(&fx.ctx(), &args(args_json))
            .await
            .unwrap();
        assert!(response.content.contains("acme/widgets"), "{endpoint}");
    }

    // Default page size, no page.
    Fixture::expect_get("/orgs/acme/repos", "2026-03-01", json!([]))
        .await
        .and(query_param("per_page", "30"))
        .and(query_param_is_missing("page"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&fx.server)
        .await;
    list_repositories(&fx.ctx(), &args(json!({"owner":"acme"})))
        .await
        .unwrap();

    // Authenticated-user-only filters are rejected when an owner is given.
    let error = list_repositories(
        &fx.ctx(),
        &args(json!({"owner":"acme","visibility":"private"})),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status_code, Some(400));
    assert!(error.message.contains("visibility"));

    for bad in [json!({"perPage":0}), json!({"page":0})] {
        let error = list_repositories(&fx.ctx(), &args(bad)).await.unwrap_err();
        assert_eq!(error.status_code, Some(400));
    }
}

#[tokio::test]
async fn get_file_encodes_path_sends_ref_and_decodes_utf8() {
    let fx = Fixture::new(&[]).await;
    let text = "fn main() {\n    println!(\"héllo\");\n}\n";
    // GitHub wraps base64 at 60 columns.
    let encoded = BASE64.encode(text);
    let wrapped = encoded
        .as_bytes()
        .chunks(60)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    Fixture::expect_get(
        "/repos/acme/widgets/contents/src/my%20dir/main.rs",
        "2022-11-28",
        json!({}),
    )
    .await
    .and(query_param("ref", "release/1.2"))
    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "type":"file","name":"main.rs","path":"src/my dir/main.rs","size":text.len(),
        "sha":"abc","encoding":"base64","content":format!("{wrapped}\n")
    })))
    .expect(1)
    .mount(&fx.server)
    .await;
    let response = get_file(
        &fx.ctx(),
        &args(json!({
            "owner":"acme","repo":"widgets","path":"/src/my dir/main.rs","ref":"release/1.2",
            "jq":"{content: content, encoding: encoding}","outputFormat":"json"
        })),
    )
    .await
    .unwrap();
    let value: Value = serde_json::from_str(&response.content).unwrap();
    assert_eq!(value["content"], json!(text));
    assert_eq!(value["encoding"], json!("utf-8"));
}

#[tokio::test]
async fn get_file_passes_directories_through_and_omits_unreadable_content() {
    let fx = Fixture::new(&[]).await;
    Fixture::expect_get("/repos/acme/widgets/contents/docs", "2022-11-28", json!({}))
        .await
        .and(query_param_is_missing("ref"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"type":"file","name":"a.md","path":"docs/a.md","size":12},
            {"type":"dir","name":"img","path":"docs/img","size":0}
        ])))
        .expect(1)
        .mount(&fx.server)
        .await;
    let response = get_file(
        &fx.ctx(),
        &args(json!({"owner":"acme","repo":"widgets","path":"docs","outputFormat":"json"})),
    )
    .await
    .unwrap();
    let value: Value = serde_json::from_str(&response.content).unwrap();
    assert_eq!(value.as_array().map(Vec::len), Some(2));
    assert_eq!(value[1]["type"], json!("dir"));

    // Binary (not UTF-8) → metadata only.
    let binary = decode_contents(json!({
        "type":"file","name":"logo.png","size":4,"encoding":"base64",
        "content": BASE64.encode([0x89u8, 0x50, 0xFF, 0xFE])
    }));
    assert_eq!(binary["contentOmitted"], json!(CONTENT_OMITTED_BINARY));
    assert!(binary.get("content").is_none());
    assert_eq!(binary["name"], json!("logo.png"));

    // Over the inline limit: GitHub sends `encoding: "none"` and no content.
    let large = decode_contents(json!({
        "type":"file","name":"big.bin","size":5_000_000,"encoding":"none","content":""
    }));
    assert_eq!(large["contentOmitted"], json!(CONTENT_OMITTED_TOO_LARGE));
    assert!(large.get("content").is_none());

    // Invalid base64 → flagged, not a panic and not passed through raw.
    let broken = decode_contents(json!({
        "type":"file","name":"x","size":3,"encoding":"base64","content":"@@@@"
    }));
    assert_eq!(broken["contentOmitted"], json!(CONTENT_OMITTED_UNDECODABLE));

    // Empty file and non-file entries keep their shape.
    let empty = decode_contents(
        json!({"type":"file","name":"e","size":0,"encoding":"base64","content":""}),
    );
    assert_eq!(empty["content"], json!(""));
    assert_eq!(empty["encoding"], json!("utf-8"));
    let link = decode_contents(json!({"type":"symlink","name":"l","size":9,"target":"../real"}));
    assert!(link.get("contentOmitted").is_none());
    assert_eq!(link["target"], json!("../real"));
}

#[tokio::test]
async fn pull_request_tools_hit_expected_endpoints() {
    let fx = Fixture::new(&[]).await;
    Fixture::expect_get("/repos/acme/widgets/pulls", "2022-11-28", json!({}))
        .await
        .and(query_param("state", "closed"))
        .and(query_param("head", "acme:feature"))
        .and(query_param("base", "main"))
        .and(query_param("sort", "updated"))
        .and(query_param("direction", "asc"))
        .and(query_param("per_page", "5"))
        .and(query_param("page", "3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"number":7,"title":"Fix"}])))
        .expect(1)
        .mount(&fx.server)
        .await;
    let response = list_pull_requests(
        &fx.ctx(),
        &args(json!({
            "owner":"acme","repo":"widgets","state":"closed","head":"acme:feature","base":"main",
            "sort":"updated","direction":"asc","perPage":5,"page":3
        })),
    )
    .await
    .unwrap();
    assert!(response.content.contains("Fix"));

    Fixture::expect_get("/repos/acme/widgets/pulls/7", "2022-11-28", json!({}))
        .await
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"number":7,"mergeable":true,"head":{"sha":"deadbeef"}})),
        )
        .expect(1)
        .mount(&fx.server)
        .await;
    let response = get_pull_request(
        &fx.ctx(),
        &args(json!({"owner":"acme","repo":"widgets","number":7,"jq":"head.sha"})),
    )
    .await
    .unwrap();
    assert!(response.content.contains("deadbeef"));
    assert!(!response.content.contains("mergeable"));

    Fixture::expect_get("/repos/acme/widgets/pulls/7/files", "2022-11-28", json!({}))
        .await
        .and(query_param("per_page", "100"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"filename":"src/lib.rs","status":"modified","patch":"@@ -1 +1 @@\n-a\n+b"},
            {"filename":"logo.png","status":"added"}
        ])))
        .expect(1)
        .mount(&fx.server)
        .await;
    let response = get_pull_request_diff(
        &fx.ctx(),
        &args(json!({"owner":"acme","repo":"widgets","number":7,"perPage":250,"page":2,"outputFormat":"json"})),
    )
    .await
    .unwrap();
    let value: Value = serde_json::from_str(&response.content).unwrap();
    assert_eq!(value["data"][0]["patch"], json!("@@ -1 +1 @@\n-a\n+b"));
    assert!(value["data"][1].get("patch").is_none());
}

#[tokio::test]
async fn issue_tools_hit_expected_endpoints() {
    let fx = Fixture::new(&[]).await;
    Fixture::expect_get("/repos/acme/widgets/issues", "2022-11-28", json!({}))
        .await
        .and(query_param("state", "all"))
        .and(query_param("labels", "bug,urgent"))
        .and(query_param("assignee", "none"))
        .and(query_param("creator", "octocat"))
        .and(query_param("since", "2026-09-01T00:00:00Z"))
        .and(query_param("sort", "comments"))
        .and(query_param("direction", "desc"))
        .and(query_param("per_page", "30"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"number":1,"title":"Bug"},
            {"number":2,"title":"PR","pull_request":{"url":"x"}}
        ])))
        .expect(1)
        .mount(&fx.server)
        .await;
    let response = list_issues(
        &fx.ctx(),
        &args(json!({
            "owner":"acme","repo":"widgets","state":"all","labels":"bug,urgent","assignee":"none",
            "creator":"octocat","since":"2026-09-01T00:00:00Z","sort":"comments","direction":"desc",
            "jq":"[?!pull_request].title"
        })),
    )
    .await
    .unwrap();
    assert!(response.content.contains("Bug"));
    assert!(!response.content.contains("PR"));

    Fixture::expect_get("/repos/acme/widgets/issues/42", "2022-11-28", json!({}))
        .await
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"number":42,"title":"Crash"})),
        )
        .expect(1)
        .mount(&fx.server)
        .await;
    let response = get_issue(
        &fx.ctx(),
        &args(json!({"owner":"acme","repo":"widgets","number":42})),
    )
    .await
    .unwrap();
    assert!(response.content.contains("Crash"));
}

#[tokio::test]
async fn workflow_tools_route_by_workflow_id_and_send_filters() {
    let fx = Fixture::new(&[]).await;
    Fixture::expect_get("/repos/acme/widgets/actions/runs", "2022-11-28", json!({}))
        .await
        .and(query_param("branch", "main"))
        .and(query_param("status", "failure"))
        .and(query_param("event", "push"))
        .and(query_param("actor", "octocat"))
        .and(query_param("per_page", "30"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"total_count":1,"workflow_runs":[{"id":30_433_642,"conclusion":"failure"}]}),
        ))
        .expect(1)
        .mount(&fx.server)
        .await;
    let response = list_workflow_runs(
        &fx.ctx(),
        &args(json!({
            "owner":"acme","repo":"widgets","branch":"main","status":"failure","event":"push","actor":"octocat"
        })),
    )
    .await
    .unwrap();
    assert!(response.content.contains("30433642"));

    Fixture::expect_get(
        "/repos/acme/widgets/actions/workflows/ci.yml/runs",
        "2022-11-28",
        json!({}),
    )
    .await
    .and(query_param("per_page", "10"))
    .respond_with(
        ResponseTemplate::new(200).set_body_json(json!({"total_count":0,"workflow_runs":[]})),
    )
    .expect(1)
    .mount(&fx.server)
    .await;
    list_workflow_runs(
        &fx.ctx(),
        &args(json!({"owner":"acme","repo":"widgets","workflowId":" ci.yml ","perPage":10})),
    )
    .await
    .unwrap();

    Fixture::expect_get(
        "/repos/acme/widgets/actions/runs/30433642/jobs",
        "2022-11-28",
        json!({}),
    )
    .await
    .and(query_param("filter", "all"))
    .and(query_param("per_page", "30"))
    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "total_count":1,
        "jobs":[{"id":1,"name":"build","conclusion":"failure","steps":[{"name":"cargo test","conclusion":"failure"}]}]
    })))
    .expect(1)
    .mount(&fx.server)
    .await;
    let response = list_workflow_jobs(
        &fx.ctx(),
        &args(json!({
            "owner":"acme","repo":"widgets","runId":30_433_642,"filter":"all",
            "jq":"jobs[?conclusion=='failure'].steps[] | [?conclusion=='failure'].name"
        })),
    )
    .await
    .unwrap();
    assert!(response.content.contains("cargo test"));
}

#[tokio::test]
async fn identifiers_are_validated_before_any_request() {
    let fx = Fixture::new(&[]).await;
    for (owner, repo, path, workflow) in [
        ("a/b", "widgets", "README.md", "ci.yml"),
        ("..", "widgets", "README.md", "ci.yml"),
        ("", "widgets", "README.md", "ci.yml"),
        ("acme", "a/b", "README.md", "ci.yml"),
        ("acme", "..", "README.md", "ci.yml"),
        ("acme", " ", "README.md", "ci.yml"),
        ("acme", "widgets", "../etc/passwd", "ci.yml"),
        ("acme", "widgets", "src//lib.rs", "ci.yml"),
        ("acme", "widgets", "", "ci.yml"),
        ("acme", "widgets", "../etc", "a/b"),
        ("acme", "widgets", "../etc", ".."),
    ] {
        let error = get_file(
            &fx.ctx(),
            &args(json!({"owner":owner,"repo":repo,"path":path})),
        )
        .await
        .err();
        let runs_error = if owner == "acme" && repo == "widgets" && workflow == "ci.yml" {
            None
        } else {
            list_workflow_runs(
                &fx.ctx(),
                &args(json!({"owner":owner,"repo":repo,"workflowId":workflow})),
            )
            .await
            .err()
        };
        // At least one of the two tools sees the bad identifier; whichever
        // does must reject it as a 400 before touching the network.
        let error = error
            .filter(|error| error.status_code == Some(400))
            .or(runs_error)
            .unwrap_or_else(|| {
                panic!("{owner:?}/{repo:?}/{path:?}/{workflow:?} should have been rejected")
            });
        assert_eq!(error.status_code, Some(400), "{owner:?}/{repo:?}/{path:?}");
    }
    let error = get_issue(
        &fx.ctx(),
        &args(json!({"owner":"a?b","repo":"widgets","number":1})),
    )
    .await
    .unwrap_err();
    assert_eq!(error.status_code, Some(400));
    let error = list_pull_requests(&fx.ctx(), &args(json!({"owner":"acme","repo":"a#b"})))
        .await
        .unwrap_err();
    assert_eq!(error.status_code, Some(400));
    assert!(fx.server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn upstream_errors_are_classified_with_the_envelope_message() {
    let fx = Fixture::new(&[]).await;
    let cases: [(u16, Value, ErrorKind, &str); 7] = [
        (
            401,
            json!({"message":"Bad credentials","documentation_url":"https://docs.github.com/rest"}),
            ErrorKind::AuthInvalid,
            "Bad credentials",
        ),
        (
            403,
            json!({"message":"Resource not accessible by personal access token"}),
            ErrorKind::AuthInvalid,
            "Insufficient permissions",
        ),
        (
            403,
            json!({"message":"API rate limit exceeded for user ID 1."}),
            ErrorKind::AuthInvalid,
            "Rate limit exceeded",
        ),
        (
            404,
            json!({"message":"Not Found"}),
            ErrorKind::ApiError,
            "Not Found",
        ),
        (
            422,
            json!({"message":"Validation Failed","errors":[{"resource":"PullRequest","field":"base","code":"invalid"}]}),
            ErrorKind::ApiError,
            "PullRequest.base: invalid",
        ),
        (
            429,
            json!({"message":"You have exceeded a secondary rate limit."}),
            ErrorKind::ApiError,
            "secondary rate limit",
        ),
        (
            500,
            Value::String("upstream exploded".into()),
            ErrorKind::ApiError,
            "upstream exploded",
        ),
    ];
    for (index, (status, body, kind, needle)) in cases.iter().enumerate() {
        let number = u64::try_from(index).unwrap();
        let endpoint = format!("/repos/acme/widgets/issues/{number}");
        let template = match body {
            Value::String(text) => ResponseTemplate::new(*status).set_body_string(text.clone()),
            other => ResponseTemplate::new(*status).set_body_json(other),
        };
        Mock::given(method("GET"))
            .and(path(&endpoint))
            .respond_with(template)
            .expect(1)
            .mount(&fx.server)
            .await;
        let error = get_issue(
            &fx.ctx(),
            &args(json!({"owner":"acme","repo":"widgets","number":number})),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind, *kind, "status {status}");
        assert_eq!(error.status_code, Some(*status), "status {status}");
        assert!(error.message.contains(needle), "{}", error.message);
        assert!(error.original.is_some(), "status {status}");
    }
}

#[tokio::test]
async fn vendor_sections_aliases_and_secret_registration() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("configs.json");
    for alias in ["github", "mcp-server-github"] {
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({alias: {"environments": {
                "GITHUB_TOKEN": "scoped-token",
                "GITHUB_API_BASE": "https://ghe.example.com/api/v3",
                "GITHUB_API_VERSION": "2026-03-01"
            }}}))
            .unwrap(),
        )
        .unwrap();
        let cfg = Config::load_from_sources(Some(&file), None, &HashMap::new());
        let vendor = GithubVendor::new();
        assert_eq!(vendor.token(&cfg).await.unwrap(), "scoped-token");
        assert_eq!(
            vendor.base_url(&cfg).unwrap(),
            "https://ghe.example.com/api/v3"
        );
        assert_eq!(vendor.api_version(&cfg), "2026-03-01");
    }
    assert!(mcp_server_devtools::auth::secrets::lookup("github", "GITHUB_TOKEN").is_some());
}

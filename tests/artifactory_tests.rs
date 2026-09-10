//! Integration tests for the `JFrog` Artifactory adapter: configuration and the
//! `/artifactory` context rule, request shape per tool (method, encoded path,
//! bearer header, `text/plain` AQL body), identifier validation, the AQL
//! compiler, error classification, and config aliases / secret registration.

use std::collections::HashMap;

use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::artifactory::{
    ArtifactoryContext, SEARCH_LIMIT_DEFAULT, SEARCH_LIMIT_MAX, build_aql, get_build_info,
    get_file_info, list_repositories, search,
};
use mcp_server_devtools::error::ErrorKind;
use mcp_server_devtools::tools::args::{
    ArtifactoryGetBuildInfoArgs, ArtifactoryGetFileInfoArgs, ArtifactoryListRepositoriesArgs,
    ArtifactorySearchArgs,
};
use mcp_server_devtools::transport::build_client;
use mcp_server_devtools::vendor::{Vendor, artifactory::ArtifactoryVendor};
use serde_json::json;
use wiremock::matchers::{body_string, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
    )
}

fn search_args(value: serde_json::Value) -> ArtifactorySearchArgs {
    serde_json::from_value(value).unwrap()
}

#[tokio::test]
async fn required_configuration_and_context_path_rule() {
    let vendor = ArtifactoryVendor::new();
    assert_eq!(vendor.name(), "artifactory");
    for value in [None, Some(""), Some("   ")] {
        let cfg = value.map_or_else(
            || Config::from_map(HashMap::new()),
            |v| config(&[("ARTIFACTORY_URL", v), ("ARTIFACTORY_TOKEN", v)]),
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

    // Origin-only URLs gain the standard context (trailing slashes and
    // whitespace trimmed first); URLs with any path are used verbatim so a
    // reverse-proxied context path is honoured.
    for (input, expected) in [
        (
            " https://mycorp.jfrog.io ",
            "https://mycorp.jfrog.io/artifactory",
        ),
        (
            "https://artifactory.example.com//",
            "https://artifactory.example.com/artifactory",
        ),
        (
            "https://artifactory.example.com/artifactory/",
            "https://artifactory.example.com/artifactory",
        ),
        (
            "https://tools.example.com/binaries/",
            "https://tools.example.com/binaries",
        ),
        ("http://localhost:8082", "http://localhost:8082/artifactory"),
    ] {
        let cfg = config(&[("ARTIFACTORY_URL", input), ("ARTIFACTORY_TOKEN", "t")]);
        assert_eq!(vendor.base_url(&cfg).unwrap(), expected, "input {input:?}");
        assert_eq!(
            ArtifactoryVendor::with_base_url(input)
                .base_url(&Config::from_map(HashMap::new()))
                .unwrap(),
            expected,
            "override {input:?}"
        );
    }
    let cfg = config(&[("ARTIFACTORY_TOKEN", " tok ")]);
    assert_eq!(vendor.token(&cfg).await.unwrap(), "tok");
    assert_eq!(
        vendor.normalize_path("api/repositories"),
        "/api/repositories"
    );
    assert_eq!(
        vendor.normalize_path("/api/repositories"),
        "/api/repositories"
    );

    for tool in [
        "artifactory_list_repositories",
        "artifactory_search",
        "artifactory_get_file_info",
        "artifactory_get_build_info",
    ] {
        assert_eq!(
            mcp_server_devtools::tools::vendor_for_tool(tool),
            Some("artifactory")
        );
    }
}

#[tokio::test]
async fn list_repositories_sends_bearer_and_filters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/artifactory/api/repositories"))
        .and(header("authorization", "Bearer art-secret"))
        .and(header("accept", "application/json"))
        .and(query_param("type", "local"))
        .and(query_param("packageType", "maven"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"key":"libs-release-local","type":"LOCAL","packageType":"Maven"},
            {"key":"libs-snapshot-local","type":"LOCAL","packageType":"Maven"}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[
        ("ARTIFACTORY_TOKEN", "art-secret"),
        ("ARTIFACTORY_URL", &server.uri()),
    ]);
    let client = build_client().unwrap();
    let vendor = ArtifactoryVendor::new();
    let ctx = ArtifactoryContext::new(&client, &cfg, &vendor);
    let args: ArtifactoryListRepositoriesArgs = serde_json::from_value(json!({
        "type": "Local", "packageType": "Maven", "jq": "[*].key", "outputFormat": "json"
    }))
    .unwrap();
    let response = list_repositories(&ctx, &args).await.unwrap();
    assert!(response.content.contains("libs-release-local"));
    assert!(!response.content.contains("LOCAL"));

    let bad: ArtifactoryListRepositoriesArgs =
        serde_json::from_value(json!({"type": "cloud"})).unwrap();
    let err = list_repositories(&ctx, &bad).await.unwrap_err();
    assert_eq!(err.status_code, Some(400));
    assert!(err.message.contains("`type` must be one of"));
}

#[tokio::test]
async fn search_posts_compiled_aql_as_plain_text() {
    let server = MockServer::start().await;
    let expected_aql = concat!(
        r#"items.find({"repo":"libs-release-local","name":{"$match":"my-app-*.jar"},"#,
        r#""path":"com/example/my-app","type":"file","#,
        r#""modified":{"$gt":"2024-06-01T00:00:00.000Z"}})"#,
        r#".include("repo","path","name","type","size","modified","created","sha256","actual_sha1")"#,
        r#".sort({"$desc":["modified"]}).limit(25)"#
    );
    Mock::given(method("POST"))
        .and(path("/artifactory/api/search/aql"))
        .and(header("authorization", "Bearer art-secret"))
        .and(header("content-type", "text/plain"))
        .and(body_string(expected_aql))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"repo":"libs-release-local","path":"com/example/my-app/1.4.2",
                         "name":"my-app-1.4.2.jar","type":"file","size":1234,
                         "modified":"2024-06-02T10:00:00.000Z","sha256":"ab"}],
            "range": {"start_pos":0,"end_pos":1,"total":1}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("ARTIFACTORY_TOKEN", "art-secret")]);
    let client = build_client().unwrap();
    let vendor = ArtifactoryVendor::with_base_url(server.uri());
    let ctx = ArtifactoryContext::new(&client, &cfg, &vendor);
    let args = search_args(json!({
        "repo": "libs-release-local", "name": "my-app-*.jar", "path": "/com/example/my-app/",
        "modifiedAfter": "2024-06-01T00:00:00.000Z", "limit": 25,
        "sortBy": "modified", "sortOrder": "desc",
        "jq": "results[*].name", "outputFormat": "json"
    }));
    let response = search(&ctx, &args).await.unwrap();
    assert!(response.content.contains("my-app-1.4.2.jar"));
    assert!(!response.content.contains("end_pos"));
}

#[test]
fn build_aql_exact_versus_wildcard_and_defaults() {
    let aql = build_aql(&search_args(json!({"repo": "generic-local"}))).unwrap();
    assert_eq!(
        aql,
        format!(
            r#"items.find({{"repo":"generic-local","type":"file"}}).include("repo","path","name","type","size","modified","created","sha256","actual_sha1").limit({SEARCH_LIMIT_DEFAULT})"#
        )
    );

    let exact = build_aql(&search_args(json!({"name": "app.jar", "path": "a/b"}))).unwrap();
    assert!(exact.contains(r#""name":"app.jar""#));
    assert!(exact.contains(r#""path":"a/b""#));
    assert!(!exact.contains("$match"));

    let wild = build_aql(&search_args(json!({"name": "*.jar", "path": "a/*"}))).unwrap();
    assert!(wild.contains(r#""name":{"$match":"*.jar"}"#));
    assert!(wild.contains(r#""path":{"$match":"a/*"}"#));

    let any = build_aql(&search_args(json!({"repo": "r", "type": "ANY"}))).unwrap();
    assert!(any.contains(r#""type":"any""#));

    let sha = "A".repeat(64);
    let by_sha = build_aql(&search_args(json!({"sha256": sha}))).unwrap();
    assert!(by_sha.contains(&format!(r#""sha256":"{}""#, "a".repeat(64))));

    let asc = build_aql(&search_args(json!({"repo": "r", "sortBy": "size"}))).unwrap();
    assert!(asc.ends_with(r#".sort({"$asc":["size"]}).limit(100)"#));
}

#[test]
fn build_aql_escapes_user_values_instead_of_splicing_them() {
    let hostile = r#"x"}).include("*")//\"#;
    let aql = build_aql(&search_args(json!({"repo": hostile, "name": hostile}))).unwrap();
    let quoted = serde_json::to_string(hostile).unwrap();
    assert!(aql.contains(&format!(r#""repo":{quoted}"#)));
    // The raw value never appears unescaped, so it cannot close the criteria
    // object or add clauses.
    assert!(!aql.contains(hostile));
    assert!(aql.starts_with("items.find({"));
    let mut parsed = serde_json::Deserializer::from_str(&aql["items.find(".len()..])
        .into_iter::<serde_json::Value>();
    let criteria = parsed.next().unwrap().unwrap();
    assert_eq!(criteria["repo"], hostile);
    assert_eq!(criteria["name"]["$match"], hostile);
    assert!(aql.contains(r#"\"}"#) && aql.contains(r"\\"));
}

#[test]
fn build_aql_rejects_unbounded_or_malformed_requests() {
    let cases = [
        (json!({}), "At least one of"),
        (json!({"repo": "  "}), "At least one of"),
        (json!({"repo": "r", "limit": 0}), "`limit` must be between"),
        (
            json!({"repo": "r", "limit": SEARCH_LIMIT_MAX + 1}),
            "`limit` must be between",
        ),
        (
            json!({"repo": "r", "type": "symlink"}),
            "`type` must be one of",
        ),
        (
            json!({"repo": "r", "sortBy": "owner"}),
            "`sortBy` must be one of",
        ),
        (
            json!({"repo": "r", "sortOrder": "desc"}),
            "`sortOrder` requires `sortBy`",
        ),
        (
            json!({"repo": "r", "sortBy": "name", "sortOrder": "down"}),
            "`sortOrder` must be one of",
        ),
        (json!({"sha256": "abc"}), "`sha256` must be 64"),
        (
            json!({"repo": "r", "modifiedAfter": "yesterday"}),
            "`modifiedAfter` must be an ISO-8601",
        ),
    ];
    for (input, expected) in cases {
        let err = build_aql(&search_args(input.clone())).unwrap_err();
        assert_eq!(err.status_code, Some(400), "input {input}");
        assert!(
            err.message.contains(expected),
            "input {input}: {}",
            err.message
        );
    }
    assert_eq!(
        build_aql(&search_args(
            json!({"repo": "r", "limit": SEARCH_LIMIT_MAX})
        ))
        .unwrap()
        .matches(&format!(".limit({SEARCH_LIMIT_MAX})"))
        .count(),
        1
    );
}

#[tokio::test]
async fn get_file_info_encodes_repo_and_path_segments() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(
            "/artifactory/api/storage/libs-release-local/com/example/my%20lib/1.0/lib.jar",
        ))
        .and(header("authorization", "Bearer art-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "repo":"libs-release-local","path":"/com/example/my lib/1.0/lib.jar",
            "size":"2048","checksums":{"sha256":"deadbeef"},"lastModified":"2024-06-02T10:00:00.000Z"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/artifactory/api/storage/libs-release-local/com/example",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "repo":"libs-release-local","path":"/com/example",
            "children":[{"uri":"/my lib","folder":true}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("ARTIFACTORY_TOKEN", "art-secret")]);
    let client = build_client().unwrap();
    let vendor = ArtifactoryVendor::with_base_url(server.uri());
    let ctx = ArtifactoryContext::new(&client, &cfg, &vendor);

    let args: ArtifactoryGetFileInfoArgs = serde_json::from_value(json!({
        "repo": "libs-release-local", "path": "/com/example/my lib/1.0/lib.jar",
        "jq": "checksums.sha256", "outputFormat": "json"
    }))
    .unwrap();
    let response = get_file_info(&ctx, &args).await.unwrap();
    assert!(response.content.contains("deadbeef"));
    assert!(!response.content.contains("2048"));

    let folder: ArtifactoryGetFileInfoArgs =
        serde_json::from_value(json!({"repo": "libs-release-local", "path": "com/example/"}))
            .unwrap();
    let response = get_file_info(&ctx, &folder).await.unwrap();
    assert!(response.content.contains("my lib"));
}

#[tokio::test]
async fn identifier_validation_rejects_structure_before_any_request() {
    let server = MockServer::start().await;
    let cfg = config(&[("ARTIFACTORY_TOKEN", "art-secret")]);
    let client = build_client().unwrap();
    let vendor = ArtifactoryVendor::with_base_url(server.uri());
    let ctx = ArtifactoryContext::new(&client, &cfg, &vendor);

    for (repo, file_path) in [
        ("a/b", "x.jar"),
        ("..", "x.jar"),
        ("", "x.jar"),
        ("repo", ""),
        ("repo", "../etc/passwd"),
        ("repo", "a//b"),
    ] {
        let args: ArtifactoryGetFileInfoArgs =
            serde_json::from_value(json!({"repo": repo, "path": file_path})).unwrap();
        let err = get_file_info(&ctx, &args).await.unwrap_err();
        assert_eq!(
            err.status_code,
            Some(400),
            "repo {repo:?} path {file_path:?}"
        );
    }
    for (name, number) in [("", "1"), ("build", "  "), ("..", "1"), ("build", ".")] {
        let args: ArtifactoryGetBuildInfoArgs =
            serde_json::from_value(json!({"buildName": name, "buildNumber": number})).unwrap();
        let err = get_build_info(&ctx, &args).await.unwrap_err();
        assert_eq!(
            err.status_code,
            Some(400),
            "name {name:?} number {number:?}"
        );
    }
    // No request reached the server for any of the rejected inputs.
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn get_build_info_encodes_name_and_passes_project() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(
            "/artifactory/api/build/my%20app%20release/2024.06.01-3",
        ))
        .and(header("authorization", "Bearer art-secret"))
        .and(query_param("project", "proj"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "buildInfo": {"name":"my app release","number":"2024.06.01-3",
                          "modules":[{"id":"com.example:my-app:1.4.2"}]},
            "uri": "https://example/artifactory/api/build/my%20app%20release/2024.06.01-3"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("ARTIFACTORY_TOKEN", "art-secret")]);
    let client = build_client().unwrap();
    let vendor = ArtifactoryVendor::with_base_url(server.uri());
    let ctx = ArtifactoryContext::new(&client, &cfg, &vendor);
    let args: ArtifactoryGetBuildInfoArgs = serde_json::from_value(json!({
        "buildName": " my app release ", "buildNumber": "2024.06.01-3", "project": "proj",
        "jq": "buildInfo.modules[0].id", "outputFormat": "json"
    }))
    .unwrap();
    let response = get_build_info(&ctx, &args).await.unwrap();
    assert!(response.content.contains("com.example:my-app:1.4.2"));
    assert!(!response.content.contains("uri"));
}

#[tokio::test]
async fn upstream_errors_are_classified_with_envelope_message_preserved() {
    let server = MockServer::start().await;
    let cfg = config(&[("ARTIFACTORY_TOKEN", "art-secret")]);
    let client = build_client().unwrap();
    let vendor = ArtifactoryVendor::with_base_url(server.uri());
    let ctx = ArtifactoryContext::new(&client, &cfg, &vendor);

    for status in [401, 403, 404, 429, 500] {
        Mock::given(method("GET"))
            .and(path(format!("/artifactory/api/build/b/{status}")))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "errors": [{"status": status, "message": format!("envelope {status}")},
                           {"status": status, "message": "second"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let args: ArtifactoryGetBuildInfoArgs =
            serde_json::from_value(json!({"buildName": "b", "buildNumber": status.to_string()}))
                .unwrap();
        let err = get_build_info(&ctx, &args).await.unwrap_err();
        assert_eq!(err.status_code, Some(status));
        assert!(
            err.message.contains(&format!("envelope {status}; second")),
            "{}",
            err.message
        );
        assert!(err.original.is_some());
        let expected_kind = if matches!(status, 401 | 403) {
            ErrorKind::AuthInvalid
        } else {
            ErrorKind::ApiError
        };
        assert_eq!(err.kind, expected_kind);
    }

    // Non-JSON bodies (reverse proxy, HTML login page) are surfaced trimmed.
    Mock::given(method("GET"))
        .and(path("/artifactory/api/build/b/502"))
        .respond_with(ResponseTemplate::new(502).set_body_string("  Bad Gateway from proxy \n"))
        .mount(&server)
        .await;
    let args: ArtifactoryGetBuildInfoArgs =
        serde_json::from_value(json!({"buildName": "b", "buildNumber": "502"})).unwrap();
    let err = get_build_info(&ctx, &args).await.unwrap_err();
    assert_eq!(err.status_code, Some(502));
    assert!(err.message.contains("Bad Gateway from proxy"));
}

#[tokio::test]
async fn missing_token_surfaces_at_call_time_without_a_request() {
    let server = MockServer::start().await;
    let cfg = config(&[("ARTIFACTORY_URL", &server.uri())]);
    let client = build_client().unwrap();
    let vendor = ArtifactoryVendor::new();
    let ctx = ArtifactoryContext::new(&client, &cfg, &vendor);
    let err = list_repositories(&ctx, &ArtifactoryListRepositoriesArgs::default())
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthMissing);
    let err = search(&ctx, &search_args(json!({"repo": "r"})))
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::AuthMissing);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn vendor_sections_aliases_and_secret_registration() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("configs.json");
    for alias in ["artifactory", "jfrog", "mcp-server-artifactory"] {
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({alias: {"environments": {
                "ARTIFACTORY_URL": "https://mycorp.jfrog.io", "ARTIFACTORY_TOKEN": "scoped-token"
            }}}))
            .unwrap(),
        )
        .unwrap();
        let cfg = Config::load_from_sources(Some(&file), None, &HashMap::new());
        assert_eq!(
            ArtifactoryVendor::new().token(&cfg).await.unwrap(),
            "scoped-token"
        );
        assert_eq!(
            ArtifactoryVendor::new().base_url(&cfg).unwrap(),
            "https://mycorp.jfrog.io/artifactory"
        );
    }
    assert!(
        mcp_server_devtools::auth::secrets::lookup("artifactory", "ARTIFACTORY_TOKEN").is_some()
    );
}

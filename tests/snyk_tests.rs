use std::collections::HashMap;

use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::snyk::{
    SnykContext, get_project, list_issues, list_orgs, list_projects, resolve_cursor,
};
use mcp_server_devtools::error::ErrorKind;
use mcp_server_devtools::tools::args::{
    SnykGetProjectArgs, SnykListIssuesArgs, SnykListOrgsArgs, SnykListProjectsArgs,
};
use mcp_server_devtools::transport::build_client;
use mcp_server_devtools::vendor::Vendor;
use mcp_server_devtools::vendor::snyk::{DEFAULT_API_VERSION, SnykVendor, validate_api_version};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "0d3728ec-eebf-484d-9c8d-3b6d3b1b7c9a";
const PROJECT: &str = "331ede0a-de94-456f-b788-166caeca58bf";

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
    )
}

fn orgs_args(value: serde_json::Value) -> SnykListOrgsArgs {
    serde_json::from_value(value).unwrap()
}

fn projects_args(value: serde_json::Value) -> SnykListProjectsArgs {
    serde_json::from_value(value).unwrap()
}

fn issues_args(value: serde_json::Value) -> SnykListIssuesArgs {
    serde_json::from_value(value).unwrap()
}

fn project_args(value: serde_json::Value) -> SnykGetProjectArgs {
    serde_json::from_value(value).unwrap()
}

#[tokio::test]
async fn configuration_defaults_trimming_version_and_tool_routing() {
    let vendor = SnykVendor::new();
    assert_eq!(vendor.name(), "snyk");

    // Missing / blank token surfaces as AuthMissing at call time.
    for value in [None, Some(""), Some("   ")] {
        let cfg = value.map_or_else(
            || Config::from_map(HashMap::new()),
            |v| config(&[("SNYK_TOKEN", v)]),
        );
        assert_eq!(
            vendor.token(&cfg).await.unwrap_err().kind,
            ErrorKind::AuthMissing
        );
        // The base URL has a default, so it never blocks boot or fail here.
        assert_eq!(vendor.base_url(&cfg).unwrap(), "https://api.snyk.io");
    }

    let cfg = config(&[
        ("SNYK_TOKEN", " tok "),
        ("SNYK_API_BASE", " https://api.eu.snyk.io/ "),
    ]);
    assert_eq!(vendor.base_url(&cfg).unwrap(), "https://api.eu.snyk.io");
    assert_eq!(vendor.token(&cfg).await.unwrap(), "tok");
    assert_eq!(
        SnykVendor::with_base_url("http://localhost/")
            .base_url(&cfg)
            .unwrap(),
        "http://localhost"
    );
    assert_eq!(vendor.normalize_path("rest/orgs"), "/rest/orgs");
    assert_eq!(vendor.normalize_path("/rest/orgs"), "/rest/orgs");

    // Version: pinned default, override, and shape validation.
    assert_eq!(vendor.api_version(&cfg).unwrap(), DEFAULT_API_VERSION);
    assert_eq!(DEFAULT_API_VERSION, "2024-10-15");
    let cfg = config(&[("SNYK_API_VERSION", " 2024-06-21~beta ")]);
    assert_eq!(vendor.api_version(&cfg).unwrap(), "2024-06-21~beta");
    for good in ["2024-10-15", "2025-01-01~experimental"] {
        assert_eq!(validate_api_version(good).unwrap(), good);
    }
    for bad in [
        "2024-10-1",
        "2024/10/15",
        "v1",
        "2024-10-15~alpha",
        "20241015",
        "",
    ] {
        let cfg = config(&[("SNYK_API_VERSION", bad), ("SNYK_TOKEN", "x")]);
        let err = if bad.is_empty() {
            // Blank falls back to the default rather than erroring.
            assert_eq!(vendor.api_version(&cfg).unwrap(), DEFAULT_API_VERSION);
            continue;
        } else {
            vendor.api_version(&cfg).unwrap_err()
        };
        assert_eq!(err.status_code, Some(400), "{bad}");
        assert!(err.message.contains("SNYK_API_VERSION"));
    }

    for tool in [
        "snyk_list_orgs",
        "snyk_list_projects",
        "snyk_list_issues",
        "snyk_get_project",
    ] {
        assert_eq!(
            mcp_server_devtools::tools::vendor_for_tool(tool),
            Some("snyk")
        );
    }
}

#[tokio::test]
async fn list_orgs_sends_token_scheme_version_and_filters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/orgs"))
        .and(header("authorization", "token snyk-secret"))
        .and(header("accept", "application/json"))
        .and(query_param("version", "2024-10-15"))
        .and(query_param("group_id", "11111111-2222-3333-4444-555555555555"))
        .and(query_param("slug", "my-company"))
        .and(query_param("limit", "5"))
        .and(query_param("starting_after", "v1.eyJpZCI6MX0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": ORG, "type": "org", "attributes": {"name": "My Company", "slug": "my-company"}}],
            "links": {"next": "/orgs?version=2024-10-15&starting_after=v1.eyJpZCI6Mn0&limit=5"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("SNYK_TOKEN", "snyk-secret")]);
    let client = build_client().unwrap();
    let vendor = SnykVendor::with_base_url(server.uri());
    let ctx = SnykContext::new(&client, &cfg, &vendor);
    let args = orgs_args(json!({
        "groupId": "11111111-2222-3333-4444-555555555555",
        "slug": "my-company",
        "limit": 5,
        "startingAfter": "v1.eyJpZCI6MX0",
        "jq": "data[0].attributes.name",
        "outputFormat": "json"
    }));
    let response = list_orgs(&ctx, &args).await.unwrap();
    assert!(response.content.contains("My Company"));
    assert!(!response.content.contains("my-company"));
}

#[tokio::test]
async fn list_orgs_defaults_limit_and_honours_version_and_base_from_config() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/orgs"))
        .and(header("authorization", "token snyk-secret"))
        .and(query_param("version", "2024-06-21~beta"))
        .and(query_param("limit", "20"))
        .and(query_param_is_missing("group_id"))
        .and(query_param_is_missing("slug"))
        .and(query_param_is_missing("starting_after"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[
        ("SNYK_TOKEN", "snyk-secret"),
        ("SNYK_API_BASE", &format!("{}/", server.uri())),
        ("SNYK_API_VERSION", "2024-06-21~beta"),
    ]);
    let client = build_client().unwrap();
    let vendor = SnykVendor::new();
    let ctx = SnykContext::new(&client, &cfg, &vendor);
    list_orgs(&ctx, &orgs_args(json!({}))).await.unwrap();

    // An invalid configured version is rejected before any request is made.
    let cfg = config(&[
        ("SNYK_TOKEN", "snyk-secret"),
        ("SNYK_API_BASE", &server.uri()),
        ("SNYK_API_VERSION", "latest"),
    ]);
    let ctx = SnykContext::new(&client, &cfg, &vendor);
    let err = list_orgs(&ctx, &orgs_args(json!({}))).await.unwrap_err();
    assert_eq!(err.status_code, Some(400));
    assert!(err.message.contains("SNYK_API_VERSION"));
}

#[tokio::test]
async fn list_projects_uses_configured_org_and_filters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/rest/orgs/{ORG}/projects")))
        .and(header("authorization", "token snyk-secret"))
        .and(query_param("version", "2024-10-15"))
        .and(query_param("names", "my-org/api:package.json,my-org/web:package.json"))
        .and(query_param("target_id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
        .and(query_param("types", "npm,maven"))
        .and(query_param("origins", "github,cli"))
        .and(query_param("limit", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": PROJECT, "type": "project", "attributes": {"name": "my-org/api:package.json", "type": "npm"}}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("SNYK_TOKEN", "snyk-secret"), ("SNYK_ORG_ID", ORG)]);
    let client = build_client().unwrap();
    let vendor = SnykVendor::with_base_url(server.uri());
    let ctx = SnykContext::new(&client, &cfg, &vendor);
    let args = projects_args(json!({
        "names": "my-org/api:package.json,my-org/web:package.json",
        "targetId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "types": "npm,maven",
        "origins": "github,cli",
        "limit": 100,
        "jq": "data[*].attributes.type",
        "outputFormat": "json"
    }));
    let response = list_projects(&ctx, &args).await.unwrap();
    assert!(response.content.contains("npm"));
}

#[tokio::test]
async fn list_issues_sends_scan_item_severity_status_and_timestamps() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/rest/orgs/{ORG}/issues")))
        .and(header("authorization", "token snyk-secret"))
        .and(query_param("version", "2024-10-15"))
        .and(query_param("scan_item.id", PROJECT))
        .and(query_param("scan_item.type", "project"))
        .and(query_param("effective_severity_level", "high,critical"))
        .and(query_param("status", "open"))
        .and(query_param("type", "package_vulnerability"))
        .and(query_param("ignored", "false"))
        .and(query_param("updated_after", "2026-08-01T00:00:00Z"))
        .and(query_param("created_after", "2026-01-01T00:00:00Z"))
        .and(query_param("limit", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "issue-1", "type": "issue", "attributes": {
                "title": "Prototype Pollution", "effective_severity_level": "high",
                "coordinates": [{"representations": [{"dependency": {"package_name": "lodash", "package_version": "4.17.20"}}]}]
            }}],
            "links": {"next": format!("/orgs/{ORG}/issues?version=2024-10-15&starting_after=v1.eyJpZCI6Mn0&limit=1")}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("SNYK_TOKEN", "snyk-secret")]);
    let client = build_client().unwrap();
    let vendor = SnykVendor::with_base_url(server.uri());
    let ctx = SnykContext::new(&client, &cfg, &vendor);
    let args = issues_args(json!({
        "orgId": ORG,
        "scanItemId": PROJECT,
        "scanItemType": "Project",
        "effectiveSeverityLevel": "High, critical",
        "status": "open",
        "type": "package_vulnerability",
        "ignored": false,
        "updatedAfter": "2026-08-01T00:00:00Z",
        "createdAfter": "2026-01-01T00:00:00Z",
        "limit": 1,
        "jq": "data[0].attributes.coordinates[0].representations[0].dependency.package_name",
        "outputFormat": "json"
    }));
    let response = list_issues(&ctx, &args).await.unwrap();
    assert!(response.content.contains("lodash"));
}

#[tokio::test]
async fn list_issues_rejects_half_scope_and_bad_enums_before_any_request() {
    let server = MockServer::start().await;
    let cfg = config(&[("SNYK_TOKEN", "snyk-secret"), ("SNYK_ORG_ID", ORG)]);
    let client = build_client().unwrap();
    let vendor = SnykVendor::with_base_url(server.uri());
    let ctx = SnykContext::new(&client, &cfg, &vendor);
    let cases = [
        (json!({"scanItemId": PROJECT}), "scanItemType"),
        (json!({"scanItemType": "project"}), "scanItemId"),
        (
            json!({"scanItemId": PROJECT, "scanItemType": "target"}),
            "scanItemType",
        ),
        (
            json!({"effectiveSeverityLevel": "high,severe"}),
            "effectiveSeverityLevel",
        ),
        (json!({"status": "ignored"}), "status"),
        (json!({"limit": 0}), "limit"),
        (json!({"limit": 101}), "limit"),
    ];
    for (value, mention) in cases {
        let err = list_issues(&ctx, &issues_args(value.clone()))
            .await
            .unwrap_err();
        assert_eq!(err.status_code, Some(400), "{value}");
        assert!(err.message.contains(mention), "{value}: {}", err.message);
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn get_project_encodes_ids_and_expands_target() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/rest/orgs/{ORG}/projects/{PROJECT}")))
        .and(header("authorization", "token snyk-secret"))
        .and(query_param("version", "2024-10-15"))
        .and(query_param("expand", "target"))
        .and(query_param_is_missing("limit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"id": PROJECT, "type": "project", "attributes": {"name": "my-org/api:package.json"}},
            "included": [{"id": "t-1", "type": "target", "attributes": {"display_name": "my-org/api"}}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("SNYK_TOKEN", "snyk-secret")]);
    let client = build_client().unwrap();
    let vendor = SnykVendor::with_base_url(server.uri());
    let ctx = SnykContext::new(&client, &cfg, &vendor);
    let args = project_args(json!({
        "orgId": format!(" {ORG} "),
        "projectId": PROJECT,
        "expand": "target",
        "jq": "included[0].attributes.display_name",
        "outputFormat": "json"
    }));
    let response = get_project(&ctx, &args).await.unwrap();
    assert!(response.content.contains("my-org/api"));

    let err = get_project(
        &ctx,
        &project_args(json!({"orgId": ORG, "projectId": PROJECT, "expand": "owner"})),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(400));
    assert!(err.message.contains("expand"));
}

#[tokio::test]
async fn org_resolution_and_identifier_validation() {
    let server = MockServer::start().await;
    let client = build_client().unwrap();
    let vendor = SnykVendor::with_base_url(server.uri());

    // No orgId argument and no SNYK_ORG_ID → the documented 400.
    let cfg = config(&[("SNYK_TOKEN", "snyk-secret")]);
    let ctx = SnykContext::new(&client, &cfg, &vendor);
    let err = list_projects(&ctx, &projects_args(json!({})))
        .await
        .unwrap_err();
    assert_eq!(err.status_code, Some(400));
    assert_eq!(
        err.message,
        "orgId is required: pass `orgId` or set SNYK_ORG_ID"
    );
    let err = get_project(&ctx, &project_args(json!({"projectId": PROJECT})))
        .await
        .unwrap_err();
    assert_eq!(err.status_code, Some(400));

    // Structural characters in path identifiers are rejected, not spliced.
    for bad in ["a/b", "..", "", "  ", "x?y", "x#y", "x%2Fy", "a b"] {
        let err = list_projects(&ctx, &projects_args(json!({"orgId": bad})))
            .await
            .unwrap_err();
        assert_eq!(err.status_code, Some(400), "orgId={bad:?}");
        let err = get_project(&ctx, &project_args(json!({"orgId": ORG, "projectId": bad})))
            .await
            .unwrap_err();
        assert_eq!(err.status_code, Some(400), "projectId={bad:?}");
        assert!(err.message.contains("projectId"), "{}", err.message);
    }
    // Query identifiers get the same treatment.
    let err = list_orgs(&ctx, &orgs_args(json!({"groupId": "../x"})))
        .await
        .unwrap_err();
    assert_eq!(err.status_code, Some(400));
    let err = list_projects(
        &ctx,
        &projects_args(json!({"orgId": ORG, "targetId": "a/b"})),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(400));
    let err = list_issues(
        &ctx,
        &issues_args(json!({"orgId": ORG, "scanItemId": "a/b", "scanItemType": "project"})),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code, Some(400));

    // A configured SNYK_ORG_ID that is malformed is rejected the same way.
    let cfg = config(&[
        ("SNYK_TOKEN", "snyk-secret"),
        ("SNYK_ORG_ID", "org/../admin"),
    ]);
    let ctx = SnykContext::new(&client, &cfg, &vendor);
    let err = list_issues(&ctx, &issues_args(json!({})))
        .await
        .unwrap_err();
    assert_eq!(err.status_code, Some(400));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn cursor_is_extracted_from_a_pasted_links_next() {
    // Pure transform, positive and negative paths.
    assert_eq!(
        resolve_cursor(" v1.eyJpZCI6MX0= ").unwrap(),
        "v1.eyJpZCI6MX0="
    );
    assert_eq!(
        resolve_cursor(&format!(
            "/orgs/{ORG}/issues?version=2024-10-15&starting_after=v1.eyJpZCI6Mn0%3D&limit=20"
        ))
        .unwrap(),
        "v1.eyJpZCI6Mn0="
    );
    assert_eq!(
        resolve_cursor("https://api.snyk.io/rest/orgs?version=2024-10-15&starting_after=abc#frag")
            .unwrap(),
        "abc"
    );
    assert_eq!(resolve_cursor("starting_after=xyz").unwrap(), "xyz");
    for bad in [
        "",
        "   ",
        "/orgs?version=2024-10-15&limit=20",
        "/orgs?starting_after=",
    ] {
        let err = resolve_cursor(bad).unwrap_err();
        assert_eq!(err.status_code, Some(400), "{bad:?}");
        assert!(err.message.contains("startingAfter"));
    }

    // And end to end: the pasted link becomes the bare cursor on the wire.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/orgs"))
        .and(query_param("starting_after", "v1.eyJpZCI6Mn0"))
        .and(query_param("limit", "20"))
        .and(query_param("version", "2024-10-15"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("SNYK_TOKEN", "snyk-secret")]);
    let client = build_client().unwrap();
    let vendor = SnykVendor::with_base_url(server.uri());
    let ctx = SnykContext::new(&client, &cfg, &vendor);
    let args = orgs_args(json!({
        "startingAfter": "/orgs?version=2024-10-15&starting_after=v1.eyJpZCI6Mn0&limit=20"
    }));
    list_orgs(&ctx, &args).await.unwrap();
}

#[tokio::test]
async fn upstream_errors_are_classified_with_json_api_details() {
    let server = MockServer::start().await;
    let cfg = config(&[("SNYK_TOKEN", "snyk-secret"), ("SNYK_ORG_ID", ORG)]);
    let client = build_client().unwrap();
    let vendor = SnykVendor::with_base_url(server.uri());
    let ctx = SnykContext::new(&client, &cfg, &vendor);

    // JSON:API envelope: title + detail joined, status preserved.
    for status in [401u16, 403, 404, 429, 500] {
        let project = format!("00000000-0000-0000-0000-0000000{status}");
        Mock::given(method("GET"))
            .and(path(format!("/rest/orgs/{ORG}/projects/{project}")))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "jsonapi": {"version": "1.0"},
                "errors": [{"status": status.to_string(), "title": "Upstream said", "detail": format!("detail for {status}")}]
            })))
            .mount(&server)
            .await;
        let err = get_project(&ctx, &project_args(json!({"projectId": project})))
            .await
            .unwrap_err();
        assert_eq!(err.status_code, Some(status));
        assert!(
            err.message
                .contains(&format!("Upstream said: detail for {status}")),
            "{}",
            err.message
        );
        assert!(err.original.is_some());
        match status {
            401 | 403 => assert_eq!(err.kind, ErrorKind::AuthInvalid),
            _ => assert_eq!(err.kind, ErrorKind::ApiError),
        }
    }
    let err = get_project(
        &ctx,
        &project_args(json!({"projectId": "00000000-0000-0000-0000-0000000429"})),
    )
    .await
    .unwrap_err();
    assert!(err.message.contains("Rate limit"));

    // Legacy `{"message": ...}` envelope and a plain-text body both survive.
    Mock::given(method("GET"))
        .and(path(format!("/rest/orgs/{ORG}/projects/legacy")))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(json!({"message": "project not found"})),
        )
        .mount(&server)
        .await;
    let err = get_project(&ctx, &project_args(json!({"projectId": "legacy"})))
        .await
        .unwrap_err();
    assert_eq!(err.status_code, Some(404));
    assert!(err.message.contains("project not found"));

    Mock::given(method("GET"))
        .and(path(format!("/rest/orgs/{ORG}/projects/text")))
        .respond_with(ResponseTemplate::new(502).set_body_string("bad gateway upstream"))
        .mount(&server)
        .await;
    let err = get_project(&ctx, &project_args(json!({"projectId": "text"})))
        .await
        .unwrap_err();
    assert_eq!(err.status_code, Some(502));
    assert!(err.message.contains("bad gateway upstream"));
    assert!(err.original.is_some());
}

#[tokio::test]
async fn vendor_sections_aliases_and_secret_registration() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("configs.json");
    for alias in ["snyk", "mcp-server-snyk"] {
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({alias: {"environments": {
                "SNYK_TOKEN": "scoped-token",
                "SNYK_API_BASE": "https://api.au.snyk.io/",
                "SNYK_ORG_ID": ORG,
                "SNYK_API_VERSION": "2024-10-15"
            }}}))
            .unwrap(),
        )
        .unwrap();
        let cfg = Config::load_from_sources(Some(&file), None, &HashMap::new());
        let vendor = SnykVendor::new();
        assert_eq!(vendor.token(&cfg).await.unwrap(), "scoped-token");
        assert_eq!(vendor.base_url(&cfg).unwrap(), "https://api.au.snyk.io");
        assert_eq!(vendor.default_org_id(&cfg), Some(ORG));
        assert_eq!(vendor.api_version(&cfg).unwrap(), "2024-10-15");
    }
    assert!(mcp_server_devtools::auth::secrets::lookup("snyk", "SNYK_TOKEN").is_some());
}

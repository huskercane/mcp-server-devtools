use std::collections::HashMap;

use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::sentry::{
    SentryContext, get_event, get_issue, list_projects, list_releases, next_cursor, search_issues,
};
use mcp_server_devtools::error::ErrorKind;
use mcp_server_devtools::tools::args::{
    SentryGetEventArgs, SentryGetIssueArgs, SentryListProjectsArgs, SentryListReleasesArgs,
    SentrySearchIssuesArgs,
};
use mcp_server_devtools::transport::build_client;
use mcp_server_devtools::vendor::{Vendor, sentry::SentryVendor};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
    )
}

fn args<T: serde::de::DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

fn link(next_cursor: &str, results: bool) -> String {
    format!(
        "<https://sentry.io/api/0/organizations/acme/issues/?&cursor=1500000000000:0:1>; rel=\"previous\"; results=\"false\"; cursor=\"1500000000000:0:1\", <https://sentry.io/api/0/organizations/acme/issues/?&cursor={next_cursor}>; rel=\"next\"; results=\"{results}\"; cursor=\"{next_cursor}\""
    )
}

#[tokio::test]
async fn configuration_defaults_and_tool_registration() {
    let vendor = SentryVendor::new();
    assert_eq!(vendor.name(), "sentry");
    for cfg in [
        Config::from_map(HashMap::new()),
        config(&[("SENTRY_TOKEN", "  ")]),
    ] {
        assert_eq!(
            vendor.token(&cfg).await.unwrap_err().kind,
            ErrorKind::AuthMissing
        );
        // No URL is required: sentry.io is the default.
        assert_eq!(vendor.base_url(&cfg).unwrap(), "https://sentry.io");
        assert!(vendor.default_organization(&cfg).is_none());
    }
    let cfg = config(&[
        ("SENTRY_TOKEN", "sntrys_secret"),
        ("SENTRY_URL", " https://sentry.example.com/ "),
        ("SENTRY_ORG", " acme "),
    ]);
    assert_eq!(vendor.token(&cfg).await.unwrap(), "sntrys_secret");
    assert_eq!(vendor.base_url(&cfg).unwrap(), "https://sentry.example.com");
    assert_eq!(vendor.default_organization(&cfg), Some("acme"));
    assert_eq!(
        SentryVendor::with_base_url("http://localhost/")
            .base_url(&cfg)
            .unwrap(),
        "http://localhost"
    );
    // Trailing slashes are significant to Sentry and must survive.
    assert_eq!(
        vendor.normalize_path("api/0/organizations/acme/projects/"),
        "/api/0/organizations/acme/projects/"
    );
    // A cached body has no Link header, so reads are never cached.
    assert!(!vendor.cache_reads("/api/0/organizations/acme/issues/"));
    assert!(!vendor.cache_reads("/api/0/organizations/acme/issues/1/"));
    for tool in [
        "sentry_list_projects",
        "sentry_search_issues",
        "sentry_get_issue",
        "sentry_get_event",
        "sentry_list_releases",
    ] {
        assert_eq!(
            mcp_server_devtools::tools::vendor_for_tool(tool),
            Some("sentry")
        );
    }
}

#[tokio::test]
async fn list_projects_sends_bearer_uses_default_org_and_extracts_next_cursor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/0/organizations/acme/projects/"))
        .and(header("authorization", "Bearer sntrys_secret"))
        .and(header("accept", "application/json"))
        .and(query_param_is_missing("cursor"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{"id":"1","slug":"web","platform":"javascript"}]))
                .insert_header("Link", link("1500000000000:100:0", true).as_str()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("SENTRY_TOKEN", "sntrys_secret"), ("SENTRY_ORG", "acme")]);
    let client = build_client().unwrap();
    let vendor = SentryVendor::with_base_url(server.uri());
    let ctx = SentryContext::new(&client, &cfg, &vendor);
    let response = list_projects(
        &ctx,
        &args::<SentryListProjectsArgs>(json!({"jq":"[*].slug","outputFormat":"json"})),
    )
    .await
    .unwrap();
    let body: Value = serde_json::from_str(&response.content).unwrap();
    assert_eq!(body["data"], json!(["web"]));
    assert_eq!(body["nextCursor"], json!("1500000000000:100:0"));
}

#[tokio::test]
async fn list_projects_passes_cursor_and_reports_last_page_as_null() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/0/organizations/other-org/projects/"))
        .and(query_param("cursor", "1500000000000:100:0"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{"id":"2","slug":"api"}]))
                .insert_header("Link", link("1500000000000:200:0", false).as_str()),
        )
        .expect(1)
        .mount(&server)
        .await;
    // The explicit argument wins over SENTRY_ORG.
    let cfg = config(&[("SENTRY_TOKEN", "sntrys_secret"), ("SENTRY_ORG", "acme")]);
    let client = build_client().unwrap();
    let vendor = SentryVendor::with_base_url(server.uri());
    let ctx = SentryContext::new(&client, &cfg, &vendor);
    let response = list_projects(
        &ctx,
        &args::<SentryListProjectsArgs>(json!({
            "organization":"other-org","cursor":"1500000000000:100:0","outputFormat":"json"
        })),
    )
    .await
    .unwrap();
    let body: Value = serde_json::from_str(&response.content).unwrap();
    assert_eq!(body["data"][0]["slug"], json!("api"));
    assert_eq!(body["nextCursor"], Value::Null);
}

#[tokio::test]
async fn search_issues_defaults_query_and_forwards_filters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/0/organizations/acme/issues/"))
        .and(header("authorization", "Bearer sntrys_secret"))
        .and(query_param("query", "is:unresolved"))
        .and(query_param("limit", "25"))
        .and(query_param_is_missing("project"))
        .and(query_param_is_missing("sort"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"id":"10","title":"boom"}])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/0/organizations/acme/issues/"))
        .and(query_param("query", "is:unresolved level:error"))
        .and(query_param("project", "4507000000000001"))
        .and(query_param("statsPeriod", "24h"))
        .and(query_param("environment", "production"))
        .and(query_param("sort", "freq"))
        .and(query_param("limit", "100"))
        .and(query_param("cursor", "abc:0:0"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{"id":"11","title":"worse"}]))
                .insert_header("Link", link("abc:100:0", true).as_str()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("SENTRY_TOKEN", "sntrys_secret")]);
    let client = build_client().unwrap();
    let vendor = SentryVendor::with_base_url(server.uri());
    let ctx = SentryContext::new(&client, &cfg, &vendor);

    let response = search_issues(
        &ctx,
        &args::<SentrySearchIssuesArgs>(json!({"organization":"acme","outputFormat":"json"})),
    )
    .await
    .unwrap();
    let body: Value = serde_json::from_str(&response.content).unwrap();
    assert_eq!(body["data"][0]["title"], json!("boom"));
    assert_eq!(body["nextCursor"], Value::Null);

    let response = search_issues(
        &ctx,
        &args::<SentrySearchIssuesArgs>(json!({
            "organization":"acme","query":"is:unresolved level:error","project":"4507000000000001",
            "statsPeriod":"24h","environment":"production","sort":"freq","limit":100,
            "cursor":"abc:0:0","jq":"[*].title","outputFormat":"json"
        })),
    )
    .await
    .unwrap();
    let body: Value = serde_json::from_str(&response.content).unwrap();
    assert_eq!(body["data"], json!(["worse"]));
    assert_eq!(body["nextCursor"], json!("abc:100:0"));
}

#[tokio::test]
async fn search_issues_rejects_bad_limit_sort_and_project_before_calling_upstream() {
    let server = MockServer::start().await;
    let cfg = config(&[("SENTRY_TOKEN", "sntrys_secret"), ("SENTRY_ORG", "acme")]);
    let client = build_client().unwrap();
    let vendor = SentryVendor::with_base_url(server.uri());
    let ctx = SentryContext::new(&client, &cfg, &vendor);
    for (bad, needle) in [
        (json!({"limit":0}), "`limit`"),
        (json!({"limit":101}), "`limit`"),
        (json!({"sort":"newest"}), "`sort`"),
        (json!({"project":"my-project"}), "`project`"),
    ] {
        let error = search_issues(&ctx, &args::<SentrySearchIssuesArgs>(bad))
            .await
            .unwrap_err();
        assert_eq!(error.status_code, Some(400));
        assert!(error.message.contains(needle), "{}", error.message);
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn get_issue_and_get_event_build_trailing_slash_paths() {
    let server = MockServer::start().await;
    let cfg = config(&[("SENTRY_TOKEN", "sntrys_secret"), ("SENTRY_ORG", "acme")]);
    let client = build_client().unwrap();
    let vendor = SentryVendor::with_base_url(server.uri());
    let ctx = SentryContext::new(&client, &cfg, &vendor);

    Mock::given(method("GET"))
        .and(path("/api/0/organizations/acme/issues/5432109876/"))
        .and(header("authorization", "Bearer sntrys_secret"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id":"5432109876","title":"boom","count":"7"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let response = get_issue(
        &ctx,
        &args::<SentryGetIssueArgs>(
            json!({"issueId":"5432109876","jq":"title","outputFormat":"json"}),
        ),
    )
    .await
    .unwrap();
    assert_eq!(response.content.trim(), "\"boom\"");

    let hex = "a1b2c3d4e5f60718a9b0c1d2e3f40516";
    for selector in ["latest", "oldest", hex] {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/0/organizations/acme/issues/5432109876/events/{selector}/"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "eventID": selector,
                "entries":[{"type":"exception","data":{"values":[{"type":"TypeError","value":"x is undefined"}]}}]
            })))
            .expect(if selector == "latest" { 2 } else { 1 })
            .mount(&server)
            .await;
    }
    for (event_id, expected) in [
        (None, "latest"),
        (Some("oldest"), "oldest"),
        (Some(hex), hex),
    ] {
        let mut value = json!({"issueId":"5432109876","outputFormat":"json"});
        if let Some(id) = event_id {
            value["eventId"] = json!(id);
        }
        let response = get_event(&ctx, &args::<SentryGetEventArgs>(value))
            .await
            .unwrap();
        let body: Value = serde_json::from_str(&response.content).unwrap();
        assert_eq!(body["eventID"], json!(expected));
    }
    let response = get_event(
        &ctx,
        &args::<SentryGetEventArgs>(json!({
            "issueId":"5432109876",
            "jq":"entries[?type=='exception'].data.values[].value | [0]",
            "outputFormat":"json"
        })),
    )
    .await
    .unwrap();
    assert_eq!(response.content.trim(), "\"x is undefined\"");
}

#[tokio::test]
async fn list_releases_forwards_filters_and_cursor() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/0/organizations/acme/releases/"))
        .and(header("authorization", "Bearer sntrys_secret"))
        .and(query_param("query", "1.4"))
        .and(query_param("project", "42"))
        .and(query_param("sort", "sessions"))
        .and(query_param("cursor", "rel:0:0"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{"version":"1.4.2","newGroups":3}]))
                .insert_header("Link", link("rel:100:0", true).as_str()),
        )
        .expect(1)
        .mount(&server)
        .await;
    let cfg = config(&[("SENTRY_TOKEN", "sntrys_secret")]);
    let client = build_client().unwrap();
    let vendor = SentryVendor::with_base_url(server.uri());
    let ctx = SentryContext::new(&client, &cfg, &vendor);
    let response = list_releases(
        &ctx,
        &args::<SentryListReleasesArgs>(json!({
            "organization":"acme","query":"1.4","project":"42","sort":"sessions",
            "cursor":"rel:0:0","outputFormat":"json"
        })),
    )
    .await
    .unwrap();
    let body: Value = serde_json::from_str(&response.content).unwrap();
    assert_eq!(body["data"][0]["version"], json!("1.4.2"));
    assert_eq!(body["nextCursor"], json!("rel:100:0"));
    assert!(
        list_releases(
            &ctx,
            &args::<SentryListReleasesArgs>(json!({"organization":"acme","project":"web"}))
        )
        .await
        .unwrap_err()
        .message
        .contains("`project`")
    );
}

#[tokio::test]
async fn list_reads_are_not_served_from_cache() {
    // Two identical requests must both reach upstream: the second page's
    // cursor lives in a header the cache would not replay.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/0/organizations/acme/projects/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([]))
                .insert_header("Cache-Control", "max-age=600")
                .insert_header("Link", link("p:100:0", true).as_str()),
        )
        .expect(2)
        .mount(&server)
        .await;
    let cfg = config(&[("SENTRY_TOKEN", "sntrys_secret"), ("SENTRY_ORG", "acme")]);
    let client = build_client().unwrap();
    let vendor = SentryVendor::with_base_url(server.uri());
    let ctx = SentryContext::new(&client, &cfg, &vendor);
    for _ in 0..2 {
        let response = list_projects(
            &ctx,
            &args::<SentryListProjectsArgs>(json!({"outputFormat":"json"})),
        )
        .await
        .unwrap();
        let body: Value = serde_json::from_str(&response.content).unwrap();
        assert_eq!(body["nextCursor"], json!("p:100:0"));
    }
}

#[tokio::test]
async fn identifiers_are_validated_and_missing_org_is_a_clear_400() {
    let server = MockServer::start().await;
    let client = build_client().unwrap();
    let vendor = SentryVendor::with_base_url(server.uri());

    let cfg = config(&[("SENTRY_TOKEN", "sntrys_secret")]);
    let ctx = SentryContext::new(&client, &cfg, &vendor);
    let error = list_projects(&ctx, &SentryListProjectsArgs::default())
        .await
        .unwrap_err();
    assert_eq!(error.status_code, Some(400));
    assert_eq!(
        error.message,
        "organization is required: pass `organization` or set SENTRY_ORG"
    );
    for bad_org in ["a/b", "..", "", "  ", "acme?x=1"] {
        let error = get_issue(
            &ctx,
            &args::<SentryGetIssueArgs>(json!({"organization":bad_org,"issueId":"1"})),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status_code, Some(400), "{bad_org:?}");
        assert!(error.message.contains("organization") || error.message.contains("`organization`"));
    }
    for bad_issue in ["a/b", "..", "", "1%2F2"] {
        for tool in ["issue", "event"] {
            let error = if tool == "issue" {
                get_issue(
                    &ctx,
                    &args::<SentryGetIssueArgs>(json!({"organization":"acme","issueId":bad_issue})),
                )
                .await
                .unwrap_err()
            } else {
                get_event(
                    &ctx,
                    &args::<SentryGetEventArgs>(json!({"organization":"acme","issueId":bad_issue})),
                )
                .await
                .unwrap_err()
            };
            assert_eq!(error.status_code, Some(400), "{tool} {bad_issue:?}");
            assert!(error.message.contains("`issueId`"));
        }
    }
    for bad_event in [
        "newest",
        "a1b2",
        "g1b2c3d4e5f60718a9b0c1d2e3f40516",
        "../latest",
    ] {
        let error = get_event(
            &ctx,
            &args::<SentryGetEventArgs>(
                json!({"organization":"acme","issueId":"1","eventId":bad_event}),
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status_code, Some(400), "{bad_event:?}");
        assert!(error.message.contains("`eventId`"));
    }
    // Missing token surfaces at call time as AuthMissing, after validation.
    let no_token = config(&[("SENTRY_ORG", "acme")]);
    let ctx = SentryContext::new(&client, &no_token, &vendor);
    assert_eq!(
        list_projects(&ctx, &SentryListProjectsArgs::default())
            .await
            .unwrap_err()
            .kind,
        ErrorKind::AuthMissing
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn upstream_errors_preserve_detail_and_status() {
    let server = MockServer::start().await;
    let cfg = config(&[("SENTRY_TOKEN", "sntrys_secret"), ("SENTRY_ORG", "acme")]);
    let client = build_client().unwrap();
    let vendor = SentryVendor::with_base_url(server.uri());
    let ctx = SentryContext::new(&client, &cfg, &vendor);
    for (status, detail) in [
        (401, "Invalid token"),
        (403, "You do not have permission to perform this action."),
        (404, "The requested resource does not exist"),
        (429, "Rate limited"),
        (500, "Internal Error"),
    ] {
        let issue_id = status.to_string();
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/0/organizations/acme/issues/{issue_id}/"
            )))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({"detail": detail})))
            .expect(1)
            .mount(&server)
            .await;
        let error = get_issue(
            &ctx,
            &args::<SentryGetIssueArgs>(json!({"issueId":issue_id})),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status_code, Some(status));
        assert!(error.message.contains(detail), "{}", error.message);
        assert!(error.original.is_some());
        if matches!(status, 401 | 403) {
            assert_eq!(error.kind, ErrorKind::AuthInvalid);
            assert!(error.message.contains("event:read"));
        } else {
            assert_eq!(error.kind, ErrorKind::ApiError);
        }
    }
    // A list endpoint error goes through the direct-fetch path and must
    // classify the same way.
    Mock::given(method("GET"))
        .and(path("/api/0/organizations/acme/releases/"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"detail":"forbidden"})))
        .mount(&server)
        .await;
    let error = list_releases(&ctx, &SentryListReleasesArgs::default())
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::AuthInvalid);
    assert!(error.message.contains("forbidden"));
}

#[test]
fn next_cursor_is_exported_for_reuse() {
    assert_eq!(
        next_cursor(&link("z:100:0", true)).as_deref(),
        Some("z:100:0")
    );
    assert_eq!(next_cursor(&link("z:100:0", false)), None);
    assert_eq!(next_cursor("not a link header"), None);
}

#[tokio::test]
async fn vendor_sections_aliases_and_secret_registration() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("configs.json");
    for alias in ["sentry", "mcp-server-sentry"] {
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({alias: {"environments": {
                "SENTRY_URL": "https://sentry.example.com", "SENTRY_TOKEN": "scoped-token", "SENTRY_ORG": "acme"
            }}}))
            .unwrap(),
        )
        .unwrap();
        let cfg = Config::load_from_sources(Some(&file), None, &HashMap::new());
        let vendor = SentryVendor::new();
        assert_eq!(vendor.token(&cfg).await.unwrap(), "scoped-token");
        assert_eq!(vendor.base_url(&cfg).unwrap(), "https://sentry.example.com");
        assert_eq!(vendor.default_organization(&cfg), Some("acme"));
    }
    assert!(mcp_server_devtools::auth::secrets::lookup("sentry", "SENTRY_TOKEN").is_some());
}

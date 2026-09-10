//! Mend (Platform API 3.0) adapter: configuration, the login-backed JWT
//! lifecycle, request shapes, identifier validation and error classification,
//! all against a wiremock standing in for one Mend instance (login and API
//! share the host).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::mend::{
    MendContext, get_project, list_applications, list_findings, list_projects,
};
use mcp_server_devtools::error::ErrorKind;
use mcp_server_devtools::tools::args::{
    MendGetProjectArgs, MendListApplicationsArgs, MendListFindingsArgs, MendListProjectsArgs,
};
use mcp_server_devtools::transport::{HttpClient, build_client};
use mcp_server_devtools::vendor::{Vendor, mend::MendVendor};
use serde_json::{Value, json};
use wiremock::matchers::{
    body_json, body_partial_json, header, method, path, query_param, query_param_is_missing,
};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ORG: &str = "0f1e2d3c-4b5a-4968-8776-655443322110";
const LOGIN_PATH: &str = "/api/v3.0/login";

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
    )
}

/// Full login inputs; the base is only set when the vendor is not overridden.
fn full_config(base: Option<&str>) -> Config {
    let mut pairs = vec![
        ("MEND_EMAIL", "dev@example.com"),
        ("MEND_USER_KEY", "user-key-secret"),
        ("MEND_ORG_UUID", ORG),
    ];
    if let Some(base) = base {
        pairs.push(("MEND_API_BASE", base));
    }
    config(&pairs)
}

fn login_body(email: &str) -> Value {
    json!({"email": email, "userKey": "user-key-secret", "orgUuid": ORG})
}

fn login_response(jwt: &str, ttl_ms: Option<u64>) -> Value {
    let mut ret = json!({"jwtToken": jwt, "userUuid": "u-1", "orgName": "Acme"});
    if let Some(ttl) = ttl_ms {
        ret["jwtTTL"] = json!(ttl);
    }
    json!({"retVal": ret, "supportToken": "st-login"})
}

/// Matches only when the request carries no `Authorization` header — the
/// login must never send one.
struct NoAuthorization;

impl wiremock::Match for NoAuthorization {
    fn matches(&self, request: &Request) -> bool {
        !request.headers.contains_key("authorization")
    }
}

async fn mount_login(server: &MockServer, jwt: &str, ttl_ms: Option<u64>, expect: u64) {
    Mock::given(method("POST"))
        .and(path(LOGIN_PATH))
        .and(header("content-type", "application/json"))
        .and(body_json(login_body("dev@example.com")))
        .and(NoAuthorization)
        .respond_with(ResponseTemplate::new(200).set_body_json(login_response(jwt, ttl_ms)))
        .expect(expect)
        .mount(server)
        .await;
}

async fn mount_get(server: &MockServer, endpoint: &str, jwt: &str, body: Value, expect: u64) {
    Mock::given(method(if endpoint.ends_with("/summaries") {
        "POST"
    } else {
        "GET"
    }))
    .and(path(endpoint))
    .and(header("authorization", &format!("Bearer {jwt}")))
    .and(header("accept", "application/json"))
    .respond_with(ResponseTemplate::new(200).set_body_json(body))
    .expect(expect)
    .mount(server)
    .await;
}

fn page(items: &Value) -> Value {
    json!({
        "response": items,
        "additionalData": {"paging": {"next": "cursor-2"}, "totalItems": 2},
        "supportToken": "st-page"
    })
}

fn applications_args(value: Value) -> MendListApplicationsArgs {
    serde_json::from_value(value).unwrap()
}

fn projects_args(value: Value) -> MendListProjectsArgs {
    serde_json::from_value(value).unwrap()
}

fn findings_args(value: Value) -> MendListFindingsArgs {
    serde_json::from_value(value).unwrap()
}

fn project_args(value: Value) -> MendGetProjectArgs {
    serde_json::from_value(value).unwrap()
}

#[tokio::test]
async fn required_configuration_base_trimming_and_tool_prefixes() {
    let client: HttpClient = build_client().unwrap();
    let vendor = MendVendor::new();
    assert_eq!(vendor.name(), "mend");

    // Every one of the four inputs is required, and only at call time.
    let full = [
        ("MEND_API_BASE", "https://api-saas.mend.io"),
        ("MEND_EMAIL", "dev@example.com"),
        ("MEND_USER_KEY", "user-key-secret"),
        ("MEND_ORG_UUID", ORG),
    ];
    for missing in 0..full.len() {
        for blank in [None, Some(""), Some("   ")] {
            let pairs: Vec<(&str, &str)> = full
                .iter()
                .enumerate()
                .filter_map(|(i, (k, v))| {
                    if i == missing {
                        blank.map(|b| (*k, b))
                    } else {
                        Some((*k, *v))
                    }
                })
                .collect();
            let cfg = config(&pairs);
            let err = vendor.bearer(&client, &cfg).await.unwrap_err();
            assert_eq!(
                err.kind,
                ErrorKind::AuthMissing,
                "missing {}",
                full[missing].0
            );
            assert!(err.message.contains(full[missing].0), "{}", err.message);
        }
    }
    assert_eq!(
        vendor
            .base_url(&Config::from_map(HashMap::new()))
            .unwrap_err()
            .kind,
        ErrorKind::AuthMissing
    );

    let cfg = config(&[("MEND_API_BASE", " https://api-saas-eu.mend.io/ ")]);
    assert_eq!(
        vendor.base_url(&cfg).unwrap(),
        "https://api-saas-eu.mend.io"
    );
    assert_eq!(
        MendVendor::with_base_url("http://localhost:1/")
            .base_url(&cfg)
            .unwrap(),
        "http://localhost:1"
    );
    assert_eq!(vendor.normalize_path("api/v3.0/x"), "/api/v3.0/x");
    assert_eq!(vendor.normalize_path("/api/v3.0/x"), "/api/v3.0/x");

    for tool in [
        "mend_list_applications",
        "mend_list_projects",
        "mend_get_project",
        "mend_list_findings",
    ] {
        assert_eq!(
            mcp_server_devtools::tools::vendor_for_tool(tool),
            Some("mend")
        );
    }
}

#[tokio::test]
async fn login_happens_once_and_jwt_is_sent_as_bearer_on_api_calls() {
    let server = MockServer::start().await;
    mount_login(&server, "jwt-1", Some(1_800_000), 1).await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v3.0/orgs/{ORG}/applications")))
        .and(header("authorization", "Bearer jwt-1"))
        .and(header("accept", "application/json"))
        .and(query_param("limit", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(&json!([
            {"uuid": "app-1", "name": "Payments"},
            {"uuid": "app-2", "name": "Web"}
        ]))))
        .expect(2)
        .mount(&server)
        .await;

    // The base comes from config here (no override) so the login URL is
    // proven to derive from MEND_API_BASE, trailing slash included.
    let cfg = full_config(Some(&format!("{}/", server.uri())));
    let client = build_client().unwrap();
    let vendor = MendVendor::new();
    let ctx = MendContext::new(&client, &cfg, &vendor);

    let first = list_applications(&ctx, &applications_args(json!({})))
        .await
        .unwrap();
    assert!(first.content.contains("Payments"));
    assert!(first.content.contains("cursor-2"));

    let second = list_applications(
        &ctx,
        &applications_args(json!({"jq": "response[*].name", "outputFormat": "json"})),
    )
    .await
    .unwrap();
    assert!(second.content.contains("Web"));
    assert!(!second.content.contains("app-2"));
    // The JWT never leaks into the rendered output.
    assert!(!first.content.contains("jwt-1"));
}

#[tokio::test]
async fn concurrent_first_calls_collapse_to_one_login() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN_PATH))
        .and(body_json(login_body("dev@example.com")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(login_response("jwt-shared", None))
                .set_delay(Duration::from_millis(250)),
        )
        .expect(1)
        .mount(&server)
        .await;
    mount_get(
        &server,
        &format!("/api/v3.0/orgs/{ORG}/projects/summaries"),
        "jwt-shared",
        json!({"response": {"uuid": "p-1", "name": "gateway"}, "supportToken": "st"}),
        6,
    )
    .await;

    let cfg = full_config(None);
    let client = build_client().unwrap();
    let vendor = Arc::new(MendVendor::with_base_url(server.uri()));

    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..6 {
        let (cfg, client, vendor) = (cfg.clone(), client.clone(), Arc::clone(&vendor));
        tasks.spawn(async move {
            let ctx = MendContext::new(&client, &cfg, &vendor);
            get_project(&ctx, &project_args(json!({"projectUuid": "p-1"})))
                .await
                .unwrap()
                .content
        });
    }
    while let Some(result) = tasks.join_next().await {
        assert!(result.unwrap().contains("gateway"));
    }
}

#[tokio::test]
async fn credential_change_triggers_a_new_login() {
    let server = MockServer::start().await;
    for (email, jwt) in [
        ("dev@example.com", "jwt-dev"),
        ("ops@example.com", "jwt-ops"),
    ] {
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .and(body_partial_json(json!({"email": email})))
            .respond_with(ResponseTemplate::new(200).set_body_json(login_response(jwt, None)))
            .expect(1)
            .mount(&server)
            .await;
        mount_get(
            &server,
            &format!("/api/v3.0/orgs/{ORG}/projects"),
            jwt,
            page(&json!([])),
            1,
        )
        .await;
    }
    let client = build_client().unwrap();
    let vendor = MendVendor::with_base_url(server.uri());
    for email in ["dev@example.com", "ops@example.com"] {
        let cfg = config(&[
            ("MEND_EMAIL", email),
            ("MEND_USER_KEY", "user-key-secret"),
            ("MEND_ORG_UUID", ORG),
        ]);
        let ctx = MendContext::new(&client, &cfg, &vendor);
        list_projects(&ctx, &projects_args(json!({})))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn expired_ttl_triggers_relogin() {
    let server = MockServer::start().await;
    // A 1 ms TTL is floored to the 1 s minimum effective lifetime after skew.
    mount_login(&server, "jwt-short", Some(1), 2).await;
    mount_get(
        &server,
        &format!("/api/v3.0/orgs/{ORG}/projects/summaries"),
        "jwt-short",
        json!({"response": {"uuid": "p-1"}}),
        2,
    )
    .await;
    let cfg = full_config(None);
    let client = build_client().unwrap();
    let vendor = MendVendor::with_base_url(server.uri());
    let ctx = MendContext::new(&client, &cfg, &vendor);
    let args = project_args(json!({"projectUuid": "p-1"}));
    get_project(&ctx, &args).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    get_project(&ctx, &args).await.unwrap();
}

#[tokio::test]
async fn login_failures_are_classified_and_never_cached() {
    let server = MockServer::start().await;
    let client = build_client().unwrap();
    let cfg = full_config(None);
    let vendor = MendVendor::with_base_url(server.uri());
    let ctx = MendContext::new(&client, &cfg, &vendor);
    let args = applications_args(json!({}));

    let rejected = Mock::given(method("POST"))
        .and(path(LOGIN_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "retVal": null, "supportToken": "st-401", "errorMessage": "Invalid user key"
        })))
        .expect(2)
        .mount_as_scoped(&server)
        .await;
    for _ in 0..2 {
        let err = list_applications(&ctx, &args).await.unwrap_err();
        assert_eq!(err.kind, ErrorKind::AuthInvalid);
        assert_eq!(err.status_code, Some(401));
        assert!(!err.message.contains("st-401"));
        for key in ["MEND_EMAIL", "MEND_USER_KEY", "MEND_ORG_UUID"] {
            assert!(err.message.contains(key), "{}", err.message);
        }
        assert!(err.original.is_none());
    }
    drop(rejected);

    Mock::given(method("POST"))
        .and(path(LOGIN_PATH))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
        .expect(1)
        .mount(&server)
        .await;
    let err = list_applications(&ctx, &args).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::ApiError);
    assert_eq!(err.status_code, Some(503));
    assert!(err.message.contains("authentication exchange failed"));
}

#[tokio::test]
async fn login_response_wrapper_variants_and_missing_jwt() {
    for (body, jwt) in [
        (
            json!({"response": {"jwtToken": "jwt-resp", "jwtTTL": 60_000}}),
            "jwt-resp",
        ),
        (json!({"jwtToken": "jwt-top"}), "jwt-top"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LOGIN_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        mount_get(
            &server,
            &format!("/api/v3.0/orgs/{ORG}/projects/summaries"),
            jwt,
            json!({"response": {"uuid": "p-1"}}),
            1,
        )
        .await;
        let client = build_client().unwrap();
        let cfg = full_config(None);
        let vendor = MendVendor::with_base_url(server.uri());
        let ctx = MendContext::new(&client, &cfg, &vendor);
        get_project(&ctx, &project_args(json!({"projectUuid": "p-1"})))
            .await
            .unwrap();
    }

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(LOGIN_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "retVal": {"userUuid": "u-1", "secret": "must-not-leak"}, "supportToken": "st"
        })))
        .mount(&server)
        .await;
    let client = build_client().unwrap();
    let cfg = full_config(None);
    let vendor = MendVendor::with_base_url(server.uri());
    let ctx = MendContext::new(&client, &cfg, &vendor);
    let err = get_project(&ctx, &project_args(json!({"projectUuid": "p-1"})))
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnexpectedError);
    assert!(err.message.contains("jwtToken"));
    // A login body is never attached to an error.
    assert!(err.original.is_none());
    assert!(!err.message.contains("must-not-leak"));
}

#[tokio::test]
async fn list_projects_request_shapes_and_page_bounds() {
    let server = MockServer::start().await;
    mount_login(&server, "jwt-1", None, 1).await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v3.0/orgs/{ORG}/projects")))
        .and(header("authorization", "Bearer jwt-1"))
        .and(query_param("limit", "200"))
        .and(query_param("cursor", "cursor-2"))
        .and(query_param_is_missing("search"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(page(&json!([{"uuid": "p-1", "name": "api gateway"}]))),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v3.0/orgs/{ORG}/projects/summaries")))
        .and(body_json(json!({"applicationUuids":["app-1"]})))
        .and(header("authorization", "Bearer jwt-1"))
        .and(query_param("limit", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(&json!([{"uuid": "p-2"}]))))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let cfg = full_config(None);
    let vendor = MendVendor::with_base_url(server.uri());
    let ctx = MendContext::new(&client, &cfg, &vendor);

    let org_wide = list_projects(
        &ctx,
        &projects_args(json!({"limit": 200, "cursor": " cursor-2 ", "search": "api gateway"})),
    )
    .await
    .unwrap();
    assert!(org_wide.content.contains("p-1"));
    let scoped = list_projects(
        &ctx,
        &projects_args(json!({"applicationUuid": " app-1 ", "limit": 1})),
    )
    .await
    .unwrap();
    assert!(scoped.content.contains("p-2"));

    for limit in [0, 201] {
        let err = list_projects(&ctx, &projects_args(json!({"limit": limit})))
            .await
            .unwrap_err();
        assert_eq!(err.status_code, Some(400));
        assert!(err.message.contains("`limit`"));
    }
}

#[tokio::test]
async fn list_findings_request_shape_and_severity_validation() {
    let server = MockServer::start().await;
    mount_login(&server, "jwt-1", None, 1).await;
    Mock::given(method("GET"))
        .and(path(
            "/api/v3.0/projects/p-1/dependencies/findings/security",
        ))
        .and(header("authorization", "Bearer jwt-1"))
        .and(query_param_is_missing("severity"))
        .and(query_param_is_missing("status"))
        .and(query_param("limit", "25"))
        .and(query_param("cursor", "c-9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(&json!([{
            "vulnerability": {"name": "CVE-2024-0001", "severity": "critical"},
            "component": {"name": "lodash", "version": "4.17.20"}, "status": "ACTIVE"
        }]))))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let cfg = full_config(None);
    let vendor = MendVendor::with_base_url(server.uri());
    let ctx = MendContext::new(&client, &cfg, &vendor);

    let response = list_findings(
        &ctx,
        &findings_args(json!({
            "projectUuid": "p-1", "severity": "Critical, HIGH", "status": "ACTIVE",
            "limit": 25, "cursor": "c-9",
            "jq": "response[*].vulnerability.name", "outputFormat": "json"
        })),
    )
    .await
    .unwrap();
    assert!(response.content.contains("CVE-2024-0001"));
    assert!(!response.content.contains("lodash"));

    for severity in ["blocker", "critical,,high", "high;low"] {
        let err = list_findings(
            &ctx,
            &findings_args(json!({"projectUuid": "p-1", "severity": severity})),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code, Some(400), "{severity}");
        assert!(err.message.contains("`severity`"));
    }
}

#[tokio::test]
async fn identifier_validation_rejects_structure_before_any_request() {
    let server = MockServer::start().await;
    // No mocks: a request reaching the server would fail with a 404, and the
    // login itself must not even happen when the org UUID is malformed.
    let client = build_client().unwrap();
    let cfg = full_config(None);
    let vendor = MendVendor::with_base_url(server.uri());
    let ctx = MendContext::new(&client, &cfg, &vendor);

    for bad in ["a/b", "..", "", "  ", "p-1?x=1", "p%2F1"] {
        let err = get_project(&ctx, &project_args(json!({"projectUuid": bad})))
            .await
            .unwrap_err();
        assert_eq!(err.status_code, Some(400), "projectUuid {bad:?}");
        assert!(err.message.contains("projectUuid"));
        let err = list_findings(&ctx, &findings_args(json!({"projectUuid": bad})))
            .await
            .unwrap_err();
        assert_eq!(err.status_code, Some(400), "projectUuid {bad:?}");
    }
    for bad in ["a/b", "..", "app#1"] {
        let err = list_projects(&ctx, &projects_args(json!({"applicationUuid": bad})))
            .await
            .unwrap_err();
        assert_eq!(err.status_code, Some(400), "applicationUuid {bad:?}");
        assert!(err.message.contains("applicationUuid"));
    }

    let bad_org = config(&[
        ("MEND_EMAIL", "dev@example.com"),
        ("MEND_USER_KEY", "user-key-secret"),
        ("MEND_ORG_UUID", "org/../admin"),
    ]);
    let ctx = MendContext::new(&client, &bad_org, &vendor);
    let err = list_applications(&ctx, &applications_args(json!({})))
        .await
        .unwrap_err();
    assert_eq!(err.status_code, Some(400));
    assert!(err.message.contains("MEND_ORG_UUID"));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn api_errors_are_classified_with_envelope_message_preserved() {
    let server = MockServer::start().await;
    mount_login(&server, "jwt-1", None, 1).await;
    let client = build_client().unwrap();
    let cfg = full_config(None);
    let vendor = MendVendor::with_base_url(server.uri());
    let ctx = MendContext::new(&client, &cfg, &vendor);

    let cases: [(u16, Value, &str); 6] = [
        (
            401,
            json!({"retVal": null, "supportToken": "st-1", "errorMessage": "Token expired"}),
            "Token expired",
        ),
        (
            403,
            json!({"error": "Forbidden", "message": "No access to project"}),
            "No access to project",
        ),
        (
            404,
            json!({"retVal": "Project not found", "supportToken": "st-4"}),
            "Project not found",
        ),
        (
            429,
            json!({"retVal": {"errorMessage": "Too many requests"}, "supportToken": "st-5"}),
            "Too many requests",
        ),
        (
            500,
            json!({"errorMessage": "Internal failure", "supportToken": "st-6"}),
            "Internal failure",
        ),
        (400, json!({"unrelated": true}), "400 Bad Request"),
    ];
    for (status, body, expected) in &cases {
        Mock::given(method("POST"))
            .and(path(format!("/api/v3.0/orgs/{ORG}/projects/summaries")))
            .and(body_json(json!({"projectUuids":[format!("p-{status}")]})))
            .respond_with(ResponseTemplate::new(*status).set_body_json(body.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let err = get_project(
            &ctx,
            &project_args(json!({"projectUuid": format!("p-{status}")})),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code, Some(*status));
        assert!(err.message.contains(expected), "{status}: {}", err.message);
        assert!(err.original.is_some());
        let expected_kind = match status {
            401 | 403 => ErrorKind::AuthInvalid,
            _ => ErrorKind::ApiError,
        };
        assert_eq!(err.kind, expected_kind, "{status}");
        if let Some(token) = body.get("supportToken").and_then(Value::as_str) {
            assert!(err.message.contains(token), "{status}: {}", err.message);
        }
    }
}

#[tokio::test]
async fn vendor_sections_aliases_and_secret_registration() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("configs.json");
    for alias in ["mend", "whitesource", "mcp-server-mend"] {
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({alias: {"environments": {
                "MEND_API_BASE": "https://api-saas.mend.io/",
                "MEND_EMAIL": "dev@example.com",
                "MEND_USER_KEY": "scoped-key",
                "MEND_ORG_UUID": ORG
            }}}))
            .unwrap(),
        )
        .unwrap();
        let cfg = Config::load_from_sources(Some(&file), None, &HashMap::new());
        let vendor = MendVendor::new();
        assert_eq!(vendor.base_url(&cfg).unwrap(), "https://api-saas.mend.io");
        assert_eq!(vendor.org_uuid(&cfg).unwrap(), ORG);
        assert_eq!(
            mcp_server_devtools::auth::vendor_secret(&cfg, "mend", "MEND_USER_KEY")
                .await
                .unwrap()
                .as_deref(),
            Some("scoped-key")
        );
    }
    let registered = mcp_server_devtools::auth::secrets::lookup("mend", "MEND_USER_KEY").unwrap();
    assert_eq!(registered.principal_key(), Some("MEND_EMAIL"));
}

#[tokio::test]
async fn refresh_exchange_is_scoped_cached_and_rotates_without_relogin() {
    let server = MockServer::start().await;
    let client = build_client().unwrap();
    let config = full_config(None);
    let vendor = MendVendor::with_base_url(server.uri());
    Mock::given(method("POST"))
        .and(path(LOGIN_PATH))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"retVal":{"refreshToken":"refresh-one"}})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(mcp_server_devtools::vendor::mend::LOGIN_REFRESH_PATH))
        .and(header("wss-refresh-token", "refresh-one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"retVal":{"jwtToken":"access-one","jwtTTL":1000,"refreshToken":"refresh-two"}}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(mcp_server_devtools::vendor::mend::LOGIN_REFRESH_PATH))
        .and(header("wss-refresh-token", "refresh-two"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"retVal":{"jwtToken":"access-two","jwtTTL":600_000}})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let (first, concurrent) = tokio::join!(
        vendor.bearer(&client, &config),
        vendor.bearer(&client, &config)
    );
    assert_eq!(first.unwrap(), "access-one");
    assert_eq!(concurrent.unwrap(), "access-one");
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(vendor.bearer(&client, &config).await.unwrap(), "access-two");
    let requests = server.received_requests().await.unwrap();
    for request in &requests[1..] {
        assert!(
            request
                .url
                .query_pairs()
                .any(|(key, value)| key == "orgUuid" && value == ORG)
        );
    }
}

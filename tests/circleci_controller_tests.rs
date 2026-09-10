#![allow(clippy::doc_markdown)]

//! Controller-pipeline tests for the `CircleCI` vendor. Exercises the full path
//! a `circleci_*` tool takes: read the static `CIRCLECI_TOKEN` from config →
//! dispatch the request with a `Authorization: Bearer <token>` header through
//! the shared transport → classify the `CircleCI` error envelope.
//!
//! The REST API is stood up on a wiremock instance, so these tests need no
//! network and no global state — the base-URL override is what makes that
//! possible.

use std::collections::HashMap;

use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::circleci::{CircleCiContext, handle_logs, handle_request};
use mcp_server_devtools::error::ErrorKind;
use mcp_server_devtools::format::OutputFormat;
use mcp_server_devtools::transport::{HttpMethod, build_client};
use mcp_server_devtools::vendor::circleci::CircleCiVendor;
use pretty_assertions::assert_eq;
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn creds() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("CIRCLECI_TOKEN".into(), "tok-123".into());
    m
}

fn vendor(server: &MockServer) -> CircleCiVendor {
    CircleCiVendor::with_base_url(server.uri())
}

#[tokio::test]
async fn get_sends_bearer_token_and_filters_response() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/project/gh/acme/web/pipeline"))
        .and(header("authorization", "Bearer tok-123"))
        .and(query_param("branch", "main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [
                {"id": "p1", "state": "created", "number": 42},
                {"id": "p2", "state": "errored", "number": 41}
            ],
            "next_page_token": null
        })))
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let mut values = creds();
    values.insert("MCP_DOWNLOAD_ALLOWED_ORIGINS".into(), server.uri());
    let config = Config::from_map(values);
    let vendor = vendor(&server);
    let ctx = CircleCiContext::new(&client, &config, &vendor);

    let mut qp = mcp_server_devtools::tools::args::QueryParams::new();
    qp.insert("branch".into(), "main".into());

    let resp = handle_request(
        &ctx,
        HttpMethod::Get,
        "/project/gh/acme/web/pipeline",
        Some(&qp),
        None,
        Some("items[*].{id: id, state: state}"),
        OutputFormat::Json,
    )
    .await
    .unwrap();

    assert!(resp.content.contains("p1"));
    assert!(resp.content.contains("created"));
    if let Some(p) = resp.raw_response_path {
        let _ = std::fs::remove_file(p);
    }
}

#[tokio::test]
async fn post_forwards_body_and_returns_created_pipeline() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/project/gh/acme/web/pipeline"))
        .and(header("authorization", "Bearer tok-123"))
        .and(body_json(json!({ "branch": "main" })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "pipe-99",
            "state": "pending",
            "number": 100
        })))
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let mut values = creds();
    values.insert("MCP_DOWNLOAD_ALLOWED_ORIGINS".into(), server.uri());
    let config = Config::from_map(values);
    let vendor = vendor(&server);
    let ctx = CircleCiContext::new(&client, &config, &vendor);

    let resp = handle_request(
        &ctx,
        HttpMethod::Post,
        "/project/gh/acme/web/pipeline",
        None,
        Some(json!({ "branch": "main" })),
        Some("{id: id, state: state}"),
        OutputFormat::Json,
    )
    .await
    .unwrap();

    assert!(resp.content.contains("pipe-99"));
    assert!(resp.content.contains("pending"));
    if let Some(p) = resp.raw_response_path {
        let _ = std::fs::remove_file(p);
    }
}

#[tokio::test]
async fn api_404_surfaces_circleci_error_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/pipeline/does-not-exist"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "message": "Pipeline not found"
        })))
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let mut values = creds();
    values.insert("MCP_DOWNLOAD_ALLOWED_ORIGINS".into(), server.uri());
    let config = Config::from_map(values);
    let vendor = vendor(&server);
    let ctx = CircleCiContext::new(&client, &config, &vendor);

    let err = handle_request(
        &ctx,
        HttpMethod::Get,
        "/pipeline/does-not-exist",
        None,
        None,
        None,
        OutputFormat::Json,
    )
    .await
    .unwrap_err();

    assert_eq!(err.status_code, Some(404));
    assert!(err.message.contains("Resource not found"));
    assert!(err.message.contains("Pipeline not found"));
}

#[tokio::test]
async fn logs_fetches_build_details_and_flattens_action_output() {
    let server = MockServer::start().await;
    let output_url = format!("{}/output/0/0", server.uri());

    Mock::given(method("GET"))
        .and(path("/project/github/acme/web/123"))
        // The token rides in the header, never the URL.
        .and(header("circle-token", "tok-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "steps": [
                {
                    "name": "Run tests",
                    "actions": [
                        {
                            "name": "cargo test",
                            "status": "failed",
                            "type": "test",
                            "output_url": output_url
                        }
                    ]
                }
            ]
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/output/0/0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"message": "running 1 test\n", "time": "2026-07-07T20:31:50Z"},
            {"message": "test redos_flag ... FAILED\n", "time": "2026-07-07T20:31:51Z"}
        ])))
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let mut values = creds();
    values.insert("MCP_DOWNLOAD_ALLOWED_ORIGINS".into(), server.uri());
    let config = Config::from_map(values);
    let vendor = vendor(&server);
    let ctx = CircleCiContext::new(&client, &config, &vendor);

    let resp = handle_logs(
        &ctx,
        &mcp_server_devtools::tools::args::CircleCiLogsArgs {
            project_slug: "gh/acme/web".into(),
            job_number: 123,
            step_number: None,
            failed_only: false,
            condensed: false,
            context_lines: None,
            output_format: Some(mcp_server_devtools::tools::args::OutputFormatArg::Json),
        },
    )
    .await
    .unwrap();

    assert!(resp.content.contains("Run tests"));
    assert!(resp.content.contains("cargo test"));
    assert!(resp.content.contains("running 1 test"));
    assert!(resp.content.contains("test redos_flag ... FAILED"));
    assert!(!resp.content.contains("output_url"));
    let raw_path = resp
        .raw_response_path
        .expect("complete logs should be saved");
    assert!(
        tokio::fs::read_to_string(&raw_path)
            .await
            .unwrap()
            .contains("test redos_flag ... FAILED")
    );
    let _ = tokio::fs::remove_file(raw_path).await;
}

/// The build-details lookup is the logs tool's first upstream request. Under
/// an enforcing call scope it must be decided at the egress chokepoint like
/// any other request — a tool-level allow does not let it out unexamined.
#[tokio::test]
async fn logs_build_details_request_is_subject_to_egress_policy() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/project/github/acme/web/123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "steps": [] })))
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let mut values = creds();
    values.insert("MCP_DOWNLOAD_ALLOWED_ORIGINS".into(), server.uri());
    let config = Config::from_map(values);
    let vendor = vendor(&server);
    let ctx = CircleCiContext::new(&client, &config, &vendor);
    let args = mcp_server_devtools::tools::args::CircleCiLogsArgs {
        project_slug: "gh/acme/web".into(),
        job_number: 123,
        step_number: None,
        failed_only: false,
        condensed: false,
        context_lines: None,
        output_format: Some(mcp_server_devtools::tools::args::OutputFormatArg::Json),
    };

    let err = mcp_server_devtools::policy::CallScope::enter(
        enforcement::deny_everything_scope("circleci", "circleci_logs"),
        handle_logs(&ctx, &args),
    )
    .await
    .unwrap_err();
    assert!(
        err.message.contains("Policy denied"),
        "the build-details request must be refused by policy: {}",
        err.message
    );
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "a denied request must never reach CircleCI"
    );
}

/// A call scope whose policy allows nothing, with a real audit sink and
/// upstream identity — the minimum an egress decision needs.
mod enforcement {
    use std::sync::Arc;
    use std::time::Duration;

    use mcp_server_devtools::policy::{
        CallScope, ClientIdentity, CredentialLabel, Enforcement, EnvironmentClass, FilePolicy,
        Principal, PrincipalAuthority, UpstreamAuthority, UpstreamIdentity,
    };
    use mcp_server_devtools::ports::{InMemoryAuditSink, PolicyDecisionPoint};

    pub fn deny_everything_scope(vendor: &'static str, tool: &str) -> Arc<CallScope> {
        let policy: Arc<dyn PolicyDecisionPoint> =
            FilePolicy::from_bytes(b"version: 1\nrules: []\n").expect("empty policy compiles");
        let slot = mcp_server_devtools::auth::secrets::for_vendor(vendor)
            .next()
            .expect("registered secret");
        let principal = Principal {
            tenant: "acme".to_owned(),
            subject: "alice@acme.example".to_owned(),
            groups: vec!["SRE".to_owned()],
            scopes: vec!["mcp:tools".to_owned()],
            authority: PrincipalAuthority::oidc("https://acme.okta.com/oauth2/default"),
        };
        Arc::new(
            CallScope::new(principal, ClientIdentity::default(), tool, "sha256:test")
                .with_enforcement(Enforcement {
                    policy,
                    audit: Arc::new(InMemoryAuditSink::new()),
                    upstream: UpstreamIdentity {
                        label: CredentialLabel::slot(slot),
                        vendor: vendor.to_owned(),
                        environment: EnvironmentClass::Qa,
                        authority: UpstreamAuthority::Shared,
                        provenance: None,
                    },
                    append_timeout: Duration::from_secs(1),
                }),
        )
    }
}

#[tokio::test]
async fn logs_rejects_non_vcs_project_slug() {
    let client = build_client().unwrap();
    let config = Config::from_map(creds());
    let vendor = CircleCiVendor::with_base_url("http://127.0.0.1:0");
    let ctx = CircleCiContext::new(&client, &config, &vendor);

    let err = handle_logs(
        &ctx,
        &mcp_server_devtools::tools::args::CircleCiLogsArgs {
            project_slug: "circleci/org-id/project-id".into(),
            job_number: 123,
            step_number: None,
            failed_only: false,
            condensed: false,
            context_lines: None,
            output_format: None,
        },
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind, ErrorKind::ApiError);
    assert!(err.message.contains("GitHub/Bitbucket"));
}

#[tokio::test]
async fn logs_failed_only_skips_successful_outputs_and_condenses_errors() {
    let server = MockServer::start().await;
    let success_url = format!("{}/output/success", server.uri());
    let failed_url = format!("{}/output/failed", server.uri());

    Mock::given(method("GET"))
        .and(path("/project/github/acme/web/124"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "steps": [{
                "name": "Run tests",
                "actions": [
                    {"name": "setup", "status": "success", "exit_code": 0, "output_url": success_url},
                    {"name": "tests", "status": "failed", "exit_code": 1, "output_url": failed_url}
                ]
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/output/success"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!([{"message": "SHOULD NOT FETCH\n"}])),
        )
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/output/failed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"message": "ordinary line\n"},
            {"message": "AssertionError: expected true\n"},
            {"message": "nearby context\n"}
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_client().unwrap();
    let mut values = creds();
    values.insert("MCP_DOWNLOAD_ALLOWED_ORIGINS".into(), server.uri());
    let config = Config::from_map(values);
    let vendor = vendor(&server);
    let ctx = CircleCiContext::new(&client, &config, &vendor);
    let resp = handle_logs(
        &ctx,
        &mcp_server_devtools::tools::args::CircleCiLogsArgs {
            project_slug: "gh/acme/web".into(),
            job_number: 124,
            step_number: Some(1),
            failed_only: true,
            condensed: true,
            context_lines: Some(1),
            output_format: Some(mcp_server_devtools::tools::args::OutputFormatArg::Json),
        },
    )
    .await
    .unwrap();

    assert!(resp.content.contains("Condensed error context"));
    assert!(resp.content.contains("AssertionError"));
    assert!(!resp.content.contains("SHOULD NOT FETCH"));
    let raw_path = resp.raw_response_path.unwrap();
    let full = tokio::fs::read_to_string(&raw_path).await.unwrap();
    assert!(full.contains("AssertionError"));
    assert!(!full.contains("SHOULD NOT FETCH"));
    let _ = tokio::fs::remove_file(raw_path).await;
}

#[tokio::test]
async fn missing_token_surfaces_auth_missing_at_call_time() {
    // A deployment without CircleCI configured must not crash; the error
    // appears only when a `circleci_*` tool is actually invoked, and before
    // any network call.
    let client = build_client().unwrap();
    let config = Config::from_map(HashMap::new());
    let vendor = CircleCiVendor::with_base_url("http://127.0.0.1:0");
    let ctx = CircleCiContext::new(&client, &config, &vendor);

    let err = handle_request(
        &ctx,
        HttpMethod::Get,
        "/me",
        None,
        None,
        None,
        OutputFormat::Json,
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind, ErrorKind::AuthMissing);
    assert!(err.message.contains("CIRCLECI_TOKEN"));
}

fn cached_config(ttl: &str) -> Config {
    let mut values = creds();
    // Wiremock can reuse origins across tests; isolate the process-local cache.
    values.insert("CIRCLECI_TOKEN".into(), uuid::Uuid::new_v4().to_string());
    values.insert("HTTP_CACHE_ENABLED".into(), "true".into());
    values.insert("HTTP_CACHE_DEFAULT_TTL_SECONDS".into(), ttl.into());
    Config::from_map(values)
}

async fn read_status(ctx: &CircleCiContext<'_>, path: &str, fresh: bool) -> serde_json::Value {
    let args = serde_json::from_value(json!({
        "path": path, "fresh": fresh, "outputFormat": "json", "jq": "items[*].status"
    }))
    .unwrap();
    let response = mcp_server_devtools::controllers::circleci::handle_fresh_read(ctx, &args)
        .await
        .unwrap();
    if let Some(path) = response.raw_response_path {
        let _ = std::fs::remove_file(path);
    }
    serde_json::from_str(&response.content).unwrap()
}

#[tokio::test]
async fn mutable_status_polling_observes_success_and_failure_despite_long_upstream_ttl() {
    for endpoint in [
        "/workflow/df722a5b-dd0f-437c-a426-efbda3a7a597/job",
        "/workflow/w1",
        "/pipeline/p1/workflow",
        "/pipeline/p1",
        "/project/bb/acme/web/pipeline",
        "/project/bb/acme/web/pipeline/mine",
        "/project/bb/acme/web/job/5185",
    ] {
        for terminal in ["success", "failed"] {
            let server = MockServer::start().await;
            let count = std::sync::atomic::AtomicUsize::new(0);
            Mock::given(method("GET"))
                .and(path(endpoint))
                .respond_with(move |_: &wiremock::Request| {
                    let status = if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                        "running"
                    } else {
                        terminal
                    };
                    ResponseTemplate::new(200)
                        .insert_header("cache-control", "max-age=3600")
                        .set_body_json(json!({"items": [{"status": status}]}))
                })
                .expect(4)
                .mount(&server)
                .await;
            let client = build_client().unwrap();
            let config = cached_config("600");
            let vendor = vendor(&server);
            let ctx = CircleCiContext::new(&client, &config, &vendor);
            for expected in ["running", "running", terminal, terminal] {
                let result = read_status(&ctx, &format!("{endpoint}?page-token=next"), false).await;
                assert_eq!(result["data"], json!([expected]));
                assert_eq!(result["cache"]["hit"], false);
                assert_eq!(result["cache"]["ageMs"], 0);
                chrono::DateTime::parse_from_rfc3339(
                    result["cache"]["fetchedAt"].as_str().unwrap(),
                )
                .unwrap();
            }
            for request in server.received_requests().await.unwrap() {
                assert_eq!(request.url.query(), Some("page-token=next"));
            }
        }
    }
}

#[tokio::test]
async fn cache_hits_age_without_extending_ttl_and_expiry_fetches_again() {
    let server = MockServer::start().await;
    let count = std::sync::atomic::AtomicUsize::new(0);
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(move |_: &wiremock::Request| {
            let status = if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                "running"
            } else {
                "success"
            };
            ResponseTemplate::new(200).set_body_json(json!({"items": [{"status": status}]}))
        })
        .expect(2)
        .mount(&server)
        .await;
    let client = build_client().unwrap();
    let config = cached_config("1");
    let vendor = vendor(&server);
    let ctx = CircleCiContext::new(&client, &config, &vendor);
    let first = read_status(&ctx, "/me", false).await;
    assert_eq!(first["cache"]["hit"], false);
    for _ in 0..3 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let hit = read_status(&ctx, "/me", false).await;
        assert_eq!(hit["data"], json!(["running"]));
        assert_eq!(hit["cache"]["hit"], true);
        assert!(hit["cache"]["ageMs"].as_u64().unwrap() >= 50);
        assert_eq!(hit["cache"]["fetchedAt"], first["cache"]["fetchedAt"]);
    }
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let expired = read_status(&ctx, "/me", false).await;
    assert_eq!(expired["data"], json!(["success"]));
    assert_eq!(expired["cache"]["hit"], false);
    assert_eq!(expired["cache"]["ageMs"], 0);
    assert_ne!(expired["cache"]["fetchedAt"], first["cache"]["fetchedAt"]);
}

#[tokio::test]
async fn fresh_reads_bypass_warm_cache_without_changing_upstream_query() {
    for terminal in ["success", "failed"] {
        let server = MockServer::start().await;
        let count = std::sync::atomic::AtomicUsize::new(0);
        Mock::given(method("GET"))
            .and(path("/me"))
            .respond_with(move |_: &wiremock::Request| {
                let status = if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    "running"
                } else {
                    terminal
                };
                ResponseTemplate::new(200).set_body_json(json!({"items": [{"status": status}]}))
            })
            .expect(4)
            .mount(&server)
            .await;
        let client = build_client().unwrap();
        let config = cached_config("600");
        let vendor = vendor(&server);
        let ctx = CircleCiContext::new(&client, &config, &vendor);
        assert_eq!(
            read_status(&ctx, "/me", false).await["data"],
            json!(["running"])
        );
        assert_eq!(read_status(&ctx, "/me", false).await["cache"]["hit"], true);
        for _ in 0..2 {
            let fresh = read_status(&ctx, "/me", true).await;
            assert_eq!(fresh["data"], json!([terminal]));
            assert_eq!(fresh["cache"]["hit"], false);
            assert_eq!(fresh["cache"]["ageMs"], 0);
        }
        let ordinary = read_status(&ctx, "/me", false).await;
        assert_eq!(ordinary["data"], json!([terminal]));
        assert_eq!(ordinary["cache"]["hit"], false);
        assert_eq!(read_status(&ctx, "/me", false).await["cache"]["hit"], true);
        for request in server.received_requests().await.unwrap() {
            assert_eq!(request.url.query(), None);
            assert!(request.body.is_empty());
        }
    }
}

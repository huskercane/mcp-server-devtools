//! WP B.2: `policy explain` — the decision and, for every rule, why it did
//! or did not fire — through the library and at the binary boundary,
//! against the shipped incident-investigation profile.

use std::path::{Path, PathBuf};
use std::process::Command;

use assert_cmd::cargo::cargo_bin;
use mcp_server_devtools::policy::extractors::for_tool;
use mcp_server_devtools::policy::{
    ActionContext, ClientIdentity, CredentialLabel, EnvironmentClass, FilePolicy, PolicyEffect,
    Principal, PrincipalAuthority, RequestRisk, UpstreamAuthority, UpstreamIdentity,
};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};

const BIN: &str = "mcp-devtools";

fn profile_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/policies/incident-investigation.yaml")
}

#[allow(clippy::needless_pass_by_value)] // `json!` literals at the call sites
fn context(
    subject: &str,
    groups: &[&str],
    tool: &str,
    arguments: Value,
    environment: EnvironmentClass,
) -> ActionContext {
    let vendor = tool.split_once('_').map_or("unknown", |(vendor, _)| vendor);
    let slot = mcp_server_devtools::auth::secrets::for_vendor(vendor)
        .next()
        .expect("registry row");
    ActionContext::assemble(
        Principal {
            tenant: "acme".to_owned(),
            subject: subject.to_owned(),
            groups: groups.iter().map(|group| (*group).to_owned()).collect(),
            scopes: vec!["mcp:tools".to_owned()],
            authority: PrincipalAuthority::Okta,
        },
        ClientIdentity::default(),
        None,
        tool,
        for_tool(tool, arguments.as_object(), RequestRisk::Read),
        None,
        UpstreamIdentity {
            label: CredentialLabel::slot(slot),
            vendor: vendor.to_owned(),
            environment,
            authority: UpstreamAuthority::Shared,
        },
    )
}

#[test]
fn explain_names_the_decisive_rule_and_the_first_key_every_other_rule_fails() {
    let policy = FilePolicy::load(&profile_path()).unwrap();

    let allowed = policy.explain(&context(
        "sre@acme.example",
        &["SRE"],
        "slack_channel_history",
        json!({ "channelId": "C0INCIDENTS" }),
        EnvironmentClass::Qa,
    ));
    assert_eq!(allowed.decision.effect, PolicyEffect::Allow);
    assert!(!allowed.unclassified);
    let by_id = |id: &str| allowed.rules.iter().find(|rule| rule.id == id).unwrap();
    assert!(by_id("sre-read-incident-channels").decisive);
    assert!(by_id("sre-read-incident-channels").matched());
    assert_eq!(by_id("sre-read-qa-datasources").mismatch, Some("vendor"));
    assert_eq!(
        by_id("sre-list-channels").mismatch,
        Some("normalized_action")
    );
    assert_eq!(
        by_id("incident-commanders-search").mismatch,
        Some("subjects")
    );
    assert_eq!(by_id("contractors-never-prod").mismatch, Some("subjects"));

    // Another channel: the allow fails on `resource_id`, nothing matches.
    let denied = policy.explain(&context(
        "sre@acme.example",
        &["SRE"],
        "slack_channel_history",
        json!({ "channelId": "C0SECRET" }),
        EnvironmentClass::Qa,
    ));
    assert_eq!(denied.decision.effect, PolicyEffect::Deny);
    assert!(denied.rules.iter().all(|rule| !rule.decisive));
    assert_eq!(
        denied
            .rules
            .iter()
            .find(|rule| rule.id == "sre-read-incident-channels")
            .unwrap()
            .mismatch,
        Some("resource_id")
    );

    // A deny wins: the contractor's Slack allow matched but is not decisive.
    let overridden = policy.explain(&context(
        "carl@contractor.example",
        &["SRE", "Contractors"],
        "slack_channel_history",
        json!({ "channelId": "C0INCIDENTS" }),
        EnvironmentClass::Prod,
    ));
    assert_eq!(
        overridden.decision.rule_id.as_deref(),
        Some("contractors-never-prod")
    );
    let allow = overridden
        .rules
        .iter()
        .find(|rule| rule.id == "sre-read-incident-channels")
        .unwrap();
    assert!(allow.matched());
    assert!(!allow.decisive);
    assert!(
        overridden
            .rules
            .iter()
            .find(|rule| rule.id == "contractors-never-prod")
            .unwrap()
            .decisive
    );

    // Unclassified: rules are traced for information, none is decisive.
    let unclassified = policy.explain(&context(
        "sre@acme.example",
        &["SRE"],
        "slack_channel_history",
        json!({ "channelId": "c0incidents/../x" }),
        EnvironmentClass::Qa,
    ));
    assert!(unclassified.unclassified);
    assert_eq!(unclassified.decision.effect, PolicyEffect::Deny);
    assert!(unclassified.rules.iter().all(|rule| !rule.decisive));
}

fn run(args: &[&str]) -> (bool, String, String) {
    run_with(args, &[])
}

/// Run the binary under an isolated configuration cascade — an empty home
/// (no `~/.mcp/configs.json`) and an empty working directory (no `.env`)
/// — plus `env`, so what `explain` reads is exactly what the test set.
fn run_with(args: &[&str], env: &[(&str, &str)]) -> (bool, String, String) {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(cargo_bin(BIN))
        .args(args)
        .env_remove("MCP_AUDIT_JOURNAL_DIR")
        .env_remove("MCP_VENDOR_ENVIRONMENT")
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .current_dir(home.path())
        .envs(env.iter().copied())
        .output()
        .expect("spawn binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn explain_at_the_binary_boundary_builds_the_context_the_gateway_would() {
    let profile = profile_path().display().to_string();
    let (ok, stdout, stderr) = run(&[
        "policy",
        "explain",
        &profile,
        "--tool",
        "slack_channel_history",
        "--arguments",
        r#"{"channelId":"C0INCIDENTS","limit":20}"#,
        "--subject",
        "sre@acme.example",
        "--group",
        "SRE",
        "--environment",
        "qa",
    ]);
    assert!(ok, "{stderr}");
    assert!(
        stdout.starts_with("ALLOW: allowed by rule sre-read-incident-channels"),
        "{stdout}"
    );
    assert!(stdout.contains("action=read_channel_history"), "{stdout}");
    assert!(
        stdout
            .contains("environment overridden by --environment (configuration says unclassified)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("✓ sre-read-incident-channels (allow) — decisive"),
        "{stdout}"
    );
    assert!(
        stdout.contains("✗ sre-read-qa-datasources (allow) — fails on `vendor`"),
        "{stdout}"
    );

    // The environment comes from configuration: the same call "in prod" is denied.
    let (ok, stdout, _) = run(&[
        "policy",
        "explain",
        &profile,
        "--tool",
        "grafana_query_logs",
        "--arguments",
        r#"{"datasourceUid":"loki-qa","query":"{}"}"#,
        "--group",
        "SRE",
        "--environment",
        "prod",
    ]);
    assert!(ok);
    assert!(
        stdout.starts_with("DENY: no rule allows this call; default deny"),
        "{stdout}"
    );
    assert!(
        stdout.contains("✗ sre-read-qa-datasources (allow) — fails on `environment`"),
        "{stdout}"
    );

    // A tool with no extractor takes the server-declared risk, as call_tool does.
    let (ok, stdout, _) = run(&[
        "policy",
        "explain",
        &profile,
        "--json",
        "--tool",
        "zoom_post",
        "--arguments",
        r#"{"path":"/users/me/meetings","body":{}}"#,
        "--group",
        "SRE",
    ]);
    assert!(ok);
    let report: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(report["action"]["request_risk"], "write");
    assert_eq!(report["action"]["resource_type"], "unknown");
    assert_eq!(report["explanation"]["unclassified"], true);
    assert_eq!(report["explanation"]["decision"]["effect"], "deny");
    assert!(
        report["policy_version"]
            .as_str()
            .unwrap()
            .starts_with("v1+sha256:")
    );

    let (ok, _, stderr) = run(&["policy", "explain", &profile, "--tool", "no_such_tool"]);
    assert!(!ok);
    assert!(stderr.contains("unknown tool"), "{stderr}");
    let (ok, _, stderr) = run(&[
        "policy",
        "explain",
        &profile,
        "--tool",
        "slack_get",
        "--arguments",
        "[]",
    ]);
    assert!(!ok);
    assert!(stderr.contains("JSON object"), "{stderr}");
}

/// A real gateway — the shipped profile, a Grafana mock, a static SRE
/// principal — serving over the HTTP router; returns its base URL.
async fn spawn_gateway(
    sink: &std::sync::Arc<mcp_server_devtools::ports::InMemoryAuditSink>,
    grafana_url: String,
) -> String {
    use mcp_server_devtools::bootstrap::{ServerBuilder, Vendors};
    use mcp_server_devtools::config::Config;
    use mcp_server_devtools::ports::{AuditSink, StaticValidator};
    use mcp_server_devtools::server::auth::{InboundAuth, InboundAuthSettings};
    use mcp_server_devtools::server::http::build_app_with_server_and_auth;
    use mcp_server_devtools::vendor::grafana::GrafanaVendor;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    let server = ServerBuilder::new()
        .config(Config::from_map(HashMap::from([
            ("GRAFANA_TOKEN".to_owned(), "glsa".to_owned()),
            ("MCP_VENDOR_ENVIRONMENT".to_owned(), "qa".to_owned()),
        ])))
        .vendors(Vendors {
            grafana: GrafanaVendor::with_base_url(grafana_url),
            ..Vendors::default()
        })
        .audit_sink(Arc::clone(sink) as Arc<dyn AuditSink>)
        .policy(FilePolicy::load(&profile_path()).unwrap())
        .require_inbound_auth(true)
        .build()
        .unwrap();
    let validator = StaticValidator::new().with(
        "sre-token",
        Principal {
            tenant: "acme".to_owned(),
            subject: "sre@acme.example".to_owned(),
            groups: vec!["SRE".to_owned()],
            scopes: vec!["mcp:tools".to_owned()],
            authority: PrincipalAuthority::Okta,
        },
    );
    let auth = InboundAuth::new(
        Arc::new(validator),
        InboundAuthSettings::from_config(
            &Config::from_map(HashMap::from([(
                "MCP_PUBLIC_URL".to_owned(),
                "https://mcp.acme.example".to_owned(),
            )])),
            vec!["https://acme.okta.com/oauth2/default".to_owned()],
        )
        .unwrap(),
    );
    let app = build_app_with_server_and_auth(
        server,
        Arc::new(auth),
        Duration::from_mins(5),
        Duration::from_mins(5),
        CancellationToken::new(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    base
}

/// One `tools/call` through the router, reporting a client identity.
async fn call_tool(base: &str, tool: &str, arguments: &Value) -> reqwest::StatusCode {
    reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", tool)
        .header("authorization", "Bearer sre-token")
        .json(&json!({
            "jsonrpc": "2.0", "id": "req-1", "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": { "name": "explain-parity", "version": "1.2.3" }
                }
            }
        }))
        .send()
        .await
        .unwrap()
        .status()
}

/// `explain` and `call_tool` build the same `ActionContext` for the same
/// call: the CLI's `action` is byte-for-byte the `action` the gateway
/// journals in the intent record — same extractor, same upstream identity
/// from the same configuration (environment, credential slot, authority),
/// same principal and client when the operator supplies them. Read from a
/// real router call, not reconstructed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explain_builds_the_context_a_real_call_is_journaled_with() {
    use mcp_server_devtools::ports::InMemoryAuditSink;
    use std::sync::Arc;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let grafana = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": {} })))
        .mount(&grafana)
        .await;
    let sink = Arc::new(InMemoryAuditSink::new());
    let gateway = spawn_gateway(&sink, grafana.uri()).await;
    let arguments = json!({ "datasourceUid": "loki-qa", "query": "{app=\"api\"}", "limit": 10 });
    assert_eq!(
        call_tool(&gateway, "grafana_query_logs", &arguments).await,
        reqwest::StatusCode::OK
    );
    let journaled = sink
        .events()
        .into_iter()
        .find(|event| event["kind"] == "tool_call_intent")
        .expect("the call was journaled");
    assert_eq!(journaled["decision"]["effect"], "allow", "{journaled}");

    // The same call, explained under the same configuration.
    let profile = profile_path().display().to_string();
    let (ok, stdout, stderr) = run_with(
        &[
            "policy",
            "explain",
            &profile,
            "--json",
            "--tool",
            "grafana_query_logs",
            "--arguments",
            &arguments.to_string(),
            "--subject",
            "sre@acme.example",
            "--group",
            "SRE",
            "--tenant",
            "acme",
            "--client-name",
            "explain-parity",
            "--client-version",
            "1.2.3",
        ],
        &[("GRAFANA_TOKEN", "glsa"), ("MCP_VENDOR_ENVIRONMENT", "qa")],
    );
    assert!(ok, "{stderr}");
    let explained: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(explained["action"], journaled["action"]);
    assert_eq!(explained["configured_environment"], "qa");
    assert_eq!(explained["explanation"]["decision"]["effect"], "allow");
    assert_eq!(
        explained["explanation"]["decision"]["rule_id"],
        journaled["decision"]["rule_id"]
    );

    // Without the configuration the gateway ran under, the same command
    // explains a different call — visibly: an unclassified environment
    // and an unconfigured credential slot, and a denial.
    let (ok, stdout, _) = run_with(
        &[
            "policy",
            "explain",
            &profile,
            "--json",
            "--tool",
            "grafana_query_logs",
            "--arguments",
            &arguments.to_string(),
            "--group",
            "SRE",
        ],
        &[],
    );
    assert!(ok);
    let unconfigured: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(unconfigured["action"]["environment"], "unclassified");
    assert_eq!(unconfigured["configured_environment"], "unclassified");
    assert_eq!(unconfigured["explanation"]["decision"]["effect"], "deny");
}

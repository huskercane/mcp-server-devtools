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
    let output = Command::new(cargo_bin(BIN))
        .args(args)
        .env_remove("MCP_AUDIT_JOURNAL_DIR")
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

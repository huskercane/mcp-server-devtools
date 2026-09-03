//! WP A.7 / A.10: the golden decision table `(principal, call) → decision`,
//! hot reload, and the `policy check` command.
//!
//! Each golden row is built through the same path production uses —
//! `extractors::for_tool` on the tool's JSON arguments, assembled with the
//! principal and a configured environment — so the table locks the whole
//! chain from arguments to decision, not just the matcher.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;
use mcp_server_devtools::config::VENDOR_GRAFANA;
use mcp_server_devtools::policy::extractors::for_tool;
use mcp_server_devtools::policy::{
    ActionContext, ClientIdentity, CredentialLabel, EnvironmentClass, FilePolicy, PolicyEffect,
    Principal, PrincipalAuthority, RequestRisk, UpstreamAuthority, UpstreamIdentity,
};
use mcp_server_devtools::ports::PolicyDecisionPoint;
use serde::Deserialize;

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

#[derive(Deserialize)]
struct Table {
    policy: String,
    rows: Vec<Row>,
}

#[derive(Deserialize)]
struct Row {
    case: String,
    principal: RowPrincipal,
    call: RowCall,
    expect: RowExpect,
}

#[derive(Deserialize)]
struct RowPrincipal {
    subject: String,
    groups: Vec<String>,
}

#[derive(Deserialize)]
struct RowCall {
    tool: String,
    arguments: serde_json::Map<String, serde_json::Value>,
    environment: String,
}

#[derive(Deserialize)]
struct RowExpect {
    effect: String,
    rule_id: Option<String>,
    #[serde(default)]
    reason_contains: Option<String>,
}

fn upstream_for(tool: &str, environment: &str) -> UpstreamIdentity {
    let vendor = tool.split_once('_').map_or("unknown", |(vendor, _)| vendor);
    let slot = mcp_server_devtools::auth::secrets::for_vendor(vendor)
        .next()
        .or_else(|| mcp_server_devtools::auth::secrets::for_vendor(VENDOR_GRAFANA).next())
        .expect("a registry row to label the slot");
    UpstreamIdentity {
        label: CredentialLabel::slot(slot),
        vendor: vendor.to_owned(),
        environment: EnvironmentClass::parse(environment).expect("fixture environment"),
        authority: UpstreamAuthority::Shared,
    }
}

fn context_for(row: &Row) -> ActionContext {
    let principal = Principal {
        tenant: "acme".to_owned(),
        subject: row.principal.subject.clone(),
        groups: row.principal.groups.clone(),
        scopes: vec!["mcp:tools".to_owned()],
        authority: PrincipalAuthority::Okta,
    };
    // Tools with no extractor take the server-declared risk; the fixture
    // rows that hit that path are writes, and it does not change their
    // (unclassified) outcome either way.
    let declared_risk = if row.call.tool.starts_with("slack_post") {
        RequestRisk::Write
    } else {
        RequestRisk::Read
    };
    let details = for_tool(&row.call.tool, Some(&row.call.arguments), declared_risk);
    ActionContext::assemble(
        principal,
        ClientIdentity::default(),
        None,
        row.call.tool.clone(),
        details,
        None,
        upstream_for(&row.call.tool, &row.call.environment),
    )
}

#[test]
fn golden_decision_table() {
    let table: Table = serde_json::from_str(
        &std::fs::read_to_string(repo_path("tests/golden/policy_decisions.json")).unwrap(),
    )
    .unwrap();
    let policy = FilePolicy::load(&repo_path(&table.policy)).expect("fixture policy compiles");
    let version = policy.version().expect("file policies are versioned");
    assert!(version.starts_with("v1+sha256:"), "{version}");

    let mut failures = Vec::new();
    for row in &table.rows {
        let decision = policy.evaluate(&context_for(row));
        let effect = match decision.effect {
            PolicyEffect::Allow => "allow",
            PolicyEffect::Deny => "deny",
        };
        let mut problems = Vec::new();
        if effect != row.expect.effect {
            problems.push(format!("effect {effect} != {}", row.expect.effect));
        }
        if decision.rule_id != row.expect.rule_id {
            problems.push(format!(
                "rule {:?} != {:?}",
                decision.rule_id, row.expect.rule_id
            ));
        }
        if let Some(needle) = &row.expect.reason_contains
            && !decision.reason.contains(needle)
        {
            problems.push(format!("reason {:?} lacks {needle:?}", decision.reason));
        }
        // Every decision names the policy that produced it.
        if decision.policy_version.as_deref() != Some(version.as_str()) {
            problems.push("policy_version missing".to_owned());
        }
        if !problems.is_empty() {
            failures.push(format!("{}: {}", row.case, problems.join("; ")));
        }
    }
    assert!(
        failures.is_empty(),
        "golden decision table mismatches:\n  {}",
        failures.join("\n  ")
    );
    assert!(
        table.rows.len() >= 20,
        "the table should stay comprehensive"
    );
}

#[tokio::test]
async fn a_changed_document_is_picked_up_and_a_broken_one_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    let allow_sre = "version: 1\nrules:\n  - id: sre\n    effect: allow\n    subjects: {groups: [SRE]}\n    match: {vendor: grafana}\n";
    std::fs::write(&path, allow_sre).unwrap();
    let policy = FilePolicy::load(&path).unwrap();
    policy.spawn_watcher(None);
    let first_version = policy.version().unwrap();

    let sre = |policy: &FilePolicy| {
        let row = Row {
            case: String::new(),
            principal: RowPrincipal {
                subject: "sre@acme.example".to_owned(),
                groups: vec!["SRE".to_owned()],
            },
            call: RowCall {
                tool: "grafana_list_datasources".to_owned(),
                arguments: serde_json::Map::new(),
                environment: "qa".to_owned(),
            },
            expect: RowExpect {
                effect: String::new(),
                rule_id: None,
                reason_contains: None,
            },
        };
        policy.evaluate(&context_for(&row))
    };
    assert_eq!(sre(&policy).effect, PolicyEffect::Allow);

    // A document that does not compile must not replace the good one.
    std::fs::write(
        &path,
        "version: 1\nrules:\n  - id: r\n    effect: allow\n    subjects: {}\n",
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        policy.version().unwrap(),
        first_version,
        "broken document must be ignored"
    );
    assert_eq!(sre(&policy).effect, PolicyEffect::Allow);

    // A good change is picked up without a restart.
    std::fs::write(&path, "version: 2\nrules: []\n").unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while policy.version().unwrap() == first_version {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("watcher picked up the new document");
    assert!(policy.version().unwrap().starts_with("v2+"));
    assert_eq!(sre(&policy).effect, PolicyEffect::Deny);
}

/// A policy file that vanishes is not an emergency deny: the last good
/// document stays in force (the same posture as a gateway whose control
/// plane is down). The state must be visible, though — on the policy and on
/// the health banner — and must clear when the file is back.
#[tokio::test]
async fn a_vanished_policy_file_keeps_the_last_policy_and_reports_degraded_health() {
    use mcp_server_devtools::bootstrap::ServerBuilder;
    use mcp_server_devtools::config::Config;
    use mcp_server_devtools::server::http::build_app_with_server;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    let document = "version: 7\nrules:\n  - id: sre\n    effect: allow\n    subjects: {groups: [SRE]}\n    match: {vendor: grafana}\n";
    std::fs::write(&path, document).unwrap();
    let policy = FilePolicy::load(&path).unwrap();
    policy.spawn_watcher(None);
    let version = policy.version().unwrap();
    assert_eq!(policy.degraded(), None);

    let server = ServerBuilder::new()
        .config(Config::from_map(HashMap::new()))
        .policy(Arc::clone(&policy) as Arc<dyn PolicyDecisionPoint>)
        .build()
        .unwrap();
    let app = build_app_with_server(
        server,
        Duration::from_mins(5),
        Duration::from_mins(5),
        tokio_util::sync::CancellationToken::new(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let banner = reqwest::get(format!("{base}/")).await.unwrap();
    assert_eq!(banner.status(), 200);
    assert!(banner.text().await.unwrap().ends_with(" is running"));

    // The file goes away. Decisions continue under the last good document;
    // the policy and the banner both say the reload is failing.
    std::fs::remove_file(&path).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while policy.degraded().is_none() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the watcher reports the missing file");
    assert_eq!(policy.version().unwrap(), version, "last good policy stays");
    assert!(
        policy.degraded().unwrap().contains("cannot read policy"),
        "{:?}",
        policy.degraded()
    );
    let banner = reqwest::get(format!("{base}/")).await.unwrap();
    assert_eq!(banner.status(), 200, "stale policy is a serving state");
    let text = banner.text().await.unwrap();
    assert!(text.contains("policy reload is failing"), "{text}");
    assert!(text.contains("last good policy in force"), "{text}");
    // The banner is unauthenticated: a category, never the reason, which
    // names the policy path on disk.
    assert!(
        !text.contains(path.to_str().unwrap()) && !text.contains("cannot read"),
        "the public banner must not carry the reload error: {text}"
    );

    // The file is back, unchanged: no longer degraded, same version.
    std::fs::write(&path, document).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while policy.degraded().is_some() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the watcher clears the degraded state");
    assert_eq!(policy.version().unwrap(), version);
    let banner = reqwest::get(format!("{base}/")).await.unwrap();
    assert!(banner.text().await.unwrap().ends_with(" is running"));
}

#[test]
fn policy_check_command_reports_compiling_and_broken_documents() {
    let good = Command::new(cargo_bin("mcp-devtools"))
        .args(["policy", "check"])
        .arg(repo_path("tests/fixtures/policy/phase-a.yaml"))
        .env_remove("MCP_AUDIT_JOURNAL_DIR")
        .output()
        .unwrap();
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    let stdout = String::from_utf8_lossy(&good.stdout);
    assert!(stdout.starts_with("OK:"), "{stdout}");
    assert!(stdout.contains("7 rules"), "{stdout}");

    let json = Command::new(cargo_bin("mcp-devtools"))
        .args(["policy", "check", "--json"])
        .arg(repo_path("tests/fixtures/policy/phase-a.yaml"))
        .output()
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["rules"], 7);

    let dir = tempfile::tempdir().unwrap();
    let broken = dir.path().join("broken.yaml");
    std::fs::write(
        &broken,
        "version: 1\nrules:\n  - id: r\n    effect: allow\n    subjects: {everyone: true}\n    match: {resource_typ: issue}\n",
    )
    .unwrap();
    let bad = Command::new(cargo_bin("mcp-devtools"))
        .args(["policy", "check"])
        .arg(&broken)
        .output()
        .unwrap();
    assert!(!bad.status.success());
    let stderr = String::from_utf8_lossy(&bad.stderr);
    assert!(stderr.contains("resource_typ"), "{stderr}");

    let missing = Command::new(cargo_bin("mcp-devtools"))
        .args(["policy", "check", "/nonexistent/policy.yaml"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
}

/// The registry helper the table uses must keep labelling slots, or the
/// upstream identity in every row is wrong in a way the table cannot see.
#[test]
fn fixture_helpers_are_sound() {
    let _ = HashMap::<String, String>::new();
    let upstream = upstream_for("grafana_query_logs", "qa");
    assert_eq!(upstream.vendor, "grafana");
    assert_eq!(upstream.environment, EnvironmentClass::Qa);
}

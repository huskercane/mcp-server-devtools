//! WPs B.5 and B.7: the activity export, the access review, and the trial
//! metrics — computed from a real journal written by the real adapter, with
//! records shaped by the real extractors, and produced through the CLI.

use std::path::Path;
use std::process::Command;

use assert_cmd::cargo::cargo_bin;
use mcp_server_devtools::audit::export::{
    ActivityFilter, ActivityRow, Format, GroupsFile, access_review, activity, write_access_review,
    write_activity,
};
use mcp_server_devtools::audit::journal::{JOURNAL_FILE_NAME, JournalAuditSink};
use mcp_server_devtools::audit::metrics::metrics;
use mcp_server_devtools::policy::extractors::for_tool;
use mcp_server_devtools::policy::{
    ActionContext, ClientIdentity, CredentialLabel, EnvironmentClass, FilePolicy, PolicyDecision,
    PolicyEffect, Principal, PrincipalAuthority, RequestRisk, UpstreamAuthority, UpstreamIdentity,
};
use mcp_server_devtools::ports::{
    AuditEvent, AuditEventKind, AuditSink, ControlEvent, ControlEventKind, PolicyDecisionPoint,
};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};

const BIN: &str = "mcp-devtools";

const POLICY: &str = "version: 1
rules:
  - id: sre-read-qa-loki
    effect: allow
    subjects: { groups: [SRE] }
    match:
      vendor: grafana
      environment: qa
      normalized_action: query_logs
      resource_type: datasource
      resource_id: [loki-qa]
  - id: sre-list
    effect: allow
    subjects: { groups: [SRE] }
    match: { vendor: grafana, normalized_action: list_datasources }
  - id: contractors-never-prod
    effect: deny
    subjects: { groups: [Contractors] }
    match: { environment: prod }
  - id: auditor-reads
    effect: allow
    subjects: { subjects: [auditor@acme.example] }
    match: { request_risk: read, resource_scope: unscoped }
";

fn principal(subject: &str, groups: &[&str]) -> Principal {
    Principal {
        tenant: "acme".to_owned(),
        subject: subject.to_owned(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
        scopes: vec!["mcp:tools".to_owned()],
        authority: PrincipalAuthority::Okta,
    }
}

fn upstream(environment: EnvironmentClass) -> UpstreamIdentity {
    let slot = mcp_server_devtools::auth::secrets::for_vendor("grafana")
        .next()
        .unwrap();
    UpstreamIdentity {
        label: CredentialLabel::slot(slot),
        vendor: "grafana".to_owned(),
        environment,
        authority: UpstreamAuthority::Shared,
        provenance: None,
    }
}

/// An intent record the way `call_tool` builds one, decided by `policy`.
#[allow(clippy::needless_pass_by_value)] // `json!` literals at the call sites
fn intent(
    policy: &FilePolicy,
    timestamp: &str,
    request_id: &str,
    who: Principal,
    tool: &str,
    arguments: Value,
    environment: EnvironmentClass,
) -> (AuditEvent, PolicyDecision) {
    let details = for_tool(tool, arguments.as_object(), RequestRisk::Read);
    let action = ActionContext::assemble(
        who.clone(),
        ClientIdentity::default(),
        None,
        tool,
        details,
        None,
        upstream(environment),
    );
    let decision = policy.evaluate(&action);
    (
        AuditEvent {
            timestamp: timestamp.to_owned(),
            kind: AuditEventKind::ToolCallIntent,
            request_id: request_id.to_owned(),
            tool_name: tool.to_owned(),
            vendor: "grafana".to_owned(),
            principal: who,
            client: ClientIdentity::default(),
            decision: decision.clone(),
            upstream_identity: upstream(environment),
            action: Some(action),
            outcome: None,
            duration_ms: None,
            egress: None,
        },
        decision,
    )
}

fn outcome(intent: &AuditEvent, timestamp: &str, outcome: &str, duration_ms: u128) -> AuditEvent {
    AuditEvent {
        timestamp: timestamp.to_owned(),
        kind: AuditEventKind::ToolCallOutcome,
        action: None,
        outcome: Some(outcome.to_owned()),
        duration_ms: Some(duration_ms),
        ..intent.clone()
    }
}

/// A day in the life of one gateway: SRE alice reads QA logs, a contractor
/// is denied in prod, alice's group is removed (her next token is denied),
/// then alice is revoked outright.
async fn write_journal(dir: &Path, policy: &FilePolicy) {
    if cfg!(windows) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::File::create(dir.join(JOURNAL_FILE_NAME)).unwrap();
    }
    let sink = JournalAuditSink::open(dir).unwrap();
    let alice = principal("alice@acme.example", &["SRE"]);
    let query = json!({ "datasourceUid": "loki-qa", "query": "{app=\"api\"}" });

    let (first, _) = intent(
        policy,
        "2026-09-03T09:00:00.000Z",
        "r1",
        alice.clone(),
        "grafana_query_logs",
        query.clone(),
        EnvironmentClass::Qa,
    );
    sink.append(&first).await.unwrap();
    sink.append(&outcome(&first, "2026-09-03T09:00:00.250Z", "success", 250))
        .await
        .unwrap();

    let (listed, _) = intent(
        policy,
        "2026-09-03T09:05:00.000Z",
        "r2",
        alice.clone(),
        "grafana_list_datasources",
        json!({}),
        EnvironmentClass::Qa,
    );
    sink.append(&listed).await.unwrap();
    sink.append(&outcome(
        &listed,
        "2026-09-03T09:05:00.100Z",
        "success",
        100,
    ))
    .await
    .unwrap();

    // Same call against prod: denied by default (the QA rule does not match).
    let (prod, decision) = intent(
        policy,
        "2026-09-03T09:10:00.000Z",
        "r3",
        alice.clone(),
        "grafana_query_logs",
        query.clone(),
        EnvironmentClass::Prod,
    );
    assert_eq!(decision.effect, PolicyEffect::Deny);
    sink.append(&prod).await.unwrap();

    let contractor = principal("carl@contractor.example", &["Contractors", "SRE"]);
    let (denied, decision) = intent(
        policy,
        "2026-09-03T09:15:00.000Z",
        "r4",
        contractor,
        "grafana_list_datasources",
        json!({}),
        EnvironmentClass::Prod,
    );
    assert_eq!(decision.rule_id.as_deref(), Some("contractors-never-prod"));
    sink.append(&denied).await.unwrap();

    // Group removed at the identity provider: the next token lacks SRE.
    let alice_without_group = principal("alice@acme.example", &[]);
    let (after_removal, decision) = intent(
        policy,
        "2026-09-03T10:00:00.000Z",
        "r5",
        alice_without_group,
        "grafana_query_logs",
        query,
        EnvironmentClass::Qa,
    );
    assert_eq!(decision.effect, PolicyEffect::Deny);
    sink.append(&after_removal).await.unwrap();

    let mut changed = ControlEvent::now(ControlEventKind::RevocationChanged);
    changed.timestamp = String::from("2026-09-03T10:30:00.000Z");
    changed.version = Some("v1+sha256:0000000000000000".to_owned());
    changed.revoked_subjects = Some(1);
    sink.append_control(&changed).await.unwrap();
    let mut rejected =
        ControlEvent::now(ControlEventKind::RevokedTokenRejected).with_reason("subject");
    rejected.timestamp = String::from("2026-09-03T10:30:01.500Z");
    rejected.principal = Some(alice);
    rejected.version = changed.version.clone();
    sink.append_control(&rejected).await.unwrap();
    // The close seals the journal with a checkpoint.
}

#[tokio::test]
async fn activity_export_flattens_every_record_and_filters() {
    let dir = tempfile::tempdir().unwrap();
    let policy = FilePolicy::from_bytes(POLICY.as_bytes()).unwrap();
    write_journal(dir.path(), &policy).await;

    let export = activity(dir.path(), &ActivityFilter::default()).unwrap();
    assert!(export.stopped.is_none());
    assert_eq!(
        export.records_read, 10,
        "9 records + the closing checkpoint"
    );
    assert_eq!(export.rows.len(), 9, "checkpoints are not activity");
    let first = &export.rows[0];
    assert_eq!(first.kind, "tool_call_intent");
    assert_eq!(first.subject.as_deref(), Some("alice@acme.example"));
    assert_eq!(first.groups.as_deref(), Some("SRE"));
    assert_eq!(first.tool.as_deref(), Some("grafana_query_logs"));
    assert_eq!(first.environment.as_deref(), Some("qa"));
    assert_eq!(first.normalized_action.as_deref(), Some("query_logs"));
    assert_eq!(first.resource_type.as_deref(), Some("datasource"));
    assert_eq!(first.resource_scope.as_deref(), Some("ids:loki-qa"));
    assert_eq!(first.effect.as_deref(), Some("allow"));
    assert_eq!(first.rule_id.as_deref(), Some("sre-read-qa-loki"));
    assert!(
        first
            .policy_version
            .as_deref()
            .unwrap()
            .starts_with("v1+sha256:")
    );
    assert_eq!(first.upstream_authority.as_deref(), Some("shared"));
    let second = &export.rows[1];
    assert_eq!(second.kind, "tool_call_outcome");
    assert_eq!(second.request_id, first.request_id);
    assert_eq!(second.outcome.as_deref(), Some("success"));
    assert_eq!(second.duration_ms, Some(250));
    let listed = &export.rows[2];
    assert_eq!(listed.resource_scope.as_deref(), Some("collection"));
    let revoked = export.rows.last().unwrap();
    assert_eq!(revoked.kind, "revoked_token_rejected");
    assert_eq!(revoked.subject.as_deref(), Some("alice@acme.example"));
    assert_eq!(revoked.reason.as_deref(), Some("subject"));

    let filtered = activity(
        dir.path(),
        &ActivityFilter {
            since: Some("2026-09-03T09:10:00Z".to_owned()),
            until: Some("2026-09-03T10:00:00Z".to_owned()),
            kinds: vec!["tool_call_intent".to_owned()],
            ..ActivityFilter::default()
        },
    )
    .unwrap();
    assert_eq!(
        filtered
            .rows
            .iter()
            .map(|row| row.request_id.clone().unwrap())
            .collect::<Vec<_>>(),
        vec!["r3", "r4"]
    );
    let by_subject = activity(
        dir.path(),
        &ActivityFilter {
            subject: Some("carl@contractor.example".to_owned()),
            ..ActivityFilter::default()
        },
    )
    .unwrap();
    assert_eq!(by_subject.rows.len(), 1);
    assert_eq!(
        by_subject.rows[0].rule_id.as_deref(),
        Some("contractors-never-prod")
    );

    let mut csv = Vec::new();
    write_activity(&export.rows, Format::Csv, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    let mut lines = csv.lines();
    assert!(
        lines
            .next()
            .unwrap()
            .starts_with("seq,timestamp,kind,request_id,subject")
    );
    assert_eq!(lines.count(), 9);
    assert!(
        csv.contains("\"{app=\\\"api\\\"}\"") || !csv.contains("{app="),
        "no raw query text in the export"
    );
    let mut jsonl = Vec::new();
    write_activity(&export.rows, Format::Jsonl, &mut jsonl).unwrap();
    let parsed: Vec<Value> = String::from_utf8(jsonl)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(parsed.len(), 9);
    assert_eq!(parsed[0]["rule_id"], "sre-read-qa-loki");
}

/// Time bounds compare at full precision: a bound a fraction of a second
/// after a record excludes it as `--since` and includes it as `--until`,
/// where a millisecond comparison would have called them equal.
#[test]
fn time_bounds_keep_sub_millisecond_precision() {
    use mcp_server_devtools::audit::export::before;

    assert!(before("2026-09-03T09:10:00Z", "2026-09-03T09:10:00.0005Z"));
    assert!(!before("2026-09-03T09:10:00.0005Z", "2026-09-03T09:10:00Z"));
    assert!(before(
        "2026-09-03T09:10:00.0001Z",
        "2026-09-03T09:10:00.0009Z"
    ));
    assert!(!before("2026-09-03T09:10:00Z", "2026-09-03T09:10:00Z"));
    // Offsets are honoured, and a malformed side falls back to text order.
    assert!(before("2026-09-03T09:10:00+01:00", "2026-09-03T09:10:00Z"));
    assert!(before("garbage", "z"));
}

/// Cells that a spreadsheet would evaluate are neutralised with an
/// apostrophe inside quotes; ordinary cells and RFC 4180 quoting are
/// unchanged.
#[test]
fn csv_cells_cannot_become_spreadsheet_formulas() {
    let rows = [
        "=HYPERLINK(\"http://x\")",
        "+1",
        "-1",
        "@SUM(A1)",
        "plain",
        "a,b",
        "say \"hi\"",
    ]
    .into_iter()
    .map(|subject| ActivityRow {
        seq: 1,
        timestamp: "2026-09-03T00:00:00Z".to_owned(),
        kind: "tool_call_intent".to_owned(),
        subject: Some(subject.to_owned()),
        rule_id: Some("-leading-dash".to_owned()),
        ..ActivityRow::default()
    })
    .collect::<Vec<_>>();
    let mut csv = Vec::new();
    write_activity(&rows, Format::Csv, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    let cells: Vec<&str> = csv
        .lines()
        .skip(1)
        .map(|line| line.split(',').nth(4).unwrap())
        .collect();
    assert_eq!(
        cells,
        vec![
            "\"'=HYPERLINK(\"\"http://x\"\")\"",
            "\"'+1\"",
            "\"'-1\"",
            "\"'@SUM(A1)\"",
            "plain",
            "\"a",
            "\"say \"\"hi\"\"\"",
        ]
    );
    assert!(csv.contains(",\"'-leading-dash\","), "{csv}");
}

#[test]
fn access_review_lists_every_rule_that_applies_to_every_member() {
    let policy = FilePolicy::from_bytes(POLICY.as_bytes()).unwrap();
    let groups = GroupsFile::parse(
        b"SRE: [alice@acme.example, carl@contractor.example]\nContractors: [carl@contractor.example]\nDevelopers: [dave@acme.example]\n",
    )
    .unwrap();
    let rows = access_review(&policy, &groups, "acme");
    let for_subject = |subject: &str| -> Vec<(String, String)> {
        rows.iter()
            .filter(|row| row.subject == subject)
            .map(|row| (row.rule_id.clone(), row.effect.clone()))
            .collect()
    };
    assert_eq!(
        for_subject("alice@acme.example"),
        vec![
            ("sre-read-qa-loki".to_owned(), "allow".to_owned()),
            ("sre-list".to_owned(), "allow".to_owned()),
        ]
    );
    assert_eq!(
        for_subject("carl@contractor.example"),
        vec![
            ("sre-read-qa-loki".to_owned(), "allow".to_owned()),
            ("sre-list".to_owned(), "allow".to_owned()),
            ("contractors-never-prod".to_owned(), "deny".to_owned()),
        ]
    );
    assert!(
        for_subject("dave@acme.example").is_empty(),
        "no rule names Developers"
    );
    // A subject named directly by a rule is reviewed even when no group lists them.
    assert_eq!(
        for_subject("auditor@acme.example"),
        vec![("auditor-reads".to_owned(), "allow".to_owned())]
    );
    let alice_loki = rows
        .iter()
        .find(|row| row.subject == "alice@acme.example" && row.rule_id == "sre-read-qa-loki")
        .unwrap();
    assert_eq!(
        alice_loki.matches["resource_id"],
        vec!["loki-qa".to_owned()]
    );
    assert_eq!(alice_loki.matches["environment"], vec!["qa".to_owned()]);
    assert_eq!(alice_loki.groups, vec!["SRE".to_owned()]);

    let mut csv = Vec::new();
    write_access_review(&rows, Format::Csv, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    assert!(csv.starts_with("subject,groups,rule_id,effect,vendor,environment,"));
    assert!(
        csv.contains("carl@contractor.example,Contractors;SRE,contractors-never-prod,deny,,prod,"),
        "{csv}"
    );
}

#[tokio::test]
async fn metrics_report_the_section_7_figures() {
    let dir = tempfile::tempdir().unwrap();
    let policy = FilePolicy::from_bytes(POLICY.as_bytes()).unwrap();
    write_journal(dir.path(), &policy).await;

    let report = metrics(dir.path(), None).unwrap();
    assert!(report.stopped.is_none());
    assert_eq!(report.records, 10);
    assert_eq!(report.calls, 5);
    assert_eq!(report.allowed_by_rule, 2);
    assert_eq!(report.denied_by_rule, 1);
    assert_eq!(report.denied_by_default, 2);
    assert_eq!(report.explicit_allow_share, Some(0.4));
    assert_eq!(report.denials_by_environment["prod"], 2);
    assert_eq!(report.denials_by_environment["qa"], 1);
    assert_eq!(
        report.cross_environment_attempts, 1,
        "alice, allowed in qa, was denied the same vendor in prod"
    );
    assert_eq!(report.outcomes["success"], 2);
    assert_eq!(report.revocation_changes, 1);
    assert_eq!(report.revoked_token_rejections, 1);
    assert_eq!(report.checkpoints, 1);
    let alice = &report.subjects["alice@acme.example"];
    assert_eq!(alice.calls, 4);
    assert_eq!(alice.allowed, 2);
    assert_eq!(alice.denied, 2);
    assert_eq!(alice.time_to_first_allow_ms, Some(0));
    // Last allowed 09:05, first denial after it 09:10 → 5 min.
    assert_eq!(alice.deny_after_allow_ms, Some(5 * 60 * 1000));
    assert_eq!(alice.revocation_window_ms, Some(1500));
    assert_eq!(alice.revoked_rejections, 1);

    let since = metrics(dir.path(), Some("2026-09-03T10:00:00Z")).unwrap();
    assert_eq!(since.calls, 1);
    assert_eq!(since.records, 4);
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

#[tokio::test]
async fn reports_are_produced_by_the_cli_and_timed() {
    let dir = tempfile::tempdir().unwrap();
    let journal = dir.path().join("journal");
    let policy = FilePolicy::from_bytes(POLICY.as_bytes()).unwrap();
    write_journal(&journal, &policy).await;
    let policy_file = dir.path().join("policy.yaml");
    std::fs::write(&policy_file, POLICY).unwrap();
    let groups_file = dir.path().join("groups.yaml");
    std::fs::write(&groups_file, "SRE: [alice@acme.example]\n").unwrap();
    let journal_arg = journal.display().to_string();

    let (ok, stdout, stderr) = run(&[
        "audit",
        "export",
        "activity",
        &journal_arg,
        "--format",
        "csv",
    ]);
    assert!(ok, "{stderr}");
    assert_eq!(stdout.lines().count(), 10, "header + 9 rows: {stdout}");
    assert!(stderr.contains("elapsed_ms="), "{stderr}");
    assert!(stderr.contains("rows=9 records_read=10"), "{stderr}");

    let out = dir.path().join("review.csv");
    let (ok, _, stderr) = run(&[
        "audit",
        "export",
        "access-review",
        "--policy",
        &policy_file.display().to_string(),
        "--groups",
        &groups_file.display().to_string(),
        "--out",
        &out.display().to_string(),
    ]);
    assert!(ok, "{stderr}");
    let review = std::fs::read_to_string(&out).unwrap();
    assert_eq!(
        review.lines().count(),
        1 + 2 + 1,
        "header, alice's two rules, the auditor's one: {review}"
    );
    assert!(stderr.contains("subjects=2"), "{stderr}");

    let (ok, stdout, stderr) = run(&["audit", "metrics", &journal_arg, "--json"]);
    assert!(ok, "{stderr}");
    let report: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(report["calls"], 5);
    assert_eq!(report["cross_environment_attempts"], 1);
    let (ok, stdout, _) = run(&["audit", "metrics", &journal_arg]);
    assert!(ok);
    assert!(stdout.contains("explicit allow share: 40.0%"), "{stdout}");

    let (_, _, stderr) = run(&[
        "audit",
        "export",
        "activity",
        &dir.path().join("nope").display().to_string(),
    ]);
    assert!(stderr.contains("cannot read"), "{stderr}");
}

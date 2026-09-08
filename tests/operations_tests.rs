//! C.7 restore proof against signed journal/checkpoints and real `SQLite`.
#![cfg(unix)]
use mcp_server_devtools::{
    audit::journal::{CheckpointPolicy, JournalAuditSink},
    policy::signing::SigningKey,
    ports::{
        AuditSink, ControlEvent, ControlEventKind, DirectoryCheckpointSink, RollupStore, UsageRow,
    },
    rollups::SqliteRollupStore,
};
use sha2::{Digest as _, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/operations/state-backup.py")
}
fn run(arguments: &[&std::ffi::OsStr]) -> std::process::Output {
    std::process::Command::new("python3")
        .arg(script())
        .args(arguments)
        .output()
        .unwrap()
}
fn assert_ok(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
async fn seed_state(
    journal: &Path,
    checkpoints: &Path,
    rollups: &Path,
) -> (JournalAuditSink, SqliteRollupStore, String) {
    let (key, _) = SigningKey::generate().unwrap();
    let public = key.verifying_key().to_base64();
    let sink = JournalAuditSink::open_with(
        journal,
        CheckpointPolicy {
            every_records: 1,
            every_seconds: Duration::from_secs(1),
            signing_key: Some(key),
            export: Some(Arc::new(
                DirectoryCheckpointSink::open(checkpoints).unwrap(),
            )),
        },
    )
    .unwrap();
    sink.append_control(&ControlEvent::now(ControlEventKind::AdminMutation))
        .await
        .unwrap();
    let store = SqliteRollupStore::open(rollups).unwrap();
    store
        .append(&[UsageRow {
            timestamp: "2026-09-04T00:00:00.000Z".into(),
            tenant: "t".into(),
            subject: "s".into(),
            vendor: "grafana".into(),
            environment: "qa".into(),
            tool_name: "grafana_query_logs".into(),
            decision: "allow".into(),
            risk: "read".into(),
            outcome: "success".into(),
            duration_ms: 1,
        }])
        .await
        .unwrap();
    (sink, store, public)
}

#[tokio::test]
async fn backup_restore_verifies_evidence_and_rejects_tampering() {
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().join("journal");
    let checkpoints = directory.path().join("checkpoints");
    let rollups = directory.path().join("usage.sqlite");
    let backup = directory.path().join("backup");
    let restored = directory.path().join("restored");
    let (sink, store, public) = seed_state(&journal, &checkpoints, &rollups).await;
    // An active writer must be refused even if the caller claims quiescence.
    let output = run(&[
        "backup".as_ref(),
        "--quiesced".as_ref(),
        "--journal".as_ref(),
        journal.as_os_str(),
        "--checkpoints".as_ref(),
        checkpoints.as_os_str(),
        "--rollups".as_ref(),
        rollups.as_os_str(),
        "--destination".as_ref(),
        backup.as_os_str(),
    ]);
    assert!(!output.status.success());
    assert!(!backup.exists());
    drop(sink);
    drop(store);
    assert_ok(&run(&[
        "backup".as_ref(),
        "--quiesced".as_ref(),
        "--journal".as_ref(),
        journal.as_os_str(),
        "--checkpoints".as_ref(),
        checkpoints.as_os_str(),
        "--rollups".as_ref(),
        rollups.as_os_str(),
        "--destination".as_ref(),
        backup.as_os_str(),
    ]));
    let binary = Path::new(env!("CARGO_BIN_EXE_mcp-devtools"));
    assert_ok(&run(&[
        "restore".as_ref(),
        "--quiesced".as_ref(),
        "--source".as_ref(),
        backup.as_os_str(),
        "--destination".as_ref(),
        restored.as_os_str(),
        "--binary".as_ref(),
        binary.as_os_str(),
        "--public-key".as_ref(),
        public.as_ref(),
    ]));
    assert_ok(
        &std::process::Command::new(binary)
            .args(["audit", "verify"])
            .arg(restored.join("journal"))
            .arg("--checkpoints")
            .arg(restored.join("checkpoints"))
            .args(["--public-key", &public, "--json"])
            .output()
            .unwrap(),
    );
    let recovered = SqliteRollupStore::open(&restored.join("rollups/usage.sqlite")).unwrap();
    assert_eq!(recovered.count().await.unwrap(), 1);
    // A changed manifest cannot bless changed signed evidence.
    let file = backup.join("journal/audit-journal.jsonl");
    let altered = std::fs::read_to_string(&file)
        .unwrap()
        .replace("admin_mutation", "policy_changed");
    std::fs::write(&file, &altered).unwrap();
    let manifest_file = backup.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_file).unwrap()).unwrap();
    manifest["files"]["journal/audit-journal.jsonl"] =
        format!("{:x}", Sha256::digest(altered.as_bytes())).into();
    std::fs::write(manifest_file, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let rejected = directory.path().join("rejected");
    let output = run(&[
        "restore".as_ref(),
        "--quiesced".as_ref(),
        "--source".as_ref(),
        backup.as_os_str(),
        "--destination".as_ref(),
        rejected.as_os_str(),
        "--binary".as_ref(),
        binary.as_os_str(),
        "--public-key".as_ref(),
        public.as_ref(),
    ]);
    assert!(!output.status.success());
    assert!(!rejected.exists());
}

#[test]
fn helm_preserves_deployment_security_and_refuses_unsupported_scaling() {
    use serde::Deserialize as _;
    let Ok(helm) = std::env::var("MCP_TEST_HELM_BIN") else {
        eprintln!("set MCP_TEST_HELM_BIN to exercise the real Helm renderer");
        return;
    };
    let chart = Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/helm/mcp-devtools");
    assert_ok(
        &std::process::Command::new(&helm)
            .arg("lint")
            .arg(&chart)
            .arg("--strict")
            .output()
            .unwrap(),
    );
    let rendered = std::process::Command::new(&helm)
        .args(["template", "proof"])
        .arg(&chart)
        .args([
            "--namespace",
            "operations-test",
            "--set",
            "ingress.enabled=true",
        ])
        .output()
        .unwrap();
    assert!(rendered.status.success());
    let text = String::from_utf8(rendered.stdout).unwrap();
    let documents: Vec<serde_json::Value> = serde_norway::Deserializer::from_str(&text)
        .map(|doc| serde_json::Value::deserialize(doc).unwrap())
        .collect();
    let deployments: Vec<_> = documents
        .iter()
        .filter(|doc| doc["kind"] == "Deployment")
        .collect();
    assert_eq!(deployments.len(), 2);
    for deployment in deployments {
        assert_eq!(deployment["metadata"]["namespace"], "operations-test");
        assert_eq!(deployment["spec"]["strategy"]["type"], "Recreate");
        let pod = &deployment["spec"]["template"]["spec"];
        assert_eq!(pod["securityContext"]["runAsNonRoot"], true);
        assert_eq!(pod["securityContext"]["fsGroup"], 65532);
        assert_eq!(pod["automountServiceAccountToken"], false);
        assert_eq!(
            pod["containers"][0]["securityContext"]["readOnlyRootFilesystem"],
            true
        );
        assert_eq!(
            pod["containers"][0]["securityContext"]["allowPrivilegeEscalation"],
            false
        );
        assert_eq!(
            pod["containers"][0]["securityContext"]["capabilities"]["drop"],
            serde_json::json!(["ALL"])
        );
        assert_eq!(
            pod["containers"][0]["image"],
            format!(
                "ghcr.io/huskercane/mcp-devtools:v{}",
                env!("CARGO_PKG_VERSION")
            )
        );
    }
    let refused = std::process::Command::new(&helm)
        .args(["template", "proof"])
        .arg(&chart)
        .args(["--set", "roles.gateway.replicas=2"])
        .output()
        .unwrap();
    assert!(!refused.status.success());
}

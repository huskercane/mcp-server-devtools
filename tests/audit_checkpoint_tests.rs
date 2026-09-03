//! WP B.6: the hash chain, signed checkpoints, the export sink, and the
//! offline verifier — against the real journal adapter on disk.
//!
//! - Checkpoints land every N records, after T seconds with unsealed
//!   records, and at a clean close; each is signed and exported.
//! - The chain runs unbroken across a reopen.
//! - The verifier catches an altered record, a forged checkpoint, an
//!   unsigned checkpoint when keys are required, the wrong key, and a
//!   truncated tail (through the export).
//! - `audit keygen` and `audit verify` at the binary boundary.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;
use mcp_server_devtools::audit::checkpoint::Checkpoint;
use mcp_server_devtools::audit::journal::{CheckpointPolicy, JOURNAL_FILE_NAME, JournalAuditSink};
use mcp_server_devtools::audit::verify::{Problem, verify};
use mcp_server_devtools::policy::signing::{SigningKey, VerifyingKey};
use mcp_server_devtools::policy::{
    ClientIdentity, CredentialLabel, EnvironmentClass, PolicyDecision, Principal,
    UpstreamAuthority, UpstreamIdentity,
};
use mcp_server_devtools::ports::{
    AuditEvent, AuditEventKind, AuditSink, DirectoryCheckpointSink, InMemoryCheckpointSink,
};
use pretty_assertions::assert_eq;
use serde_json::Value;

const BIN: &str = "mcp-devtools";

fn event() -> AuditEvent {
    let slot = mcp_server_devtools::auth::secrets::for_vendor("jira")
        .next()
        .unwrap();
    AuditEvent {
        timestamp: "2026-09-03T00:00:00.000Z".to_owned(),
        kind: AuditEventKind::ToolCallIntent,
        request_id: "1".to_owned(),
        tool_name: "jira_get".to_owned(),
        vendor: "jira".to_owned(),
        principal: Principal::local(),
        client: ClientIdentity::default(),
        decision: PolicyDecision::local_allow(),
        upstream_identity: UpstreamIdentity {
            label: CredentialLabel::slot(slot),
            vendor: "jira".to_owned(),
            environment: EnvironmentClass::Unclassified,
            authority: UpstreamAuthority::Shared,
        },
        action: None,
        outcome: None,
        duration_ms: None,
        egress: None,
    }
}

fn prepare(dir: &Path) {
    if cfg!(windows) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::File::create(dir.join(JOURNAL_FILE_NAME)).unwrap();
    }
}

fn lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn policy(
    every_records: u64,
    every_seconds: Duration,
    key: Option<&[u8]>,
    export: Option<Arc<dyn mcp_server_devtools::ports::CheckpointSink>>,
) -> CheckpointPolicy {
    CheckpointPolicy {
        every_records,
        every_seconds,
        // Keys are not `Clone`: the journal gets its own instance from the
        // PKCS#8 document, the test keeps the public half.
        signing_key: key.map(|pkcs8| SigningKey::from_pkcs8(pkcs8).unwrap()),
        export,
    }
}

/// A fresh signing key: its PKCS#8 document for the journal, its public
/// half for the verifier.
fn signing_key() -> (Vec<u8>, VerifyingKey) {
    let (key, pkcs8) = SigningKey::generate().unwrap();
    (pkcs8, key.verifying_key())
}

#[tokio::test]
async fn checkpoints_land_every_n_records_signed_and_exported_and_the_close_seals_the_tail() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    prepare(&journal_dir);
    let (key, public) = signing_key();
    let export = Arc::new(InMemoryCheckpointSink::new());
    let sink = JournalAuditSink::open_with(
        &journal_dir,
        policy(
            3,
            Duration::from_mins(10),
            Some(&key),
            Some(Arc::clone(&export) as Arc<dyn mcp_server_devtools::ports::CheckpointSink>),
        ),
    )
    .unwrap();
    let mut seqs = Vec::new();
    for _ in 0..7 {
        seqs.push(sink.append(&event()).await.unwrap());
    }
    // Records 1..3, checkpoint 4, records 5..7, checkpoint 8, record 9.
    assert_eq!(seqs, vec![1, 2, 3, 5, 6, 7, 9]);
    let path = journal_dir.join(JOURNAL_FILE_NAME);
    let on_disk = lines(&path);
    assert_eq!(on_disk.len(), 9);
    assert_eq!(on_disk[3]["kind"], "checkpoint");
    assert_eq!(on_disk[3]["covers_from"], 1);
    assert_eq!(on_disk[3]["covers_to"], 3);
    assert!(on_disk[3]["previous_checkpoint"].is_null());
    assert_eq!(on_disk[3]["key_id"], public.key_id());
    assert!(on_disk[3]["signature"].is_string());
    assert_eq!(on_disk[7]["covers_from"], 5);
    assert_eq!(on_disk[7]["covers_to"], 7);
    assert_eq!(on_disk[7]["previous_checkpoint"], 4);

    let exported = export.exported();
    assert_eq!(exported.len(), 2);
    assert_eq!(exported[0].0, 4);
    assert_eq!(exported[1].0, 8);
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(raw.contains(std::str::from_utf8(&exported[1].1).unwrap()));

    let report = verify(&journal_dir, std::slice::from_ref(&public), None).unwrap();
    assert!(report.ok(), "{:?}", report.problems);
    assert_eq!(report.records, 9);
    assert_eq!(report.checkpoints, 2);
    assert_eq!(report.signed_checkpoints, 2);
    assert_eq!(report.sealed_through, Some(7));
    assert_eq!(report.unsealed_records, 1);

    // A clean close seals record 9.
    drop(sink);
    let report = verify(&journal_dir, &[public], None).unwrap();
    assert!(report.ok(), "{:?}", report.problems);
    assert_eq!(report.checkpoints, 3);
    assert_eq!(report.sealed_through, Some(9));
    assert_eq!(report.unsealed_records, 0);
    assert_eq!(report.last_seq, 10);
    assert_eq!(export.exported().len(), 3);
}

#[tokio::test]
async fn a_checkpoint_is_written_after_the_time_bound_with_unsealed_records() {
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let sink = JournalAuditSink::open_with(
        dir.path(),
        policy(1_000_000, Duration::from_secs(1), None, None),
    )
    .unwrap();
    sink.append(&event()).await.unwrap();
    let path = dir.path().join(JOURNAL_FILE_NAME);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while lines(&path).len() < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "no time-based checkpoint"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let on_disk = lines(&path);
    assert_eq!(on_disk[1]["kind"], "checkpoint");
    assert!(
        on_disk[1]["signature"].is_null(),
        "unsigned policy: no signature"
    );
    // No new records: no further checkpoints, however long we wait.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(lines(&path).len(), 2);
    let report = verify(dir.path(), &[], None).unwrap();
    assert!(report.ok(), "{:?}", report.problems);
    // Keys demanded but the checkpoint is unsigned: a finding.
    let (_, public) = signing_key();
    let report = verify(dir.path(), &[public], None).unwrap();
    assert_eq!(report.problems, vec![Problem::Unsigned { seq: 2 }]);
}

#[tokio::test]
async fn the_chain_runs_unbroken_across_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let (key, public) = signing_key();
    {
        let sink = JournalAuditSink::open_with(
            dir.path(),
            policy(2, Duration::from_mins(10), Some(&key), None),
        )
        .unwrap();
        sink.append(&event()).await.unwrap();
        sink.append(&event()).await.unwrap();
        sink.append(&event()).await.unwrap();
        // seq: 1, 2, [3], 4 — the close seals 4 with [5].
    }
    {
        let sink = JournalAuditSink::open_with(
            dir.path(),
            policy(2, Duration::from_mins(10), Some(&key), None),
        )
        .unwrap();
        assert_eq!(sink.append(&event()).await.unwrap(), 6);
        assert_eq!(sink.append(&event()).await.unwrap(), 7);
        // [8] after two records, then the close has nothing to seal.
    }
    let report = verify(dir.path(), &[public], None).unwrap();
    assert!(report.ok(), "{:?}", report.problems);
    assert_eq!(report.last_seq, 8);
    assert_eq!(report.checkpoints, 3);
    let on_disk = lines(&dir.path().join(JOURNAL_FILE_NAME));
    assert_eq!(on_disk[7]["covers_from"], 6);
    assert_eq!(on_disk[7]["previous_checkpoint"], 5);
}

// Five tamper scenarios against one journal; splitting would hide that
// each is a different class of edit the same verifier catches.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn the_verifier_catches_edits_forgeries_wrong_keys_and_a_truncated_tail() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let export_dir = dir.path().join("exports");
    prepare(&journal_dir);
    let (key, public) = signing_key();
    let export = Arc::new(DirectoryCheckpointSink::open(&export_dir).unwrap());
    {
        let sink = JournalAuditSink::open_with(
            &journal_dir,
            policy(
                2,
                Duration::from_mins(10),
                Some(&key),
                Some(export as Arc<dyn mcp_server_devtools::ports::CheckpointSink>),
            ),
        )
        .unwrap();
        for _ in 0..4 {
            sink.append(&event()).await.unwrap();
        }
        // 1, 2, [3], 4, 5, [6]; nothing unsealed at close.
    }
    let path = journal_dir.join(JOURNAL_FILE_NAME);
    let pristine = std::fs::read_to_string(&path).unwrap();
    let report = verify(
        &journal_dir,
        std::slice::from_ref(&public),
        Some(&export_dir),
    )
    .unwrap();
    assert!(report.ok(), "{:?}", report.problems);
    assert_eq!(report.exports_checked, 2);

    // 1. An altered record before a checkpoint.
    let edited = pristine.replacen(
        "\"tool_name\":\"jira_get\"",
        "\"tool_name\":\"jira_put\"",
        1,
    );
    assert_ne!(edited, pristine);
    std::fs::write(&path, &edited).unwrap();
    let report = verify(
        &journal_dir,
        std::slice::from_ref(&public),
        Some(&export_dir),
    )
    .unwrap();
    assert!(
        report
            .problems
            .iter()
            .any(|problem| matches!(problem, Problem::ChainMismatch { seq: 3, .. })),
        "{:?}",
        report.problems
    );

    // 2. A forged checkpoint: chain recomputed to match the edit, but the
    //    signature cannot be.
    let mut forged_lines: Vec<String> = edited.lines().map(str::to_owned).collect();
    let mut chain = mcp_server_devtools::audit::checkpoint::Chain::genesis();
    for line in &forged_lines[..2] {
        chain.extend(format!("{line}\n").as_bytes());
    }
    let mut forged: Value = serde_json::from_str(&forged_lines[2]).unwrap();
    forged["chain"] = Value::String(chain.label());
    forged_lines[2] = forged.to_string();
    std::fs::write(&path, forged_lines.join("\n") + "\n").unwrap();
    let report = verify(
        &journal_dir,
        std::slice::from_ref(&public),
        Some(&export_dir),
    )
    .unwrap();
    assert!(
        report
            .problems
            .iter()
            .any(|problem| matches!(problem, Problem::BadSignature { seq: 3, .. })),
        "{:?}",
        report.problems
    );
    assert!(
        report
            .problems
            .iter()
            .any(|problem| matches!(problem, Problem::ExportDiffers { seq: 3 })),
        "the export still holds the genuine checkpoint: {:?}",
        report.problems
    );

    // 3. The wrong key names every checkpoint as signed by an unknown key.
    std::fs::write(&path, &pristine).unwrap();
    let (_, other) = signing_key();
    let report = verify(&journal_dir, &[other], None).unwrap();
    assert_eq!(report.problems.len(), 2);
    assert!(report.problems.iter().all(|problem| matches!(
        problem,
        Problem::BadSignature { detail, .. } if detail.contains("unknown key")
    )));

    // 4. A truncated tail: the journal ends after checkpoint 3, but the
    //    export knows about checkpoint 6.
    let truncated: String = pristine
        .lines()
        .take(3)
        .fold(String::new(), |mut text, line| {
            text.push_str(line);
            text.push('\n');
            text
        });
    std::fs::write(&path, truncated).unwrap();
    let report = verify(
        &journal_dir,
        std::slice::from_ref(&public),
        Some(&export_dir),
    )
    .unwrap();
    assert_eq!(
        report.problems,
        vec![Problem::ExportBeyondJournal {
            seq: 6,
            journal_last_seq: 3
        }]
    );
    // Without the export, the truncation is invisible — which is why the
    // export exists.
    let report = verify(&journal_dir, &[public], None).unwrap();
    assert!(report.ok(), "{:?}", report.problems);

    // 5. A torn tail and a gap are reported, not skipped.
    std::fs::write(&path, format!("{pristine}{{\"seq\":7,\"kind\":\"x\"")).unwrap();
    let report = verify(&journal_dir, &[], None).unwrap();
    assert!(
        matches!(&report.problems[..], [Problem::Unreadable { detail }] if detail.contains("torn"))
    );
    let gapped: String = pristine
        .lines()
        .enumerate()
        .filter(|(index, _)| *index != 3)
        .fold(String::new(), |mut text, (_, line)| {
            text.push_str(line);
            text.push('\n');
            text
        });
    std::fs::write(&path, gapped).unwrap();
    let report = verify(&journal_dir, &[], None).unwrap();
    assert!(
        matches!(&report.problems[..], [Problem::Unreadable { detail }] if detail.contains("expected sequence 4"))
    );
}

/// A sink whose copy of one checkpoint fails, the way a full export disk
/// or a broken mount would.
struct FailingExport {
    inner: DirectoryCheckpointSink,
    fails_at: u64,
}

impl mcp_server_devtools::ports::CheckpointSink for FailingExport {
    fn export(&self, seq: u64, line: &[u8]) -> std::io::Result<()> {
        if seq == self.fails_at {
            return Err(std::io::Error::other("export disk full"));
        }
        self.inner.export(seq, line)
    }
}

/// An export that failed is a finding, not a hole: the journal keeps
/// serving (the copy is not the evidence), but the verifier names the
/// checkpoint whose copy is missing — because once it is missing, a
/// truncation back to that checkpoint is exactly what the export could no
/// longer contradict.
#[tokio::test]
async fn a_failed_export_is_reported_as_missing_and_duplicates_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let journal_dir = dir.path().join("journal");
    let export_dir = dir.path().join("exports");
    prepare(&journal_dir);
    let (key, public) = signing_key();
    let export = Arc::new(FailingExport {
        inner: DirectoryCheckpointSink::open(&export_dir).unwrap(),
        fails_at: 6,
    });
    {
        let sink = JournalAuditSink::open_with(
            &journal_dir,
            policy(
                2,
                Duration::from_mins(10),
                Some(&key),
                Some(export as Arc<dyn mcp_server_devtools::ports::CheckpointSink>),
            ),
        )
        .unwrap();
        for _ in 0..4 {
            // The failed copy of checkpoint 6 refuses nothing.
            sink.append(&event()).await.unwrap();
        }
        // 1, 2, [3], 4, 5, [6]: checkpoint 3 exported, checkpoint 6 not.
    }
    let report = verify(
        &journal_dir,
        std::slice::from_ref(&public),
        Some(&export_dir),
    )
    .unwrap();
    assert_eq!(report.exports_checked, 1);
    assert_eq!(report.problems, vec![Problem::ExportMissing { seq: 6 }]);
    // Without the export directory the journal itself is sound.
    assert!(
        verify(&journal_dir, std::slice::from_ref(&public), None)
            .unwrap()
            .ok()
    );

    // The scenario the finding guards against: cut the journal back to
    // checkpoint 3. Nothing in the export contradicts it — which is why
    // the missing export above had to be reported while it still could be.
    let path = journal_dir.join(JOURNAL_FILE_NAME);
    let pristine = std::fs::read_to_string(&path).unwrap();
    let truncated: String = pristine
        .lines()
        .take(3)
        .fold(String::new(), |mut text, line| {
            text.push_str(line);
            text.push('\n');
            text
        });
    std::fs::write(&path, truncated).unwrap();
    let report = verify(
        &journal_dir,
        std::slice::from_ref(&public),
        Some(&export_dir),
    )
    .unwrap();
    assert!(report.ok(), "{:?}", report.problems);

    // Two files naming the same sequence are reported, whatever they hold.
    std::fs::write(&path, &pristine).unwrap();
    std::fs::copy(
        export_dir.join(DirectoryCheckpointSink::file_name(3)),
        export_dir.join("checkpoint-3.jsonl"),
    )
    .unwrap();
    let report = verify(
        &journal_dir,
        std::slice::from_ref(&public),
        Some(&export_dir),
    )
    .unwrap();
    assert_eq!(
        report.problems,
        vec![
            Problem::ExportDuplicate { seq: 3 },
            Problem::ExportMissing { seq: 6 }
        ]
    );
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

fn arg(path: &Path) -> String {
    path.display().to_string()
}

#[tokio::test]
async fn audit_keygen_and_verify_at_the_binary_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let key_file: PathBuf = dir.path().join("audit.key");
    let (ok, stdout, stderr) = run(&["audit", "keygen", "--out", &arg(&key_file), "--json"]);
    assert!(ok, "{stderr}");
    let generated: Value = serde_json::from_str(stdout.trim()).unwrap();
    let public_key = generated["public_key"].as_str().unwrap().to_owned();

    let journal_dir = dir.path().join("journal");
    prepare(&journal_dir);
    {
        let sink = JournalAuditSink::open_with(
            &journal_dir,
            CheckpointPolicy {
                every_records: 2,
                every_seconds: Duration::from_mins(10),
                signing_key: Some(SigningKey::load(&key_file).unwrap()),
                export: None,
            },
        )
        .unwrap();
        for _ in 0..3 {
            sink.append(&event()).await.unwrap();
        }
    }
    let (ok, stdout, stderr) = run(&[
        "audit",
        "verify",
        &arg(&journal_dir),
        "--public-key",
        &public_key,
    ]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("OK: no problems found"), "{stdout}");
    assert!(stdout.contains("checkpoints: 2 (2 signed)"), "{stdout}");

    let (ok, stdout, stderr) = run(&["audit", "verify", &arg(&journal_dir), "--json"]);
    assert!(ok, "{stderr}");
    let report: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(report["records"], 5);
    assert_eq!(
        report["signed_checkpoints"], 0,
        "no key given: signatures not checked"
    );

    // Corrupt one byte: exit 1 and the problem named.
    let path = journal_dir.join(JOURNAL_FILE_NAME);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replacen("jira_get", "jira_del", 1)).unwrap();
    let (ok, stdout, stderr) = run(&[
        "audit",
        "verify",
        &arg(&journal_dir),
        "--public-key",
        &public_key,
    ]);
    assert!(!ok);
    assert!(stdout.contains("chain mismatch"), "{stdout}");
    assert!(stderr.contains("problem(s) found"), "{stderr}");

    // The checkpoint record itself parses as the documented shape.
    let checkpoint: Checkpoint = serde_json::from_str(text.lines().nth(2).unwrap()).unwrap();
    assert_eq!(checkpoint.covers_to, 2);
}

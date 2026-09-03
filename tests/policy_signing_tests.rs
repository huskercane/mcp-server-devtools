//! WP B.3: signed policy bundles and journaled policy changes.
//!
//! - A gateway with a verifying key applies only documents whose detached
//!   signature verifies; anything else is refused at load and ignored on
//!   reload, with the last good policy in force.
//! - Every policy load, change, and rejection is a control record in the
//!   audit journal, and a change is durable **before** it takes effect.
//! - A change whose record cannot be made durable is not applied.
//! - `policy keygen` / `policy sign` / `policy check --public-key` round
//!   trip at the binary boundary.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;
use mcp_server_devtools::policy::signing::{Domain, SigningKey, VerifyingKey, write_detached};
use mcp_server_devtools::policy::{BundleAudit, FilePolicy};
use mcp_server_devtools::ports::audit_sink::{AppendFuture, AuditEvent, ControlEvent};
use mcp_server_devtools::ports::{AuditSink, InMemoryAuditSink, PolicyDecisionPoint};
use pretty_assertions::assert_eq;
use serde_json::Value;

const BIN: &str = "mcp-devtools";
const V1: &[u8] = b"version: 1\nrules: []\n";
const V2: &[u8] = b"version: 2\nrules: []\n";
const V3: &[u8] = b"version: 3\nrules: []\n";

fn write_signed(path: &Path, bytes: &[u8], key: &SigningKey) {
    std::fs::write(path, bytes).unwrap();
    write_detached(path, &key.sign(Domain::PolicyBundle, bytes)).unwrap();
}

/// Poll `condition` until it holds or `bound` elapses (the watcher ticks
/// every 500 ms).
async fn wait_until(bound: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + bound;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    condition()
}

fn control_events(sink: &InMemoryAuditSink, kind: &str) -> Vec<Value> {
    sink.events()
        .into_iter()
        .filter(|event| event["kind"] == kind)
        .collect()
}

#[test]
fn a_verifying_key_refuses_unsigned_and_missigned_documents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    let (key, _) = SigningKey::generate().unwrap();
    let (other, _) = SigningKey::generate().unwrap();

    std::fs::write(&path, V1).unwrap();
    let error = FilePolicy::load_verified(&path, key.verifying_key())
        .err()
        .expect("unsigned document refused")
        .to_string();
    assert!(error.contains("signature"), "{error}");

    write_detached(&path, &other.sign(Domain::PolicyBundle, V1)).unwrap();
    let error = FilePolicy::load_verified(&path, key.verifying_key())
        .err()
        .expect("wrong key refused")
        .to_string();
    assert!(error.contains("does not verify"), "{error}");
    assert!(error.contains(&key.verifying_key().key_id()), "{error}");

    // The right key, but over a different domain: a revocation-list
    // signature over the same bytes is not a policy signature.
    write_detached(&path, &key.sign(Domain::RevocationList, V1)).unwrap();
    assert!(FilePolicy::load_verified(&path, key.verifying_key()).is_err());

    write_signed(&path, V1, &key);
    let policy = FilePolicy::load_verified(&path, key.verifying_key()).unwrap();
    assert!(policy.requires_signature());
    let status = policy.signature().expect("verified");
    assert!(status.verified);
    assert_eq!(
        status.key_id.as_deref(),
        Some(key.verifying_key().key_id().as_str())
    );
    assert!(policy.version().unwrap().starts_with("v1+sha256:"));

    // Unsigned load still works without a key (local dry runs).
    assert!(FilePolicy::load(&path).unwrap().signature().is_none());
}

/// Records the policy version in force at the moment each control record
/// is appended — the "journaled before it took effect" witness.
struct VersionWitness {
    inner: InMemoryAuditSink,
    policy: Mutex<Option<Arc<FilePolicy>>>,
    versions_at_append: Mutex<Vec<(String, Option<String>)>>,
}

impl VersionWitness {
    fn bind(&self, policy: &Arc<FilePolicy>) {
        *self.policy.lock().unwrap() = Some(Arc::clone(policy));
    }
}

impl AuditSink for VersionWitness {
    fn append<'a>(&'a self, event: &'a AuditEvent) -> AppendFuture<'a> {
        self.inner.append(event)
    }

    fn append_control<'a>(&'a self, event: &'a ControlEvent) -> AppendFuture<'a> {
        let in_force = self
            .policy
            .lock()
            .unwrap()
            .as_ref()
            .and_then(PolicyDecisionPoint::version);
        let kind = serde_json::to_value(event.kind)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        self.versions_at_append
            .lock()
            .unwrap()
            .push((kind, in_force));
        self.inner.append_control(event)
    }

    fn is_available(&self) -> bool {
        self.inner.is_available()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_is_journaled_before_it_takes_effect_and_rejections_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    let (key, _) = SigningKey::generate().unwrap();
    write_signed(&path, V1, &key);
    let policy = FilePolicy::load_verified(&path, key.verifying_key()).unwrap();
    let v1 = policy.version().unwrap();

    let witness = Arc::new(VersionWitness {
        inner: InMemoryAuditSink::new(),
        policy: Mutex::new(None),
        versions_at_append: Mutex::new(Vec::new()),
    });
    witness.bind(&policy);
    policy.spawn_watcher(
        Some(BundleAudit {
            sink: Arc::clone(&witness) as Arc<dyn AuditSink>,
            append_timeout: Duration::from_secs(5),
        }),
        None,
    );

    // The policy in force is journaled when the watcher starts.
    assert!(
        wait_until(Duration::from_secs(3), || {
            !control_events(&witness.inner, "policy_loaded").is_empty()
        })
        .await
    );
    let loaded = &control_events(&witness.inner, "policy_loaded")[0];
    assert_eq!(loaded["version"], v1);
    assert_eq!(loaded["signature"]["verified"], true);
    assert_eq!(loaded["source"], path.display().to_string());

    // An unsigned edit: refused, last good policy in force, journaled once
    // no matter how many polls see it.
    std::fs::write(&path, V2).unwrap();
    assert!(
        wait_until(Duration::from_secs(3), || {
            !control_events(&witness.inner, "policy_rejected").is_empty()
        })
        .await
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let rejected = control_events(&witness.inner, "policy_rejected");
    assert_eq!(
        rejected.len(),
        1,
        "one record per distinct failure: {rejected:?}"
    );
    assert_eq!(rejected[0]["previous_version"], v1);
    assert!(
        rejected[0]["reason"]
            .as_str()
            .unwrap()
            .contains("does not verify"),
        "{:?}",
        rejected[0]
    );
    assert!(
        rejected[0]["version"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"),
        "the refused bytes are identifiable: {:?}",
        rejected[0]
    );
    assert_eq!(policy.version().unwrap(), v1);
    assert!(policy.degraded().is_some());

    // Now signed: applied, and the change record was appended while v1 was
    // still in force.
    write_detached(&path, &key.sign(Domain::PolicyBundle, V2)).unwrap();
    assert!(
        wait_until(Duration::from_secs(3), || {
            policy.version().unwrap().starts_with("v2+")
        })
        .await
    );
    assert!(policy.degraded().is_none());
    let changed = control_events(&witness.inner, "policy_changed");
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0]["previous_version"], v1);
    assert_eq!(changed[0]["version"], policy.version().unwrap());
    assert_eq!(changed[0]["signature"]["verified"], true);
    let at_append = witness.versions_at_append.lock().unwrap().clone();
    let (_, in_force) = at_append
        .iter()
        .find(|(kind, _)| kind == "policy_changed")
        .expect("witnessed the change record");
    assert_eq!(
        in_force.as_deref(),
        Some(v1.as_str()),
        "the change record must be durable before the new policy is in force"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_whose_record_cannot_be_journaled_is_not_applied() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    let (key, _) = SigningKey::generate().unwrap();
    write_signed(&path, V1, &key);
    let policy = FilePolicy::load_verified(&path, key.verifying_key()).unwrap();
    let v1 = policy.version().unwrap();
    let sink = Arc::new(InMemoryAuditSink::new());
    policy.spawn_watcher(
        Some(BundleAudit {
            sink: Arc::clone(&sink) as Arc<dyn AuditSink>,
            append_timeout: Duration::from_secs(1),
        }),
        None,
    );
    assert!(
        wait_until(Duration::from_secs(3), || {
            !control_events(&sink, "policy_loaded").is_empty()
        })
        .await
    );

    sink.set_failing(true);
    write_signed(&path, V3, &key);
    assert!(
        wait_until(Duration::from_secs(3), || {
            policy
                .degraded()
                .is_some_and(|reason| reason.contains("could not be journaled"))
        })
        .await,
        "degraded: {:?}",
        policy.degraded()
    );
    assert_eq!(
        policy.version().unwrap(),
        v1,
        "a change nobody can prove is not applied"
    );
    assert!(control_events(&sink, "policy_changed").is_empty());

    sink.set_failing(false);
    assert!(
        wait_until(Duration::from_secs(3), || {
            policy.version().unwrap().starts_with("v3+")
        })
        .await
    );
    assert!(policy.degraded().is_none());
    assert_eq!(control_events(&sink, "policy_changed").len(), 1);
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

#[test]
fn keygen_sign_and_check_round_trip_at_the_binary_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let key_file: PathBuf = dir.path().join("policy-signing.key");
    let policy = dir.path().join("policy.yaml");
    std::fs::write(&policy, V1).unwrap();

    let (ok, stdout, stderr) = run(&["policy", "keygen", "--out", &arg(&key_file), "--json"]);
    assert!(ok, "{stderr}");
    let generated: Value = serde_json::from_str(stdout.trim()).unwrap();
    let public_key = generated["public_key"].as_str().unwrap().to_owned();
    let key_id = generated["key_id"].as_str().unwrap().to_owned();
    assert!(VerifyingKey::from_base64(&public_key).is_ok());
    assert!(key_file.is_file());

    // A second keygen at the same path refuses to overwrite.
    let (ok, _, stderr) = run(&["policy", "keygen", "--out", &arg(&key_file)]);
    assert!(!ok);
    assert!(stderr.contains("already exists"), "{stderr}");

    // Unsigned: `check` alone passes, `check --public-key` fails.
    let (ok, _, _) = run(&["policy", "check", &arg(&policy)]);
    assert!(ok);
    let (ok, _, stderr) = run(&[
        "policy",
        "check",
        &arg(&policy),
        "--public-key",
        &public_key,
    ]);
    assert!(!ok);
    assert!(stderr.contains("signature"), "{stderr}");

    let (ok, stdout, stderr) = run(&["policy", "sign", &arg(&policy), "--key", &arg(&key_file)]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains(&key_id), "{stdout}");
    assert!(dir.path().join("policy.yaml.sig").is_file());

    let (ok, stdout, stderr) = run(&[
        "policy",
        "check",
        &arg(&policy),
        "--public-key",
        &public_key,
        "--json",
    ]);
    assert!(ok, "{stderr}");
    let checked: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(checked["signature"]["verified"], true);
    assert_eq!(checked["signature"]["key_id"], key_id);

    // Edit without re-signing: the gateway would refuse this, and so does check.
    std::fs::write(&policy, V2).unwrap();
    let (ok, _, stderr) = run(&[
        "policy",
        "check",
        &arg(&policy),
        "--public-key",
        &public_key,
    ]);
    assert!(!ok);
    assert!(stderr.contains("does not verify"), "{stderr}");

    // Signing a document that does not compile is refused.
    std::fs::write(&policy, b"version: 1\nrules: [{id: x}]\n").unwrap();
    let (ok, _, stderr) = run(&["policy", "sign", &arg(&policy), "--key", &arg(&key_file)]);
    assert!(!ok);
    assert!(stderr.contains("policy.yaml"), "{stderr}");

    // The wrong key is a category, not a crash.
    let (ok, _, stderr) = run(&["policy", "check", &arg(&policy), "--public-key", "nope"]);
    assert!(!ok);
    assert!(stderr.contains("--public-key"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn sign_refuses_a_key_file_other_users_can_read() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("k");
    let (_, pkcs8) = SigningKey::generate().unwrap();
    std::fs::write(&key_file, pkcs8).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let policy = dir.path().join("policy.yaml");
    std::fs::write(&policy, V1).unwrap();
    let (ok, _, stderr) = run(&["policy", "sign", &arg(&policy), "--key", &arg(&key_file)]);
    assert!(!ok);
    assert!(stderr.contains("readable by other users"), "{stderr}");
    let _: io::Result<()> = Ok(());
}

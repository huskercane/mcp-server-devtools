//! C.3: the syslog adapter and the shipper against a **real** syslog-ng
//! receiver over mutual TLS — the real-receiver proof for the RFC 5424 /
//! RFC 5425 framing, the TLS client certificate, and resume across a
//! shipper restart (plan §3.9 "Audit forwarding"; the `siem` job in
//! `rust.yml`).
//!
//! Skipped unless `MCP_TEST_SYSLOG_ADDR` (a `syslog+tls://host:port` URL)
//! and `MCP_TEST_SYSLOG_OUTPUT` (the file the receiver writes, as the test
//! sees it) are set. To run locally:
//!
//! ```bash
//! mkdir -p /tmp/mcp-audit && chmod 777 /tmp/mcp-audit
//! docker run -d --name syslog-ng -p 127.0.0.1:6514:6514 \
//!   -v "$PWD/tests/fixtures/syslog-ng/syslog-ng.conf:/etc/syslog-ng/syslog-ng.conf:ro" \
//!   -v "$PWD/tests/fixtures/tls:/etc/syslog-ng/tls:ro" \
//!   -v /tmp/mcp-audit:/var/log/mcp-audit \
//!   balabit/syslog-ng:4.10.1 -F --no-caps
//! MCP_TEST_SYSLOG_ADDR=syslog+tls://127.0.0.1:6514 \
//! MCP_TEST_SYSLOG_OUTPUT=/tmp/mcp-audit/messages \
//!   cargo test --test siem_live_tests -- --nocapture
//! ```

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mcp_server_devtools::audit::forward::Shipper;
use mcp_server_devtools::audit::forward::syslog::{SyslogForwarder, SyslogSettings, TlsOptions};
use mcp_server_devtools::audit::journal::JournalAuditSink;
use mcp_server_devtools::audit::reader::JournalReader;
use mcp_server_devtools::ports::{AuditForwarder, AuditSink, ControlEvent, ControlEventKind};
use support::tls_syslog_receiver::fixture;

fn receiver() -> Option<(String, PathBuf)> {
    let addr = std::env::var("MCP_TEST_SYSLOG_ADDR")
        .ok()?
        .trim()
        .to_owned();
    let output = std::env::var("MCP_TEST_SYSLOG_OUTPUT")
        .ok()?
        .trim()
        .to_owned();
    (!addr.is_empty() && !output.is_empty()).then(|| (addr, PathBuf::from(output)))
}

/// A run-unique origin so lines from earlier runs (the file persists
/// across tests) are distinguishable.
fn origin() -> String {
    format!("mcp-live-{}", uuid::Uuid::new_v4().simple())
}

fn forwarder(addr: &str, origin: &str) -> Arc<dyn AuditForwarder> {
    let settings =
        SyslogSettings::parse_url(addr, origin.to_owned(), Duration::from_secs(5)).unwrap();
    let tls = TlsOptions {
        ca_file: Some(fixture("ca.pem")),
        client_cert: Some(fixture("client.pem")),
        client_key: Some(fixture("client-key.pem")),
    };
    Arc::new(SyslogForwarder::new(settings, &tls).expect("build the syslog forwarder"))
}

/// The `<MSGID> <MSG>` lines the receiver wrote whose MSG carries our
/// marker reason, parsed back to `(msgid, record)`.
async fn wait_for_lines(
    output: &Path,
    marker: &str,
    at_least: usize,
) -> Vec<(String, serde_json::Value)> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let text = std::fs::read_to_string(output).unwrap_or_default();
        let lines: Vec<(String, serde_json::Value)> = text
            .lines()
            .filter(|line| line.contains(marker))
            .filter_map(|line| {
                let (msgid, msg) = line.split_once(' ')?;
                let msg = msg.strip_prefix('\u{feff}').unwrap_or(msg);
                Some((msgid.to_owned(), serde_json::from_str(msg).ok()?))
            })
            .collect();
        if lines.len() >= at_least {
            return lines;
        }
        assert!(
            Instant::now() < deadline,
            "receiver output {} holds {} matching lines, wanted {at_least}:\n{text}",
            output.display(),
            lines.len()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn write_journal(dir: &Path, marker: &str, kinds: &[ControlEventKind]) {
    let sink = JournalAuditSink::open(dir).unwrap();
    for kind in kinds {
        sink.append_control(&ControlEvent::now(*kind).with_reason(marker))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn journal_records_reach_syslog_ng_over_mutual_tls_and_resume_after_a_restart() {
    let Some((addr, output)) = receiver() else {
        eprintln!(
            "MCP_TEST_SYSLOG_ADDR / MCP_TEST_SYSLOG_OUTPUT not set; skipping the syslog-ng live test"
        );
        return;
    };
    let origin = origin();
    let marker = format!("marker-{origin}");
    let dir = tempfile::tempdir().unwrap();
    write_journal(
        dir.path(),
        &marker,
        &[
            ControlEventKind::PolicyLoaded,
            ControlEventKind::PolicyRejected,
            ControlEventKind::RevocationLoaded,
        ],
    )
    .await;

    // First shipper: everything, in order, mutual TLS.
    {
        let mut shipper =
            Shipper::open(forwarder(&addr, &origin), dir.path(), dir.path(), 2).unwrap();
        assert_eq!(shipper.drain().await.expect("delivered to syslog-ng"), 4);
        assert_eq!(shipper.cursor().acknowledged, 4);
    }
    // The checkpoint record carries no reason, so match it by the journal
    // bytes instead: read the journal and check every line arrived.
    let journal_lines: Vec<serde_json::Value> = JournalReader::open(dir.path())
        .unwrap()
        .map(|record| record.unwrap().value)
        .collect();
    let lines = wait_for_lines(&output, &marker, 3).await;
    assert_eq!(
        lines
            .iter()
            .map(|(msgid, _)| msgid.as_str())
            .collect::<Vec<_>>(),
        ["policy_loaded", "policy_rejected", "revocation_loaded"]
    );
    for ((_, got), expected) in lines.iter().zip(&journal_lines) {
        assert_eq!(got, expected, "syslog-ng holds the journal's own line");
    }

    // Restart: more records, a fresh shipper, the cursor resumes — the
    // receiver sees the new records once and the old ones not again.
    write_journal(dir.path(), &marker, &[ControlEventKind::PolicyChanged]).await;
    {
        let mut shipper =
            Shipper::open(forwarder(&addr, &origin), dir.path(), dir.path(), 256).unwrap();
        assert_eq!(shipper.cursor().acknowledged, 4);
        assert_eq!(shipper.drain().await.unwrap(), 2);
    }
    let lines = wait_for_lines(&output, &marker, 4).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let lines_after_settling = wait_for_lines(&output, &marker, 4).await;
    assert_eq!(
        lines.len(),
        lines_after_settling.len(),
        "no duplicates arrived after the resume"
    );
    assert_eq!(
        lines
            .iter()
            .map(|(msgid, _)| msgid.as_str())
            .collect::<Vec<_>>(),
        [
            "policy_loaded",
            "policy_rejected",
            "revocation_loaded",
            "policy_changed"
        ]
    );
    let seqs: Vec<u64> = lines
        .iter()
        .map(|(_, record)| record["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(
        seqs,
        [1, 2, 3, 5],
        "sequence 4 is the checkpoint, which carries no marker"
    );
}

#[tokio::test]
async fn syslog_ng_refuses_a_forwarder_without_the_client_certificate() {
    let Some((addr, _)) = receiver() else {
        return;
    };
    let settings =
        SyslogSettings::parse_url(&addr, "mcp-live-nocert".into(), Duration::from_secs(5)).unwrap();
    let forwarder = SyslogForwarder::new(
        settings,
        &TlsOptions {
            ca_file: Some(fixture("ca.pem")),
            ..TlsOptions::default()
        },
    )
    .unwrap();
    let error = forwarder
        .deliver(&[support::audit_forwarder_conformance::record(
            1,
            "policy_loaded",
            false,
            b"{\"seq\":1}",
        )])
        .await
        .expect_err("required-trusted peer verification must refuse us");
    assert!(
        error.category == mcp_server_devtools::ports::ForwardError::INTERRUPTED
            || error.category == mcp_server_devtools::ports::ForwardError::UNREACHABLE,
        "{error}"
    );
}

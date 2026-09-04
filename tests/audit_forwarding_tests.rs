//! WP C.3: forwarding the audit journal to a SIEM behind the
//! `AuditForwarder` port (plan §3.3, §3.9).
//!
//! Three layers:
//!
//! 1. the adapter conformance suite over every adapter — in-memory, syslog
//!    over TLS against an in-process RFC 5425 receiver (server-only TLS and
//!    mutual TLS), Splunk HEC and generic JSON against wiremock;
//! 2. the shipper against a **real** journal (`JournalAuditSink`): order,
//!    the cursor, resume across a restart with no duplicate and no hole, a
//!    receiver outage that retains and then catches up, a torn tail, a
//!    corrupt journal that is reported and never skipped, and the append
//!    path that keeps acknowledging while the receiver is down;
//! 3. the composition: an in-process server with a real journal and a real
//!    HEC adapter, a tool call, the record at the collector; and the binary
//!    boundary, where the role decides whether the shipper runs and a bad
//!    URL refuses startup.

mod support;

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use mcp_server_devtools::audit::forward::http::{HttpFormat, HttpForwarder};
use mcp_server_devtools::audit::forward::syslog::{SyslogForwarder, SyslogSettings, TlsOptions};
use mcp_server_devtools::audit::forward::{CURSOR_FILE_NAME, Cursor, ShipError, Shipper};
use mcp_server_devtools::audit::journal::JournalAuditSink;
use mcp_server_devtools::audit::reader::JournalReader;
use mcp_server_devtools::bootstrap::{ServerBuilder, Vendors};
use mcp_server_devtools::config::Config;
use mcp_server_devtools::ports::{
    AuditForwarder, AuditSink, ControlEvent, ControlEventKind, ForwardError, InMemoryAuditForwarder,
};
use mcp_server_devtools::server::http::build_app_with_server;
use mcp_server_devtools::vendor::jira::JiraVendor;
use serde_json::{Value, json};
use support::audit_forwarder_conformance::{Done, Fixture, Received, conformance};
use support::tls_syslog_receiver::{Receiver, fixture};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

// ---------------------------------------------------------------------------
// 1. Conformance
// ---------------------------------------------------------------------------

struct MemoryFixture(Arc<InMemoryAuditForwarder>);

impl Fixture for MemoryFixture {
    fn forwarder(&self) -> Arc<dyn AuditForwarder> {
        Arc::clone(&self.0) as Arc<dyn AuditForwarder>
    }
    fn received(&self) -> Received<'_> {
        Box::pin(async move {
            self.0
                .received()
                .into_iter()
                .map(|record| (record.seq, serde_json::from_slice(&record.json).unwrap()))
                .collect()
        })
    }
    fn set_down(&self, down: bool) -> Done<'_> {
        self.0.set_down(down);
        Box::pin(async {})
    }
    fn name(&self) -> &'static str {
        "memory"
    }
}

#[tokio::test]
async fn in_memory_forwarder_conforms() {
    conformance(&MemoryFixture(Arc::new(InMemoryAuditForwarder::new()))).await;
}

struct SyslogFixture {
    receiver: Receiver,
    forwarder: Arc<SyslogForwarder>,
}

impl SyslogFixture {
    async fn new(mutual: bool) -> Self {
        let receiver = Receiver::start(mutual).await;
        let settings =
            SyslogSettings::parse_url(&receiver.url(), "gateway-0".into(), Duration::from_secs(2))
                .unwrap();
        let tls = TlsOptions {
            ca_file: Some(fixture("ca.pem")),
            client_cert: mutual.then(|| fixture("client.pem")),
            client_key: mutual.then(|| fixture("client-key.pem")),
        };
        let forwarder = Arc::new(SyslogForwarder::new(settings, &tls).unwrap());
        Self {
            receiver,
            forwarder,
        }
    }
}

impl Fixture for SyslogFixture {
    fn forwarder(&self) -> Arc<dyn AuditForwarder> {
        Arc::clone(&self.forwarder) as Arc<dyn AuditForwarder>
    }
    fn received(&self) -> Received<'_> {
        Box::pin(async move {
            // The receiver parses in the background; give it a moment.
            tokio::time::sleep(Duration::from_millis(150)).await;
            self.receiver
                .messages()
                .into_iter()
                .map(|message| {
                    let json = message.json();
                    (json["seq"].as_u64().unwrap(), json)
                })
                .collect()
        })
    }
    fn set_down(&self, down: bool) -> Done<'_> {
        Box::pin(self.receiver.set_down(down))
    }
    fn name(&self) -> &'static str {
        "syslog"
    }
}

#[tokio::test]
async fn syslog_tls_forwarder_conforms() {
    let fixture = SyslogFixture::new(false).await;
    conformance(&fixture).await;
    // The RFC 5424 header: facility 13, warning for the denial.
    let messages = fixture.receiver.messages();
    assert_eq!(messages[0].pri, 110);
    assert_eq!(messages[1].pri, 108, "the egress denial is a warning");
    assert!(
        messages[0]
            .header
            .starts_with("1 2026-09-04T12:00:00.123Z gateway-0 mcp-devtools - tool_call_intent -"),
        "{}",
        messages[0].header
    );
}

#[tokio::test]
async fn syslog_mutual_tls_forwarder_conforms() {
    conformance(&SyslogFixture::new(true).await).await;
}

#[tokio::test]
async fn syslog_receiver_that_requires_a_client_certificate_refuses_without_one() {
    let receiver = Receiver::start(true).await;
    let settings =
        SyslogSettings::parse_url(&receiver.url(), "o".into(), Duration::from_secs(2)).unwrap();
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
            1, "k", false, b"{}",
        )])
        .await
        .unwrap_err();
    assert_eq!(error.category, ForwardError::INTERRUPTED, "{error}");
    assert!(receiver.messages().is_empty());
}

#[tokio::test]
async fn syslog_forwarder_refuses_an_untrusted_receiver_certificate() {
    let receiver = Receiver::start(false).await;
    let settings =
        SyslogSettings::parse_url(&receiver.url(), "o".into(), Duration::from_secs(2)).unwrap();
    // System roots only: the fixture CA is not among them.
    let forwarder = SyslogForwarder::new(settings, &TlsOptions::default()).unwrap();
    let error = forwarder
        .deliver(&[support::audit_forwarder_conformance::record(
            1, "k", false, b"{}",
        )])
        .await
        .unwrap_err();
    assert_eq!(error.category, ForwardError::UNREACHABLE, "{error}");
    assert!(error.detail.contains("TLS handshake"), "{error}");
    assert!(receiver.messages().is_empty());
}

/// A wiremock responder that plays a collector: answers 200 and keeps the
/// body while up, 503 while down — so what it kept is exactly what it
/// acknowledged.
struct Collector {
    format: HttpFormat,
    down: Arc<std::sync::atomic::AtomicBool>,
    acknowledged: Arc<std::sync::Mutex<Vec<(u64, Value)>>>,
}

impl wiremock::Respond for Collector {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        if self.down.load(std::sync::atomic::Ordering::Acquire) {
            return ResponseTemplate::new(503)
                .set_body_json(json!({"text": "Server is busy", "code": 9}));
        }
        let records: Vec<(u64, Value)> = match self.format {
            HttpFormat::SplunkHec => request
                .body
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| {
                    let event: Value =
                        serde_json::from_slice(line).expect("one HEC event per line");
                    assert_eq!(event["host"], "gateway-0");
                    assert_eq!(event["source"], "mcp-devtools");
                    assert_eq!(event["sourcetype"], "mcp-devtools:audit");
                    assert!(
                        event["time"].is_number(),
                        "HEC time from the record timestamp"
                    );
                    let record = event["event"].clone();
                    (record["seq"].as_u64().unwrap(), record)
                })
                .collect(),
            HttpFormat::Json => {
                let array: Vec<Value> =
                    serde_json::from_slice(&request.body).expect("a JSON array");
                array
                    .into_iter()
                    .map(|record| (record["seq"].as_u64().unwrap(), record))
                    .collect()
            }
        };
        self.acknowledged.lock().unwrap().extend(records);
        ResponseTemplate::new(200).set_body_json(json!({"text": "Success", "code": 0}))
    }
}

struct HttpFixture {
    server: MockServer,
    forwarder: Arc<HttpForwarder>,
    down: Arc<std::sync::atomic::AtomicBool>,
    acknowledged: Arc<std::sync::Mutex<Vec<(u64, Value)>>>,
}

impl HttpFixture {
    async fn new(format: HttpFormat) -> Self {
        let server = MockServer::start().await;
        let (url, token, path_, auth) = match format {
            HttpFormat::SplunkHec => (
                format!("{}/services/collector/event", server.uri()),
                "hec-token-fixture",
                "/services/collector/event",
                "Splunk hec-token-fixture",
            ),
            HttpFormat::Json => (
                format!("{}/ingest", server.uri()),
                "bearer-fixture",
                "/ingest",
                "Bearer bearer-fixture",
            ),
        };
        let down = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let acknowledged = Arc::new(std::sync::Mutex::new(Vec::new()));
        Mock::given(method("POST"))
            .and(path(path_))
            .and(header("authorization", auth))
            .and(header("content-type", "application/json"))
            .respond_with(Collector {
                format,
                down: Arc::clone(&down),
                acknowledged: Arc::clone(&acknowledged),
            })
            .mount(&server)
            .await;
        let forwarder = HttpForwarder::new(
            &url,
            None,
            Some(token.to_owned()),
            "gateway-0".into(),
            None,
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(forwarder.format(), format);
        Self {
            server,
            forwarder: Arc::new(forwarder),
            down,
            acknowledged,
        }
    }
}

impl Fixture for HttpFixture {
    fn forwarder(&self) -> Arc<dyn AuditForwarder> {
        Arc::clone(&self.forwarder) as Arc<dyn AuditForwarder>
    }
    fn received(&self) -> Received<'_> {
        Box::pin(async move { self.acknowledged.lock().unwrap().clone() })
    }
    fn set_down(&self, down: bool) -> Done<'_> {
        self.down.store(down, std::sync::atomic::Ordering::Release);
        Box::pin(async {})
    }
    fn name(&self) -> &'static str {
        self.forwarder.name()
    }
}

#[tokio::test]
async fn splunk_hec_forwarder_conforms() {
    conformance(&HttpFixture::new(HttpFormat::SplunkHec).await).await;
}

#[tokio::test]
async fn generic_json_forwarder_conforms() {
    conformance(&HttpFixture::new(HttpFormat::Json).await).await;
}

#[tokio::test]
async fn hec_rejection_reports_the_collector_text_and_never_the_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"text": "Invalid token", "code": 4})),
        )
        .mount(&server)
        .await;
    let forwarder = HttpForwarder::new(
        &format!("{}/services/collector", server.uri()),
        None,
        Some("hec-token-fixture".into()),
        "o".into(),
        None,
        Duration::from_secs(2),
    )
    .unwrap();
    let error = forwarder
        .deliver(&[support::audit_forwarder_conformance::record(
            1, "k", false, b"{}",
        )])
        .await
        .unwrap_err();
    assert_eq!(error.category, ForwardError::REJECTED);
    assert_eq!(error.detail, "http 403: Invalid token");
    assert!(!format!("{error:?}").contains("hec-token-fixture"));
}

// ---------------------------------------------------------------------------
// 2. The shipper against a real journal
// ---------------------------------------------------------------------------

/// Append `n` control records to a real journal in `dir`; returns the
/// sequences assigned. The sink is dropped (closed cleanly), which seals
/// the journal with a checkpoint record.
async fn write_journal(dir: &Path, kinds: &[ControlEventKind]) -> Vec<u64> {
    let sink = JournalAuditSink::open(dir).expect("open journal");
    let mut seqs = Vec::with_capacity(kinds.len());
    for kind in kinds {
        let event = ControlEvent::now(*kind).with_reason("test");
        seqs.push(sink.append_control(&event).await.expect("append"));
    }
    seqs
}

fn journal_seqs(dir: &Path) -> Vec<(u64, String)> {
    JournalReader::open(dir)
        .unwrap()
        .map(|record| {
            let record = record.unwrap();
            (record.seq, record.kind)
        })
        .collect()
}

fn read_cursor(dir: &Path) -> Cursor {
    serde_json::from_slice(&std::fs::read(dir.join(CURSOR_FILE_NAME)).unwrap()).unwrap()
}

#[tokio::test]
async fn shipper_forwards_every_record_in_order_and_persists_the_cursor() {
    let dir = tempfile::tempdir().unwrap();
    write_journal(
        dir.path(),
        &[
            ControlEventKind::PolicyLoaded,
            ControlEventKind::PolicyRejected,
            ControlEventKind::RevocationLoaded,
        ],
    )
    .await;
    let in_journal = journal_seqs(dir.path());
    assert_eq!(
        in_journal.len(),
        4,
        "three records and the closing checkpoint"
    );

    let forwarder = Arc::new(InMemoryAuditForwarder::new());
    let mut shipper = Shipper::open(
        Arc::clone(&forwarder) as Arc<dyn AuditForwarder>,
        dir.path(),
        dir.path(),
        2,
    )
    .unwrap();
    assert_eq!(shipper.cursor().acknowledged, 0);

    let count = shipper.drain().await.unwrap();
    assert_eq!(count, 4);
    let received = forwarder.received();
    assert_eq!(
        received.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert_eq!(
        received.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>(),
        in_journal
            .iter()
            .map(|(_, kind)| kind.as_str())
            .collect::<Vec<_>>()
    );
    assert!(received[1].adverse, "policy_rejected is adverse");
    assert!(!received[0].adverse);
    assert_eq!(forwarder.deliveries(), 2, "batch size 2 → two deliveries");

    // Byte-for-byte: what the receiver holds is the journal's own line.
    let lines: Vec<Vec<u8>> = JournalReader::open(dir.path())
        .unwrap()
        .map(|r| r.unwrap().line)
        .collect();
    for (captured, line) in received.iter().zip(&lines) {
        assert_eq!(captured.json.as_slice(), line.strip_suffix(b"\n").unwrap());
    }

    let cursor = read_cursor(dir.path());
    assert_eq!(cursor.acknowledged, 4);
    assert_eq!(
        cursor.offset,
        lines.iter().map(Vec::len).sum::<usize>() as u64
    );
    assert!(cursor.chain.starts_with("sha256:"));
    assert_eq!(shipper.cursor(), &cursor);

    // Nothing more: no delivery, cursor untouched.
    assert_eq!(shipper.drain().await.unwrap(), 0);
    assert_eq!(forwarder.deliveries(), 2);
}

#[tokio::test]
async fn shipper_resumes_from_the_cursor_after_a_restart_without_duplicates_or_holes() {
    let dir = tempfile::tempdir().unwrap();
    write_journal(
        dir.path(),
        &[
            ControlEventKind::PolicyLoaded,
            ControlEventKind::RevocationLoaded,
        ],
    )
    .await;
    let forwarder = Arc::new(InMemoryAuditForwarder::new());
    {
        let mut shipper = Shipper::open(
            Arc::clone(&forwarder) as Arc<dyn AuditForwarder>,
            dir.path(),
            dir.path(),
            256,
        )
        .unwrap();
        assert_eq!(shipper.drain().await.unwrap(), 3);
    }
    // The process restarts; more records land (the journal reopens and
    // continues its sequence).
    write_journal(dir.path(), &[ControlEventKind::PolicyChanged]).await;
    let mut shipper = Shipper::open(
        Arc::clone(&forwarder) as Arc<dyn AuditForwarder>,
        dir.path(),
        dir.path(),
        256,
    )
    .unwrap();
    assert_eq!(
        shipper.cursor().acknowledged,
        3,
        "resumed from the persisted cursor"
    );
    assert_eq!(
        shipper.drain().await.unwrap(),
        2,
        "the new record and the new checkpoint"
    );
    assert_eq!(forwarder.sequences(), vec![1, 2, 3, 4, 5]);
    assert_eq!(journal_seqs(dir.path()).len(), 5);
}

#[tokio::test]
async fn receiver_outage_retains_the_journal_and_the_shipper_catches_up() {
    let dir = tempfile::tempdir().unwrap();
    write_journal(dir.path(), &[ControlEventKind::PolicyLoaded]).await;
    let forwarder = Arc::new(InMemoryAuditForwarder::new());
    let mut shipper = Shipper::open(
        Arc::clone(&forwarder) as Arc<dyn AuditForwarder>,
        dir.path(),
        dir.path(),
        256,
    )
    .unwrap();

    forwarder.set_down(true);
    let error = shipper.drain().await.unwrap_err();
    assert!(matches!(error, ShipError::Deliver(_)), "{error}");
    assert_eq!(error.category(), ForwardError::UNREACHABLE);
    assert_eq!(
        shipper.cursor().acknowledged,
        0,
        "nothing acknowledged, cursor unchanged"
    );
    assert!(
        !dir.path().join(CURSOR_FILE_NAME).exists(),
        "no cursor written for an unacknowledged batch"
    );
    assert!(forwarder.received().is_empty());

    forwarder.set_down(false);
    assert_eq!(shipper.drain().await.unwrap(), 2);
    assert_eq!(forwarder.sequences(), vec![1, 2]);
    assert_eq!(read_cursor(dir.path()).acknowledged, 2);
}

#[tokio::test]
async fn a_torn_tail_is_left_for_the_next_round_and_a_gap_is_never_skipped() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    write_journal(dir.path(), &[ControlEventKind::PolicyLoaded]).await;
    let journal = dir
        .path()
        .join(mcp_server_devtools::audit::journal::JOURNAL_FILE_NAME);
    let forwarder = Arc::new(InMemoryAuditForwarder::new());
    let mut shipper = Shipper::open(
        Arc::clone(&forwarder) as Arc<dyn AuditForwarder>,
        dir.path(),
        dir.path(),
        256,
    )
    .unwrap();

    // A writer mid-append: the complete records go, the torn line waits.
    {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&journal)
            .unwrap();
        file.write_all(b"{\"seq\":3,\"kind\":\"tool_call_int")
            .unwrap();
    }
    assert_eq!(shipper.drain().await.unwrap(), 2);
    assert_eq!(shipper.cursor().acknowledged, 2);
    // The line completes; the next round forwards it.
    {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&journal)
            .unwrap();
        file.write_all(b"ent\",\"timestamp\":\"2026-09-04T00:00:00.000Z\"}\n")
            .unwrap();
    }
    assert_eq!(shipper.drain().await.unwrap(), 1);
    assert_eq!(forwarder.sequences(), vec![1, 2, 3]);

    // A gap (sequence 5 after 3) is reported, not skipped: the cursor stays
    // before it and every later round reports it again.
    {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&journal)
            .unwrap();
        file.write_all(b"{\"seq\":5,\"kind\":\"tool_call_intent\"}\n")
            .unwrap();
    }
    for _ in 0..2 {
        let error = shipper.drain().await.unwrap_err();
        assert!(matches!(error, ShipError::Journal(_)), "{error}");
        assert_eq!(error.category(), "journal_unreadable");
        assert!(
            error.to_string().contains("expected sequence 4, found 5"),
            "{error}"
        );
    }
    assert_eq!(shipper.cursor().acknowledged, 3);
    assert_eq!(forwarder.sequences(), vec![1, 2, 3]);
}

#[tokio::test]
async fn a_cursor_for_another_journal_is_discarded_and_forwarding_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    write_journal(dir.path(), &[ControlEventKind::PolicyLoaded]).await;
    std::fs::write(
        state.path().join(CURSOR_FILE_NAME),
        serde_json::to_vec(&Cursor {
            acknowledged: 7,
            offset: 10,
            chain: "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            journal: "/somewhere/else/audit-journal.jsonl".into(),
        })
        .unwrap(),
    )
    .unwrap();
    let forwarder = Arc::new(InMemoryAuditForwarder::new());
    let mut shipper = Shipper::open(
        Arc::clone(&forwarder) as Arc<dyn AuditForwarder>,
        dir.path(),
        state.path(),
        256,
    )
    .unwrap();
    assert_eq!(shipper.cursor().acknowledged, 0);
    assert_eq!(shipper.drain().await.unwrap(), 2);
    assert_eq!(read_cursor(state.path()).acknowledged, 2);
}

#[tokio::test]
async fn the_append_path_keeps_acknowledging_while_the_receiver_is_down() {
    let dir = tempfile::tempdir().unwrap();
    let sink = Arc::new(JournalAuditSink::open(dir.path()).unwrap());
    let forwarder = Arc::new(InMemoryAuditForwarder::new());
    forwarder.set_down(true);
    let shipper = Shipper::open(
        Arc::clone(&forwarder) as Arc<dyn AuditForwarder>,
        dir.path(),
        dir.path(),
        256,
    )
    .unwrap();
    let health = Arc::new(mcp_server_devtools::audit::forward::ForwardHealth::default());
    let cancel = CancellationToken::new();
    let task =
        tokio::spawn(shipper.run(Arc::clone(&health), Duration::from_secs(1), cancel.clone()));

    // Appends are acknowledged at the journal's own pace, whatever the
    // receiver does: fifty durable records while every delivery fails.
    let started = std::time::Instant::now();
    for _ in 0..50 {
        sink.append_control(&ControlEvent::now(ControlEventKind::PolicyLoaded))
            .await
            .unwrap();
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "appends waited on the receiver"
    );
    assert!(sink.is_available());

    // The banner would say so.
    tokio::time::timeout(Duration::from_secs(5), async {
        while health.degraded().is_none() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("forwarding reported degraded");
    assert_eq!(health.degraded(), Some(ForwardError::UNREACHABLE));
    assert_eq!(health.acknowledged(), 0);

    // Receiver back: the run loop catches up (its backoff is bounded by
    // the interval it started with, doubled a few times).
    forwarder.set_down(false);
    tokio::time::timeout(Duration::from_secs(20), async {
        while health.acknowledged() < 50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("shipper caught up");
    assert_eq!(health.degraded(), None);
    assert_eq!(forwarder.sequences(), (1..=50).collect::<Vec<_>>());
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

// ---------------------------------------------------------------------------
// 3. Composition: a tool call's records reach the collector
// ---------------------------------------------------------------------------

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<HashMap<_, _>>(),
    )
}

async fn call_jira_get(base: &str) -> Value {
    let response = reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "jira_get")
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "jira_get",
                "arguments": { "path": "/rest/api/3/myself" },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": { "name": "forward-test", "version": "0.0.0" }
                }
            }
        }))
        .send()
        .await
        .expect("tools/call");
    assert_eq!(response.status(), 200);
    let body = response.text().await.expect("body");
    if let Ok(value) = serde_json::from_str(&body) {
        return value;
    }
    body.lines()
        .filter_map(|line| {
            line.strip_prefix("data: ")
                .or_else(|| line.strip_prefix("data:"))
        })
        .find_map(|data| serde_json::from_str(data.trim()).ok())
        .unwrap_or_else(|| panic!("unparseable response:\n{body}"))
}

#[tokio::test]
async fn a_tool_calls_intent_and_outcome_reach_a_splunk_collector_from_the_real_journal() {
    let jira = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/myself"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accountId": "a"})))
        .mount(&jira)
        .await;
    let collector = HttpFixture::new(HttpFormat::SplunkHec).await;
    let journal = tempfile::tempdir().unwrap();

    let server = ServerBuilder::new()
        .config(config(&[
            ("ATLASSIAN_USER_EMAIL", "alice@example.com"),
            ("ATLASSIAN_API_TOKEN", "test-token"),
            ("MCP_AUDIT_JOURNAL_DIR", journal.path().to_str().unwrap()),
            (
                "MCP_AUDIT_FORWARD_URL",
                &format!("{}/services/collector/event", collector.server.uri()),
            ),
            ("MCP_AUDIT_FORWARD_TOKEN", "hec-token-fixture"),
            ("MCP_AUDIT_FORWARD_ORIGIN", "gateway-0"),
            ("MCP_AUDIT_FORWARD_INTERVAL_SECONDS", "1"),
        ]))
        .vendors(Vendors {
            jira: JiraVendor::with_base_url(jira.uri()),
            ..Vendors::default()
        })
        .build()
        .unwrap();
    let cancel = CancellationToken::new();
    assert_eq!(
        server.start_audit_forwarding(cancel.clone()).unwrap(),
        Some("splunk-hec")
    );
    let health = server.forward_health();

    let app = build_app_with_server(
        server,
        Duration::from_mins(5),
        Duration::from_mins(5),
        cancel.clone(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let result = call_jira_get(&base).await;
    assert!(result.get("error").is_none(), "{result}");

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let received = collector.received().await;
            if received
                .iter()
                .any(|(_, record)| record["kind"] == "tool_call_outcome")
            {
                return received;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map(|received| {
        let kinds: Vec<&str> = received
            .iter()
            .map(|(_, r)| r["kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["tool_call_intent", "tool_call_outcome"]);
        assert_eq!(received[0].1["tool_name"], "jira_get");
        assert_eq!(received[0].1["upstream_identity"]["vendor"], "jira");
        let raw = serde_json::to_string(&received).unwrap();
        assert!(
            !raw.contains("test-token"),
            "the collector saw a credential"
        );
    })
    .expect("the tool call's records reached the collector");
    assert!(health.acknowledged() >= 2);
    cancel.cancel();
}

#[tokio::test]
async fn forwarding_with_no_journal_or_an_unknown_scheme_refuses_to_start() {
    for (pairs, expected) in [
        (
            vec![("MCP_AUDIT_FORWARD_URL", "https://siem.example/ingest")],
            "names a journal to forward",
        ),
        (
            vec![
                ("MCP_AUDIT_FORWARD_URL", "kafka://siem.example/audit"),
                ("MCP_AUDIT_JOURNAL_DIR", "/tmp"),
            ],
            "no audit forwarder for `kafka://`",
        ),
        (
            vec![
                ("MCP_AUDIT_FORWARD_URL", "syslog+tcp://siem.example:514"),
                ("MCP_AUDIT_JOURNAL_DIR", "/tmp"),
            ],
            "plaintext syslog",
        ),
        (
            vec![
                ("MCP_AUDIT_FORWARD_URL", "http://siem.example/ingest"),
                ("MCP_AUDIT_JOURNAL_DIR", "/tmp"),
            ],
            "https",
        ),
        (
            vec![
                (
                    "MCP_AUDIT_FORWARD_URL",
                    "https://splunk.example/services/collector",
                ),
                ("MCP_AUDIT_JOURNAL_DIR", "/tmp"),
            ],
            "collector token",
        ),
        (
            vec![
                ("MCP_AUDIT_FORWARD_URL", "syslog+tls://siem.example"),
                ("MCP_AUDIT_JOURNAL_DIR", "/tmp"),
                ("MCP_AUDIT_FORWARD_CA_FILE", "/nonexistent/ca.pem"),
            ],
            "cannot read",
        ),
        (
            vec![
                ("MCP_AUDIT_FORWARD_URL", "https://siem.example/ingest"),
                ("MCP_AUDIT_JOURNAL_DIR", "/tmp"),
                ("MCP_AUDIT_FORWARD_FORMAT", "csv"),
            ],
            "expected `hec` or `json`",
        ),
    ] {
        let journal = tempfile::tempdir().unwrap();
        let pairs: Vec<(&str, &str)> = pairs
            .into_iter()
            .map(|(k, v)| {
                if k == "MCP_AUDIT_JOURNAL_DIR" {
                    (k, journal.path().to_str().unwrap())
                } else {
                    (k, v)
                }
            })
            .collect();
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let config = Config::from_map(owned.into_iter().collect());
        let server = ServerBuilder::new().config(config).build().unwrap();
        let error = server
            .start_audit_forwarding(CancellationToken::new())
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains(expected), "{expected:?} not in {message}");
        assert!(message.contains("refusing to start"), "{message}");
    }
}

#[tokio::test]
async fn an_unreachable_receiver_does_not_stop_startup() {
    let journal = tempfile::tempdir().unwrap();
    // Something to forward; the process's own startup records need a
    // policy, which this test does not configure.
    write_journal(journal.path(), &[ControlEventKind::PolicyLoaded]).await;
    let server = ServerBuilder::new()
        .config(config(&[
            ("MCP_AUDIT_JOURNAL_DIR", journal.path().to_str().unwrap()),
            ("MCP_AUDIT_FORWARD_URL", "syslog+tls://127.0.0.1:1"),
            ("MCP_AUDIT_FORWARD_INTERVAL_SECONDS", "1"),
        ]))
        .build()
        .unwrap();
    let cancel = CancellationToken::new();
    assert_eq!(
        server.start_audit_forwarding(cancel.clone()).unwrap(),
        Some("syslog")
    );
    server.journal_startup().await.unwrap();
    let health = server.forward_health();
    tokio::time::timeout(Duration::from_secs(5), async {
        while health.degraded().is_none() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("degraded, not dead");
    assert_eq!(health.degraded(), Some(ForwardError::UNREACHABLE));
    assert!(server.audit_available(), "the journal is unaffected");
    cancel.cancel();
}

// ---------------------------------------------------------------------------
// 4. The binary boundary: the role decides
// ---------------------------------------------------------------------------

const STARTUP_MARKER: &str = "listening on streamable-HTTP transport";

async fn start_binary(
    args: &[&str],
    env: &[(&str, &str)],
) -> Result<(tokio::process::Child, u16), String> {
    let mut command = tokio::process::Command::new(assert_cmd::cargo::cargo_bin("mcp-devtools"));
    command
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("MCP_AUTH_MODE")
        .env_remove("MCP_BIND_ADDR")
        .env_remove("MCP_ROLE")
        .env("PORT", "0")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("spawn binary");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let collected = {
        use tokio::io::AsyncReadExt as _;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut collected = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let text = String::from_utf8_lossy(&collected).into_owned();
            if text.contains(STARTUP_MARKER) {
                break text;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for startup; stderr:\n{text}"
            );
            match tokio::time::timeout(remaining, stderr.read(&mut buf)).await {
                Ok(Ok(0)) => return Err(text),
                Ok(Ok(read)) => collected.extend_from_slice(&buf[..read]),
                Ok(Err(error)) => panic!("reading stderr failed: {error}"),
                Err(_) => {}
            }
        }
    };
    let (_, rest) = collected
        .split_once("127.0.0.1:")
        .expect("startup line carries the bound address");
    let port: u16 = rest
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .expect("bound port");
    Ok((child, port))
}

#[tokio::test]
async fn the_control_role_forwards_and_the_gateway_role_does_not() {
    let collector = HttpFixture::new(HttpFormat::SplunkHec).await;
    let url = format!("{}/services/collector/event", collector.server.uri());
    for (role, expect_forwarding) in [("control", true), ("gateway", false), ("all", true)] {
        let journal = tempfile::tempdir().unwrap();
        // Records written before the process starts: what a restart resumes.
        write_journal(journal.path(), &[ControlEventKind::PolicyLoaded]).await;
        let before = collector.received().await.len();
        let (child, port) = start_binary(
            &["serve", "--transport", "http", "--role", role],
            &[
                ("MCP_AUDIT_JOURNAL_DIR", journal.path().to_str().unwrap()),
                ("MCP_AUDIT_FORWARD_URL", &url),
                ("MCP_AUDIT_FORWARD_TOKEN", "hec-token-fixture"),
                ("MCP_AUDIT_FORWARD_ORIGIN", "gateway-0"),
                ("MCP_AUDIT_FORWARD_INTERVAL_SECONDS", "1"),
            ],
        )
        .await
        .expect("started");
        let banner = reqwest::get(format!("http://127.0.0.1:{port}/"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(!banner.contains("forwarding"), "healthy banner: {banner}");
        let arrived = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if collector.received().await.len() > before {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap_or(false);
        assert_eq!(arrived, expect_forwarding, "role {role}");
        if expect_forwarding {
            assert!(
                journal.path().join(CURSOR_FILE_NAME).exists(),
                "role {role}: cursor persisted"
            );
        } else {
            assert!(
                !journal.path().join(CURSOR_FILE_NAME).exists(),
                "role {role}: no shipper ran"
            );
        }
        drop(child);
    }
}

#[tokio::test]
async fn a_bad_forwarding_url_refuses_startup_at_the_binary_boundary() {
    let journal = tempfile::tempdir().unwrap();
    let stderr = start_binary(
        &["serve", "--transport", "http", "--role", "control"],
        &[
            ("MCP_AUDIT_JOURNAL_DIR", journal.path().to_str().unwrap()),
            ("MCP_AUDIT_FORWARD_URL", "kafka://siem.example/audit"),
        ],
    )
    .await
    .expect_err("must not start");
    assert!(
        stderr.contains("no audit forwarder for `kafka://`"),
        "{stderr}"
    );
    assert!(stderr.contains("refusing to start"), "{stderr}");
}

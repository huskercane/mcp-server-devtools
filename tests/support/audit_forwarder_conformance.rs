//! The adapter conformance suite for `AuditForwarder` (plan §3.9): the same
//! behavioural assertions against every adapter — in-memory, syslog over
//! TLS, Splunk HEC, generic JSON — so a new receiver is proven by running
//! the existing suite.

use std::sync::Arc;

use mcp_server_devtools::ports::{AuditForwarder, ForwardError, ForwardRecord};
use serde_json::Value;

/// What `received` resolves to.
pub type Received<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Vec<(u64, Value)>> + Send + 'a>>;
/// What `set_down` resolves to.
pub type Done<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;

/// A receiver a test can inspect and take down.
pub trait Fixture {
    fn forwarder(&self) -> Arc<dyn AuditForwarder>;
    /// Every record the receiver holds, as `(seq, the record as JSON)`, in
    /// arrival order. Async because a network receiver drains in the
    /// background.
    fn received(&self) -> Received<'_>;
    /// Make the receiver refuse (or vanish) until told otherwise. Async so
    /// a network receiver can finish closing before the next delivery.
    fn set_down(&self, down: bool) -> Done<'_>;
    /// The adapter's fixed name.
    fn name(&self) -> &'static str;
}

pub fn record<'a>(seq: u64, kind: &'a str, adverse: bool, json: &'a [u8]) -> ForwardRecord<'a> {
    ForwardRecord {
        seq,
        kind,
        timestamp: Some("2026-09-04T12:00:00.123Z"),
        adverse,
        json,
    }
}

/// Run the suite.
pub async fn conformance(fixture: &dyn Fixture) {
    let forwarder = fixture.forwarder();
    assert_eq!(forwarder.name(), fixture.name());

    // A batch is delivered whole, in order, byte for byte: the receiver
    // holds the journal's lines, not a rendering of them. One record has
    // a multi-line-looking JSON string and a non-ASCII character, so a
    // receiver that re-framed on newlines or re-encoded would show it.
    let json1 = br#"{"seq":1,"kind":"tool_call_intent","timestamp":"2026-09-04T12:00:00.123Z","tool_name":"grafana_query_logs","vendor":"grafana","decision":{"effect":"allow"}}"#;
    let json2 = r#"{"seq":2,"kind":"egress_decision","timestamp":"2026-09-04T12:00:00.124Z","decision":{"effect":"deny","reason":"line one\nline two é"}}"#.as_bytes();
    let json3 = br#"{"seq":3,"kind":"checkpoint","timestamp":"2026-09-04T12:00:00.125Z","chain":"sha256:00"}"#;
    let batch = [
        record(1, "tool_call_intent", false, json1),
        record(2, "egress_decision", true, json2),
        record(3, "checkpoint", false, json3),
    ];
    forwarder
        .deliver(&batch)
        .await
        .expect("first batch acknowledged");
    let received = fixture.received().await;
    assert_eq!(
        received.iter().map(|(seq, _)| *seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "{}: every record, in order",
        fixture.name()
    );
    for ((_, got), expected) in received
        .iter()
        .zip([json1.as_slice(), json2, json3.as_slice()])
    {
        let expected: Value = serde_json::from_slice(expected).unwrap();
        assert_eq!(
            got,
            &expected,
            "{}: record bytes survived the trip",
            fixture.name()
        );
    }

    // A second batch continues; the receiver sees no duplicate of the first.
    let json4 = br#"{"seq":4,"kind":"tool_call_outcome"}"#;
    forwarder
        .deliver(&[record(4, "tool_call_outcome", false, json4)])
        .await
        .expect("second batch acknowledged");
    assert_eq!(
        fixture
            .received()
            .await
            .iter()
            .map(|(seq, _)| *seq)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );

    // Receiver down: an error with a category from the fixed vocabulary,
    // no acknowledgement, no partial capture.
    fixture.set_down(true).await;
    let json5 = br#"{"seq":5,"kind":"tool_call_intent"}"#;
    let error = forwarder
        .deliver(&[record(5, "tool_call_intent", false, json5)])
        .await
        .expect_err("down receiver must not acknowledge");
    assert!(
        [
            ForwardError::UNREACHABLE,
            ForwardError::REJECTED,
            ForwardError::TIMEOUT,
            ForwardError::INTERRUPTED,
        ]
        .contains(&error.category),
        "{}: category {error:?}",
        fixture.name()
    );
    assert!(
        !error.to_string().contains("seq\":5"),
        "{}: error quotes the record",
        fixture.name()
    );
    assert_eq!(
        fixture.received().await.len(),
        4,
        "{}: nothing captured while down",
        fixture.name()
    );

    // Receiver back: the same batch is re-delivered and acknowledged —
    // the shipper's retry, at the adapter level (a reconnect, for syslog).
    fixture.set_down(false).await;
    forwarder
        .deliver(&[record(5, "tool_call_intent", false, json5)])
        .await
        .expect("acknowledged after recovery");
    assert_eq!(
        fixture
            .received()
            .await
            .iter()
            .map(|(seq, _)| *seq)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
}

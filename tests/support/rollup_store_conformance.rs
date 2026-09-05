//! The adapter conformance suite for `RollupStore` (plan §3.9): the same
//! rows in, the same named reports out, for every adapter — `SQLite` on a
//! file, `SQLite` in memory, and the in-memory reference. The reference's
//! reports are computed in Rust (`ports::rollup_store::compute`), so the
//! suite is also what holds the SQL to the port's semantics.

use std::sync::Arc;

use mcp_server_devtools::ports::{
    Bucket, Report, ReportQuery, RollupError, RollupStore, UsageRow, Window,
};

#[allow(clippy::too_many_arguments)]
pub fn row(
    ts: &str,
    subject: &str,
    vendor: &str,
    env: &str,
    tool: &str,
    decision: &str,
    outcome: &str,
    ms: u64,
) -> UsageRow {
    UsageRow {
        timestamp: ts.to_owned(),
        tenant: "acme".to_owned(),
        subject: subject.to_owned(),
        vendor: vendor.to_owned(),
        environment: env.to_owned(),
        tool_name: tool.to_owned(),
        decision: decision.to_owned(),
        risk: if tool.contains("post") {
            "write"
        } else {
            "read"
        }
        .to_owned(),
        outcome: outcome.to_owned(),
        duration_ms: ms,
    }
}

/// A fixed data set with every shape the reports care about.
pub fn fixture_rows() -> Vec<UsageRow> {
    vec![
        row(
            "2026-09-04T10:00:00Z",
            "alice",
            "grafana",
            "qa",
            "grafana_query_logs",
            "allow",
            "success",
            40,
        ),
        row(
            "2026-09-04T10:05:00Z",
            "alice",
            "grafana",
            "qa",
            "grafana_query_logs",
            "allow",
            "error",
            60,
        ),
        row(
            "2026-09-04T10:10:00Z",
            "alice",
            "grafana",
            "prod",
            "grafana_query_logs",
            "deny",
            "policy_denied",
            0,
        ),
        row(
            "2026-09-04T11:00:00Z",
            "bob",
            "jira",
            "prod",
            "jira_get",
            "allow",
            "success",
            100,
        ),
        row(
            "2026-09-04T11:30:00Z",
            "bob",
            "jira",
            "prod",
            "jira_post",
            "deny",
            "policy_denied",
            0,
        ),
        row(
            "2026-09-05T09:00:00Z",
            "carol",
            "slack",
            "qa",
            "slack_read_channel",
            "allow",
            "success",
            20,
        ),
        row(
            "2026-09-05T09:00:01Z",
            "carol",
            "grafana",
            "qa",
            "grafana_query_logs",
            "deny",
            "policy_denied",
            0,
        ),
    ]
}

/// Run the suite against `store` (which must start empty).
#[allow(clippy::too_many_lines)]
pub async fn conformance(store: &Arc<dyn RollupStore>) {
    assert_eq!(
        store.count().await.unwrap(),
        0,
        "{}: starts empty",
        store.name()
    );
    let empty = store
        .report(&ReportQuery::Totals {
            window: Window::all(),
        })
        .await
        .unwrap();
    assert_eq!(
        empty,
        Report::Totals(mcp_server_devtools::ports::Totals::default()),
        "{}: totals over nothing",
        store.name()
    );

    store.append(&fixture_rows()).await.unwrap();
    store.append(&[]).await.unwrap();
    assert_eq!(store.count().await.unwrap(), 7);

    // Totals, all time.
    let Report::Totals(totals) = store
        .report(&ReportQuery::Totals {
            window: Window::all(),
        })
        .await
        .unwrap()
    else {
        panic!("shape");
    };
    assert_eq!(
        (totals.rows, totals.allowed, totals.denied, totals.failed),
        (7, 4, 3, 1),
        "{}",
        store.name()
    );
    assert_eq!((totals.subjects, totals.vendors), (3, 3));
    assert!((totals.allow_share.unwrap() - 4.0 / 7.0).abs() < 1e-9);
    assert!(
        (totals.mean_duration_ms.unwrap() - 55.0).abs() < 1e-9,
        "{}: mean over allowed calls",
        store.name()
    );
    assert_eq!(
        totals.cross_environment_attempts,
        1,
        "{}: alice denied in prod after allows in qa",
        store.name()
    );
    assert_eq!(
        totals.first_timestamp.as_deref(),
        Some("2026-09-04T10:00:00Z")
    );
    assert_eq!(
        totals.last_timestamp.as_deref(),
        Some("2026-09-05T09:00:01Z")
    );

    // A window: inclusive since, exclusive until.
    let window = Window {
        since: Some("2026-09-04T10:05:00Z".into()),
        until: Some("2026-09-05T09:00:01Z".into()),
    };
    let Report::Totals(windowed) = store
        .report(&ReportQuery::Totals {
            window: window.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("shape");
    };
    assert_eq!(
        (windowed.rows, windowed.allowed, windowed.denied),
        (5, 3, 2),
        "{}",
        store.name()
    );
    assert_eq!(
        windowed.cross_environment_attempts,
        1,
        "{}: the qa allow at 10:05 is inside the window",
        store.name()
    );

    // Groups: sorted by key, per-group figures.
    let Report::Groups { rows } = store
        .report(&ReportQuery::ByPrincipal {
            window: Window::all(),
        })
        .await
        .unwrap()
    else {
        panic!("shape");
    };
    assert_eq!(
        rows.iter().map(|r| r.key.as_str()).collect::<Vec<_>>(),
        ["alice", "bob", "carol"]
    );
    assert_eq!(
        (
            rows[0].rows,
            rows[0].allowed,
            rows[0].denied,
            rows[0].failed
        ),
        (3, 2, 1, 1)
    );
    assert!((rows[0].mean_duration_ms.unwrap() - 50.0).abs() < 1e-9);
    assert_eq!(
        rows[0].first_timestamp.as_deref(),
        Some("2026-09-04T10:00:00Z")
    );
    assert_eq!(
        rows[0].last_timestamp.as_deref(),
        Some("2026-09-04T10:10:00Z")
    );
    assert_eq!((rows[2].rows, rows[2].allowed, rows[2].denied), (2, 1, 1));

    let Report::Groups { rows } = store
        .report(&ReportQuery::ByVendor {
            window: Window::all(),
        })
        .await
        .unwrap()
    else {
        panic!("shape");
    };
    assert_eq!(
        rows.iter()
            .map(|r| (r.key.as_str(), r.rows, r.denied))
            .collect::<Vec<_>>(),
        [("grafana", 4, 2), ("jira", 2, 1), ("slack", 1, 0)]
    );

    let Report::Groups { rows } = store
        .report(&ReportQuery::ByTool {
            window: Window::all(),
        })
        .await
        .unwrap()
    else {
        panic!("shape");
    };
    assert_eq!(
        rows.iter().map(|r| r.key.as_str()).collect::<Vec<_>>(),
        [
            "grafana_query_logs",
            "jira_get",
            "jira_post",
            "slack_read_channel"
        ]
    );

    let Report::Groups { rows } = store
        .report(&ReportQuery::DenialsByEnvironment {
            window: Window::all(),
        })
        .await
        .unwrap()
    else {
        panic!("shape");
    };
    assert_eq!(
        rows.iter()
            .map(|r| (r.key.as_str(), r.rows, r.allowed, r.denied))
            .collect::<Vec<_>>(),
        [("prod", 2, 0, 2), ("qa", 1, 0, 1)],
        "{}: denials only",
        store.name()
    );
    assert!(rows[0].mean_duration_ms.is_none());

    // Timeline.
    let Report::Timeline { rows } = store
        .report(&ReportQuery::Timeline {
            window: Window::all(),
            bucket: Bucket::Day,
        })
        .await
        .unwrap()
    else {
        panic!("shape");
    };
    assert_eq!(
        rows.iter()
            .map(|r| (r.bucket.as_str(), r.rows, r.allowed, r.denied))
            .collect::<Vec<_>>(),
        [("2026-09-04", 5, 3, 2), ("2026-09-05", 2, 1, 1)]
    );
    let Report::Timeline { rows } = store
        .report(&ReportQuery::Timeline {
            window: Window::all(),
            bucket: Bucket::Hour,
        })
        .await
        .unwrap()
    else {
        panic!("shape");
    };
    assert_eq!(
        rows.iter().map(|r| r.bucket.as_str()).collect::<Vec<_>>(),
        ["2026-09-04T10", "2026-09-04T11", "2026-09-05T09"]
    );

    // Prune: strictly before.
    assert_eq!(
        store.prune("2026-09-04T11:00:00Z").await.unwrap(),
        3,
        "{}",
        store.name()
    );
    assert_eq!(store.count().await.unwrap(), 4);
    assert_eq!(store.prune("2026-09-04T11:00:00Z").await.unwrap(), 0);
    let Report::Totals(after) = store
        .report(&ReportQuery::Totals {
            window: Window::all(),
        })
        .await
        .unwrap()
    else {
        panic!("shape");
    };
    assert_eq!(
        after.first_timestamp.as_deref(),
        Some("2026-09-04T11:00:00Z")
    );

    // The JSON shapes are stable (C.4 serves them): round-trip a report.
    let json = serde_json::to_value(&after).unwrap();
    assert_eq!(json["rows"], 4);
    let query: ReportQuery =
        serde_json::from_value(serde_json::json!({"report": "by_vendor", "window": {}})).unwrap();
    assert_eq!(
        query,
        ReportQuery::ByVendor {
            window: Window::all()
        }
    );
    let _: RollupError = RollupError::new(RollupError::INVALID, "shape check only");
}

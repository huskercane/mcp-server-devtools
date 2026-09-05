//! WP C.6: the `RollupStore` port across its adapters — `SQLite` on a file,
//! `SQLite` in memory, and the in-memory reference — plus the `SQLite`
//! adapter's own contract: migrations forward-only, a newer file refused,
//! reopen keeps the rows, and the consumer's batching, retry, and prune.

mod support;

use std::sync::Arc;
use std::time::Duration;

use mcp_server_devtools::ports::{
    BoundedUsageChannel, InMemoryRollupStore, Report, ReportQuery, RollupStore, UsageEvent,
    UsageSink, Window,
};
use mcp_server_devtools::rollups::{Consumer, RollupHealth, SqliteRollupStore};
use support::rollup_store_conformance::{conformance, fixture_rows};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn in_memory_store_conforms() {
    let store: Arc<dyn RollupStore> = Arc::new(InMemoryRollupStore::new());
    conformance(&store).await;
}

#[tokio::test]
async fn sqlite_in_memory_conforms() {
    let store: Arc<dyn RollupStore> = Arc::new(SqliteRollupStore::open_in_memory().unwrap());
    conformance(&store).await;
}

#[tokio::test]
async fn sqlite_file_conforms_and_survives_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rollups").join("usage.db");
    {
        let store: Arc<dyn RollupStore> = Arc::new(SqliteRollupStore::open(&path).unwrap());
        conformance(&store).await;
    }
    let reopened = SqliteRollupStore::open(&path).unwrap();
    assert_eq!(
        reopened.schema_version().unwrap(),
        SqliteRollupStore::latest_schema_version()
    );
    assert_eq!(reopened.count().await.unwrap(), 4, "rows survive a reopen");
}

#[test]
fn sqlite_refuses_a_file_from_a_newer_binary() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("usage.db");
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch("PRAGMA user_version = 99;")
            .unwrap();
    }
    let error = SqliteRollupStore::open(&path).unwrap_err();
    assert_eq!(
        error.category,
        mcp_server_devtools::ports::RollupError::CORRUPT
    );
    assert!(error.detail.contains("schema version 99"), "{error}");
}

fn event(subject: &str, decision: &str) -> UsageEvent {
    UsageEvent {
        timestamp: "2026-09-04T12:00:00Z".to_owned(),
        tenant: "acme".to_owned(),
        subject: subject.to_owned(),
        tool_name: "grafana_query_logs".to_owned(),
        vendor: "grafana".to_owned(),
        environment: "qa".to_owned(),
        decision: decision.to_owned(),
        risk: "read".to_owned(),
        outcome: if decision == "allow" {
            "success"
        } else {
            "policy_denied"
        }
        .to_owned(),
        duration_ms: 7,
    }
}

async fn wait_until(deadline: Duration, mut done: impl FnMut() -> bool) {
    tokio::time::timeout(deadline, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("condition met in time");
}

#[tokio::test]
async fn consumer_batches_events_into_the_store_and_retries_a_failing_store() {
    let (sink, receiver) = BoundedUsageChannel::new(64);
    let store = Arc::new(InMemoryRollupStore::new());
    let health = Arc::new(RollupHealth::default());
    let cancel = CancellationToken::new();
    let consumer = Consumer::new(
        Arc::clone(&store) as Arc<dyn RollupStore>,
        receiver,
        Arc::clone(&health),
        None,
    );
    let task = tokio::spawn(consumer.run(cancel.clone()));

    for _ in 0..10 {
        sink.record(event("alice", "allow"));
    }
    wait_until(Duration::from_secs(5), || health.appended() == 10).await;
    assert_eq!(store.count().await.unwrap(), 10);
    assert!(
        health.batches() <= 10,
        "linger batches, rather than one append per event"
    );

    // The store fails: events are kept and retried; the request path
    // (the sink) never notices.
    store.set_failing(true);
    sink.record(event("bob", "deny"));
    wait_until(Duration::from_secs(5), || health.degraded().is_some()).await;
    assert_eq!(
        health.degraded(),
        Some(mcp_server_devtools::ports::RollupError::UNAVAILABLE)
    );
    assert_eq!(sink.dropped(), 0);
    store.set_failing(false);
    wait_until(Duration::from_secs(10), || health.appended() == 11).await;
    assert_eq!(health.degraded(), None);
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
        rows.iter()
            .map(|r| (r.key.as_str(), r.rows))
            .collect::<Vec<_>>(),
        [("alice", 10), ("bob", 1)]
    );

    // Cancellation drains what is buffered.
    sink.record(event("carol", "allow"));
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(store.count().await.unwrap(), 12);
}

#[tokio::test]
async fn consumer_prunes_by_retention() {
    let store = Arc::new(InMemoryRollupStore::new());
    store.append(&fixture_rows()).await.unwrap();
    let (_sink, receiver) = BoundedUsageChannel::new(8);
    let health = Arc::new(RollupHealth::default());
    let consumer = Consumer::new(
        Arc::clone(&store) as Arc<dyn RollupStore>,
        receiver,
        Arc::clone(&health),
        Some(Duration::from_secs(1)),
    );
    // Everything in the fixture dated before now (the fixture reaches
    // into 2026-09-05, which may still be the future on the machine).
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let expected = fixture_rows()
        .iter()
        .filter(|row| row.timestamp < now)
        .count() as u64;
    consumer.prune(Duration::from_secs(1)).await;
    assert_eq!(health.pruned(), expected);
    assert_eq!(store.count().await.unwrap(), 7 - expected);
}

#[tokio::test]
async fn the_consumer_prunes_on_its_cadence_while_no_events_arrive() {
    // Retention must not wait for traffic: a quiet control plane still
    // applies it, or expired rows outlive the window indefinitely.
    let store = Arc::new(InMemoryRollupStore::new());
    store.append(&fixture_rows()).await.unwrap();
    let (sink, receiver) = BoundedUsageChannel::new(8);
    let health = Arc::new(RollupHealth::default());
    let cancel = CancellationToken::new();
    let consumer = Consumer::new(
        Arc::clone(&store) as Arc<dyn RollupStore>,
        receiver,
        Arc::clone(&health),
        Some(Duration::from_secs(1)),
    )
    .prune_every(Duration::from_millis(50));
    let task = tokio::spawn(consumer.run(cancel.clone()));

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let expected = fixture_rows()
        .iter()
        .filter(|row| row.timestamp < now)
        .count() as u64;
    assert!(expected > 0, "the fixture has rows to prune");
    // Nothing is recorded; the sink is only kept alive so the channel does
    // not close and end the consumer.
    wait_until(Duration::from_secs(5), || health.pruned() >= expected).await;
    assert_eq!(store.count().await.unwrap(), 7 - health.pruned());
    assert_eq!(health.appended(), 0, "no traffic was needed");

    drop(sink);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn channel_overflow_drops_with_a_counter_and_never_blocks() {
    let (sink, _receiver) = BoundedUsageChannel::new(2);
    for _ in 0..5 {
        sink.record(event("alice", "allow"));
    }
    assert_eq!(sink.dropped(), 3);
}

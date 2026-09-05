//! Rebuildable `SQLite` activity projection. A background reader consumes the
//! journal; HTTP queries only read this database. It never authorizes actions.
use super::{
    export::{ActivityExport, ActivityFilter, flatten, instant},
    reader::{JournalReader, Position},
};
use crate::ports::activity_reports::{ActivityFuture, ActivityReports, ActivityUnavailable};
use rusqlite::{Connection, params};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub struct SqliteActivityReports {
    connection: Arc<Mutex<Connection>>,
    ready: AtomicBool,
}
impl SqliteActivityReports {
    pub fn open(path: &Path) -> Result<Arc<Self>, ActivityUnavailable> {
        let connection = Connection::open(path).map_err(|_| ActivityUnavailable)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| ActivityUnavailable)?;
        connection.execute_batch("PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS activity_v1(seq INTEGER PRIMARY KEY, ts INTEGER, subject TEXT, vendor TEXT, kind TEXT NOT NULL, row_json TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS activity_v1_ts ON activity_v1(ts);")
            .map_err(|_| ActivityUnavailable)?;
        Ok(Arc::new(Self {
            connection: Arc::new(Mutex::new(connection)),
            ready: AtomicBool::new(false),
        }))
    }

    /// Start one reader. On process restart the projection is rebuilt from the
    /// source, avoiding stale rows after a journal restore or path change.
    pub fn spawn(self: &Arc<Self>, source: PathBuf, cancel: CancellationToken) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut position = Position::start();
            let mut first = true;
            loop {
                if cancel.is_cancelled() {
                    return;
                }
                let Some(store) = weak.upgrade() else {
                    return;
                };
                let worker = store.clone();
                let source = source.clone();
                let outcome =
                    tokio::task::spawn_blocking(move || worker.ingest(&source, position, first))
                        .await;
                match outcome {
                    Ok(Ok((next, caught_up))) => {
                        position = next;
                        first = false;
                        store.ready.store(caught_up, Ordering::Release);
                        if !caught_up {
                            continue;
                        }
                    }
                    _ => store.ready.store(false, Ordering::Release),
                }
                drop(store);
                tokio::select! { () = cancel.cancelled() => return, () = tokio::time::sleep(Duration::from_millis(500)) => {} }
            }
        });
    }

    fn ingest(
        &self,
        source: &Path,
        start: Position,
        first: bool,
    ) -> Result<(Position, bool), ActivityUnavailable> {
        let mut reader = JournalReader::resume(source, start).map_err(|_| ActivityUnavailable)?;
        let mut connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let transaction = connection.transaction().map_err(|_| ActivityUnavailable)?;
        if first {
            transaction
                .execute("DELETE FROM activity_v1", [])
                .map_err(|_| ActivityUnavailable)?;
        }
        let mut caught_up = false;
        for _ in 0..1000 {
            let Some(record) = reader.next() else {
                caught_up = true;
                break;
            };
            let record = record.map_err(|_| ActivityUnavailable)?;
            if record.is_checkpoint() {
                continue;
            }
            let row = flatten(record.seq, &record.kind, &record.value);
            let json = serde_json::to_string(&row).map_err(|_| ActivityUnavailable)?;
            transaction.execute("INSERT INTO activity_v1(seq,ts,subject,vendor,kind,row_json) VALUES (?1,?2,?3,?4,?5,?6)",
                params![i64::try_from(row.seq).map_err(|_| ActivityUnavailable)?, instant(&row.timestamp), row.subject, row.vendor, row.kind, json]).map_err(|_| ActivityUnavailable)?;
        }
        transaction.commit().map_err(|_| ActivityUnavailable)?;
        Ok((reader.position(), caught_up))
    }
}
impl ActivityReports for SqliteActivityReports {
    fn activity<'a>(&'a self, filter: &'a ActivityFilter) -> ActivityFuture<'a> {
        Box::pin(async move {
            if !self.ready.load(Ordering::Acquire) {
                return Err(ActivityUnavailable);
            }
            let connection = self.connection.clone();
            let filter = filter.clone();
            tokio::task::spawn_blocking(move || {
                let connection = connection
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut statement = connection
                    .prepare(
                        "SELECT row_json FROM activity_v1 WHERE
                    (?1 IS NULL OR ts >= ?1) AND (?2 IS NULL OR ts < ?2) AND
                    (?3 IS NULL OR subject = ?3) AND (?4 IS NULL OR vendor = ?4) ORDER BY seq",
                    )
                    .map_err(|_| ActivityUnavailable)?;
                let rows = statement
                    .query_map(
                        params![
                            filter.since.as_deref().and_then(instant),
                            filter.until.as_deref().and_then(instant),
                            filter.subject,
                            filter.vendor
                        ],
                        |row| row.get::<_, String>(0),
                    )
                    .map_err(|_| ActivityUnavailable)?;
                let mut export = ActivityExport::default();
                for row in rows {
                    let row: super::export::ActivityRow =
                        serde_json::from_str(&row.map_err(|_| ActivityUnavailable)?)
                            .map_err(|_| ActivityUnavailable)?;
                    export.records_read += 1;
                    if !filter.kinds.is_empty() && !filter.kinds.contains(&row.kind) {
                        continue;
                    }
                    if export.rows.len() == 10_000 {
                        export.stopped = Some("row_limit: narrow the time window".into());
                        break;
                    }
                    export.rows.push(row);
                }
                Ok(export)
            })
            .await
            .map_err(|_| ActivityUnavailable)?
        })
    }
}

//! `SQLite` adapter for [`RollupStore`] (WP C.6, the first adapter).
//!
//! One file, one connection, WAL mode, `synchronous=NORMAL` (a rollup is
//! not evidence: losing the last transaction on power loss is acceptable,
//! and the journal has the record anyway). `rusqlite` is synchronous, so
//! every operation runs under `spawn_blocking` with the connection behind a
//! `std::sync::Mutex` that is never held across an `.await`.
//!
//! ## Migrations belong here
//!
//! [`MIGRATIONS`] is an ordered list; `user_version` records how many have
//! run; opening applies the rest in one transaction each. Forward only: a
//! file whose `user_version` is *ahead* of this binary is refused, never
//! downgraded. The domain never learns the schema exists (§3.9).
//!
//! ## No SQL crosses the port
//!
//! Every report is a fixed statement here, parameterised by the window.
//! The results are the port's own types, and the conformance suite holds
//! them to the in-memory reference implementation
//! (`ports::rollup_store::compute`) row for row.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension as _, params};

use crate::ports::rollup_store::ratio;
use crate::ports::{
    Bucket, GroupRow, Report, ReportQuery, RollupError, RollupFuture, RollupStore, TimelineRow,
    Totals, UsageRow, Window,
};

/// The schema, one forward-only step per entry. Never edit an entry that
/// has shipped; append.
const MIGRATIONS: &[&str] = &[
    // 1: the usage table and the indexes the reports need.
    "CREATE TABLE usage (
        id          INTEGER PRIMARY KEY,
        ts          TEXT    NOT NULL,
        tenant      TEXT    NOT NULL,
        subject     TEXT    NOT NULL,
        vendor      TEXT    NOT NULL,
        environment TEXT    NOT NULL,
        tool        TEXT    NOT NULL,
        decision    TEXT    NOT NULL,
        risk        TEXT    NOT NULL,
        outcome     TEXT    NOT NULL,
        duration_ms INTEGER NOT NULL
    );
    CREATE INDEX usage_ts ON usage (ts);
    CREATE INDEX usage_subject_ts ON usage (subject, ts);
    CREATE INDEX usage_vendor_ts ON usage (vendor, ts);",
];

/// The `SQLite` adapter.
pub struct SqliteRollupStore {
    path: PathBuf,
    connection: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for SqliteRollupStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteRollupStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

fn unavailable(error: &rusqlite::Error) -> RollupError {
    RollupError::new(RollupError::UNAVAILABLE, error.to_string())
}

/// A count column: `SQLite` integers are `i64`; a count is never negative.
fn count(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    row.get::<_, i64>(index)
        .map(|value| u64::try_from(value).unwrap_or_default())
}

impl SqliteRollupStore {
    /// Open (creating if needed) the database at `path` and bring its
    /// schema up to date.
    ///
    /// # Errors
    ///
    /// When the file cannot be opened, a migration fails, or the file's
    /// schema is newer than this binary knows.
    pub fn open(path: &Path) -> Result<Self, RollupError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|error| {
                RollupError::new(
                    RollupError::UNAVAILABLE,
                    format!("cannot create {}: {}", parent.display(), error.kind()),
                )
            })?;
        }
        let connection = Connection::open(path).map_err(|error| unavailable(&error))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = NORMAL;
                 PRAGMA foreign_keys = ON;",
            )
            .map_err(|error| unavailable(&error))?;
        migrate(&connection)?;
        Ok(Self {
            path: path.to_path_buf(),
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// An in-process, private database — tests and `memory://`-style
    /// development without a file.
    ///
    /// # Errors
    ///
    /// When `SQLite` cannot create it.
    pub fn open_in_memory() -> Result<Self, RollupError> {
        let connection = Connection::open_in_memory().map_err(|error| unavailable(&error))?;
        migrate(&connection)?;
        Ok(Self {
            path: PathBuf::from(":memory:"),
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// The schema version the file is at.
    ///
    /// # Errors
    ///
    /// When the pragma cannot be read.
    pub fn schema_version(&self) -> Result<u32, RollupError> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        user_version(&connection)
    }

    /// How many migrations this binary knows.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // a source-controlled static slice
    pub const fn latest_schema_version() -> u32 {
        MIGRATIONS.len() as u32
    }

    /// Run `work` on the connection off the async runtime.
    async fn blocking<T, F>(&self, work: F) -> Result<T, RollupError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, RollupError> + Send + 'static,
    {
        let connection = Arc::clone(&self.connection);
        tokio::task::spawn_blocking(move || {
            let guard = connection
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            work(&guard)
        })
        .await
        .map_err(|error| RollupError::new(RollupError::UNAVAILABLE, error.to_string()))?
    }
}

fn user_version(connection: &Connection) -> Result<u32, RollupError> {
    connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
        .map_err(|error| unavailable(&error))
}

fn migrate(connection: &Connection) -> Result<(), RollupError> {
    let current = user_version(connection)?;
    let latest = SqliteRollupStore::latest_schema_version();
    if current > latest {
        return Err(RollupError::new(
            RollupError::CORRUPT,
            format!(
                "the rollup database is at schema version {current}, newer than this binary's \
                 {latest}; refusing to downgrade"
            ),
        ));
    }
    for (index, step) in MIGRATIONS.iter().enumerate().skip(current as usize) {
        let version = u32::try_from(index)
            .map_err(|_| RollupError::new(RollupError::CORRUPT, "too many migrations"))?
            + 1;
        connection
            .execute_batch(&format!(
                "BEGIN; {step}; PRAGMA user_version = {version}; COMMIT;"
            ))
            .map_err(|error| {
                RollupError::new(
                    RollupError::CORRUPT,
                    format!("migration {version} failed: {error}"),
                )
            })?;
    }
    Ok(())
}

/// `WHERE` clause and parameters for a window. Both bounds are always
/// bound (with sentinels) so the statements stay fixed.
fn bounds(window: &Window) -> (String, String) {
    (
        window.since.clone().unwrap_or_default(),
        window
            .until
            .clone()
            .unwrap_or_else(|| "\u{10FFFF}".to_owned()),
    )
}

const WINDOW: &str = "ts >= ?1 AND ts < ?2";

fn query_totals(connection: &Connection, window: &Window) -> Result<Totals, RollupError> {
    let (since, until) = bounds(window);
    let mut out = connection
        .query_row(
            &format!(
                "SELECT COUNT(*),
                        COALESCE(SUM(decision = 'allow'), 0),
                        COALESCE(SUM(decision <> 'allow'), 0),
                        COALESCE(SUM(decision = 'allow' AND outcome <> 'success'), 0),
                        COUNT(DISTINCT subject),
                        COUNT(DISTINCT vendor),
                        COALESCE(SUM(CASE WHEN decision = 'allow' THEN duration_ms END), 0),
                        MIN(ts),
                        MAX(ts)
                 FROM usage WHERE {WINDOW}"
            ),
            params![since, until],
            |row| {
                Ok((
                    count(row, 0)?,
                    count(row, 1)?,
                    count(row, 2)?,
                    count(row, 3)?,
                    count(row, 4)?,
                    count(row, 5)?,
                    count(row, 6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .map(
            |(rows, allowed, denied, failed, subjects, vendors, duration, first, last)| Totals {
                rows,
                allowed,
                denied,
                failed,
                subjects,
                vendors,
                allow_share: (rows > 0).then(|| ratio(allowed, rows)),
                mean_duration_ms: (allowed > 0).then(|| ratio(duration, allowed)),
                cross_environment_attempts: 0,
                first_timestamp: first,
                last_timestamp: last,
            },
        )
        .map_err(|error| unavailable(&error))?;
    out.cross_environment_attempts = connection
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM usage d
                 WHERE {WINDOW} AND d.decision <> 'allow' AND EXISTS (
                     SELECT 1 FROM usage a
                     WHERE a.ts >= ?1 AND a.ts < ?2 AND a.decision = 'allow'
                       AND a.subject = d.subject AND a.vendor = d.vendor
                       AND a.environment <> d.environment)"
            ),
            params![since, until],
            |row| count(row, 0),
        )
        .map_err(|error| unavailable(&error))?;
    Ok(out)
}

fn query_groups(
    connection: &Connection,
    window: &Window,
    column: &str,
    denials_only: bool,
) -> Result<Vec<GroupRow>, RollupError> {
    let (since, until) = bounds(window);
    let filter = if denials_only {
        " AND decision <> 'allow'"
    } else {
        ""
    };
    let mut statement = connection
        .prepare(&format!(
            "SELECT {column},
                    COUNT(*),
                    COALESCE(SUM(decision = 'allow'), 0),
                    COALESCE(SUM(decision <> 'allow'), 0),
                    COALESCE(SUM(decision = 'allow' AND outcome <> 'success'), 0),
                    COALESCE(SUM(CASE WHEN decision = 'allow' THEN duration_ms END), 0),
                    MIN(ts), MAX(ts)
             FROM usage WHERE {WINDOW}{filter}
             GROUP BY {column} ORDER BY {column}"
        ))
        .map_err(|error| unavailable(&error))?;
    let rows = statement
        .query_map(params![since, until], |row| {
            let allowed = count(row, 2)?;
            let duration = count(row, 5)?;
            Ok(GroupRow {
                key: row.get(0)?,
                rows: count(row, 1)?,
                allowed,
                denied: count(row, 3)?,
                failed: count(row, 4)?,
                mean_duration_ms: (allowed > 0).then(|| ratio(duration, allowed)),
                first_timestamp: row.get(6)?,
                last_timestamp: row.get(7)?,
            })
        })
        .map_err(|error| unavailable(&error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| unavailable(&error))?;
    Ok(rows)
}

fn query_timeline(
    connection: &Connection,
    window: &Window,
    bucket: Bucket,
) -> Result<Vec<TimelineRow>, RollupError> {
    let (since, until) = bounds(window);
    let width = match bucket {
        Bucket::Hour => 13,
        Bucket::Day => 10,
    };
    let mut statement = connection
        .prepare(&format!(
            "SELECT substr(ts, 1, {width}) AS bucket,
                    COUNT(*),
                    COALESCE(SUM(decision = 'allow'), 0),
                    COALESCE(SUM(decision <> 'allow'), 0)
             FROM usage WHERE {WINDOW}
             GROUP BY bucket ORDER BY bucket"
        ))
        .map_err(|error| unavailable(&error))?;
    let rows = statement
        .query_map(params![since, until], |row| {
            Ok(TimelineRow {
                bucket: row.get(0)?,
                rows: count(row, 1)?,
                allowed: count(row, 2)?,
                denied: count(row, 3)?,
            })
        })
        .map_err(|error| unavailable(&error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| unavailable(&error))?;
    Ok(rows)
}

impl RollupStore for SqliteRollupStore {
    fn name(&self) -> &'static str {
        "sqlite"
    }

    fn append<'a>(&'a self, rows: &'a [UsageRow]) -> RollupFuture<'a, ()> {
        let rows = rows.to_vec();
        Box::pin(async move {
            if rows.is_empty() {
                return Ok(());
            }
            self.blocking(move |connection| {
                let transaction = connection
                    .unchecked_transaction()
                    .map_err(|error| unavailable(&error))?;
                {
                    let mut insert = transaction
                        .prepare_cached(
                            "INSERT INTO usage (ts, tenant, subject, vendor, environment, tool, \
                             decision, risk, outcome, duration_ms) \
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        )
                        .map_err(|error| unavailable(&error))?;
                    for row in &rows {
                        insert
                            .execute(params![
                                row.timestamp,
                                row.tenant,
                                row.subject,
                                row.vendor,
                                row.environment,
                                row.tool_name,
                                row.decision,
                                row.risk,
                                row.outcome,
                                i64::try_from(row.duration_ms).unwrap_or(i64::MAX),
                            ])
                            .map_err(|error| unavailable(&error))?;
                    }
                }
                transaction.commit().map_err(|error| unavailable(&error))
            })
            .await
        })
    }

    fn report<'a>(&'a self, query: &'a ReportQuery) -> RollupFuture<'a, Report> {
        let query = query.clone();
        Box::pin(async move {
            self.blocking(move |connection| match &query {
                ReportQuery::Totals { window } => {
                    query_totals(connection, window).map(Report::Totals)
                }
                ReportQuery::ByPrincipal { window } => {
                    query_groups(connection, window, "subject", false)
                        .map(|rows| Report::Groups { rows })
                }
                ReportQuery::ByVendor { window } => {
                    query_groups(connection, window, "vendor", false)
                        .map(|rows| Report::Groups { rows })
                }
                ReportQuery::ByTool { window } => query_groups(connection, window, "tool", false)
                    .map(|rows| Report::Groups { rows }),
                ReportQuery::DenialsByEnvironment { window } => {
                    query_groups(connection, window, "environment", true)
                        .map(|rows| Report::Groups { rows })
                }
                ReportQuery::Timeline { window, bucket } => {
                    query_timeline(connection, window, *bucket)
                        .map(|rows| Report::Timeline { rows })
                }
            })
            .await
        })
    }

    fn prune<'a>(&'a self, before: &'a str) -> RollupFuture<'a, u64> {
        let before = before.to_owned();
        Box::pin(async move {
            self.blocking(move |connection| {
                connection
                    .execute("DELETE FROM usage WHERE ts < ?1", params![before])
                    .map(|deleted| deleted as u64)
                    .map_err(|error| unavailable(&error))
            })
            .await
        })
    }

    fn count(&self) -> RollupFuture<'_, u64> {
        Box::pin(async move {
            self.blocking(|connection| {
                connection
                    .query_row("SELECT COUNT(*) FROM usage", [], |row| count(row, 0))
                    .optional()
                    .map(Option::unwrap_or_default)
                    .map_err(|error| unavailable(&error))
            })
            .await
        })
    }
}

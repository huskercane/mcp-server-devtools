//! Usage rollups (plan §3.9 "Usage rollups and reports", WP C.6): the
//! adapters behind [`crate::ports::RollupStore`] and the consumer that
//! feeds them from the lossy usage channel.
//!
//! - [`sqlite`] is the first adapter: one embedded file, migrations owned
//!   here and applied forward-only at open, WAL journaling. It is a
//!   *first-adapter choice*, not the design (§3.9): a partner who will not
//!   run a file database on `control` gets a `PostgreSQL` adapter behind the
//!   same port, and `postgres://` is already a typed "not compiled in"
//!   refusal so the intent is visible.
//! - [`consumer`] drains the [`crate::ports::BoundedUsageChannel`] into a
//!   store in batches, off the request path, and prunes on a cadence.
//!
//! Selection is a URI in `MCP_ROLLUP_STORE` (`sqlite:///path`,
//! `memory://` for development, `postgres://…` refused by name), resolved
//! in `bootstrap/rollups.rs` and nowhere else.

pub mod consumer;
pub mod sqlite;

pub use consumer::{Consumer, RollupHealth};
pub use sqlite::SqliteRollupStore;

/// Config key: the rollup store URI. Setting it enables rollups on the
/// roles that serve the control plane.
pub const STORE_KEY: &str = "MCP_ROLLUP_STORE";
/// Config key: days of usage kept (default 90; `0` keeps everything).
pub const RETENTION_DAYS_KEY: &str = "MCP_ROLLUP_RETENTION_DAYS";
/// Config key: how many usage events the channel holds before dropping
/// (default 4096, 64–65536).
pub const CHANNEL_CAPACITY_KEY: &str = "MCP_USAGE_CHANNEL_CAPACITY";

pub const DEFAULT_RETENTION_DAYS: u64 = 90;
pub const DEFAULT_CHANNEL_CAPACITY: usize = 4096;

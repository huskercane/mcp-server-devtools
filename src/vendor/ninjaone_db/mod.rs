#![allow(clippy::doc_markdown)]

//! Read-only PostgreSQL access for allowlisted NinjaOne QA/dev environments.
//!
//! The caller selects an environment alias and, for a division query, a
//! `db_host` key returned by `centraldb.division`. Network hostnames are always
//! resolved from `NINJAONE_DB_ENVIRONMENTS`; no tool accepts a raw hostname.
//!
//! ## Where each concern lives
//!
//! - [`environments`] owns the config document: what it means, and which
//!   environments, hosts, and database names a caller may address.
//! - [`read_only_sql`] owns the guard on caller-supplied SQL.
//! - [`crate::vendor::postgres`] owns the connection mechanics, shared with
//!   [`wrds`](crate::vendor::wrds).
//!
//! What is left here is this vendor's own session policy: a read-only
//! transaction, a row cap, and the three queries the tools expose.

pub mod environments;
pub mod read_only_sql;

use std::sync::RwLock;
use std::time::Duration;

use serde_json::Value;
use tokio_postgres::types::ToSql;

use crate::config::{Config, VENDOR_NINJAONE};
use crate::error::{McpError, api_error, auth_missing};
use crate::vendor::postgres::{self, ConnectSpec, PgVendor, TlsCache};

use environments::{Environments, Target};

pub const DEFAULT_ROW_LIMIT: u32 = 500;
pub const MAX_ROW_LIMIT: u32 = 10_000;
/// Row cap for `resolve_division`. The lookup is a human disambiguation aid,
/// not a data export, so it is capped far below the general limit.
const RESOLVE_LIMIT: u32 = 25;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const APPLICATION_NAME: &str = "mcp-devtools-ninjaone-readonly";

/// Identity and session policy this vendor hands the shared Postgres adapter.
const PG: PgVendor = PgVendor::new("NinjaOne database", Duration::from_secs(10));

/// Read-only Postgres access to the configured NinjaOne QA/dev environments.
///
/// Holds two lazily-populated caches and no connection: the TLS client config,
/// and the parsed environment document keyed by the raw config text it came
/// from. Both are rebuilt on demand, so a runtime config reload is picked up on
/// the next call without a restart.
#[derive(Default)]
pub struct NinjaOneDbVendor {
    tls: TlsCache,
    environments: RwLock<Option<CachedEnvironments>>,
}

/// A parsed document plus the exact config text it was parsed from. The raw
/// text is the cache key: `NINJAONE_DB_ENVIRONMENTS` can change under a running
/// server, and comparing the source is both cheaper and more obviously correct
/// than tracking a version counter.
struct CachedEnvironments {
    raw: String,
    parsed: Environments,
}

impl NinjaOneDbVendor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn resolve_division(
        &self,
        config: &Config,
        environment: &str,
        lookup: &str,
    ) -> Result<Value, McpError> {
        const SQL: &str = "SELECT uid, db_name, db_host, db_zone, db_state, \
             ltdr_shard_id, hostname \
             FROM division \
             WHERE uid::text = $1 \
                OR db_name = $1 \
                OR db_host = $1 \
                OR lower(db_name) LIKE '%' || lower($1) || '%' \
                OR lower(coalesce(hostname, '')) LIKE '%' || lower($1) || '%' \
             ORDER BY CASE \
                 WHEN uid::text = $1 THEN 0 \
                 WHEN db_name = $1 THEN 1 \
                 WHEN db_host = $1 THEN 2 \
                 ELSE 3 END, db_name";

        let lookup = lookup.trim();
        if lookup.is_empty() {
            return Err(invalid_input("division lookup must not be blank"));
        }
        let environments = self.environments(config)?;
        let (_, env) = environments.get(environment)?;
        let target = env.central_target()?;
        self.query_json(&target, SQL, &[&lookup], RESOLVE_LIMIT)
            .await
    }

    pub async fn query_central(
        &self,
        config: &Config,
        environment: &str,
        sql: &str,
        limit: u32,
    ) -> Result<Value, McpError> {
        read_only_sql::validate(sql)?;
        let environments = self.environments(config)?;
        let (_, env) = environments.get(environment)?;
        let target = env.central_target()?;
        self.query_json(&target, sql, &[], limit).await
    }

    pub async fn query_division(
        &self,
        config: &Config,
        environment: &str,
        db_host: Option<&str>,
        db_name: &str,
        sql: &str,
        limit: u32,
    ) -> Result<Value, McpError> {
        read_only_sql::validate(sql)?;
        let environments = self.environments(config)?;
        let (alias, env) = environments.get(environment)?;
        let target = env.division_target(db_host, db_name, &alias)?;
        self.query_json(&target, sql, &[], limit).await
    }

    /// The parsed environment document for the current config, parsing it only
    /// when the underlying text differs from what was last parsed.
    fn environments(&self, config: &Config) -> Result<Environments, McpError> {
        let raw = config
            .get_for(VENDOR_NINJAONE, "NINJAONE_DB_ENVIRONMENTS")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                auth_missing(
                    "NINJAONE_DB_ENVIRONMENTS is required for NinjaOne database tools. Set it under the `ninjaone` section of ~/.mcp/configs.json, either as a nested JSON object or as a JSON-encoded string.",
                )
            })?;

        if let Some(cached) = self.read_cache()
            && cached.raw == raw
        {
            return Ok(cached.parsed);
        }

        let parsed = Environments::parse(raw)?;
        // A poisoned lock only means some other caller panicked mid-parse; the
        // cache is a pure optimisation, so recovering is correct.
        *self
            .environments
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(CachedEnvironments {
            raw: raw.to_owned(),
            parsed: parsed.clone(),
        });
        Ok(parsed)
    }

    fn read_cache(&self) -> Option<CachedEnvironments> {
        let guard = self
            .environments
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.as_ref().map(|cached| CachedEnvironments {
            raw: cached.raw.clone(),
            parsed: cached.parsed.clone(),
        })
    }

    /// Run one query inside an explicit read-only transaction and return the
    /// rows as a JSON array.
    ///
    /// The read-only transaction is this vendor's own layer on top of the
    /// session-level settings: these are shared QA/dev databases other people
    /// depend on, so a write is refused by the server even if the SQL guard and
    /// the session options were both somehow bypassed.
    async fn query_json(
        &self,
        target: &Target,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
        limit: u32,
    ) -> Result<Value, McpError> {
        let mut client = self.connect(target).await?;
        client
            .batch_execute(&PG.read_only_session_sql())
            .await
            .map_err(|err| PG.classify(&err))?;

        let transaction = client
            .build_transaction()
            .read_only(true)
            .start()
            .await
            .map_err(|err| PG.classify(&err))?;
        let wrapped = postgres::wrap_query(sql, limit);
        let row = transaction
            .query_one(&wrapped, params)
            .await
            .map_err(|err| PG.classify(&err))?;
        let result = row.try_get(0).map_err(|err| PG.decode_error(&err))?;
        transaction
            .commit()
            .await
            .map_err(|err| PG.classify(&err))?;
        Ok(result)
    }

    async fn connect(&self, target: &Target) -> Result<tokio_postgres::Client, McpError> {
        postgres::connect(
            &self.tls,
            PG,
            ConnectSpec {
                host: &target.host,
                port: target.port,
                database: &target.database,
                user: &target.username,
                password: &target.password,
                ssl_mode: target.ssl_mode,
                allow_invalid_certificates: target.allow_invalid_certificates,
                application_name: APPLICATION_NAME,
                connect_timeout: CONNECT_TIMEOUT,
                startup_options: Some(PG.connect_options()),
            },
        )
        .await
    }
}

/// Clamp a caller-supplied row limit into `[1, MAX_ROW_LIMIT]`, defaulting when
/// absent.
#[must_use]
pub fn clamp_row_limit(requested: Option<u32>) -> u32 {
    requested
        .unwrap_or(DEFAULT_ROW_LIMIT)
        .clamp(1, MAX_ROW_LIMIT)
}

/// A caller-fixable input problem: the same 400 the HTTP vendors return for a
/// bad request.
pub(crate) fn invalid_input(message: impl Into<String>) -> McpError {
    api_error(message.into(), Some(400), None)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config_with_environments(json: &str) -> Config {
        Config::from_map(HashMap::from([(
            "NINJAONE_DB_ENVIRONMENTS".to_owned(),
            json.to_owned(),
        )]))
    }

    #[test]
    fn row_limit_is_bounded() {
        assert_eq!(clamp_row_limit(None), DEFAULT_ROW_LIMIT);
        assert_eq!(clamp_row_limit(Some(0)), 1);
        assert_eq!(clamp_row_limit(Some(u32::MAX)), MAX_ROW_LIMIT);
    }

    #[test]
    fn missing_environment_document_is_an_auth_error() {
        let vendor = NinjaOneDbVendor::new();
        let error = vendor
            .environments(&Config::from_map(HashMap::new()))
            .unwrap_err();
        assert!(
            error
                .message
                .contains("NINJAONE_DB_ENVIRONMENTS is required")
        );
    }

    #[test]
    fn document_is_parsed_once_per_config_revision() {
        let vendor = NinjaOneDbVendor::new();
        let first = config_with_environments(
            r#"{"qa5":{"centralHost":"central.qa5.internal","divisionHosts":{"host-1":"division-1.qa5.internal"},"username":"reader","password":"secret"}}"#,
        );
        vendor.environments(&first).unwrap();
        assert!(vendor.read_cache().is_some());
        // Same text: the cached document answers without reparsing.
        assert!(vendor.environments(&first).unwrap().get("qa5").is_ok());

        // A runtime config reload changes the text, so the next call reparses
        // rather than serving a document the operator has replaced.
        let second = config_with_environments(
            r#"{"dev1":{"centralHost":"central.dev1.internal","divisionHosts":{"h":"d.dev1.internal"},"username":"reader","password":"secret"}}"#,
        );
        let environments = vendor.environments(&second).unwrap();
        assert!(environments.get("qa5").is_err());
        assert!(environments.get("dev1").is_ok());
    }

    #[tokio::test]
    async fn refuses_unconfigured_db_host_before_connecting() {
        let config = config_with_environments(
            r#"{"dev-backup2":{"centralHost":"central.dev.internal","divisionHosts":{"known-host":"division.dev.internal"},"username":"reader","password":"secret","sslMode":"disable"}}"#,
        );
        let error = NinjaOneDbVendor::new()
            .query_division(
                &config,
                "dev-backup2",
                Some("attacker.example.com"),
                "div_acme_Ab12Cd34Ef",
                "SELECT 1",
                1,
            )
            .await
            .unwrap_err();
        assert!(error.message.contains("is not allowlisted"));
    }

    #[tokio::test]
    async fn refuses_a_write_before_connecting() {
        let config = config_with_environments(
            r#"{"qa5":{"centralHost":"central.qa5.internal","divisionHosts":{"h":"d"},"username":"reader","password":"secret"}}"#,
        );
        let error = NinjaOneDbVendor::new()
            .query_central(&config, "qa5", "DELETE FROM device", 1)
            .await
            .unwrap_err();
        assert!(error.message.contains("is not allowed"));
    }
}

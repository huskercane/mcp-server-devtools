#![allow(clippy::doc_markdown)]

//! The `NINJAONE_DB_ENVIRONMENTS` document: parsing, validation, and the
//! allowlists it encodes.
//!
//! This module owns every decision about *which* database a tool call is
//! permitted to reach — environment aliases, division host keys, division
//! database names. None of it touches a socket, so all of it is testable
//! without a Postgres server.
//!
//! ## Whole-document validation is deliberate
//!
//! [`Environments::parse`] validates every entry, not just the one being
//! requested. A document containing a `prod` key is refused outright, so a
//! `qa5` query fails too. That is the intended behaviour: a config file that
//! holds production credentials next to QA ones is a mistake an operator needs
//! to see immediately, and partially honouring such a file would hide it.

use std::collections::BTreeMap;

use serde::Deserialize;
use tokio_postgres::config::SslMode;

use crate::error::McpError;

use super::invalid_input;

const DEFAULT_PORT: u16 = 5432;
const DEFAULT_CENTRAL_DATABASE: &str = "centraldb";
/// Postgres' own identifier limit; a longer name cannot name a real database.
const MAX_DB_NAME_LEN: usize = 63;

/// One environment exactly as written in the config document. Field names are
/// camelCase because the document is hand-edited JSON.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Environment {
    pub central_host: String,
    #[serde(default = "default_central_database")]
    pub central_database: String,
    pub division_hosts: BTreeMap<String, DivisionHost>,
    pub username: String,
    pub password: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_ssl_mode")]
    ssl_mode: String,
    /// Permit TLS connections whose certificate is not trusted by the OS or
    /// does not match the configured hostname. This is deliberately separate
    /// from `sslMode`: `prefer` controls TLS fallback, not authentication.
    #[serde(default)]
    pub allow_invalid_certificates: bool,
}

/// One allowlisted division database server. The object form is self-contained
/// because a division server may use credentials and connection settings that
/// differ from the environment's central database. A hostname string remains
/// accepted for compatibility and inherits the central connection settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum DivisionHost {
    Inherited(String),
    Separate(DivisionConnection),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DivisionConnection {
    pub host: String,
    pub username: String,
    pub password: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_ssl_mode")]
    ssl_mode: String,
    #[serde(default)]
    pub allow_invalid_certificates: bool,
}

fn default_central_database() -> String {
    DEFAULT_CENTRAL_DATABASE.to_owned()
}

const fn default_port() -> u16 {
    DEFAULT_PORT
}

fn default_ssl_mode() -> String {
    "require".to_owned()
}

/// Where one query is allowed to connect. Always derived from an
/// [`Environment`]; a hostname never originates from a tool argument.
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub database: String,
    pub username: String,
    pub password: String,
    pub port: u16,
    pub ssl_mode: SslMode,
    pub allow_invalid_certificates: bool,
}

impl Environment {
    /// The central (`centraldb`) database for this environment.
    pub fn central_target(&self) -> Result<Target, McpError> {
        Ok(Target {
            host: self.central_host.clone(),
            database: self.central_database.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            port: self.port,
            ssl_mode: self.ssl_mode()?,
            allow_invalid_certificates: self.allow_invalid_certificates,
        })
    }

    /// A division database, addressed by an allowlisted `db_host` key from
    /// `centraldb.division` plus the division's own database name. When the
    /// central row has no host key, a single configured division host is
    /// unambiguous and is selected automatically.
    ///
    /// Both caller inputs are checked here: the host key must be one this
    /// environment declares (the caller never supplies a hostname), and the
    /// database name must match the division naming convention.
    pub fn division_target(
        &self,
        db_host: Option<&str>,
        db_name: &str,
        alias: &str,
    ) -> Result<Target, McpError> {
        let host_key = match db_host.map(str::trim).filter(|key| !key.is_empty()) {
            Some(key) => key,
            None if self.division_hosts.len() == 1 => self
                .division_hosts
                .keys()
                .next()
                .expect("a single-entry map has a key"),
            None => {
                return Err(invalid_input(format!(
                    "db_host is required for environment `{alias}` because it has multiple allowlisted divisionHosts"
                )));
            }
        };
        let connection = self.division_hosts.get(host_key).ok_or_else(|| {
            invalid_input(format!(
                "db_host `{host_key}` is not allowlisted for environment `{alias}`"
            ))
        })?;
        let database = validated_db_name(db_name)?.to_owned();
        match connection {
            DivisionHost::Inherited(host) => Ok(Target {
                host: host.clone(),
                database,
                username: self.username.clone(),
                password: self.password.clone(),
                port: self.port,
                ssl_mode: self.ssl_mode()?,
                allow_invalid_certificates: self.allow_invalid_certificates,
            }),
            DivisionHost::Separate(connection) => Ok(Target {
                host: connection.host.clone(),
                database,
                username: connection.username.clone(),
                password: connection.password.clone(),
                port: connection.port,
                ssl_mode: parse_ssl_mode(&connection.ssl_mode)?,
                allow_invalid_certificates: connection.allow_invalid_certificates,
            }),
        }
    }

    fn ssl_mode(&self) -> Result<SslMode, McpError> {
        parse_ssl_mode(&self.ssl_mode)
    }

    fn validate(&self, alias: &str) -> Result<(), McpError> {
        if self.central_host.trim().is_empty()
            || self.central_database.trim().is_empty()
            || self.username.trim().is_empty()
            || self.password.is_empty()
            || self.division_hosts.is_empty()
        {
            return Err(invalid_input(format!(
                "environment `{alias}` must define non-empty centralHost, centralDatabase, divisionHosts, username, and password values"
            )));
        }
        for (key, connection) in &self.division_hosts {
            if key.trim().is_empty() || !connection.is_valid() {
                return Err(invalid_input(format!(
                    "environment `{alias}` contains a blank divisionHosts key or incomplete connection; object entries require non-empty host, username, and password values"
                )));
            }
            connection.ssl_mode()?;
        }
        self.ssl_mode()?;
        Ok(())
    }
}

impl DivisionHost {
    fn is_valid(&self) -> bool {
        match self {
            Self::Inherited(host) => !host.trim().is_empty(),
            Self::Separate(connection) => {
                !connection.host.trim().is_empty()
                    && !connection.username.trim().is_empty()
                    && !connection.password.is_empty()
            }
        }
    }

    fn ssl_mode(&self) -> Result<SslMode, McpError> {
        match self {
            Self::Inherited(_) => Ok(SslMode::Require),
            Self::Separate(connection) => parse_ssl_mode(&connection.ssl_mode),
        }
    }
}

/// A parsed and fully validated `NINJAONE_DB_ENVIRONMENTS` document.
///
/// Constructing one is the only way to reach an [`Environment`], so every
/// environment handed to the connection path has already passed validation.
#[derive(Debug, Clone)]
pub struct Environments {
    entries: BTreeMap<String, Environment>,
}

impl Environments {
    /// Parse and validate the whole document. See the module docs on why a
    /// single bad entry rejects the lot.
    pub fn parse(raw: &str) -> Result<Self, McpError> {
        let entries: BTreeMap<String, Environment> = serde_json::from_str(raw).map_err(|err| {
            invalid_input(format!(
                "NINJAONE_DB_ENVIRONMENTS must be a valid JSON object: {err}"
            ))
        })?;
        for (alias, environment) in &entries {
            validate_alias(alias)?;
            environment.validate(alias)?;
        }
        Ok(Self { entries })
    }

    /// Look up an environment by the alias a tool caller asked for. The lookup
    /// is case-insensitive; the alias syntax/scope rules still apply, so a
    /// caller cannot reach a non-qa/dev name even by spelling.
    pub fn get(&self, requested: &str) -> Result<(String, &Environment), McpError> {
        let alias = normalize_alias(requested);
        validate_alias(&alias)?;
        let environment = self.entries.get(&alias).ok_or_else(|| {
            invalid_input(format!(
                "environment `{alias}` is not in the configured QA/dev allowlist"
            ))
        })?;
        Ok((alias, environment))
    }
}

fn normalize_alias(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

/// Aliases are restricted to `qa*` / `dev*` in a conservative character set.
/// The scope rule is the actual security boundary — production is unsupported
/// by construction, not by omission — and the character set keeps an alias from
/// carrying path or separator tricks into an error message or a lookup.
fn validate_alias(alias: &str) -> Result<(), McpError> {
    let syntax_ok = !alias.is_empty()
        && alias.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        });
    let scope_ok = alias.starts_with("qa") || alias.starts_with("dev");
    if !syntax_ok || !scope_ok {
        return Err(invalid_input(format!(
            "environment alias `{alias}` is refused: NinjaOne database access is restricted to aliases beginning with `qa` or `dev`; production is intentionally unsupported"
        )));
    }
    Ok(())
}

fn parse_ssl_mode(value: &str) -> Result<SslMode, McpError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "disable" => Ok(SslMode::Disable),
        "prefer" => Ok(SslMode::Prefer),
        "require" => Ok(SslMode::Require),
        other => Err(invalid_input(format!(
            "unsupported NinjaOne database sslMode `{other}`; use disable, prefer, or require"
        ))),
    }
}

/// Division databases are named `div_<company>_<suffix>`. Constraining the name
/// keeps a caller from addressing `centraldb` (or anything else) through the
/// division tool, and the character set keeps it a plain identifier.
fn validated_db_name(db_name: &str) -> Result<&str, McpError> {
    let db_name = db_name.trim();
    if db_name.len() > MAX_DB_NAME_LEN
        || !db_name.starts_with("div_")
        || !db_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(invalid_input(
            "db_name must follow the NinjaOne division database convention `div_<company>_<suffix>` using only letters, digits, and underscores",
        ));
    }
    Ok(db_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_ENV: &str = r#"{"qa5":{"centralHost":"central.qa5.internal","divisionHosts":{"host-1":"division-1.qa5.internal"},"username":"reader","password":"secret"}}"#;

    #[test]
    fn applies_defaults_and_is_case_insensitive_on_lookup() {
        let environments = Environments::parse(ONE_ENV).unwrap();
        let (alias, environment) = environments.get("QA5").unwrap();
        assert_eq!(alias, "qa5");
        assert_eq!(environment.central_database, "centraldb");
        assert_eq!(environment.port, 5432);
        assert_eq!(
            environment.central_target().unwrap().ssl_mode,
            SslMode::Require
        );
        assert!(!environment.allow_invalid_certificates);
    }

    #[test]
    fn environment_aliases_are_qa_or_dev_only() {
        for alias in ["qa5", "qa-west_2", "dev-backup2"] {
            validate_alias(alias).unwrap();
        }
        for alias in ["prod", "production", "stage", "qa/../../prod", "QA5"] {
            assert!(validate_alias(alias).is_err(), "accepted {alias}");
        }
    }

    #[test]
    fn refuses_any_document_containing_a_production_alias() {
        let error = Environments::parse(
            r#"{"qa5":{"centralHost":"qa","divisionHosts":{"h":"d"},"username":"reader","password":"secret"},"prod":{"centralHost":"prod","divisionHosts":{"h":"prod"},"username":"reader","password":"secret"}}"#,
        )
        .unwrap_err();
        assert!(
            error
                .message
                .contains("production is intentionally unsupported")
        );
    }

    #[test]
    fn division_target_enforces_host_allowlist_and_name_convention() {
        let environments = Environments::parse(ONE_ENV).unwrap();
        let (alias, environment) = environments.get("qa5").unwrap();

        let target = environment
            .division_target(Some("host-1"), "div_acme_Ab12Cd34Ef", &alias)
            .unwrap();
        assert_eq!(target.host, "division-1.qa5.internal");
        assert_eq!(target.database, "div_acme_Ab12Cd34Ef");

        let denied = environment
            .division_target(Some("attacker.example.com"), "div_acme_Ab12Cd34Ef", &alias)
            .unwrap_err();
        assert!(denied.message.contains("is not allowlisted"));

        for name in ["centraldb", "div_acme;drop", "div/acme", ""] {
            assert!(
                environment
                    .division_target(Some("host-1"), name, &alias)
                    .is_err(),
                "accepted {name}"
            );
        }
    }

    #[test]
    fn division_target_uses_only_host_when_db_host_is_absent() {
        let environments = Environments::parse(ONE_ENV).unwrap();
        let (alias, environment) = environments.get("qa5").unwrap();

        let target = environment
            .division_target(None, "div_acme_Ab12Cd34Ef", &alias)
            .unwrap();

        assert_eq!(target.host, "division-1.qa5.internal");
        assert_eq!(target.username, "reader");
        assert_eq!(target.password, "secret");
    }

    #[test]
    fn division_target_uses_its_own_complete_connection() {
        let environments = Environments::parse(
            r#"{"qa5":{"centralHost":"central","divisionHosts":{"host-1":{"host":"division","username":"division_reader","password":"division_secret","port":6432,"sslMode":"disable","allowInvalidCertificates":true}},"username":"central_reader","password":"central_secret"}}"#,
        )
        .unwrap();
        let (alias, environment) = environments.get("qa5").unwrap();

        let central = environment.central_target().unwrap();
        let division = environment
            .division_target(Some("host-1"), "div_acme_123", &alias)
            .unwrap();

        assert_eq!(central.username, "central_reader");
        assert_eq!(central.password, "central_secret");
        assert_eq!(central.port, 5432);
        assert_eq!(division.host, "division");
        assert_eq!(division.username, "division_reader");
        assert_eq!(division.password, "division_secret");
        assert_eq!(division.port, 6432);
        assert_eq!(division.ssl_mode, SslMode::Disable);
        assert!(division.allow_invalid_certificates);
    }

    #[test]
    fn division_target_requires_db_host_when_multiple_hosts_are_configured() {
        let environments = Environments::parse(
            r#"{"qa5":{"centralHost":"c","divisionHosts":{"host-1":"d1","host-2":"d2"},"username":"r","password":"s"}}"#,
        )
        .unwrap();
        let (alias, environment) = environments.get("qa5").unwrap();

        let error = environment
            .division_target(None, "div_acme_Ab12Cd34Ef", &alias)
            .unwrap_err();

        assert!(error.message.contains("multiple allowlisted divisionHosts"));
    }

    #[test]
    fn rejects_blank_fields_and_unknown_ssl_modes() {
        for document in [
            r#"{"qa5":{"centralHost":"","divisionHosts":{"h":"d"},"username":"r","password":"s"}}"#,
            r#"{"qa5":{"centralHost":"c","divisionHosts":{},"username":"r","password":"s"}}"#,
            r#"{"qa5":{"centralHost":"c","divisionHosts":{"h":" "},"username":"r","password":"s"}}"#,
            r#"{"qa5":{"centralHost":"c","divisionHosts":{"h":{"host":"d","username":"","password":"s"}},"username":"r","password":"s"}}"#,
            r#"{"qa5":{"centralHost":"c","divisionHosts":{"h":{"host":"d","username":"r","password":"s","sslMode":"verify-full"}},"username":"r","password":"s"}}"#,
            r#"{"qa5":{"centralHost":"c","divisionHosts":{"h":"d"},"username":"r","password":"s","sslMode":"verify-full"}}"#,
        ] {
            assert!(
                Environments::parse(document).is_err(),
                "accepted {document}"
            );
        }
    }

    #[test]
    fn carries_explicit_invalid_certificate_opt_in_to_targets() {
        let environments = Environments::parse(
            r#"{"qa5":{"centralHost":"c","divisionHosts":{"h":"d"},"username":"r","password":"s","allowInvalidCertificates":true}}"#,
        )
        .unwrap();
        let (_, environment) = environments.get("qa5").unwrap();

        assert!(
            environment
                .central_target()
                .unwrap()
                .allow_invalid_certificates
        );
        assert!(
            environment
                .division_target(Some("h"), "div_acme_123", "qa5")
                .unwrap()
                .allow_invalid_certificates
        );
    }
}

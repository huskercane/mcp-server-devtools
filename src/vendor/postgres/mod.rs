#![allow(clippy::doc_markdown)]

//! Shared PostgreSQL adapter plumbing for the two non-HTTP vendors.
//!
//! [`wrds`](crate::vendor::wrds) and [`ninjaone_db`](crate::vendor::ninjaone_db)
//! are both direct Postgres connections rather than REST APIs, so neither rides
//! the HTTP [`Vendor`](crate::vendor::Vendor) trait. What they do share is the
//! whole mechanical layer underneath their queries: building and caching a
//! rustls client config from the OS trust store, dialling with a spawned driver
//! task, wrapping a caller `SELECT` so Postgres aggregates it to JSONB
//! server-side, and mapping [`tokio_postgres::Error`] onto the crate's
//! [`McpError`] envelope.
//!
//! That mechanism is identical for both; only the *policy* differs (which
//! credentials, which hosts are reachable, whether the caller's SQL is
//! pre-validated, whether the query runs inside an explicit read-only
//! transaction). So this module owns the mechanism and each vendor keeps its own
//! policy — no trait, no port: there is exactly one way to speak the Postgres
//! wire protocol here, and inventing an interface over it would buy nothing.
//!
//! Vendor identity travels as a [`PgVendor`] value purely so error messages name
//! the right integration.

pub mod error;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio_postgres::Config as PgConfig;
use tokio_postgres::config::SslMode;
use tokio_postgres::{Client, NoTls};
use tokio_postgres_rustls::MakeRustlsConnect;
use tracing::debug;

use crate::error::{McpError, OriginalError, api_error};

/// Which integration a connection belongs to. Carried only so errors and log
/// lines name the right vendor, and so the statement timeout each one pins is
/// reported in its own timeout message.
#[derive(Debug, Clone, Copy)]
pub struct PgVendor {
    /// Human-facing name used to prefix every error (`"WRDS"`,
    /// `"NinjaOne database"`).
    pub name: &'static str,
    /// Per-statement timeout this vendor pins on every session.
    pub statement_timeout: Duration,
}

impl PgVendor {
    pub const fn new(name: &'static str, statement_timeout: Duration) -> Self {
        Self {
            name,
            statement_timeout,
        }
    }

    /// Statement timeout in the milliseconds Postgres wants. Saturating rather
    /// than truncating: a caller-configured absurd timeout should clamp, not
    /// silently wrap to a short one.
    #[must_use]
    pub fn statement_timeout_ms(&self) -> u32 {
        u32::try_from(self.statement_timeout.as_millis()).unwrap_or(u32::MAX)
    }

    /// `SET` statements pinning a session read-only with this vendor's
    /// statement timeout. Both values are server-controlled — never caller
    /// input — so interpolating them is safe.
    #[must_use]
    pub fn read_only_session_sql(&self) -> String {
        format!(
            "SET default_transaction_read_only = on; \
             SET statement_timeout = {};",
            self.statement_timeout_ms()
        )
    }

    /// Postgres `options` string applying the same two settings at connection
    /// time, so a session is read-only from its first statement rather than
    /// from the first `SET` round-trip.
    #[must_use]
    pub fn connect_options(&self) -> String {
        format!(
            "-c default_transaction_read_only=on -c statement_timeout={}",
            self.statement_timeout_ms()
        )
    }

    /// Map a [`tokio_postgres::Error`] onto this vendor's [`McpError`].
    #[must_use]
    pub fn classify(&self, err: &tokio_postgres::Error) -> McpError {
        error::classify(*self, err)
    }

    /// The result column came back as something other than the JSONB document
    /// the wrapper guarantees — a client/server mismatch, not caller input.
    #[must_use]
    pub fn decode_error(&self, err: &tokio_postgres::Error) -> McpError {
        api_error(
            format!("{}: failed to decode result: {err}", self.name),
            None,
            None,
        )
    }
}

/// Lazily-built, cached rustls client config.
///
/// Building one loads the OS trust store, so it is worth caching, but no vendor
/// should pay that cost at startup when its tools may never be called. Not
/// [`Clone`]: the cache is per-vendor-instance and lives behind the server's
/// `Arc<ServerState>`.
#[derive(Default)]
pub struct TlsCache {
    verified: OnceLock<Arc<ClientConfig>>,
    unverified: OnceLock<Arc<ClientConfig>>,
}

impl TlsCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the cached config, building it on first use. On a build failure
    /// nothing is cached and the (rare) error propagates, so a later call can
    /// retry.
    pub fn get_or_build(
        &self,
        vendor: PgVendor,
        allow_invalid_certificates: bool,
    ) -> Result<Arc<ClientConfig>, McpError> {
        let cell = if allow_invalid_certificates {
            &self.unverified
        } else {
            &self.verified
        };
        if let Some(config) = cell.get() {
            return Ok(config.clone());
        }
        let config = Arc::new(build_tls_config(vendor, allow_invalid_certificates)?);
        // A concurrent builder may have won the race; either value is valid.
        let _ = cell.set(config.clone());
        Ok(config)
    }
}

/// Everything needed to dial one Postgres session. All fields are
/// server-resolved: no caller-supplied hostname ever reaches here.
#[derive(Debug)]
pub struct ConnectSpec<'a> {
    pub host: &'a str,
    pub port: u16,
    pub database: &'a str,
    pub user: &'a str,
    pub password: &'a str,
    pub ssl_mode: SslMode,
    /// Explicit escape hatch for QA/dev servers using a custom, untrusted, or
    /// hostname-mismatched certificate. Encryption is retained, but server
    /// identity is not authenticated.
    pub allow_invalid_certificates: bool,
    pub application_name: &'a str,
    pub connect_timeout: Duration,
    /// Postgres startup `options`, applied before the first statement runs.
    ///
    /// Opt-in per vendor rather than always-on: a connection pooler between
    /// client and server may reject a startup packet carrying `-c` settings, so
    /// a vendor that reaches its database through one keeps this `None` and
    /// pins the same settings with a `SET` after connecting instead.
    pub startup_options: Option<String>,
}

/// Open a fresh authenticated connection and spawn its driver task.
///
/// The returned client owns the connection; dropping it ends the driver. TLS is
/// used unless the spec explicitly disables it — `SslMode::Disable` is only
/// reachable from a vendor's own configuration, never from a tool argument.
pub async fn connect(
    tls: &TlsCache,
    vendor: PgVendor,
    spec: ConnectSpec<'_>,
) -> Result<Client, McpError> {
    let mut pg = PgConfig::new();
    pg.host(spec.host)
        .port(spec.port)
        .dbname(spec.database)
        .user(spec.user)
        .password(spec.password)
        .ssl_mode(spec.ssl_mode)
        .application_name(spec.application_name)
        .connect_timeout(spec.connect_timeout);
    if let Some(options) = &spec.startup_options {
        pg.options(options);
    }

    debug!(
        vendor = vendor.name,
        host = %spec.host,
        port = spec.port,
        database = %spec.database,
        "postgres: connecting"
    );

    if spec.ssl_mode == SslMode::Disable {
        let (client, connection) = pg
            .connect(NoTls)
            .await
            .map_err(|err| vendor.classify(&err))?;
        spawn_driver(vendor, connection);
        return Ok(client);
    }

    let connector = MakeRustlsConnect::new(
        (*tls.get_or_build(vendor, spec.allow_invalid_certificates)?).clone(),
    );
    let (client, connection) = pg
        .connect(connector)
        .await
        .map_err(|err| vendor.classify(&err))?;
    spawn_driver(vendor, connection);
    Ok(client)
}

/// Drive one connection to completion in the background. A closed connection is
/// expected (the client was dropped), so this only logs at debug.
fn spawn_driver<S, T>(vendor: PgVendor, connection: tokio_postgres::Connection<S, T>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    T: tokio_postgres::tls::TlsStream + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            debug!(vendor = vendor.name, error = %err, "postgres: connection closed");
        }
    });
}

/// Wrap a caller `SELECT` so Postgres aggregates it to a JSONB array
/// server-side and the row count is capped.
///
/// A trailing `;` is stripped so the wrapped subquery parses; any *embedded*
/// statement separator simply fails to parse, which is the desired rejection of
/// multi-statement input. `limit` is a server-clamped integer, never a string
/// from the caller.
#[must_use]
pub fn wrap_query(base_sql: &str, limit: u32) -> String {
    let trimmed = base_sql.trim().trim_end_matches(';').trim_end();
    format!(
        "SELECT coalesce(jsonb_agg(__r), '[]'::jsonb) AS data \
         FROM (SELECT to_jsonb(__t) AS __r FROM ({trimmed}) __t LIMIT {limit}) __s"
    )
}

/// Build a rustls client config: OS trust store for roots by default, or the
/// explicit unauthenticated verifier for an opted-in QA/dev environment.
/// aws-lc-rs (already linked via reqwest) supplies crypto. Explicit provider
/// selection avoids depending on a process-global default being installed.
fn build_tls_config(
    vendor: PgVendor,
    allow_invalid_certificates: bool,
) -> Result<ClientConfig, McpError> {
    let mut roots = rustls::RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    for cert in loaded.certs {
        let _ = roots.add(cert);
    }
    if roots.is_empty() && !allow_invalid_certificates {
        return Err(api_error(
            format!(
                "{} TLS: no system root certificates are available to validate the server",
                vendor.name
            ),
            None,
            loaded
                .errors
                .first()
                .map(|err| OriginalError::String(err.to_string())),
        ));
    }

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| {
            api_error(
                format!("{} TLS setup failed: {err}", vendor.name),
                None,
                None,
            )
        })?;
    if allow_invalid_certificates {
        Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptInvalidCertificates))
            .with_no_client_auth())
    } else {
        Ok(builder.with_root_certificates(roots).with_no_client_auth())
    }
}

/// Explicitly unauthenticated TLS verifier used only by an environment whose
/// configuration opts into invalid certificates. This mirrors the semantics
/// of clients' common `danger_accept_invalid_certs` switch.
#[derive(Debug)]
struct AcceptInvalidCertificates;

impl ServerCertVerifier for AcceptInvalidCertificates {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_VENDOR: PgVendor = PgVendor::new("Test", Duration::from_secs(30));

    #[test]
    fn wrap_query_strips_trailing_semicolon_and_caps_rows() {
        let sql = wrap_query("SELECT 1 AS n;  ", 50);
        assert!(sql.contains("FROM (SELECT 1 AS n) __t"));
        assert!(sql.ends_with("LIMIT 50) __s"));
        assert!(sql.starts_with("SELECT coalesce(jsonb_agg"));
    }

    #[test]
    fn session_settings_carry_the_vendor_timeout() {
        assert_eq!(TEST_VENDOR.statement_timeout_ms(), 30_000);
        assert_eq!(
            TEST_VENDOR.read_only_session_sql(),
            "SET default_transaction_read_only = on; SET statement_timeout = 30000;"
        );
        assert_eq!(
            TEST_VENDOR.connect_options(),
            "-c default_transaction_read_only=on -c statement_timeout=30000"
        );
    }

    #[test]
    fn absurd_timeout_clamps_instead_of_wrapping() {
        let vendor = PgVendor::new("Test", Duration::from_secs(u64::from(u32::MAX)));
        assert_eq!(vendor.statement_timeout_ms(), u32::MAX);
    }
}

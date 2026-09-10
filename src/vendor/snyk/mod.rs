#![allow(clippy::doc_markdown)]

//! Snyk REST API vendor implementation.
//!
//! Snyk is the dependency / container / IaC scanner; this vendor reads the
//! findings it has already recorded (organizations, projects, issues) over
//! the **REST API** (`{base}/rest/...`). Nothing here triggers a scan.
//!
//! Three Snyk-specific facts shape the adapter:
//!
//! - **Auth scheme is `token`, not `Bearer`.** Snyk's documented header is
//!   `Authorization: token <API_TOKEN>`. That scheme is carried as a
//!   [`Credentials::ApiKeyHeader`](crate::auth::Credentials::ApiKeyHeader)
//!   over the standard `Authorization` header (see
//!   [`SnykVendor::credentials`]) so the shared transport emits it verbatim.
//! - **Every REST call requires a `version` query parameter** (a date,
//!   optionally suffixed `~beta` / `~experimental`). The pinned default is
//!   [`DEFAULT_API_VERSION`]; `SNYK_API_VERSION` overrides it and is validated
//!   at call time by [`validate_api_version`].
//! - **Regional tenants use a different host** (`api.eu.snyk.io`,
//!   `api.au.snyk.io`); `SNYK_API_BASE` selects it.
//!
//! Everything after auth (path normalisation, query encoding, transport,
//! output rendering, JMESPath filtering) is the shared vendor-neutral
//! machinery.

pub mod error;

use http::StatusCode;

use crate::auth::Credentials;
use crate::config::{Config, VENDOR_SNYK};
use crate::error::{McpError, api_error, auth_missing};
use crate::vendor::Vendor;

/// Production API base. Overridable via `SNYK_API_BASE` (regional tenants:
/// `https://api.eu.snyk.io`, `https://api.au.snyk.io`) or
/// [`SnykVendor::with_base_url`] (tests).
pub const DEFAULT_API_BASE: &str = "https://api.snyk.io";

/// Pinned REST API version sent as the mandatory `version` query parameter.
/// Snyk versions the REST surface by date; this is the GA release the tool
/// schemas and descriptions were written against. `SNYK_API_VERSION`
/// overrides it (for example to opt into a `~beta` endpoint revision).
pub const DEFAULT_API_VERSION: &str = "2024-10-15";

/// Name of the mandatory version query parameter.
pub const VERSION_PARAM: &str = "version";

/// Organizations the token can see: `GET /rest/orgs`.
pub const ORGS_PATH: &str = "/rest/orgs";

/// Projects in an organization: `GET /rest/orgs/{org_id}/projects`. The
/// controller splices a validated, percent-encoded org id in.
pub const ORG_PROJECTS_SUFFIX: &str = "projects";

/// Issues (findings) in an organization: `GET /rest/orgs/{org_id}/issues`.
pub const ORG_ISSUES_SUFFIX: &str = "issues";

/// Snyk REST API [`Vendor`] strategy.
///
/// Cheap to clone: it holds only an optional base-URL override. There is no
/// token cache — the API token is static and read from config per request.
#[derive(Debug, Clone, Default)]
pub struct SnykVendor {
    /// Optional API base override (tests → wiremock). `None` resolves
    /// `SNYK_API_BASE` from config, falling back to [`DEFAULT_API_BASE`].
    base_url_override: Option<String>,
}

impl SnykVendor {
    /// Production constructor. Resolves `SNYK_API_BASE` from config at
    /// request time.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the API base (tests → wiremock).
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url_override: Some(base_url.into()),
        }
    }

    /// Resolve the API token from the `snyk` config section. Errors with a
    /// clear, actionable message at tool-call time when the token is absent,
    /// so a deployment without Snyk still boots.
    pub async fn token(&self, config: &Config) -> Result<String, McpError> {
        crate::auth::vendor_secret(config, VENDOR_SNYK, "SNYK_TOKEN")
            .await?
            .ok_or_else(|| {
                auth_missing(
                    "SNYK_TOKEN is required for snyk_* tools. Set a Snyk API token \
                     (Account settings → Auth Token, or a service account token) under \
                     the `snyk` section of ~/.mcp/configs.json or in the environment.",
                )
            })
    }

    /// Resolve the token and wrap it in Snyk's `Authorization: token <TOKEN>`
    /// scheme. The transport's `Bearer` carrier would send the wrong scheme,
    /// so the full value is built here and sent as a custom-header credential
    /// over the standard `Authorization` header.
    pub async fn credentials(&self, config: &Config) -> Result<Credentials, McpError> {
        let token = self.token(config).await?;
        Ok(Credentials::ApiKeyHeader {
            header_name: "Authorization".into(),
            key: format!("token {token}"),
        })
    }

    /// Resolve the REST API version to send: `SNYK_API_VERSION` when set (and
    /// well-formed), otherwise [`DEFAULT_API_VERSION`].
    pub fn api_version(&self, config: &Config) -> Result<String, McpError> {
        match config
            .get_for(VENDOR_SNYK, "SNYK_API_VERSION")
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            Some(raw) => validate_api_version(raw).map(str::to_owned),
            None => Ok(DEFAULT_API_VERSION.to_owned()),
        }
    }

    /// Resolve the default organization id from `SNYK_ORG_ID`, if configured.
    pub fn default_org_id<'c>(&self, config: &'c Config) -> Option<&'c str> {
        config
            .get_for(VENDOR_SNYK, "SNYK_ORG_ID")
            .map(str::trim)
            .filter(|v| !v.is_empty())
    }
}

/// Check that a REST API version is `YYYY-MM-DD`, optionally followed by
/// `~beta` or `~experimental`, and return it trimmed. Snyk rejects anything
/// else with an opaque 400, so the shape is checked here with a message that
/// names the config key.
pub fn validate_api_version(raw: &str) -> Result<&str, McpError> {
    let version = raw.trim();
    let (date, suffix) = version
        .split_once('~')
        .map_or((version, None), |(date, suffix)| (date, Some(suffix)));
    let date_ok = date.len() == 10
        && date.bytes().enumerate().all(|(index, byte)| {
            if index == 4 || index == 7 {
                byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        });
    let suffix_ok = matches!(suffix, None | Some("beta" | "experimental"));
    if date_ok && suffix_ok {
        Ok(version)
    } else {
        Err(api_error(
            format!(
                "SNYK_API_VERSION must be a date like 2024-10-15, optionally followed by \
                 `~beta` or `~experimental` (got {version:?})"
            ),
            Some(400),
            None,
        ))
    }
}

impl Vendor for SnykVendor {
    fn name(&self) -> &'static str {
        VENDOR_SNYK
    }

    /// Resolve the API base. Priority: explicit `with_base_url` (tests) →
    /// `SNYK_API_BASE` config → [`DEFAULT_API_BASE`]. A trailing slash is
    /// trimmed so the appended `/rest/...` path never produces a double slash.
    fn base_url(&self, config: &Config) -> Result<String, McpError> {
        let url = self
            .base_url_override
            .as_deref()
            .or_else(|| config.get_for(VENDOR_SNYK, "SNYK_API_BASE"))
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .unwrap_or(DEFAULT_API_BASE);
        Ok(url.trim_end_matches('/').to_owned())
    }

    /// Verbatim passthrough — the controller supplies the full `/rest/...`
    /// path. We only ensure a leading `/`, matching the other single-host
    /// vendors.
    fn normalize_path(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        }
    }

    fn classify_error(&self, status: StatusCode, body: &str) -> McpError {
        error::classify(status, body)
    }
}

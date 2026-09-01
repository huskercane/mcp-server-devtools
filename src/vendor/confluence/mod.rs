//! Confluence Cloud vendor implementation.
//!
//! - Base URL is selected from `ATLASSIAN_API_TOKEN_MODE` (resolved
//!   per-request, never at server construction). Classic tokens use the site
//!   URL; scoped tokens use Atlassian's Confluence gateway and a Cloud ID.
//! - Path normalisation only ensures a leading `/`; Confluence callers pass
//!   the full path (e.g. `/wiki/api/v2/spaces`, `/wiki/rest/api/search`).
//! - Error parsing handles the canonical Confluence v2 envelope plus the
//!   legacy `message` / `errorMessages` / `errors[]` shapes (see [`error`]).

pub mod error;

use std::fmt::Write as _;

use reqwest::StatusCode;

use crate::config::{Config, VENDOR_CONFLUENCE, VENDOR_JIRA};
use crate::error::{McpError, auth_missing};
use crate::vendor::Vendor;

const TOKEN_MODE_KEY: &str = "ATLASSIAN_API_TOKEN_MODE";
const CLOUD_ID_KEY: &str = "ATLASSIAN_CLOUD_ID";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenMode {
    Classic,
    Scoped,
}

impl TokenMode {
    fn resolve(config: &Config) -> Result<Self, McpError> {
        let Some(raw) = config.get_for(VENDOR_CONFLUENCE, TOKEN_MODE_KEY) else {
            return Ok(Self::Classic);
        };
        match raw.trim().to_ascii_lowercase().as_str() {
            "classic" => Ok(Self::Classic),
            "scoped" => Ok(Self::Scoped),
            value => Err(auth_missing(format!(
                "Invalid {TOKEN_MODE_KEY} value {value:?}; expected `classic` or `scoped`."
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::Scoped => "scoped",
        }
    }
}

/// Confluence Cloud [`Vendor`] strategy.
///
/// Two construction paths:
/// - [`ConfluenceVendor::new`] (production) defers base-URL resolution to
///   [`Vendor::base_url`], which reads `ATLASSIAN_SITE_NAME` from the
///   per-request [`Config`]. Missing site name surfaces as a tool-call
///   error, never a startup failure.
/// - [`ConfluenceVendor::with_base_url`] (tests) pins an absolute URL —
///   typically a wiremock — and skips the env lookup entirely.
#[derive(Debug, Clone, Default)]
pub struct ConfluenceVendor {
    base_url_override: Option<String>,
}

impl ConfluenceVendor {
    /// New vendor that derives its base URL from `ATLASSIAN_SITE_NAME` at
    /// request time. Construction itself is infallible.
    pub fn new() -> Self {
        Self {
            base_url_override: None,
        }
    }

    /// New vendor pinned to a caller-supplied base URL. Used by tests to
    /// point the same vendor at a wiremock without touching the
    /// [`Config`].
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url_override: Some(base_url.into()),
        }
    }

    fn classic_base_url(config: &Config) -> Result<String, McpError> {
        let raw = config
            .get_for_with_fallback(VENDOR_CONFLUENCE, &[VENDOR_JIRA], "ATLASSIAN_SITE_NAME")
            .ok_or_else(|| {
                auth_missing(
                    "ATLASSIAN_SITE_NAME is required for conf_* tools using classic tokens. Set the env var (e.g. `mycompany` for mycompany.atlassian.net) or add it under the `confluence` (or `jira`) section of ~/.mcp/configs.json.",
                )
            })?;
        let site = raw.trim();
        if site.is_empty() {
            return Err(auth_missing("ATLASSIAN_SITE_NAME is set but empty."));
        }
        Ok(format!("https://{site}.atlassian.net"))
    }

    fn scoped_base_url(config: &Config) -> Result<String, McpError> {
        let raw = config
            .get_for(VENDOR_CONFLUENCE, CLOUD_ID_KEY)
            .ok_or_else(|| {
                auth_missing(
                    "ATLASSIAN_CLOUD_ID is required when ATLASSIAN_API_TOKEN_MODE is `scoped`. Add it to the `confluence` section of ~/.mcp/configs.json.",
                )
            })?;
        let cloud_id = raw.trim();
        if cloud_id.is_empty() {
            return Err(auth_missing(
                "ATLASSIAN_CLOUD_ID is set but empty; a Cloud ID is required for scoped Confluence API tokens.",
            ));
        }
        Ok(format!(
            "https://api.atlassian.com/ex/confluence/{cloud_id}"
        ))
    }
}

impl Vendor for ConfluenceVendor {
    fn name(&self) -> &'static str {
        VENDOR_CONFLUENCE
    }

    /// Resolve the absolute base URL. When constructed via
    /// [`Self::with_base_url`], returns the pinned override. Otherwise
    /// looks up `ATLASSIAN_SITE_NAME` (vendor-scoped to `confluence`,
    /// with fallback to the shared overlay) and builds
    /// `https://{site}.atlassian.net`. An empty or missing value surfaces
    /// as [`crate::error::auth_missing`] so the user sees a clear
    /// configuration error at tool-call time.
    fn base_url(&self, config: &Config) -> Result<String, McpError> {
        if let Some(base) = &self.base_url_override {
            return Ok(base.clone());
        }
        match TokenMode::resolve(config)? {
            TokenMode::Classic => Self::classic_base_url(config),
            TokenMode::Scoped => Self::scoped_base_url(config),
        }
    }

    fn classify_error_with_context(
        &self,
        status: StatusCode,
        body: &str,
        config: &Config,
        base_url: &str,
    ) -> McpError {
        let mut err = error::classify(status, body);
        if status == StatusCode::UNAUTHORIZED {
            let mode = TokenMode::resolve(config).map_or("unknown", TokenMode::as_str);
            let _ = write!(
                err.message,
                " Selected Confluence token mode: {mode}; base URL: {base_url}. Verify the token-owner email, token expiry or revocation, the URL required by the token mode, and the token's Confluence scopes."
            );
        }
        err
    }

    /// Confluence paths pass through verbatim — callers supply the full
    /// `/wiki/api/v2/...` or `/wiki/rest/api/...` path. We only ensure a
    /// leading `/`.
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

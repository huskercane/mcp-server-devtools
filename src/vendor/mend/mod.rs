//! Mend Platform API 3.0 vendor implementation.
//!
//! Mend (formerly `WhiteSource`) departs from the static-token vendors the way
//! Zoom does: the credentials the operator configures are **not** what goes
//! on the wire. The `mend` config section holds an instance API base
//! (`MEND_API_BASE`), the account `MEND_EMAIL`, its `MEND_USER_KEY` (secret,
//! keychain-backed) and the organization `MEND_ORG_UUID`; those are exchanged
//! at `POST /api/v3.0/login` for a refresh token, then at
//! `POST /api/v3.0/login/accessToken` for a short-lived JWT it caches and renews (see [`token`]). Credential lookup therefore lives on
//! [`MendVendor::bearer`], not in the shared Atlassian resolver.
//!
//! Everything after auth is conventional:
//! - **Base URL** — required config, because the same binary serves the US
//!   `SaaS` (`https://api-saas.mend.io`), the EU `SaaS`
//!   (`https://api-saas-eu.mend.io`) and legacy hosts
//!   (`https://api-app.whitesourcesoftware.com`). The 3.0 paths start with
//!   `/api/v3.0`, so the configured base is the bare host. The login and API
//!   calls share the host, so [`MendVendor::with_base_url`] overrides both.
//! - **Path normalisation** — verbatim, only ensuring a leading `/`.
//! - **Error parsing** — the `{retVal, supportToken, errorMessage}` and
//!   `{error, message}` envelopes (see [`error`]).
//!
//! Legacy `WhiteSource` 2.0 (`/api/v2.0`, `requestType` bodies) is a different
//! API generation and is deliberately not mixed in here.

pub mod error;
pub mod token;

use std::sync::Arc;

use http::StatusCode;

use crate::config::{Config, VENDOR_MEND};
use crate::error::{McpError, auth_missing};
use crate::transport::HttpClient;
use crate::vendor::Vendor;
use token::TokenCache;

// ---------------------------------------------------------------------------
// Platform API 3.0 endpoints.
//
// IMPORTANT: these paths — and the `retVal` / `response` / `additionalData`
// envelope names the controller and token module read — were **not**
// verified against Mend's public documentation when this adapter was written
// (the API portal is a JavaScript application that could not be scraped).
// They are fixture-tested (`tests/mend_tests.rs`) against the shapes described
// in the integration plan and must be validated against a live Platform API
// 3.0 tenant before the tool schema is frozen — in particular the
// application/project terminology (3.0 "applications" are the former
// "products") and whether each endpoint exists on the tenant's plan.
// Keeping every path in this one block means a live-tenant correction is a
// single edit.
// ---------------------------------------------------------------------------

/// API generation prefix every 3.0 path starts with.
pub const API_PREFIX: &str = "/api/v3.0";

/// Login exchange: `POST` `{email, userKey, orgUuid}` → JWT. Never sent
/// through the shared transport (its response holds the bearer) and never
/// cached — `request_is_cacheable` refuses any `/login` URL as well.
pub const LOGIN_PATH: &str = "/api/v3.0/login";

/// Refresh-token rotation endpoint (`wss-refresh-token` header). Documented
/// used to mint and rotate access tokens; see [`token`].
pub const LOGIN_REFRESH_PATH: &str = "/api/v3.0/login/accessToken";

/// `GET` the applications (former "products") of an organization.
#[must_use]
pub fn org_applications_path(org_uuid: &str) -> String {
    format!("{API_PREFIX}/orgs/{org_uuid}/applications")
}

/// `GET` every project of an organization.
#[must_use]
pub fn org_projects_path(org_uuid: &str) -> String {
    format!("{API_PREFIX}/orgs/{org_uuid}/projects")
}

/// `GET` the SCA (dependency) security findings of one project.
#[must_use]
pub fn project_security_findings_path(project_uuid: &str) -> String {
    format!("{API_PREFIX}/projects/{project_uuid}/dependencies/findings/security")
}

/// Mend Platform API 3.0 [`Vendor`] strategy.
///
/// Cheap to clone: the token cache is shared via [`Arc`] so every clone of a
/// vendor instance (the one in `Vendors` and any borrow of it) sees the same
/// cached JWT.
#[derive(Debug, Clone, Default)]
pub struct MendVendor {
    /// Optional base override (tests → wiremock). `None` resolves
    /// `MEND_API_BASE` from config. Covers both the login and the API host —
    /// they are the same host on every Mend instance.
    base_url_override: Option<String>,
    /// Per-instance JWT cache. Shared across clones via `Arc`.
    cache: Arc<TokenCache>,
}

impl MendVendor {
    /// Production constructor: resolves `MEND_API_BASE` from config at request
    /// time and starts with an empty token cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the instance base (tests → wiremock). Applies to the login
    /// exchange and the API calls alike.
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url_override: Some(base_url.into()),
            cache: Arc::new(TokenCache::new()),
        }
    }

    /// The organization UUID every `mend_*` tool operates in. An identifier,
    /// not a credential, so a plain config read.
    pub fn org_uuid(&self, config: &Config) -> Result<String, McpError> {
        require_cred(config, "MEND_ORG_UUID")
    }

    /// Resolve a valid JWT for the configured account, logging in and caching
    /// as needed. This is the Mend credential entry point — the shared
    /// Atlassian resolver is never consulted. Every missing setting surfaces
    /// here as [`ErrorKind::AuthMissing`](crate::error::ErrorKind::AuthMissing)
    /// at tool-call time, never at startup.
    pub async fn bearer(&self, client: &HttpClient, config: &Config) -> Result<String, McpError> {
        let base = self.base_url(config)?;
        let email = require_cred(config, "MEND_EMAIL")?;
        let org_uuid = self.org_uuid(config)?;
        // Only the user key is keychain-backed; email and org UUID are
        // identifiers.
        let user_key = crate::auth::vendor_secret(config, VENDOR_MEND, "MEND_USER_KEY")
            .await?
            .ok_or_else(|| missing_cred("MEND_USER_KEY"))?;
        self.cache
            .bearer(client, &base, &email, &org_uuid, &user_key)
            .await
    }
}

/// Read a required, non-secret Mend setting from the `mend` config section.
fn require_cred(config: &Config, key: &str) -> Result<String, McpError> {
    config
        .get_for(VENDOR_MEND, key)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| missing_cred(key))
}

fn missing_cred(key: &str) -> McpError {
    auth_missing(format!(
        "{key} is required for mend_* tools. Set the Platform API 3.0 login inputs \
         (MEND_API_BASE + MEND_EMAIL + MEND_USER_KEY + MEND_ORG_UUID) under the `mend` \
         section of ~/.mcp/configs.json or in the environment."
    ))
}

impl Vendor for MendVendor {
    fn name(&self) -> &'static str {
        VENDOR_MEND
    }

    /// Resolve the instance base. Priority: explicit `with_base_url` (tests)
    /// → `MEND_API_BASE` config. A trailing slash is trimmed so the appended
    /// `/api/v3.0/...` path never produces a double slash. Errors (not
    /// panics) when the base is absent so a deployment without Mend boots.
    fn base_url(&self, config: &Config) -> Result<String, McpError> {
        if let Some(base) = &self.base_url_override {
            return Ok(base.trim_end_matches('/').to_owned());
        }
        let url = config
            .get_for(VENDOR_MEND, "MEND_API_BASE")
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                auth_missing(
                    "MEND_API_BASE is required for mend_* tools. Set it to your instance's \
                     API host (e.g. https://api-saas.mend.io, https://api-saas-eu.mend.io \
                     or https://api-app.whitesourcesoftware.com; no path) under the `mend` \
                     section of ~/.mcp/configs.json or in the environment.",
                )
            })?;
        Ok(url.trim_end_matches('/').to_owned())
    }

    /// Verbatim passthrough — the controller supplies the full `/api/v3.0/...`
    /// path. We only ensure a leading `/`.
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

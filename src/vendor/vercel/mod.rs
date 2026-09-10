//! Vercel REST API adapter.
//!
//! Vercel is where a front-end build either deployed or did not: a push creates
//! a **deployment** that moves through `QUEUED → BUILDING → READY | ERROR |
//! CANCELED`, and the build/runtime log ("events") is what explains an `ERROR`.
//! This vendor reads that back over the public REST API at
//! `https://api.vercel.com` — projects, deployments, a single deployment, and
//! its bounded event log. Nothing here writes.
//!
//! Shape of the integration:
//! - **Base URL is fixed** (`https://api.vercel.com`); only
//!   [`VercelVendor::with_base_url`] (tests → wiremock) changes it. There is no
//!   self-hosted Vercel, so no URL config key exists.
//! - Authentication is an **account token** (`VERCEL_TOKEN`, created under
//!   Account Settings → Tokens) carried as `Authorization: Bearer <token>` via
//!   [`crate::auth::Credentials::Bearer`]. Read from config per request; there
//!   is no token cache or refresh.
//! - **Scope** is explicit: Vercel resolves a request against the personal
//!   account unless a `teamId` query parameter names a team. Every tool takes
//!   `teamId?`; the controller resolves argument → `VERCEL_TEAM_ID` config →
//!   none, and sends the parameter only when one resolved. A token scoped to a
//!   team but used without `teamId` sees an empty personal account, which is why
//!   the 401/403/404 messages call the scope out.
//! - Vercel **versions endpoints individually** (`/v9/projects`,
//!   `/v6/deployments`, `/v13/deployments/{id}`, `/v3/deployments/{id}/events`);
//!   the versions are pinned here as path constants so a tool never drifts to a
//!   different response shape unnoticed.

pub mod error;

use http::StatusCode;

use crate::config::{Config, VENDOR_VERCEL};
use crate::error::{McpError, auth_missing};
use crate::vendor::Vendor;

/// Production API base. Fixed; [`VercelVendor::with_base_url`] points tests at a
/// wiremock instead.
pub const DEFAULT_API_BASE: &str = "https://api.vercel.com";

/// Project list endpoint (`GET`). The body carries `pagination.next`, the
/// `from` value for the following page.
pub const PROJECTS_PATH: &str = "/v9/projects";

/// Deployment list endpoint (`GET`), filterable by project, state, target, and
/// a `since`/`until` millisecond window.
pub const DEPLOYMENTS_PATH: &str = "/v6/deployments";

/// Prefix of the single-deployment endpoint: `GET /v13/deployments/{id}`.
pub const DEPLOYMENT_PATH_PREFIX: &str = "/v13/deployments";

/// Prefix of the deployment events (build + runtime log) endpoint:
/// `GET /v3/deployments/{id}/events`. The `follow=1` streaming mode of this
/// endpoint is never used — the transport is request/response only.
pub const DEPLOYMENT_EVENTS_PATH_PREFIX: &str = "/v3/deployments";

/// Suffix of the deployment events endpoint.
pub const DEPLOYMENT_EVENTS_PATH_SUFFIX: &str = "/events";

/// Vercel [`Vendor`] strategy.
///
/// Cheap to clone: it holds only an optional base-URL override. The account
/// token is static and read from config per request, so there is no cache.
#[derive(Debug, Clone, Default)]
pub struct VercelVendor {
    /// Optional API base override (tests → wiremock). `None` resolves to
    /// [`DEFAULT_API_BASE`].
    base_url_override: Option<String>,
}

impl VercelVendor {
    /// Production constructor: talks to [`DEFAULT_API_BASE`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the API base (tests → wiremock).
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url_override: Some(base_url.into()),
        }
    }

    /// Resolve the account token from the `vercel` config section. Errors with
    /// a clear, actionable message at tool-call time when the token is absent so
    /// a deployment without Vercel still boots.
    pub async fn token(&self, config: &Config) -> Result<String, McpError> {
        crate::auth::vendor_secret(config, VENDOR_VERCEL, "VERCEL_TOKEN")
            .await?
            .ok_or_else(|| {
                auth_missing(
                    "VERCEL_TOKEN is required for vercel_* tools. Create an account token \
                     under Vercel → Account Settings → Tokens and set it under the `vercel` \
                     section of ~/.mcp/configs.json or in the environment.",
                )
            })
    }

    /// Default team scope from `VERCEL_TEAM_ID` (Team Settings → General).
    /// `None` when unset or blank — requests are then personal-account scoped
    /// unless the tool call passes `teamId`.
    #[must_use]
    pub fn default_team_id<'c>(&self, config: &'c Config) -> Option<&'c str> {
        config
            .get_for(VENDOR_VERCEL, "VERCEL_TEAM_ID")
            .map(str::trim)
            .filter(|id| !id.is_empty())
    }
}

/// `GET /v13/deployments/{id}` for an already-validated deployment id or
/// hostname.
#[must_use]
pub fn deployment_path(deployment: &str) -> String {
    let mut path = String::with_capacity(DEPLOYMENT_PATH_PREFIX.len() + 1 + deployment.len());
    path.push_str(DEPLOYMENT_PATH_PREFIX);
    path.push('/');
    path.push_str(deployment);
    path
}

/// `GET /v3/deployments/{id}/events` for an already-validated deployment id or
/// hostname.
#[must_use]
pub fn deployment_events_path(deployment: &str) -> String {
    let mut path = String::with_capacity(
        DEPLOYMENT_EVENTS_PATH_PREFIX.len()
            + 1
            + deployment.len()
            + DEPLOYMENT_EVENTS_PATH_SUFFIX.len(),
    );
    path.push_str(DEPLOYMENT_EVENTS_PATH_PREFIX);
    path.push('/');
    path.push_str(deployment);
    path.push_str(DEPLOYMENT_EVENTS_PATH_SUFFIX);
    path
}

impl Vendor for VercelVendor {
    fn name(&self) -> &'static str {
        VENDOR_VERCEL
    }

    /// The fixed production base, or the test override. A trailing slash is
    /// trimmed so the appended `/vN/...` path never produces a double slash.
    /// Infallible: Vercel has no URL config key.
    fn base_url(&self, _config: &Config) -> Result<String, McpError> {
        Ok(self
            .base_url_override
            .as_deref()
            .unwrap_or(DEFAULT_API_BASE)
            .trim_end_matches('/')
            .to_owned())
    }

    /// Verbatim passthrough — the controller supplies the full versioned path.
    /// Only a leading `/` is ensured, matching the other single-host vendors.
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

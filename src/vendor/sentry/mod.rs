#![allow(clippy::doc_markdown)]

//! Sentry REST API vendor implementation.
//!
//! Sentry is the error tracker: applications report exceptions, Sentry groups
//! them into **issues**, and each issue carries many **events** (stack trace,
//! breadcrumbs, contexts). This vendor reads that state back over Sentry's
//! Web API (`{base}/api/0/...`) for the "what is broken in production right
//! now" question.
//!
//! Shape:
//! - **Base URL defaults to `https://sentry.io`** and is overridable via
//!   `SENTRY_URL` for self-hosted installs and the EU region
//!   (`https://de.sentry.io`). The same token works for SaaS and self-hosted,
//!   so no default is required config.
//! - Authentication is an **auth token** (`SENTRY_TOKEN`) sent as
//!   `Authorization: Bearer <token>`. Organization auth tokens and user auth
//!   tokens both work; the read tools need `org:read`, `project:read`, and
//!   `event:read`. Credential lookup is a plain config read on
//!   [`SentryVendor::token`] — the shared Atlassian resolver is never consulted.
//! - `SENTRY_ORG` is the optional default organization slug: every
//!   organization-scoped tool takes `organization?` and falls back to it.
//! - **Reads are never served from the local cache** ([`Vendor::cache_reads`]
//!   returns `false`): Sentry paginates with a `Link` *response header*, and
//!   a cached body has no headers, so a cache hit would silently drop the
//!   `nextCursor`. Issue and event state also changes by the second, which is
//!   the wrong shape for a body cache anyway.
//! - **Trailing slashes are significant**: Sentry redirects (or 404s) a path
//!   without one, so every endpoint template here ends in `/`.

pub mod error;

use http::StatusCode;

use crate::config::{Config, VENDOR_SENTRY};
use crate::error::{McpError, auth_missing};
use crate::vendor::Vendor;

/// Production API base. Overridable via `SENTRY_URL` (self-hosted / regional)
/// or [`SentryVendor::with_base_url`] (tests).
pub const DEFAULT_API_BASE: &str = "https://sentry.io";

/// Prefix shared by every organization-scoped endpoint this vendor uses.
pub const ORGANIZATIONS_PREFIX: &str = "/api/0/organizations";

/// `GET /api/0/organizations/{org}/projects/` — the organization's projects.
#[must_use]
pub fn projects_path(org: &str) -> String {
    format!("{ORGANIZATIONS_PREFIX}/{org}/projects/")
}

/// `GET /api/0/organizations/{org}/issues/` — issue search across the
/// organization (Sentry search syntax via `query`).
#[must_use]
pub fn issues_path(org: &str) -> String {
    format!("{ORGANIZATIONS_PREFIX}/{org}/issues/")
}

/// `GET /api/0/organizations/{org}/issues/{issue}/` — one issue's metadata
/// and aggregate stats.
#[must_use]
pub fn issue_path(org: &str, issue_id: &str) -> String {
    format!("{ORGANIZATIONS_PREFIX}/{org}/issues/{issue_id}/")
}

/// `GET /api/0/organizations/{org}/issues/{issue}/events/{event}/` — one
/// event (`latest`, `oldest`, or a 32-hex id) of an issue, with its full
/// stack trace, breadcrumbs, and contexts.
#[must_use]
pub fn issue_event_path(org: &str, issue_id: &str, event_id: &str) -> String {
    format!("{ORGANIZATIONS_PREFIX}/{org}/issues/{issue_id}/events/{event_id}/")
}

/// `GET /api/0/organizations/{org}/releases/` — the organization's releases.
#[must_use]
pub fn releases_path(org: &str) -> String {
    format!("{ORGANIZATIONS_PREFIX}/{org}/releases/")
}

/// Sentry Web API [`Vendor`] strategy.
///
/// Cheap to clone: it holds only an optional base-URL override. There is no
/// token cache — the auth token is static and read from config per request.
#[derive(Debug, Clone, Default)]
pub struct SentryVendor {
    /// Optional API base override (tests → wiremock). `None` resolves
    /// `SENTRY_URL` from config, falling back to [`DEFAULT_API_BASE`].
    base_url_override: Option<String>,
}

impl SentryVendor {
    /// Production constructor. Resolves `SENTRY_URL` from config at request
    /// time.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the API base (tests → wiremock).
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url_override: Some(base_url.into()),
        }
    }

    /// Resolve the auth token from the `sentry` config section. Errors with a
    /// clear, actionable message at tool-call time when the token is absent.
    pub async fn token(&self, config: &Config) -> Result<String, McpError> {
        crate::auth::vendor_secret(config, VENDOR_SENTRY, "SENTRY_TOKEN")
            .await?
            .ok_or_else(|| {
                auth_missing(
                    "SENTRY_TOKEN is required for sentry_* tools. Create an organization \
                     auth token (Organization Settings → Auth Tokens) with the `org:read`, \
                     `project:read`, and `event:read` scopes and set it under the `sentry` \
                     section of ~/.mcp/configs.json or in the environment.",
                )
            })
    }

    /// The default organization slug (`SENTRY_ORG`), if configured. Tools fall
    /// back to it when the caller omits `organization`.
    #[must_use]
    pub fn default_organization<'c>(&self, config: &'c Config) -> Option<&'c str> {
        config
            .get_for(VENDOR_SENTRY, "SENTRY_ORG")
            .map(str::trim)
            .filter(|org| !org.is_empty())
    }
}

impl Vendor for SentryVendor {
    fn name(&self) -> &'static str {
        VENDOR_SENTRY
    }

    /// Resolve the API base. Priority: explicit `with_base_url` (tests) →
    /// `SENTRY_URL` config → [`DEFAULT_API_BASE`]. A trailing slash is trimmed
    /// so the appended `/api/0/...` path never produces a double slash.
    fn base_url(&self, config: &Config) -> Result<String, McpError> {
        let url = self
            .base_url_override
            .as_deref()
            .or_else(|| config.get_for(VENDOR_SENTRY, "SENTRY_URL"))
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .unwrap_or(DEFAULT_API_BASE);
        Ok(url.trim_end_matches('/').to_owned())
    }

    /// Verbatim passthrough — the controller supplies the full `/api/0/...`
    /// path (trailing slash included). Only a leading `/` is ensured.
    fn normalize_path(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        }
    }

    /// Never cache Sentry reads: the `Link` pagination header is not part of
    /// the cached body, so a cache hit on a list endpoint would drop the
    /// `nextCursor`; issue/event/release state is live data besides.
    fn cache_reads(&self, _path: &str) -> bool {
        false
    }

    fn classify_error(&self, status: StatusCode, body: &str) -> McpError {
        error::classify(status, body)
    }
}

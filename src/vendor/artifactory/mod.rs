#![allow(clippy::doc_markdown)]

//! JFrog Artifactory REST API vendor implementation.
//!
//! Artifactory is the binary repository behind most build pipelines: builds
//! resolve dependencies from it and publish their outputs (and `build-info`)
//! back to it. This vendor reads that state over Artifactory's REST API
//! (`{base}/artifactory/api/...`) — repository discovery, AQL search, item
//! storage metadata, and build information — all read-only.
//!
//! Configuration follows the SonarQube / Grafana model:
//! - **Base URL is required config** (`ARTIFACTORY_URL`): the same binary
//!   serves JFrog Cloud (`https://mycorp.jfrog.io`) and self-hosted installs
//!   (`https://artifactory.example.com`, possibly behind a reverse proxy at a
//!   custom context path), so there is no sensible default. When the URL is
//!   an **origin only** (no path component) the standard `/artifactory`
//!   context is appended once; when it carries any path it is used verbatim
//!   so a proxied install at `https://tools.example.com/repo-manager` (or one
//!   that already ends in `/artifactory`) is honoured. See
//!   [`normalize_base_url`].
//! - Authentication is a JFrog **access token** (`ARTIFACTORY_TOKEN` — an
//!   identity token generated from the user profile, or a scoped access
//!   token from Platform → Access Tokens) carried as
//!   `Authorization: Bearer <token>` via [`Credentials::Bearer`](crate::auth::Credentials::Bearer).
//!   API keys (`X-JFrog-Art-Api`) are deprecated by JFrog and not supported.
//!
//! Everything after auth (path normalisation, query encoding, transport, error
//! classification, output rendering, JMESPath filtering) is the shared
//! vendor-neutral machinery.

pub mod error;

use http::StatusCode;

use crate::config::{Config, VENDOR_ARTIFACTORY};
use crate::error::{McpError, auth_missing};
use crate::vendor::Vendor;

/// Repository listing endpoint: `GET /api/repositories` with optional
/// `type` and `packageType` filters.
pub const REPOSITORIES_PATH: &str = "/api/repositories";

/// Artifactory Query Language endpoint. Despite being a search it is a
/// `POST` whose body is the AQL text (`Content-Type: text/plain`).
pub const AQL_SEARCH_PATH: &str = "/api/search/aql";

/// Storage (item info) endpoint prefix: `GET /api/storage/{repo}/{path}`
/// returns file metadata (size, checksums, timestamps) for a file and a
/// `children` listing for a folder.
pub const STORAGE_PATH_PREFIX: &str = "/api/storage";

/// Build-info endpoint prefix: `GET /api/build/{name}/{number}` returns the
/// published build information (modules, artifacts, dependencies, agent,
/// VCS, properties).
pub const BUILD_PATH_PREFIX: &str = "/api/build";

/// The default Artifactory context path appended to an origin-only URL.
const DEFAULT_CONTEXT: &str = "/artifactory";

/// JFrog Artifactory REST API [`Vendor`] strategy.
///
/// Cheap to clone: it holds only an optional base-URL override. There is no
/// token cache — the access token is static and read from config per request.
#[derive(Debug, Clone, Default)]
pub struct ArtifactoryVendor {
    /// Optional API base override (tests → wiremock). `None` resolves
    /// `ARTIFACTORY_URL` from config.
    base_url_override: Option<String>,
}

impl ArtifactoryVendor {
    /// Production constructor. Resolves `ARTIFACTORY_URL` from config at
    /// request time.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the API base (tests → wiremock). The override goes through
    /// the same [`normalize_base_url`] rule as the configured value, so an
    /// origin-only override gains the `/artifactory` context too.
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url_override: Some(base_url.into()),
        }
    }

    /// Resolve the access token from the `artifactory` config section. Errors
    /// with a clear, actionable message at tool-call time when it is absent —
    /// never at startup, so a deployment without Artifactory still boots.
    pub async fn token(&self, config: &Config) -> Result<String, McpError> {
        crate::auth::vendor_secret(config, VENDOR_ARTIFACTORY, "ARTIFACTORY_TOKEN")
            .await?
            .ok_or_else(|| {
                auth_missing(
                    "ARTIFACTORY_TOKEN is required for artifactory_* tools. Set a JFrog \
                     access token (Edit Profile → Generate an Identity Token, or \
                     Platform → Access Tokens) under the `artifactory` section of \
                     ~/.mcp/configs.json or in the environment.",
                )
            })
    }
}

/// Normalise a configured Artifactory URL into the API base.
///
/// - Surrounding whitespace and trailing slashes are trimmed.
/// - An **origin-only** URL (`https://mycorp.jfrog.io`,
///   `https://artifactory.example.com/`) gains the standard `/artifactory`
///   context, because that is where the REST API lives on every JFrog
///   Platform and default self-hosted install.
/// - A URL that already carries a path (`https://host/artifactory`,
///   `https://proxy.example.com/binaries`) is used verbatim: a reverse-proxied
///   install at a custom context path cannot be guessed, so the operator
///   states it in full.
///
/// Whether the value has a path component is decided by parsing it as a URL;
/// a value that does not parse is only trimmed and left for the transport's
/// canonicalizer to reject with its own diagnostic.
#[must_use]
pub fn normalize_base_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    let origin_only = url::Url::parse(trimmed)
        .ok()
        .filter(url::Url::has_host)
        .is_some_and(|parsed| matches!(parsed.path(), "" | "/"));
    if origin_only {
        let mut base = String::with_capacity(trimmed.len() + DEFAULT_CONTEXT.len());
        base.push_str(trimmed);
        base.push_str(DEFAULT_CONTEXT);
        base
    } else {
        trimmed.to_owned()
    }
}

impl Vendor for ArtifactoryVendor {
    fn name(&self) -> &'static str {
        VENDOR_ARTIFACTORY
    }

    /// Resolve the Artifactory base. Priority: explicit `with_base_url`
    /// (tests) → `ARTIFACTORY_URL` config. Both go through
    /// [`normalize_base_url`]. Errors (not panics) when `ARTIFACTORY_URL` is
    /// absent so a deployment without Artifactory still boots.
    fn base_url(&self, config: &Config) -> Result<String, McpError> {
        let raw = self
            .base_url_override
            .as_deref()
            .or_else(|| config.get_for(VENDOR_ARTIFACTORY, "ARTIFACTORY_URL"))
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .ok_or_else(|| {
                auth_missing(
                    "ARTIFACTORY_URL is required for artifactory_* tools. Set it to your \
                     Artifactory URL — an origin such as https://mycorp.jfrog.io gains the \
                     standard /artifactory context automatically; a URL with a path (e.g. a \
                     reverse-proxied https://tools.example.com/artifactory) is used as-is — \
                     under the `artifactory` section of ~/.mcp/configs.json or in the \
                     environment.",
                )
            })?;
        Ok(normalize_base_url(raw))
    }

    /// Verbatim passthrough — the controller supplies the full `/api/...`
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

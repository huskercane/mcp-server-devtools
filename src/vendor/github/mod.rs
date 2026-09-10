#![allow(clippy::doc_markdown)]

//! GitHub REST API vendor implementation.
//!
//! Ten read-only, purpose-built tools sit on GitHub's REST API (repositories,
//! file contents, pull requests, issues, Actions runs and jobs). Everything
//! here is scoped to a `{owner}/{repo}` pair the caller names explicitly, so
//! the endpoint templates live in this module as constants and the controller
//! splices validated identifiers into them.
//!
//! - **Base URL** defaults to `https://api.github.com`; `GITHUB_API_BASE`
//!   overrides it for GitHub Enterprise Server, whose REST root is
//!   `https://ghe.example.com/api/v3`. A trailing slash is trimmed.
//! - **Authentication** is a personal access token (fine-grained or classic)
//!   carried as `Authorization: Bearer <token>` — the same
//!   [`Credentials::Bearer`](crate::auth::Credentials::Bearer) carrier the
//!   other token vendors use. Missing config surfaces as
//!   [`auth_missing`] at tool-call time, never at startup.
//! - **API version** is pinned per request through `X-GitHub-Api-Version`
//!   (default `2022-11-28`, override via `GITHUB_API_VERSION`) so a server-side
//!   default bump cannot change a response shape under us.
//!
//! Error bodies are the documented `{"message", "documentation_url",
//! "errors"}` envelope, parsed in [`error`].

pub mod error;

use http::StatusCode;

use crate::config::{Config, VENDOR_GITHUB};
use crate::error::{McpError, auth_missing};
use crate::vendor::Vendor;

/// Production API base. Overridable via `GITHUB_API_BASE` (Enterprise Server
/// `…/api/v3`) or [`GithubVendor::with_base_url`] (tests).
pub const DEFAULT_API_BASE: &str = "https://api.github.com";

/// REST API version sent as `X-GitHub-Api-Version` unless `GITHUB_API_VERSION`
/// overrides it. This default is pinned in request-shape fixtures; use a
/// version supported by your hosted or Enterprise Server deployment.
pub const DEFAULT_API_VERSION: &str = "2022-11-28";

/// Request header that pins the REST API version.
pub const API_VERSION_HEADER: &str = "X-GitHub-Api-Version";

/// Repositories visible to the authenticated user (`GET /user/repos`).
pub const USER_REPOS_PATH: &str = "/user/repos";

/// Repositories of an organization: `/orgs/{owner}/repos`.
pub fn org_repos_path(owner: &str) -> String {
    format!("/orgs/{owner}/repos")
}

/// Public repositories of a user: `/users/{owner}/repos`.
pub fn user_repos_path(owner: &str) -> String {
    format!("/users/{owner}/repos")
}

/// Contents of a file or directory: `/repos/{owner}/{repo}/contents/{path}`.
/// `path` must already be percent-encoded segment by segment.
pub fn contents_path(owner: &str, repo: &str, encoded_path: &str) -> String {
    format!("/repos/{owner}/{repo}/contents/{encoded_path}")
}

/// Pull request list: `/repos/{owner}/{repo}/pulls`.
pub fn pulls_path(owner: &str, repo: &str) -> String {
    format!("/repos/{owner}/{repo}/pulls")
}

/// One pull request: `/repos/{owner}/{repo}/pulls/{number}`.
pub fn pull_path(owner: &str, repo: &str, number: u64) -> String {
    format!("/repos/{owner}/{repo}/pulls/{number}")
}

/// Files changed by a pull request, with per-file unified `patch` text:
/// `/repos/{owner}/{repo}/pulls/{number}/files`.
pub fn pull_files_path(owner: &str, repo: &str, number: u64) -> String {
    format!("/repos/{owner}/{repo}/pulls/{number}/files")
}

/// Issue list (pull requests included): `/repos/{owner}/{repo}/issues`.
pub fn issues_path(owner: &str, repo: &str) -> String {
    format!("/repos/{owner}/{repo}/issues")
}

/// One issue: `/repos/{owner}/{repo}/issues/{number}`.
pub fn issue_path(owner: &str, repo: &str, number: u64) -> String {
    format!("/repos/{owner}/{repo}/issues/{number}")
}

/// All workflow runs of a repository: `/repos/{owner}/{repo}/actions/runs`.
pub fn workflow_runs_path(owner: &str, repo: &str) -> String {
    format!("/repos/{owner}/{repo}/actions/runs")
}

/// Runs of one workflow (numeric id or file name such as `ci.yml`):
/// `/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs`.
pub fn workflow_id_runs_path(owner: &str, repo: &str, workflow_id: &str) -> String {
    format!("/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs")
}

/// Jobs of one workflow run: `/repos/{owner}/{repo}/actions/runs/{run_id}/jobs`.
pub fn run_jobs_path(owner: &str, repo: &str, run_id: u64) -> String {
    format!("/repos/{owner}/{repo}/actions/runs/{run_id}/jobs")
}

/// GitHub REST API [`Vendor`] strategy.
///
/// Cheap to clone: it holds only an optional base-URL override. The token is
/// static and read from config per request, so there is no token cache.
#[derive(Debug, Clone, Default)]
pub struct GithubVendor {
    /// Optional API base override (tests → wiremock). `None` resolves
    /// `GITHUB_API_BASE` from config, falling back to [`DEFAULT_API_BASE`].
    base_url_override: Option<String>,
}

impl GithubVendor {
    /// Production constructor. Resolves `GITHUB_API_BASE` from config at
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

    /// Resolve the personal access token from the `github` config section.
    /// Errors with a clear, actionable message at tool-call time when it is
    /// absent.
    pub async fn token(&self, config: &Config) -> Result<String, McpError> {
        crate::auth::vendor_secret(config, VENDOR_GITHUB, "GITHUB_TOKEN")
            .await?
            .ok_or_else(|| {
                auth_missing(
                    "GITHUB_TOKEN is required for github_* tools. Set a fine-grained or \
                     classic personal access token (Settings → Developer settings → \
                     Personal access tokens) under the `github` section of \
                     ~/.mcp/configs.json or in the environment.",
                )
            })
    }

    /// The REST API version to pin on every request: `GITHUB_API_VERSION` when
    /// set and non-blank, otherwise [`DEFAULT_API_VERSION`].
    pub fn api_version<'a>(&self, config: &'a Config) -> &'a str {
        config
            .get_for(VENDOR_GITHUB, "GITHUB_API_VERSION")
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .unwrap_or(DEFAULT_API_VERSION)
    }
}

impl Vendor for GithubVendor {
    fn name(&self) -> &'static str {
        VENDOR_GITHUB
    }

    /// Resolve the API base. Priority: explicit `with_base_url` (tests) →
    /// `GITHUB_API_BASE` config → [`DEFAULT_API_BASE`]. A trailing slash is
    /// trimmed so the appended path never produces a double slash.
    fn base_url(&self, config: &Config) -> Result<String, McpError> {
        let url = self
            .base_url_override
            .as_deref()
            .or_else(|| config.get_for(VENDOR_GITHUB, "GITHUB_API_BASE"))
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .unwrap_or(DEFAULT_API_BASE);
        Ok(url.trim_end_matches('/').to_owned())
    }

    /// Verbatim passthrough — the controller supplies full endpoint paths. We
    /// only ensure a leading `/`, matching the other single-host vendors.
    fn normalize_path(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        }
    }

    /// Actions runs and jobs change status at any moment (queued → in
    /// progress → completed, re-runs), so those responses are never served
    /// from or admitted to the local cache. Repository, file, PR and issue
    /// reads keep the default caching behaviour.
    fn cache_reads(&self, path: &str) -> bool {
        !path
            .split(['?', '#'])
            .next()
            .unwrap_or(path)
            .split('/')
            .any(|part| part == "actions")
    }

    fn classify_error(&self, status: StatusCode, body: &str) -> McpError {
        error::classify(status, body)
    }
}

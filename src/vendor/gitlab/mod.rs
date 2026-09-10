#![allow(clippy::doc_markdown)]

//! GitLab REST API (v4) vendor implementation.
//!
//! One adapter serves GitLab.com and Self-Managed instances: the API base is
//! `https://gitlab.com/api/v4` unless `GITLAB_API_BASE` points at a
//! self-managed host. A configured base that stops at the host
//! (`https://gitlab.example.com`) has `/api/v4` appended once, so both spellings
//! resolve to the same wire form.
//!
//! Authentication is a personal, project, or group access token
//! (`GITLAB_TOKEN`, `read_api` scope) carried as `Authorization: Bearer`. GitLab
//! also accepts the custom `PRIVATE-TOKEN` header, but the shared transport only
//! strips the standard `Authorization` header on cross-origin redirects, so the
//! bearer form is the one this adapter sends — never `PRIVATE-TOKEN`.
//!
//! Everything after auth (path canonicalization, query encoding, transport,
//! raw-response persistence, output rendering, JMESPath filtering) is the
//! shared vendor-neutral machinery. Endpoint templates live here so the
//! controller splices validated identifiers into a fixed shape.

pub mod error;

use http::StatusCode;

use crate::config::{Config, VENDOR_GITLAB};
use crate::error::{McpError, auth_missing};
use crate::vendor::Vendor;

/// Production API base. Overridable via `GITLAB_API_BASE` (Self-Managed) or
/// [`GitlabVendor::with_base_url`] (tests).
pub const DEFAULT_API_BASE: &str = "https://gitlab.com/api/v4";

/// Suffix every GitLab REST base must end with. Appended once when the
/// configured value stops at the host.
pub const API_SUFFIX: &str = "/api/v4";

/// Project listing (`GET /projects`) — visible projects, filtered by
/// `membership` / `owned` / `search`.
pub const PROJECTS_PATH: &str = "/projects";

/// Group listing root; `/groups/{id}/projects` lists a group's projects.
pub const GROUPS_PATH: &str = "/groups";

/// `GET /groups/{group}/projects` — the projects under one group (numeric id
/// or percent-encoded full path).
#[must_use]
pub fn group_projects_path(group: &str) -> String {
    format!("{GROUPS_PATH}/{group}/projects")
}

/// `GET /projects/{project}/repository/files/{path}?ref=` — file metadata plus
/// base64 content at one ref. `path` must already be a single encoded segment.
#[must_use]
pub fn repository_file_path(project: &str, encoded_path: &str) -> String {
    format!("{PROJECTS_PATH}/{project}/repository/files/{encoded_path}")
}

/// `GET /projects/{project}/merge_requests` — merge-request listing.
#[must_use]
pub fn merge_requests_path(project: &str) -> String {
    format!("{PROJECTS_PATH}/{project}/merge_requests")
}

/// `GET /projects/{project}/merge_requests/{iid}` — one merge request by its
/// project-scoped IID.
#[must_use]
pub fn merge_request_path(project: &str, iid: u64) -> String {
    format!("{PROJECTS_PATH}/{project}/merge_requests/{iid}")
}

/// `GET /projects/{project}/merge_requests/{iid}/diffs` — the per-file diffs
/// of a merge request (paginated).
#[must_use]
pub fn merge_request_diffs_path(project: &str, iid: u64) -> String {
    format!("{PROJECTS_PATH}/{project}/merge_requests/{iid}/diffs")
}

/// `GET /projects/{project}/issues` — issue listing.
#[must_use]
pub fn issues_path(project: &str) -> String {
    format!("{PROJECTS_PATH}/{project}/issues")
}

/// `GET /projects/{project}/issues/{iid}` — one issue by its project-scoped
/// IID.
#[must_use]
pub fn issue_path(project: &str, iid: u64) -> String {
    format!("{PROJECTS_PATH}/{project}/issues/{iid}")
}

/// `GET /projects/{project}/pipelines` — pipeline listing.
#[must_use]
pub fn pipelines_path(project: &str) -> String {
    format!("{PROJECTS_PATH}/{project}/pipelines")
}

/// `GET /projects/{project}/pipelines/{pipeline_id}/jobs` — the jobs of one
/// pipeline.
#[must_use]
pub fn pipeline_jobs_path(project: &str, pipeline_id: u64) -> String {
    format!("{PROJECTS_PATH}/{project}/pipelines/{pipeline_id}/jobs")
}

/// `GET /projects/{project}/jobs/{job_id}/trace` — the plain-text log of one
/// job, served from the API origin (not an artifact download).
#[must_use]
pub fn job_trace_path(project: &str, job_id: u64) -> String {
    format!("{PROJECTS_PATH}/{project}/jobs/{job_id}/trace")
}

/// GitLab REST API [`Vendor`] strategy.
///
/// Cheap to clone: it holds only an optional base-URL override. There is no
/// token cache — the access token is static and read from config per request.
#[derive(Debug, Clone, Default)]
pub struct GitlabVendor {
    /// Optional API base override (tests → wiremock). `None` resolves
    /// `GITLAB_API_BASE` from config, falling back to [`DEFAULT_API_BASE`].
    base_url_override: Option<String>,
}

impl GitlabVendor {
    /// Production constructor. Resolves `GITLAB_API_BASE` from config at
    /// request time.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the API base (tests → wiremock). The same `/api/v4` suffix
    /// rule applies, so a bare wiremock URI works as-is.
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url_override: Some(base_url.into()),
        }
    }

    /// Resolve the access token from the `gitlab` config section. This is the
    /// GitLab credential entry point — the shared Atlassian resolver is never
    /// consulted. Errors with an actionable message at tool-call time when the
    /// token is absent, so a deployment without GitLab still boots.
    pub async fn token(&self, config: &Config) -> Result<String, McpError> {
        crate::auth::vendor_secret(config, VENDOR_GITLAB, "GITLAB_TOKEN")
            .await?
            .ok_or_else(|| {
                auth_missing(
                    "GITLAB_TOKEN is required for gitlab_* tools. Set a personal, project, \
                     or group access token with the `read_api` scope (add `read_repository` \
                     for file reads) under the `gitlab` section of ~/.mcp/configs.json or in \
                     the environment.",
                )
            })
    }
}

/// Trim whitespace and trailing slashes, then make sure the base ends in
/// `/api/v4` exactly once.
fn normalize_base(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.ends_with(API_SUFFIX) {
        trimmed.to_owned()
    } else {
        let mut out = String::with_capacity(trimmed.len() + API_SUFFIX.len());
        out.push_str(trimmed);
        out.push_str(API_SUFFIX);
        out
    }
}

impl Vendor for GitlabVendor {
    fn name(&self) -> &'static str {
        VENDOR_GITLAB
    }

    /// Resolve the API base. Priority: explicit `with_base_url` (tests) →
    /// `GITLAB_API_BASE` config → GitLab.com. A trailing slash is trimmed and
    /// `/api/v4` is appended when missing, so `https://gitlab.example.com`
    /// and `https://gitlab.example.com/api/v4/` both resolve to
    /// `https://gitlab.example.com/api/v4`.
    fn base_url(&self, config: &Config) -> Result<String, McpError> {
        let raw = self
            .base_url_override
            .as_deref()
            .or_else(|| config.get_for(VENDOR_GITLAB, "GITLAB_API_BASE"))
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .unwrap_or(DEFAULT_API_BASE);
        Ok(normalize_base(raw))
    }

    /// Verbatim passthrough — the controller supplies the full `/projects/...`
    /// path. We only ensure a leading `/`, matching the other single-host
    /// vendors.
    fn normalize_path(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        }
    }

    /// CI state is live: a pipeline can be retried after a terminal result
    /// and a job trace grows while the job runs. Never serve those from the
    /// local response cache. Repository, MR, and issue reads keep the default.
    fn cache_reads(&self, path: &str) -> bool {
        !path
            .split(['?', '#'])
            .next()
            .unwrap_or(path)
            .split('/')
            .any(|part| matches!(part, "pipelines" | "jobs" | "trace"))
    }

    fn classify_error(&self, status: StatusCode, body: &str) -> McpError {
        error::classify(status, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_gets_api_v4_exactly_once() {
        assert_eq!(
            normalize_base("https://gitlab.example.com"),
            "https://gitlab.example.com/api/v4"
        );
        assert_eq!(
            normalize_base(" https://gitlab.example.com/api/v4/ "),
            "https://gitlab.example.com/api/v4"
        );
        assert_eq!(
            normalize_base("https://gitlab.example.com/gitlab/"),
            "https://gitlab.example.com/gitlab/api/v4"
        );
    }
}

// The field-level doc strings below travel as the JSON Schema descriptions
// published to MCP clients.
#![allow(clippy::doc_markdown)]

//! Argument DTOs for the `vercel_*` tools.
//!
//! Every tool carries `teamId?` (argument → `VERCEL_TEAM_ID` → personal
//! account), `jq?` and `outputFormat?`. List page sizes are validated and
//! capped in the controller; the schema documents the bounds.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::OutputFormatArg;

/// Arguments for `vercel_list_projects` (`GET /v9/projects`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VercelListProjectsArgs {
    /// Vercel team id (`team_xxx`, Team Settings → General) that owns the
    /// projects. Overrides `VERCEL_TEAM_ID`. Omit for the personal account when
    /// no default team is configured. Required for team-owned projects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,

    /// Filter projects by name substring, e.g. "storefront".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,

    /// Page size, 1–100 (default 20). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Pagination cursor: pass the previous response's `pagination.next` value
    /// (a millisecond timestamp such as "1718000000000") to fetch the next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,

    /// Only projects created before this millisecond timestamp, e.g.
    /// "1718000000000".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,

    /// Filter to the project(s) linked to this Git repository URL, e.g.
    /// "https://github.com/acme/storefront".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_url: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "projects[*].{id: id, name: name, framework: framework}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `vercel_list_deployments` (`GET /v6/deployments`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VercelListDeploymentsArgs {
    /// Vercel team id (`team_xxx`, Team Settings → General) that owns the
    /// deployments. Overrides `VERCEL_TEAM_ID`. Omit for the personal account
    /// when no default team is configured. Required for team-owned projects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,

    /// Project id (`prj_xxx`) or project name to list deployments for, e.g.
    /// "storefront". Omit for every project in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,

    /// Deployment application name filter (the `app` field, usually the
    /// project name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,

    /// Filter by deployment state, comma-separated: `BUILDING`, `ERROR`,
    /// `INITIALIZING`, `QUEUED`, `READY`, `CANCELED`. Example: "ERROR" to find
    /// failed deployments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// Filter by target environment: `production` or `preview`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    /// Page size, 1–100 (default 20). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Only deployments created after this millisecond timestamp, e.g.
    /// "1718000000000".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,

    /// Only deployments created before this millisecond timestamp, e.g.
    /// "1718000000000". Use the previous page's `pagination.next` to page
    /// backwards through history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "deployments[*].{uid: uid, state: state, url: url, created: created}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `vercel_get_deployment` (`GET /v13/deployments/{deployment}`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VercelGetDeploymentArgs {
    /// Deployment id (`dpl_xxx`) or deployment hostname such as
    /// "storefront-abc123-acme.vercel.app" (without scheme or path).
    pub deployment: String,

    /// Vercel team id (`team_xxx`, Team Settings → General) that owns the
    /// deployment. Overrides `VERCEL_TEAM_ID`. Omit for the personal account
    /// when no default team is configured. Required for team-owned projects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "{id: id, state: readyState, url: url, error: errorMessage}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `vercel_get_deployment_logs`
/// (`GET /v3/deployments/{deployment}/events`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VercelGetDeploymentLogsArgs {
    /// Deployment id (`dpl_xxx`) or deployment hostname such as
    /// "storefront-abc123-acme.vercel.app" (without scheme or path).
    pub deployment: String,

    /// Vercel team id (`team_xxx`, Team Settings → General) that owns the
    /// deployment. Overrides `VERCEL_TEAM_ID`. Omit for the personal account
    /// when no default team is configured. Required for team-owned projects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,

    /// Maximum number of log events to return, 1–1000 (default 100). Output is
    /// also bounded by the shared response cap; keep this small.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Read order: `forward` (oldest first, default) or `backward` (newest
    /// first — use with a small `limit` to see the tail of a failed build).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,

    /// Include build (compile) logs, not just runtime events. Default true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builds: Option<bool>,

    /// Only events at or after this millisecond timestamp, e.g.
    /// "1718000000000".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,

    /// Only events at or before this millisecond timestamp, e.g.
    /// "1718000000000".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,

    /// Filter runtime request events by HTTP status code, e.g. "500" or the
    /// range form "5xx".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "[?type=='stderr'].{at: created, text: payload.text}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

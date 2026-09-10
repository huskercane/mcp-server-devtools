// The field-level doc strings below travel as the JSON Schema descriptions
// published to MCP clients.
#![allow(clippy::doc_markdown)]

//! Argument DTOs for the `github_*` tools.
//!
//! Every tool is scoped to an explicit `owner` / `repo` pair (except
//! `github_list_repositories`, which discovers them). `perPage` is bounded to
//! GitHub's `1..=100` (default 30) and `page` is 1-based, both enforced in the
//! controller. `jq` and `outputFormat` are on every tool.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::OutputFormatArg;

/// Which kind of account `owner` names when listing repositories.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GithubOwnerType {
    /// An organization: `GET /orgs/{owner}/repos`.
    #[default]
    Org,
    /// A user account: `GET /users/{owner}/repos`.
    User,
}

/// Arguments for `github_list_repositories`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GithubListRepositoriesArgs {
    /// Organization or user login to list repositories for, e.g. "octocat".
    /// Omit to list the repositories the token's user can access
    /// (`GET /user/repos`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,

    /// Whether `owner` is an organization ("org", the default) or a user
    /// ("user"). Ignored when `owner` is omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_type: Option<GithubOwnerType>,

    /// Repository type filter (GitHub `type`). Organizations: "all",
    /// "public", "private", "forks", "sources", "member". Users: "all",
    /// "owner", "member". Authenticated user: "all", "owner", "public",
    /// "private", "member" (cannot be combined with `visibility` or
    /// `affiliation`).
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub repo_type: Option<String>,

    /// Authenticated-user listing only (no `owner`): "all", "public", or
    /// "private".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,

    /// Authenticated-user listing only (no `owner`): comma-separated
    /// "owner", "collaborator", "organization_member", e.g.
    /// "owner,collaborator".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affiliation: Option<String>,

    /// Sort key: "created", "updated", "pushed", or "full_name" (default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,

    /// Sort direction: "asc" or "desc". Defaults to "asc" for "full_name",
    /// otherwise "desc".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,

    /// Results per page, 1-100 (default 30). Values above 100 are capped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,

    /// 1-based page number to fetch. Increment it to continue past a full
    /// page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "[*].{name: full_name, private: private, default: default_branch}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `github_get_file`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GithubGetFileArgs {
    /// Repository owner (organization or user login), e.g. "octocat".
    pub owner: String,

    /// Repository name without the owner, e.g. "hello-world".
    pub repo: String,

    /// Path of the file or directory inside the repository, e.g.
    /// "src/main.rs" or "docs". Slashes separate directories; `..` is
    /// rejected.
    pub path: String,

    /// Branch name, tag, or commit SHA to read at, e.g. "main" or
    /// "v1.2.0". Omit for the repository's default branch.
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "content" for a file, "[*].{name: name, type: type}" for a
    /// directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `github_list_pull_requests`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GithubListPullRequestsArgs {
    /// Repository owner (organization or user login), e.g. "octocat".
    pub owner: String,

    /// Repository name without the owner, e.g. "hello-world".
    pub repo: String,

    /// Pull request state: "open" (default), "closed", or "all".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// Filter by head branch as "user:ref-name" or "organization:ref-name",
    /// e.g. "octocat:feature-x".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,

    /// Filter by base branch name, e.g. "main".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,

    /// Sort key: "created" (default), "updated", "popularity", or
    /// "long-running".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,

    /// Sort direction: "asc" or "desc" (default "desc" when sorting by
    /// "created", otherwise "asc").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,

    /// Results per page, 1-100 (default 30). Values above 100 are capped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,

    /// 1-based page number to fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "[*].{number: number, title: title, author: user.login, draft: draft}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `github_get_pull_request`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GithubGetPullRequestArgs {
    /// Repository owner (organization or user login), e.g. "octocat".
    pub owner: String,

    /// Repository name without the owner, e.g. "hello-world".
    pub repo: String,

    /// Pull request number as shown in the GitHub UI (not the global id),
    /// e.g. 1347.
    pub number: u64,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "{title: title, state: state, mergeable: mergeable, head: head.ref, base: base.ref}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `github_get_pull_request_diff`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GithubGetPullRequestDiffArgs {
    /// Repository owner (organization or user login), e.g. "octocat".
    pub owner: String,

    /// Repository name without the owner, e.g. "hello-world".
    pub repo: String,

    /// Pull request number as shown in the GitHub UI, e.g. 1347.
    pub number: u64,

    /// Files per page, 1-100 (default 30). Values above 100 are capped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,

    /// 1-based page number. A pull request touching more files than
    /// `perPage` needs further pages; increment `page` until a short page
    /// comes back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "[*].{file: filename, status: status, patch: patch}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `github_list_issues`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GithubListIssuesArgs {
    /// Repository owner (organization or user login), e.g. "octocat".
    pub owner: String,

    /// Repository name without the owner, e.g. "hello-world".
    pub repo: String,

    /// Issue state: "open" (default), "closed", or "all".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// Comma-separated label names an issue must carry, e.g. "bug,urgent".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<String>,

    /// Assignee login, or "none" for unassigned, or "*" for any assignee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,

    /// Login of the user who opened the issue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,

    /// Only issues updated at or after this ISO 8601 timestamp, e.g.
    /// "2026-09-01T00:00:00Z".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,

    /// Sort key: "created" (default), "updated", or "comments".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,

    /// Sort direction: "asc" or "desc" (default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,

    /// Results per page, 1-100 (default 30). Values above 100 are capped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,

    /// 1-based page number to fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "[?!pull_request].{number: number, title: title, labels: labels[*].name}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `github_get_issue`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GithubGetIssueArgs {
    /// Repository owner (organization or user login), e.g. "octocat".
    pub owner: String,

    /// Repository name without the owner, e.g. "hello-world".
    pub repo: String,

    /// Issue number as shown in the GitHub UI (not the global id), e.g. 42.
    pub number: u64,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "{title: title, state: state, body: body, labels: labels[*].name}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `github_list_workflow_runs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GithubListWorkflowRunsArgs {
    /// Repository owner (organization or user login), e.g. "octocat".
    pub owner: String,

    /// Repository name without the owner, e.g. "hello-world".
    pub repo: String,

    /// Restrict to one workflow: its numeric id or its file name in
    /// `.github/workflows`, e.g. "ci.yml". Omit for runs of every workflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_id: Option<String>,

    /// Only runs for this branch, e.g. "main".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,

    /// Run status or conclusion: "completed", "in_progress", "queued",
    /// "success", "failure", "cancelled", "timed_out", "action_required",
    /// "neutral", "skipped", "stale", "requested", "waiting", "pending".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// Triggering event, e.g. "push", "pull_request", "workflow_dispatch",
    /// "schedule".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,

    /// Login of the user who triggered the run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,

    /// Results per page, 1-100 (default 30). Values above 100 are capped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,

    /// 1-based page number to fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "workflow_runs[*].{id: id, name: name, status: status, conclusion: conclusion, branch: head_branch}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `github_list_workflow_jobs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GithubListWorkflowJobsArgs {
    /// Repository owner (organization or user login), e.g. "octocat".
    pub owner: String,

    /// Repository name without the owner, e.g. "hello-world".
    pub repo: String,

    /// Workflow run id (the `id` from `github_list_workflow_runs`), e.g.
    /// 30433642.
    pub run_id: u64,

    /// "latest" (default) returns jobs from the most recent attempt only;
    /// "all" includes every re-run attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,

    /// Results per page, 1-100 (default 30). Values above 100 are capped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,

    /// 1-based page number to fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "jobs[?conclusion=='failure'].{name: name, steps: steps[?conclusion=='failure'].name}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Explicit bounded download; returns an owner-scoped artifact, never inline bytes.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GithubGetJobLogsArgs {
    pub owner: String,
    pub repo: String,
    pub job_id: u64,
    /// Maximum transferred bytes, default 32 MiB, hard maximum 512 MiB.
    pub max_bytes: Option<u64>,
}

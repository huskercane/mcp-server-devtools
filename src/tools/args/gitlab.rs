// The field-level doc strings below travel as the JSON Schema descriptions
// published to MCP clients; they are written for the LLM that fills them in.
#![allow(clippy::doc_markdown)]

//! Argument DTOs for the `gitlab_*` tools.
//!
//! Every project-scoped tool takes `project`: a numeric project id (`42`) or
//! a namespace path (`group/subgroup/project`). Issue and merge-request
//! identifiers are the **project-scoped `iid`** shown in the GitLab UI and
//! URL (`!12`, `#7`), not the global `id`. Pipeline and job identifiers are
//! global ids. List tools page with GitLab's offset `page` / `perPage`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::OutputFormatArg;

/// Arguments for `gitlab_list_projects`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitlabListProjectsArgs {
    /// Substring to match against project name and path, e.g. "payments".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,

    /// Only projects the token's user is a member of. Defaults to true;
    /// set false to include every visible (public/internal) project, which
    /// on GitLab.com is a very large set. Ignored when `groupId` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<bool>,

    /// Only projects owned by the token's user (or, with `groupId`, owned by
    /// the group).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owned: Option<bool>,

    /// Scope the listing to one group: a numeric group id ("123") or a full
    /// group path ("my-org/platform"). Switches the call to
    /// `GET /groups/{groupId}/projects`; subgroups' projects are not included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,

    /// Sort field: `id`, `name`, `path`, `created_at`, `updated_at`,
    /// `last_activity_at`, `star_count`. Default `created_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_by: Option<String>,

    /// Sort direction: `asc` or `desc` (default `desc`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,

    /// Page size, 1–100 (default 20). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,

    /// 1-based page number. Continue with the response nextPage when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "[*].{id: id, path: path_with_namespace, branch: default_branch}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `gitlab_get_file`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitlabGetFileArgs {
    /// Project: numeric id ("42") or namespace path ("group/subgroup/project").
    pub project: String,

    /// File path inside the repository, e.g. "src/main.rs" or
    /// ".gitlab-ci.yml". No leading slash, no `.` / `..` segments.
    pub path: String,

    /// Branch name, tag, or commit SHA to read the file at, e.g. "main".
    /// Required by GitLab — there is no implicit default branch.
    #[serde(rename = "ref")]
    pub git_ref: String,

    /// JMESPath expression to filter/transform the response, e.g.
    /// "{path: file_path, size: size, content: content}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `gitlab_list_merge_requests`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitlabListMergeRequestsArgs {
    /// Project: numeric id ("42") or namespace path ("group/subgroup/project").
    pub project: String,

    /// Merge-request state: `opened`, `closed`, `merged`, `locked`, or `all`
    /// (GitLab's default is `all`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// Only merge requests from this source branch, e.g. "feature/login".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_branch: Option<String>,

    /// Only merge requests targeting this branch, e.g. "main".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_branch: Option<String>,

    /// Comma-separated label names the merge request must carry, e.g.
    /// "bug,backend". Use "None" for unlabelled, "Any" for any label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<String>,

    /// Only merge requests authored by this username, e.g. "jdoe".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_username: Option<String>,

    /// Sort field: `created_at` (default), `updated_at`, `title`, `merged_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_by: Option<String>,

    /// Sort direction: `asc` or `desc` (default `desc`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,

    /// Page size, 1–100 (default 20). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,

    /// 1-based page number. Continue with the response nextPage when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "[*].{iid: iid, title: title, state: state, author: author.username}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `gitlab_get_merge_request`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitlabGetMergeRequestArgs {
    /// Project: numeric id ("42") or namespace path ("group/subgroup/project").
    pub project: String,

    /// Project-scoped merge-request IID — the number in the UI and URL
    /// (`!12` → 12), NOT the global merge-request id.
    pub iid: u64,

    /// JMESPath expression to filter/transform the response, e.g.
    /// "{title: title, state: state, sha: sha, pipeline: head_pipeline.status}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `gitlab_get_merge_request_diff`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitlabGetMergeRequestDiffArgs {
    /// Project: numeric id ("42") or namespace path ("group/subgroup/project").
    pub project: String,

    /// Project-scoped merge-request IID — the number in the UI and URL
    /// (`!12` → 12), NOT the global merge-request id.
    pub iid: u64,

    /// Files per page, 1–100 (default 20). Each entry carries a full unified
    /// diff, so keep this small.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,

    /// 1-based page number. Continue with the response nextPage when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,

    /// JMESPath expression to filter/transform the response, e.g.
    /// "[*].{file: new_path, added: new_file, deleted: deleted_file}" to list
    /// changed files without the diff bodies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `gitlab_list_issues`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitlabListIssuesArgs {
    /// Project: numeric id ("42") or namespace path ("group/subgroup/project").
    pub project: String,

    /// Issue state: `opened`, `closed`, or `all` (GitLab's default is `all`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// Comma-separated label names the issue must carry, e.g. "bug,p1".
    /// Use "None" for unlabelled, "Any" for any label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<String>,

    /// Only issues assigned to this username, e.g. "jdoe".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee_username: Option<String>,

    /// Only issues authored by this username, e.g. "jdoe".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_username: Option<String>,

    /// Full-text search over issue title and description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,

    /// Sort field: `created_at` (default), `updated_at`, `priority`,
    /// `due_date`, `relative_position`, `label_priority`, `milestone_due`,
    /// `popularity`, `weight`, `title`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_by: Option<String>,

    /// Sort direction: `asc` or `desc` (default `desc`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,

    /// Page size, 1–100 (default 20). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,

    /// 1-based page number. Continue with the response nextPage when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "[*].{iid: iid, title: title, state: state, labels: labels}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `gitlab_get_issue`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitlabGetIssueArgs {
    /// Project: numeric id ("42") or namespace path ("group/subgroup/project").
    pub project: String,

    /// Project-scoped issue IID — the number in the UI and URL (`#7` → 7),
    /// NOT the global issue id.
    pub iid: u64,

    /// JMESPath expression to filter/transform the response, e.g.
    /// "{title: title, state: state, description: description, labels: labels}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `gitlab_list_pipelines`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitlabListPipelinesArgs {
    /// Project: numeric id ("42") or namespace path ("group/subgroup/project").
    pub project: String,

    /// Only pipelines for this branch or tag, e.g. "main".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,

    /// Pipeline status: `created`, `waiting_for_resource`, `preparing`,
    /// `pending`, `running`, `success`, `failed`, `canceled`, `skipped`,
    /// `manual`, `scheduled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// Trigger source: `push`, `web`, `trigger`, `schedule`, `api`,
    /// `external`, `pipeline`, `chat`, `webide`, `merge_request_event`,
    /// `external_pull_request_event`, `parent_pipeline`, …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Only pipelines for this commit SHA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,

    /// Sort field: `id` (default), `status`, `ref`, `updated_at`, `user_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_by: Option<String>,

    /// Sort direction: `asc` or `desc` (default `desc`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,

    /// Page size, 1–100 (default 20). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,

    /// 1-based page number. Continue with the response nextPage when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "[*].{id: id, status: status, ref: ref, sha: sha}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `gitlab_list_pipeline_jobs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitlabListPipelineJobsArgs {
    /// Project: numeric id ("42") or namespace path ("group/subgroup/project").
    pub project: String,

    /// Global pipeline id, as returned by `gitlab_list_pipelines` (`id`).
    pub pipeline_id: u64,

    /// One job status to filter on: `created`, `pending`, `running`, `failed`,
    /// `success`, `canceled`, `skipped`, `manual`. A single value only — to
    /// combine statuses, call once per status or filter with `jq`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Include retried jobs (earlier attempts) in the listing. Default false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_retried: Option<bool>,

    /// Page size, 1–100 (default 20). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_page: Option<u32>,

    /// 1-based page number. Continue with the response nextPage when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "[*].{id: id, name: name, stage: stage, status: status}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `gitlab_get_job_trace`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitlabGetJobTraceArgs {
    /// Project: numeric id ("42") or namespace path ("group/subgroup/project").
    pub project: String,

    /// Global job id, as returned by `gitlab_list_pipeline_jobs` (`id`).
    pub job_id: u64,

    /// Maximum encoded and decoded trace bytes (default 32 MiB, maximum 512 MiB).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,

    /// Reserved; leave unset. Trace bytes and previews are not filtered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Reserved; small traces are text and large trace metadata is JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

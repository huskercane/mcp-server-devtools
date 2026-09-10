#![allow(clippy::doc_markdown)]

//! GitHub controller path.
//!
//! Ten read-only tools sit on GitHub's REST API, all authenticated with a
//! static personal access token (`GITHUB_TOKEN`) injected as
//! `Authorization: Bearer` via [`Credentials::Bearer`] and pinned to one REST
//! API version through the `X-GitHub-Api-Version` header:
//!
//! - [`list_repositories`] — `GET /user/repos`, `/orgs/{owner}/repos`, or
//!   `/users/{owner}/repos` depending on `owner` / `ownerType`.
//! - [`get_file`] — `GET /repos/{owner}/{repo}/contents/{path}`; base64 file
//!   bodies are decoded to text when they are UTF-8, otherwise only metadata
//!   is returned (see [`decode_contents`]).
//! - [`list_pull_requests`] / [`get_pull_request`] / [`get_pull_request_diff`]
//!   — the PR list, one PR, and its changed files with per-file `patch`.
//! - [`list_issues`] / [`get_issue`] — issues (pull requests appear here too).
//! - [`list_workflow_runs`] / [`list_workflow_jobs`] — Actions runs and the
//!   jobs (with step results) of one run.
//!
//! Every caller-supplied identifier spliced into a path goes through
//! [`plain_segment`] / [`encode_path`], so a crafted value cannot re-shape the
//! endpoint. Page sizes are bounded to GitHub's `1..=100`. Everything after
//! that — base-URL resolution, query encoding, transport, error
//! classification, output rendering, raw-response persistence, and JMESPath
//! filtering — is the same code the other vendors use.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, Engine as _, GeneralPurpose, GeneralPurposeConfig};
use serde_json::Value;

use crate::auth::Credentials;
use crate::config::Config;
use crate::controllers::api::{
    ControllerResponse, HandleContext, dispatch_with_options, normalize_and_append,
};
use crate::controllers::segment::{encode_path, plain_segment, trimmed};
use crate::error::{McpError, api_error};
use crate::format::{OutputFormat, jmespath::apply_jq_filter, render};
use crate::tools::args::{
    GithubGetFileArgs, GithubGetIssueArgs, GithubGetPullRequestArgs, GithubGetPullRequestDiffArgs,
    GithubListIssuesArgs, GithubListPullRequestsArgs, GithubListRepositoriesArgs,
    GithubListWorkflowJobsArgs, GithubListWorkflowRunsArgs, GithubOwnerType, OutputFormatArg,
    QueryParams,
};
use crate::transport::{HttpClient, HttpMethod, RequestOptions, ResponseBody, fetch};
use crate::vendor::github::{
    API_VERSION_HEADER, GithubVendor, USER_REPOS_PATH, contents_path, issue_path, issues_path,
    org_repos_path, pull_files_path, pull_path, pulls_path, run_jobs_path, user_repos_path,
    workflow_id_runs_path, workflow_runs_path,
};

/// GitHub's default page size.
pub const DEFAULT_PER_PAGE: u32 = 30;

/// GitHub's maximum `per_page`; larger requests are capped, not rejected.
pub const MAX_PER_PAGE: u32 = 100;

/// Marker key added to a contents response whose `content` was not returned
/// as text. The value says why.
pub const CONTENT_OMITTED_KEY: &str = "contentOmitted";

/// `contentOmitted` reason for binary / non-UTF-8 files.
pub const CONTENT_OMITTED_BINARY: &str = "binary or non-UTF-8 content; only metadata is returned";

/// `contentOmitted` reason for files GitHub declines to inline (1–100 MB).
pub const CONTENT_OMITTED_TOO_LARGE: &str =
    "file larger than GitHub's inline limit; only metadata is returned";

/// `contentOmitted` reason for a `content` that was not valid base64.
pub const CONTENT_OMITTED_UNDECODABLE: &str =
    "content could not be base64-decoded; only metadata is returned";

/// GitHub-specific request context. Carries the concrete [`GithubVendor`]
/// (not a `&dyn Vendor`) so the token and API-version reads can be driven,
/// plus the shared client and config.
pub struct GithubContext<'a> {
    pub client: &'a HttpClient,
    pub config: &'a Config,
    pub vendor: &'a GithubVendor,
}

impl<'a> GithubContext<'a> {
    pub fn new(client: &'a HttpClient, config: &'a Config, vendor: &'a GithubVendor) -> Self {
        Self {
            client,
            config,
            vendor,
        }
    }
}

/// List repositories of an organization, a user, or the token's own user.
///
/// Kept as an `async fn` — there are `?`s on validation and token resolution
/// before the dispatch await.
pub async fn list_repositories(
    ctx: &GithubContext<'_>,
    args: &GithubListRepositoriesArgs,
) -> Result<ControllerResponse, McpError> {
    let mut qp = QueryParams::new();
    let path = if let Some(owner) = trimmed(args.owner.as_ref()) {
        if args.visibility.is_some() || args.affiliation.is_some() {
            return Err(api_error(
                "`visibility` and `affiliation` apply only to the authenticated user's \
                 listing — omit `owner` to use them, or use `type` instead.",
                Some(400),
                None,
            ));
        }
        let owner = plain_segment(owner, "owner")?;
        match args.owner_type.unwrap_or_default() {
            GithubOwnerType::Org => org_repos_path(owner),
            GithubOwnerType::User => user_repos_path(owner),
        }
    } else {
        insert_trimmed(&mut qp, "visibility", args.visibility.as_ref());
        insert_trimmed(&mut qp, "affiliation", args.affiliation.as_ref());
        USER_REPOS_PATH.to_owned()
    };
    insert_trimmed(&mut qp, "type", args.repo_type.as_ref());
    insert_trimmed(&mut qp, "sort", args.sort.as_ref());
    insert_trimmed(&mut qp, "direction", args.direction.as_ref());
    page_params(&mut qp, args.per_page, args.page)?;
    dispatch(ctx, &path, &qp, args.jq.as_deref(), args.output_format).await
}

/// Read a file (decoded to text when UTF-8) or list a directory at a ref.
///
/// Kept as an `async fn` — the response is post-processed after the await.
pub async fn get_file(
    ctx: &GithubContext<'_>,
    args: &GithubGetFileArgs,
) -> Result<ControllerResponse, McpError> {
    let owner = plain_segment(&args.owner, "owner")?;
    let repo = plain_segment(&args.repo, "repo")?;
    let encoded = encode_path(&args.path, "path")?;
    let mut qp = QueryParams::new();
    insert_trimmed(&mut qp, "ref", args.git_ref.as_ref());
    let path = normalize_and_append(ctx.vendor, &contents_path(owner, repo, &encoded), Some(&qp));

    let token = ctx.vendor.token(ctx.config).await?;
    let creds = Credentials::Bearer { token };
    let response = fetch(
        ctx.client,
        ctx.vendor,
        &creds,
        ctx.config,
        &path,
        request_options(ctx),
    )
    .await?;

    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    let content = match response.data {
        ResponseBody::Json(value) => {
            let decoded = decode_contents(value);
            render(&apply_jq_filter(&decoded, args.jq.as_deref()), fmt)
        }
        ResponseBody::Text(text) => text,
        ResponseBody::Empty => render(&Value::Object(serde_json::Map::new()), fmt),
    };
    Ok(ControllerResponse {
        content,
        raw_response_path: response.raw_response_path,
    })
}

/// List pull requests of a repository.
pub async fn list_pull_requests(
    ctx: &GithubContext<'_>,
    args: &GithubListPullRequestsArgs,
) -> Result<ControllerResponse, McpError> {
    let owner = plain_segment(&args.owner, "owner")?;
    let repo = plain_segment(&args.repo, "repo")?;
    let mut qp = QueryParams::new();
    insert_trimmed(&mut qp, "state", args.state.as_ref());
    insert_trimmed(&mut qp, "head", args.head.as_ref());
    insert_trimmed(&mut qp, "base", args.base.as_ref());
    insert_trimmed(&mut qp, "sort", args.sort.as_ref());
    insert_trimmed(&mut qp, "direction", args.direction.as_ref());
    page_params(&mut qp, args.per_page, args.page)?;
    let path = pulls_path(owner, repo);
    dispatch(ctx, &path, &qp, args.jq.as_deref(), args.output_format).await
}

/// One pull request by number.
pub async fn get_pull_request(
    ctx: &GithubContext<'_>,
    args: &GithubGetPullRequestArgs,
) -> Result<ControllerResponse, McpError> {
    let owner = plain_segment(&args.owner, "owner")?;
    let repo = plain_segment(&args.repo, "repo")?;
    let path = pull_path(owner, repo, args.number);
    dispatch(
        ctx,
        &path,
        &QueryParams::new(),
        args.jq.as_deref(),
        args.output_format,
    )
    .await
}

/// Files changed by a pull request, each with its unified `patch` when
/// GitHub inlines one (it omits `patch` for large and binary files).
pub async fn get_pull_request_diff(
    ctx: &GithubContext<'_>,
    args: &GithubGetPullRequestDiffArgs,
) -> Result<ControllerResponse, McpError> {
    let owner = plain_segment(&args.owner, "owner")?;
    let repo = plain_segment(&args.repo, "repo")?;
    let mut qp = QueryParams::new();
    page_params(&mut qp, args.per_page, args.page)?;
    let path = pull_files_path(owner, repo, args.number);
    dispatch(ctx, &path, &qp, args.jq.as_deref(), args.output_format).await
}

/// List issues (and pull requests, which GitHub returns from the same
/// endpoint) of a repository.
pub async fn list_issues(
    ctx: &GithubContext<'_>,
    args: &GithubListIssuesArgs,
) -> Result<ControllerResponse, McpError> {
    let owner = plain_segment(&args.owner, "owner")?;
    let repo = plain_segment(&args.repo, "repo")?;
    let mut qp = QueryParams::new();
    insert_trimmed(&mut qp, "state", args.state.as_ref());
    insert_trimmed(&mut qp, "labels", args.labels.as_ref());
    insert_trimmed(&mut qp, "assignee", args.assignee.as_ref());
    insert_trimmed(&mut qp, "creator", args.creator.as_ref());
    insert_trimmed(&mut qp, "since", args.since.as_ref());
    insert_trimmed(&mut qp, "sort", args.sort.as_ref());
    insert_trimmed(&mut qp, "direction", args.direction.as_ref());
    page_params(&mut qp, args.per_page, args.page)?;
    let path = issues_path(owner, repo);
    dispatch(ctx, &path, &qp, args.jq.as_deref(), args.output_format).await
}

/// One issue by number.
pub async fn get_issue(
    ctx: &GithubContext<'_>,
    args: &GithubGetIssueArgs,
) -> Result<ControllerResponse, McpError> {
    let owner = plain_segment(&args.owner, "owner")?;
    let repo = plain_segment(&args.repo, "repo")?;
    let path = issue_path(owner, repo, args.number);
    dispatch(
        ctx,
        &path,
        &QueryParams::new(),
        args.jq.as_deref(),
        args.output_format,
    )
    .await
}

/// Actions workflow runs of a repository, optionally of one workflow.
pub async fn list_workflow_runs(
    ctx: &GithubContext<'_>,
    args: &GithubListWorkflowRunsArgs,
) -> Result<ControllerResponse, McpError> {
    let owner = plain_segment(&args.owner, "owner")?;
    let repo = plain_segment(&args.repo, "repo")?;
    let path = match trimmed(args.workflow_id.as_ref()) {
        Some(workflow_id) => {
            let workflow_id = plain_segment(workflow_id, "workflowId")?;
            workflow_id_runs_path(owner, repo, workflow_id)
        }
        None => workflow_runs_path(owner, repo),
    };
    let mut qp = QueryParams::new();
    insert_trimmed(&mut qp, "branch", args.branch.as_ref());
    insert_trimmed(&mut qp, "status", args.status.as_ref());
    insert_trimmed(&mut qp, "event", args.event.as_ref());
    insert_trimmed(&mut qp, "actor", args.actor.as_ref());
    page_params(&mut qp, args.per_page, args.page)?;
    dispatch(ctx, &path, &qp, args.jq.as_deref(), args.output_format).await
}

/// Jobs (with step results) of one workflow run.
pub async fn list_workflow_jobs(
    ctx: &GithubContext<'_>,
    args: &GithubListWorkflowJobsArgs,
) -> Result<ControllerResponse, McpError> {
    let owner = plain_segment(&args.owner, "owner")?;
    let repo = plain_segment(&args.repo, "repo")?;
    let mut qp = QueryParams::new();
    insert_trimmed(&mut qp, "filter", args.filter.as_ref());
    page_params(&mut qp, args.per_page, args.page)?;
    let path = run_jobs_path(owner, repo, args.run_id);
    dispatch(ctx, &path, &qp, args.jq.as_deref(), args.output_format).await
}

/// Post-process a `GET …/contents/{path}` body so the caller gets readable
/// text instead of base64:
///
/// - A directory listing (JSON array) passes through untouched.
/// - A file with `encoding: "base64"` is decoded (GitHub wraps the base64 at
///   60 columns, so whitespace is stripped first). Valid UTF-8 replaces
///   `content` and `encoding` becomes `"utf-8"`; anything else drops `content`
///   and adds [`CONTENT_OMITTED_KEY`] explaining why.
/// - A file whose `content` is empty or absent while `size` is non-zero is
///   one GitHub declined to inline (1–100 MB, `encoding: "none"`); `content`
///   is dropped and [`CONTENT_OMITTED_TOO_LARGE`] is added.
/// - Symlinks and submodules (`type` other than `file`) pass through.
pub fn decode_contents(value: Value) -> Value {
    let Value::Object(mut obj) = value else {
        return value;
    };
    let is_file = obj
        .get("type")
        .and_then(Value::as_str)
        .is_none_or(|t| t == "file");
    if !is_file {
        return Value::Object(obj);
    }

    let is_base64 = obj
        .get("encoding")
        .and_then(Value::as_str)
        .is_some_and(|e| e.eq_ignore_ascii_case("base64"));
    let has_content = obj
        .get("content")
        .and_then(Value::as_str)
        .is_some_and(|c| c.bytes().any(|b| !b.is_ascii_whitespace()));

    if has_content && is_base64 {
        let compact: Vec<u8> = obj
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        match BASE64.decode(&compact).map(String::from_utf8) {
            Ok(Ok(text)) => {
                obj.insert("content".to_owned(), Value::String(text));
                obj.insert("encoding".to_owned(), Value::String("utf-8".to_owned()));
            }
            Ok(Err(_)) => omit_content(&mut obj, CONTENT_OMITTED_BINARY),
            Err(_) => omit_content(&mut obj, CONTENT_OMITTED_UNDECODABLE),
        }
        return Value::Object(obj);
    }

    if !has_content {
        match obj.get("size").and_then(Value::as_u64) {
            Some(0) => {
                obj.insert("content".to_owned(), Value::String(String::new()));
                obj.insert("encoding".to_owned(), Value::String("utf-8".to_owned()));
            }
            Some(_) => omit_content(&mut obj, CONTENT_OMITTED_TOO_LARGE),
            None => {}
        }
    }
    Value::Object(obj)
}

/// Standard alphabet, padding accepted but not required — GitHub pads, but
/// a decoder that tolerates its absence costs nothing and avoids a spurious
/// "undecodable" on a hand-trimmed fixture.
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn omit_content(obj: &mut serde_json::Map<String, Value>, reason: &str) {
    obj.remove("content");
    obj.insert(
        CONTENT_OMITTED_KEY.to_owned(),
        Value::String(reason.to_owned()),
    );
}

/// Resolve the token, pin the API version, and dispatch through the shared
/// pipeline (egress policy, cache, raw-response persistence, jq, rendering).
///
/// Kept as an `async fn` — there is a `?` on the token resolution before the
/// dispatch await, so the single-tail-await `impl Future` optimisation does
/// not apply.
async fn dispatch(
    ctx: &GithubContext<'_>,
    path: &str,
    qp: &QueryParams,
    jq: Option<&str>,
    output_format: Option<OutputFormatArg>,
) -> Result<ControllerResponse, McpError> {
    let token = ctx.vendor.token(ctx.config).await?;
    let creds = Credentials::Bearer { token };
    let handle = HandleContext::new(ctx.client, ctx.config, ctx.vendor);
    let normalized = normalize_and_append(ctx.vendor, path, Some(qp));
    let fmt = output_format.map_or(OutputFormat::Toon, Into::into);
    if qp.contains_key("per_page") {
        let mut options = request_options(ctx);
        options.fresh = true; // The ordinary response cache does not retain Link headers.
        let response = fetch(
            ctx.client,
            ctx.vendor,
            &creds,
            ctx.config,
            &normalized,
            options,
        )
        .await?;
        return Ok(super::paged::response(
            response,
            jq,
            fmt,
            path.ends_with("/files"),
        ));
    }
    dispatch_with_options(&handle, &creds, &normalized, jq, fmt, request_options(ctx)).await
}

/// `GET` with the pinned `X-GitHub-Api-Version`. The transport already sends
/// `Accept: application/json`, which GitHub honours.
fn request_options(ctx: &GithubContext<'_>) -> RequestOptions {
    RequestOptions {
        method: Some(HttpMethod::Get),
        headers: vec![(
            API_VERSION_HEADER.to_owned(),
            ctx.vendor.api_version(ctx.config).to_owned(),
        )],
        ..RequestOptions::default()
    }
}

/// Bound `perPage` to `1..=100` (default 30, larger values capped) and
/// `page` to `>= 1`, then add both as `per_page` / `page`.
fn page_params(
    qp: &mut QueryParams,
    per_page: Option<u32>,
    page: Option<u32>,
) -> Result<(), McpError> {
    let per_page = match per_page {
        None => DEFAULT_PER_PAGE,
        Some(0) => {
            return Err(api_error(
                format!("`perPage` must be between 1 and {MAX_PER_PAGE}"),
                Some(400),
                None,
            ));
        }
        Some(n) => n.min(MAX_PER_PAGE),
    };
    qp.insert("per_page".into(), per_page.to_string());
    match page {
        None => {}
        Some(0) => {
            return Err(api_error("`page` must be 1 or greater", Some(400), None));
        }
        Some(n) => {
            qp.insert("page".into(), n.to_string());
        }
    }
    Ok(())
}

/// Insert `key` when the optional value is present and non-blank.
fn insert_trimmed(qp: &mut QueryParams, key: &str, value: Option<&String>) {
    if let Some(v) = trimmed(value) {
        qp.insert(key.to_owned(), v.to_owned());
    }
}

/// Download one job's log through credential-safe, authorized redirects.
pub async fn get_job_logs(
    ctx: &GithubContext<'_>,
    args: &crate::tools::args::GithubGetJobLogsArgs,
) -> Result<ControllerResponse, McpError> {
    let owner = plain_segment(&args.owner, "owner")?;
    let repo = plain_segment(&args.repo, "repo")?;
    if args.job_id == 0 {
        return Err(api_error("jobId must be positive", Some(400), None));
    }
    let policy = super::download::policy(args.max_bytes)?;
    let credentials = Credentials::Bearer {
        token: ctx.vendor.token(ctx.config).await?,
    };
    let artifact = crate::transport::fetch_streamed_artifact_with_policy(
        ctx.vendor,
        &credentials,
        ctx.config,
        &format!("/repos/{owner}/{repo}/actions/jobs/{}/logs", args.job_id),
        request_options(ctx),
        "github-job",
        "log",
        "text/plain",
        policy,
    )
    .await?;
    Ok(super::download::response(&super::download::metadata(
        &artifact, ctx.config,
    )))
}

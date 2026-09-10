#![allow(clippy::doc_markdown)]

//! GitLab controller path.
//!
//! Ten read tools sit on GitLab's REST API v4, all authenticated with a static
//! access token (`GITLAB_TOKEN`) injected as `Authorization: Bearer` via
//! [`Credentials::Bearer`]. They cover the repository → merge request / issue →
//! pipeline → job → trace workflow:
//!
//! - [`list_projects`] — `GET /projects` or `GET /groups/{group}/projects`.
//! - [`get_file`] — `GET /projects/{project}/repository/files/{path}?ref=`,
//!   with the base64 body decoded to text when it is valid UTF-8.
//! - [`list_merge_requests`], [`get_merge_request`], [`get_merge_request_diff`].
//! - [`list_issues`], [`get_issue`].
//! - [`list_pipelines`], [`list_pipeline_jobs`], [`get_job_trace`].
//!
//! Identifier handling is the security-relevant part. A `project` is either a
//! numeric id (used verbatim) or a namespace path that GitLab expects as ONE
//! percent-encoded segment (`group%2Fsubgroup%2Fproject`); [`namespace_segment`]
//! validates and encodes it so a crafted value cannot add or remove path
//! segments. Issue / MR IIDs and pipeline / job ids are `u64`, so they cannot
//! carry structure at all. File paths go through the same segment rules as
//! [`encode_path`](crate::controllers::segment::encode_path) and are then encoded as a single segment, which is how
//! GitLab addresses `repository/files/{file_path}`.
//!
//! Everything after auth — base-URL resolution, query encoding, transport,
//! error classification, output rendering, raw-response persistence, and
//! JMESPath filtering — is the same code the other vendors use.

use base64::prelude::{BASE64_STANDARD, Engine as _};
use serde_json::Value;

use crate::auth::Credentials;
use crate::config::Config;
use crate::controllers::api::{
    ControllerResponse, HandleContext, dispatch_with_creds, normalize_and_append,
};
use crate::controllers::segment::{encode_segment, trimmed};
use crate::error::{McpError, api_error};
use crate::format::{OutputFormat, jmespath::apply_jq_filter, render};
use crate::tools::args::{
    GitlabGetFileArgs, GitlabGetIssueArgs, GitlabGetJobTraceArgs, GitlabGetMergeRequestArgs,
    GitlabGetMergeRequestDiffArgs, GitlabListIssuesArgs, GitlabListMergeRequestsArgs,
    GitlabListPipelineJobsArgs, GitlabListPipelinesArgs, GitlabListProjectsArgs, OutputFormatArg,
    QueryParams,
};
use crate::transport::{HttpClient, HttpMethod, RequestOptions, ResponseBody, fetch};
use crate::vendor::gitlab::{
    GitlabVendor, PROJECTS_PATH, group_projects_path, issue_path, issues_path, job_trace_path,
    merge_request_diffs_path, merge_request_path, merge_requests_path, pipeline_jobs_path,
    pipelines_path, repository_file_path,
};

/// Default and maximum `per_page` for every list tool. GitLab caps `per_page`
/// at 100; the default keeps token cost low.
pub const DEFAULT_PER_PAGE: u32 = 20;
pub const MAX_PER_PAGE: u32 = 100;

/// Marker stored in `contentOmitted` when a file's bytes are not UTF-8 text.
pub const BINARY_CONTENT_NOTE: &str = "binary or non-UTF-8 content; only metadata is returned";

/// Marker stored in `contentOmitted` when GitLab's `content` was not decodable
/// base64 (should not happen; kept so the caller sees why text is absent).
pub const UNDECODABLE_CONTENT_NOTE: &str =
    "content was not valid base64; only metadata is returned";

const MR_STATES: &[&str] = &["opened", "closed", "merged", "locked", "all"];
const ISSUE_STATES: &[&str] = &["opened", "closed", "all"];
const SORT_DIRECTIONS: &[&str] = &["asc", "desc"];
const JOB_SCOPES: &[&str] = &[
    "created", "pending", "running", "failed", "success", "canceled", "skipped", "manual",
];

/// GitLab-specific request context. Carries the concrete [`GitlabVendor`] (not
/// a `&dyn Vendor`) so the token read can be driven, plus the shared client and
/// config.
pub struct GitlabContext<'a> {
    pub client: &'a HttpClient,
    pub config: &'a Config,
    pub vendor: &'a GitlabVendor,
}

impl<'a> GitlabContext<'a> {
    pub fn new(client: &'a HttpClient, config: &'a Config, vendor: &'a GitlabVendor) -> Self {
        Self {
            client,
            config,
            vendor,
        }
    }
}

/// Validate a project or group identifier and return the single path segment
/// GitLab expects: a numeric id verbatim, a namespace path percent-encoded so
/// its `/` separators become `%2F`. Rejects empty values, whitespace / control
/// characters, and empty / `.` / `..` segments so the value cannot re-shape
/// the templated endpoint.
///
/// # Errors
///
/// A 400-shaped [`McpError`] naming `what` when the value is not acceptable.
pub fn namespace_segment(raw: &str, what: &str) -> Result<String, McpError> {
    let value = raw.trim().trim_matches('/');
    if value.is_empty() {
        return Err(api_error(
            format!("`{what}` must not be empty"),
            Some(400),
            None,
        ));
    }
    if value.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(value.to_owned());
    }
    if value
        .bytes()
        .any(|b| b <= 0x20 || b == 0x7F || matches!(b, b'?' | b'#' | b'%'))
    {
        return Err(api_error(
            format!(
                "`{what}` must be a numeric id or a namespace path like `group/subgroup/project` \
                 (no whitespace, `?`, `#`, or `%`)"
            ),
            Some(400),
            None,
        ));
    }
    if value
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(api_error(
            format!("`{what}` must not contain empty, `.` or `..` segments"),
            Some(400),
            None,
        ));
    }
    Ok(encode_segment(value))
}

/// Validate a repository file path with [`encode_path`](crate::controllers::segment::encode_path)'s segment rules and
/// encode the whole thing as ONE segment (`src%2Fmain.rs`), which is how
/// GitLab's `repository/files/{file_path}` endpoint addresses files.
///
/// # Errors
///
/// A 400-shaped [`McpError`] when the path is empty or contains an empty / `.`
/// / `..` segment.
pub fn file_segment(raw: &str) -> Result<String, McpError> {
    let value = raw.trim().trim_matches('/');
    if value.is_empty() {
        return Err(api_error("`path` must not be empty", Some(400), None));
    }
    if value
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(api_error(
            "`path` must not contain empty, `.` or `..` segments",
            Some(400),
            None,
        ));
    }
    Ok(encode_segment(value))
}

/// Append GitLab's offset pagination (`per_page`, `page`) after bounds
/// checking. `per_page` defaults to [`DEFAULT_PER_PAGE`] and is always sent;
/// `page` is sent only when supplied (GitLab defaults to 1).
fn page_params(
    qp: &mut QueryParams,
    per_page: Option<u32>,
    page: Option<u32>,
) -> Result<(), McpError> {
    let per_page = per_page.unwrap_or(DEFAULT_PER_PAGE);
    if !(1..=MAX_PER_PAGE).contains(&per_page) {
        return Err(api_error(
            format!("`perPage` must be between 1 and {MAX_PER_PAGE}"),
            Some(400),
            None,
        ));
    }
    qp.insert("per_page".into(), per_page.to_string());
    if let Some(page) = page {
        if page == 0 {
            return Err(api_error("`page` must be 1 or greater", Some(400), None));
        }
        qp.insert("page".into(), page.to_string());
    }
    Ok(())
}

/// Insert `key` when the optional value is present and non-blank.
fn insert_opt(qp: &mut QueryParams, key: &str, value: Option<&String>) {
    if let Some(value) = trimmed(value) {
        qp.insert(key.to_owned(), value.to_owned());
    }
}

/// Insert `key` when the optional value is present, after checking it is one
/// of `allowed` (GitLab would answer 400 otherwise; failing here is cheaper
/// and names the accepted values).
fn insert_enum(
    qp: &mut QueryParams,
    key: &str,
    what: &str,
    value: Option<&String>,
    allowed: &[&str],
) -> Result<(), McpError> {
    if let Some(value) = trimmed(value) {
        if !allowed.contains(&value) {
            return Err(api_error(
                format!("`{what}` must be one of: {}", allowed.join(", ")),
                Some(400),
                None,
            ));
        }
        qp.insert(key.to_owned(), value.to_owned());
    }
    Ok(())
}

fn output_format(arg: Option<OutputFormatArg>) -> OutputFormat {
    arg.map_or(OutputFormat::Toon, Into::into)
}

/// Resolve the token, then dispatch a `GET` through the shared pipeline.
/// Kept as an `async fn` — there is a `?` on the token resolution before the
/// dispatch await, so the single-tail-await `impl Future` optimisation does
/// not apply.
async fn dispatch_get(
    ctx: &GitlabContext<'_>,
    path: &str,
    qp: Option<&QueryParams>,
    jq: Option<&str>,
    fmt: OutputFormat,
) -> Result<ControllerResponse, McpError> {
    let token = ctx.vendor.token(ctx.config).await?;
    let creds = Credentials::Bearer { token };
    let handle = HandleContext::new(ctx.client, ctx.config, ctx.vendor);
    if qp.is_some_and(|query| query.contains_key("per_page")) {
        let normalized = normalize_and_append(ctx.vendor, path, qp);
        let response = fetch(
            ctx.client,
            ctx.vendor,
            &creds,
            ctx.config,
            &normalized,
            RequestOptions {
                fresh: true,
                ..Default::default()
            },
        )
        .await?;
        return Ok(super::paged::response(response, jq, fmt, false));
    }
    dispatch_with_creds(&handle, &creds, HttpMethod::Get, path, qp, None, jq, fmt).await
}

/// List projects visible to the token, or the projects of one group when
/// `groupId` is set. `membership` defaults to `true` on the global listing
/// so GitLab.com does not return every public project.
pub async fn list_projects(
    ctx: &GitlabContext<'_>,
    args: &GitlabListProjectsArgs,
) -> Result<ControllerResponse, McpError> {
    let mut qp = QueryParams::new();
    let path = if let Some(group) = trimmed(args.group_id.as_ref()) {
        group_projects_path(&namespace_segment(group, "groupId")?)
    } else {
        qp.insert(
            "membership".into(),
            args.membership.unwrap_or(true).to_string(),
        );
        PROJECTS_PATH.to_owned()
    };
    insert_opt(&mut qp, "search", args.search.as_ref());
    if let Some(owned) = args.owned {
        qp.insert("owned".into(), owned.to_string());
    }
    insert_opt(&mut qp, "order_by", args.order_by.as_ref());
    insert_enum(&mut qp, "sort", "sort", args.sort.as_ref(), SORT_DIRECTIONS)?;
    page_params(&mut qp, args.per_page, args.page)?;
    dispatch_get(
        ctx,
        &path,
        Some(&qp),
        args.jq.as_deref(),
        output_format(args.output_format),
    )
    .await
}

/// Read one file's metadata and content at an explicit ref. GitLab returns
/// the content base64-encoded; it is decoded here and replaced with UTF-8 text
/// (`encoding: "utf-8"`) when it is text, otherwise `content` is dropped and
/// `contentOmitted` explains why. Uses [`fetch`] directly (not
/// [`dispatch_with_creds`]) because the body is transformed before jq and
/// rendering run.
pub async fn get_file(
    ctx: &GitlabContext<'_>,
    args: &GitlabGetFileArgs,
) -> Result<ControllerResponse, McpError> {
    let project = namespace_segment(&args.project, "project")?;
    let file = file_segment(&args.path)?;
    let git_ref = args.git_ref.trim();
    if git_ref.is_empty() {
        return Err(api_error(
            "`ref` is required: a branch name, tag, or commit SHA",
            Some(400),
            None,
        ));
    }
    let mut qp = QueryParams::new();
    qp.insert("ref".into(), git_ref.to_owned());
    let normalized = normalize_and_append(
        ctx.vendor,
        &repository_file_path(&project, &file),
        Some(&qp),
    );

    let token = ctx.vendor.token(ctx.config).await?;
    let creds = Credentials::Bearer { token };
    let response = fetch(
        ctx.client,
        ctx.vendor,
        &creds,
        ctx.config,
        &normalized,
        RequestOptions {
            method: Some(HttpMethod::Get),
            ..RequestOptions::default()
        },
    )
    .await?;

    let data = match response.data {
        ResponseBody::Json(value) => decode_file_content(value),
        ResponseBody::Text(text) => Value::String(text),
        ResponseBody::Empty => Value::Object(serde_json::Map::new()),
    };
    let filtered = apply_jq_filter(&data, args.jq.as_deref());
    Ok(ControllerResponse {
        content: render(&filtered, output_format(args.output_format)),
        raw_response_path: response.raw_response_path,
    })
}

/// Replace GitLab's base64 `content` with decoded UTF-8 text, or drop it and
/// record why when the bytes are not text. Any body that is not the expected
/// `{encoding: "base64", content: "..."}` shape is returned untouched.
fn decode_file_content(mut value: Value) -> Value {
    let Some(map) = value.as_object_mut() else {
        return value;
    };
    if map.get("encoding").and_then(Value::as_str) != Some("base64") {
        return value;
    }
    let Some(encoded) = map.get("content").and_then(Value::as_str) else {
        return value;
    };
    let decoded = if encoded.bytes().any(|b| b.is_ascii_whitespace()) {
        let compact: String = encoded
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        BASE64_STANDARD.decode(compact)
    } else {
        BASE64_STANDARD.decode(encoded)
    };
    match decoded.map(String::from_utf8) {
        Ok(Ok(text)) => {
            map.insert("content".into(), Value::String(text));
            map.insert("encoding".into(), Value::String("utf-8".into()));
        }
        Ok(Err(_)) => {
            map.remove("content");
            map.insert(
                "contentOmitted".into(),
                Value::String(BINARY_CONTENT_NOTE.into()),
            );
        }
        Err(_) => {
            map.remove("content");
            map.insert(
                "contentOmitted".into(),
                Value::String(UNDECODABLE_CONTENT_NOTE.into()),
            );
        }
    }
    value
}

/// List a project's merge requests with the common filters.
pub async fn list_merge_requests(
    ctx: &GitlabContext<'_>,
    args: &GitlabListMergeRequestsArgs,
) -> Result<ControllerResponse, McpError> {
    let project = namespace_segment(&args.project, "project")?;
    let mut qp = QueryParams::new();
    insert_enum(&mut qp, "state", "state", args.state.as_ref(), MR_STATES)?;
    insert_opt(&mut qp, "source_branch", args.source_branch.as_ref());
    insert_opt(&mut qp, "target_branch", args.target_branch.as_ref());
    insert_opt(&mut qp, "labels", args.labels.as_ref());
    insert_opt(&mut qp, "author_username", args.author_username.as_ref());
    insert_opt(&mut qp, "order_by", args.order_by.as_ref());
    insert_enum(&mut qp, "sort", "sort", args.sort.as_ref(), SORT_DIRECTIONS)?;
    page_params(&mut qp, args.per_page, args.page)?;
    dispatch_get(
        ctx,
        &merge_requests_path(&project),
        Some(&qp),
        args.jq.as_deref(),
        output_format(args.output_format),
    )
    .await
}

/// Fetch one merge request by project-scoped IID.
pub async fn get_merge_request(
    ctx: &GitlabContext<'_>,
    args: &GitlabGetMergeRequestArgs,
) -> Result<ControllerResponse, McpError> {
    let project = namespace_segment(&args.project, "project")?;
    dispatch_get(
        ctx,
        &merge_request_path(&project, args.iid),
        None,
        args.jq.as_deref(),
        output_format(args.output_format),
    )
    .await
}

/// Fetch the per-file diffs of one merge request (paginated). GitLab may
/// omit a `diff` body and flag the entry `too_large` / `collapsed`; that flag
/// is passed through untouched.
pub async fn get_merge_request_diff(
    ctx: &GitlabContext<'_>,
    args: &GitlabGetMergeRequestDiffArgs,
) -> Result<ControllerResponse, McpError> {
    let project = namespace_segment(&args.project, "project")?;
    let mut qp = QueryParams::new();
    page_params(&mut qp, args.per_page, args.page)?;
    dispatch_get(
        ctx,
        &merge_request_diffs_path(&project, args.iid),
        Some(&qp),
        args.jq.as_deref(),
        output_format(args.output_format),
    )
    .await
}

/// List a project's issues with the common filters.
pub async fn list_issues(
    ctx: &GitlabContext<'_>,
    args: &GitlabListIssuesArgs,
) -> Result<ControllerResponse, McpError> {
    let project = namespace_segment(&args.project, "project")?;
    let mut qp = QueryParams::new();
    insert_enum(&mut qp, "state", "state", args.state.as_ref(), ISSUE_STATES)?;
    insert_opt(&mut qp, "labels", args.labels.as_ref());
    insert_opt(
        &mut qp,
        "assignee_username",
        args.assignee_username.as_ref(),
    );
    insert_opt(&mut qp, "author_username", args.author_username.as_ref());
    insert_opt(&mut qp, "search", args.search.as_ref());
    insert_opt(&mut qp, "order_by", args.order_by.as_ref());
    insert_enum(&mut qp, "sort", "sort", args.sort.as_ref(), SORT_DIRECTIONS)?;
    page_params(&mut qp, args.per_page, args.page)?;
    dispatch_get(
        ctx,
        &issues_path(&project),
        Some(&qp),
        args.jq.as_deref(),
        output_format(args.output_format),
    )
    .await
}

/// Fetch one issue by project-scoped IID.
pub async fn get_issue(
    ctx: &GitlabContext<'_>,
    args: &GitlabGetIssueArgs,
) -> Result<ControllerResponse, McpError> {
    let project = namespace_segment(&args.project, "project")?;
    dispatch_get(
        ctx,
        &issue_path(&project, args.iid),
        None,
        args.jq.as_deref(),
        output_format(args.output_format),
    )
    .await
}

/// List a project's pipelines with the common filters.
pub async fn list_pipelines(
    ctx: &GitlabContext<'_>,
    args: &GitlabListPipelinesArgs,
) -> Result<ControllerResponse, McpError> {
    let project = namespace_segment(&args.project, "project")?;
    let mut qp = QueryParams::new();
    insert_opt(&mut qp, "ref", args.git_ref.as_ref());
    insert_opt(&mut qp, "status", args.status.as_ref());
    insert_opt(&mut qp, "source", args.source.as_ref());
    insert_opt(&mut qp, "sha", args.sha.as_ref());
    insert_opt(&mut qp, "order_by", args.order_by.as_ref());
    insert_enum(&mut qp, "sort", "sort", args.sort.as_ref(), SORT_DIRECTIONS)?;
    page_params(&mut qp, args.per_page, args.page)?;
    dispatch_get(
        ctx,
        &pipelines_path(&project),
        Some(&qp),
        args.jq.as_deref(),
        output_format(args.output_format),
    )
    .await
}

/// List the jobs of one pipeline. `scope` is a single status; GitLab's
/// repeated `scope[]` form is not exposed.
pub async fn list_pipeline_jobs(
    ctx: &GitlabContext<'_>,
    args: &GitlabListPipelineJobsArgs,
) -> Result<ControllerResponse, McpError> {
    let project = namespace_segment(&args.project, "project")?;
    let mut qp = QueryParams::new();
    insert_enum(&mut qp, "scope", "scope", args.scope.as_ref(), JOB_SCOPES)?;
    if let Some(include_retried) = args.include_retried {
        qp.insert("include_retried".into(), include_retried.to_string());
    }
    page_params(&mut qp, args.per_page, args.page)?;
    dispatch_get(
        ctx,
        &pipeline_jobs_path(&project, args.pipeline_id),
        Some(&qp),
        args.jq.as_deref(),
        output_format(args.output_format),
    )
    .await
}

/// Stream a job trace into the shared artifact store. Small traces retain the
/// plain-text contract; larger traces return a bounded preview and artifact handle.
pub async fn get_job_trace(
    ctx: &GitlabContext<'_>,
    args: &GitlabGetJobTraceArgs,
) -> Result<ControllerResponse, McpError> {
    let project = namespace_segment(&args.project, "project")?;
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
        &job_trace_path(&project, args.job_id),
        RequestOptions::default(),
        "gitlab-trace",
        "log",
        "text/plain",
        policy,
    )
    .await?;
    let mut metadata = super::download::metadata(&artifact, ctx.config);
    if artifact.artifact.size <= crate::constants::data_limits::STREAM_PREVIEW_HEAD_SIZE as u64 {
        return Ok(ControllerResponse {
            content: artifact.head,
            raw_response_path: None,
        });
    }
    metadata["preview"] = serde_json::json!({"head": artifact.head, "tail": artifact.tail});
    Ok(super::download::response(&metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn namespace_segment_accepts_ids_and_encodes_paths() {
        assert_eq!(namespace_segment(" 42 ", "project").unwrap(), "42");
        assert_eq!(
            namespace_segment("group/sub-group/my.project", "project").unwrap(),
            "group%2Fsub-group%2Fmy.project"
        );
        for bad in [
            "", "  ", "/", "a//b", "a/./b", "../x", "a b", "a?b", "a%2Fb", "..",
        ] {
            assert_eq!(
                namespace_segment(bad, "project").unwrap_err().status_code,
                Some(400),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn file_segment_is_one_encoded_segment() {
        assert_eq!(file_segment("src/main.rs").unwrap(), "src%2Fmain.rs");
        assert_eq!(file_segment("/docs/a b.md/").unwrap(), "docs%2Fa%20b.md");
        for bad in ["", "/", "a//b", "../secret", "a/./b"] {
            assert_eq!(file_segment(bad).unwrap_err().status_code, Some(400));
        }
    }

    #[test]
    fn decode_file_content_handles_text_binary_and_garbage() {
        let text = decode_file_content(json!({"encoding":"base64","content":"aGVsbG8=","size":5}));
        assert_eq!(text["content"], "hello");
        assert_eq!(text["encoding"], "utf-8");
        assert_eq!(text["size"], 5);

        let wrapped = decode_file_content(json!({"encoding":"base64","content":"aGVs\nbG8="}));
        assert_eq!(wrapped["content"], "hello");

        let binary = decode_file_content(json!({"encoding":"base64","content":"/wD/AA=="}));
        assert!(binary.get("content").is_none());
        assert_eq!(binary["contentOmitted"], BINARY_CONTENT_NOTE);

        let garbage = decode_file_content(json!({"encoding":"base64","content":"!!not base64!!"}));
        assert!(garbage.get("content").is_none());
        assert_eq!(garbage["contentOmitted"], UNDECODABLE_CONTENT_NOTE);

        let other = decode_file_content(json!({"encoding":"text","content":"raw"}));
        assert_eq!(other["content"], "raw");
    }
}

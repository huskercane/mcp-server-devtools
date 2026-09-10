#![allow(clippy::doc_markdown)]

//! Vercel controller path.
//!
//! Four read tools sit on Vercel's REST API, all authenticated with a static
//! account token (`VERCEL_TOKEN`) injected as `Authorization: Bearer` via
//! [`Credentials::Bearer`]:
//!
//! - [`list_projects`] — `GET /v9/projects`: discover project ids/names,
//!   optionally by name substring or linked repository URL.
//! - [`list_deployments`] — `GET /v6/deployments`: the deployment history of a
//!   project (or the whole scope), filterable by state / target / time window.
//! - [`get_deployment`] — `GET /v13/deployments/{id}`: one deployment's status,
//!   URL, commit metadata, and error summary.
//! - [`get_deployment_logs`] — `GET /v3/deployments/{id}/events`: the bounded
//!   build + runtime event log. `follow=1` (server-side streaming) is never
//!   sent; the log is bounded by `limit` and the shared response cap.
//!
//! **Scope.** Vercel resolves every request against the personal account unless
//! a `teamId` query parameter names a team. [`resolve_team_id`] applies the
//! precedence tool argument → `VERCEL_TEAM_ID` config → none, and only sends the
//! parameter when one resolved. Team-owned projects are invisible (404) without
//! it, so the docs and error messages point at it.
//!
//! Everything after auth — query encoding, transport, error classification,
//! output rendering, raw-response persistence, and JMESPath filtering — is the
//! same code the other vendors use.

use crate::transport::HttpClient;

use crate::auth::Credentials;
use crate::config::Config;
use crate::controllers::api::{ControllerResponse, HandleContext, dispatch_with_creds};
use crate::controllers::segment::{plain_segment, trimmed};
use crate::error::{McpError, api_error};
use crate::format::OutputFormat;
use crate::tools::args::{
    QueryParams, VercelGetDeploymentArgs, VercelGetDeploymentLogsArgs, VercelListDeploymentsArgs,
    VercelListProjectsArgs,
};
use crate::transport::HttpMethod;
use crate::vendor::vercel::{
    DEPLOYMENTS_PATH, PROJECTS_PATH, VercelVendor, deployment_events_path, deployment_path,
};

/// Default page size for the two list tools.
pub const DEFAULT_LIST_LIMIT: u32 = 20;

/// Upper bound Vercel accepts for list page sizes.
pub const MAX_LIST_LIMIT: u32 = 100;

/// Default number of log events returned by [`get_deployment_logs`].
pub const DEFAULT_LOG_LIMIT: u32 = 100;

/// Upper bound on log events per call. Vercel accepts more, but the shared
/// response cap makes larger pages pointless — page with `since`/`until`.
pub const MAX_LOG_LIMIT: u32 = 1000;

/// Deployment states Vercel's `state` filter understands.
const DEPLOYMENT_STATES: [&str; 6] = [
    "BUILDING",
    "ERROR",
    "INITIALIZING",
    "QUEUED",
    "READY",
    "CANCELED",
];

/// Deployment targets Vercel's `target` filter understands.
const DEPLOYMENT_TARGETS: [&str; 2] = ["production", "preview"];

/// Event read orders the events endpoint understands.
const LOG_DIRECTIONS: [&str; 2] = ["forward", "backward"];

/// Vercel-specific request context. Carries the concrete [`VercelVendor`]
/// (not a `&dyn Vendor`) so the token and default-team reads can be driven,
/// plus the shared client and config.
pub struct VercelContext<'a> {
    pub client: &'a HttpClient,
    pub config: &'a Config,
    pub vendor: &'a VercelVendor,
}

impl<'a> VercelContext<'a> {
    pub fn new(client: &'a HttpClient, config: &'a Config, vendor: &'a VercelVendor) -> Self {
        Self {
            client,
            config,
            vendor,
        }
    }
}

/// List projects in scope (`GET /v9/projects`). Kept as an `async fn` — there
/// is a `?` on argument validation and the token read before the dispatch
/// await, so the single-tail-await `impl Future` optimisation does not apply.
pub async fn list_projects(
    ctx: &VercelContext<'_>,
    args: &VercelListProjectsArgs,
) -> Result<ControllerResponse, McpError> {
    let mut qp = scoped_query(ctx, args.team_id.as_ref())?;
    qp.insert(
        "limit".into(),
        bounded_limit(args.limit, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT)?.to_string(),
    );
    insert_trimmed(&mut qp, "search", args.search.as_ref());
    insert_trimmed(&mut qp, "from", args.from.as_ref());
    insert_trimmed(&mut qp, "until", args.until.as_ref());
    insert_trimmed(&mut qp, "repoUrl", args.repo_url.as_ref());

    let token = ctx.vendor.token(ctx.config).await?;
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    dispatch(ctx, token, PROJECTS_PATH, &qp, args.jq.as_deref(), fmt).await
}

/// List deployments (`GET /v6/deployments`), optionally for one project and
/// filtered by state / target / time window. Kept as an `async fn` — there is a
/// `?` on argument validation and the token read before the dispatch await.
pub async fn list_deployments(
    ctx: &VercelContext<'_>,
    args: &VercelListDeploymentsArgs,
) -> Result<ControllerResponse, McpError> {
    let mut qp = scoped_query(ctx, args.team_id.as_ref())?;
    qp.insert(
        "limit".into(),
        bounded_limit(args.limit, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT)?.to_string(),
    );
    insert_trimmed(&mut qp, "projectId", args.project_id.as_ref());
    insert_trimmed(&mut qp, "app", args.app.as_ref());
    if let Some(state) = trimmed(args.state.as_ref()) {
        qp.insert("state".into(), normalized_states(state)?);
    }
    if let Some(target) = trimmed(args.target.as_ref()) {
        qp.insert(
            "target".into(),
            one_of(target, &DEPLOYMENT_TARGETS, "target")?.to_owned(),
        );
    }
    insert_trimmed(&mut qp, "since", args.since.as_ref());
    insert_trimmed(&mut qp, "until", args.until.as_ref());

    let token = ctx.vendor.token(ctx.config).await?;
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    dispatch(ctx, token, DEPLOYMENTS_PATH, &qp, args.jq.as_deref(), fmt).await
}

/// Fetch one deployment (`GET /v13/deployments/{id}`) by id or hostname. Kept
/// as an `async fn` — there is a `?` on identifier validation and the token
/// read before the dispatch await.
pub async fn get_deployment(
    ctx: &VercelContext<'_>,
    args: &VercelGetDeploymentArgs,
) -> Result<ControllerResponse, McpError> {
    let deployment = plain_segment(&args.deployment, "deployment")?;
    let qp = scoped_query(ctx, args.team_id.as_ref())?;
    let path = deployment_path(deployment);

    let token = ctx.vendor.token(ctx.config).await?;
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    dispatch(ctx, token, &path, &qp, args.jq.as_deref(), fmt).await
}

/// Fetch a deployment's bounded build + runtime event log
/// (`GET /v3/deployments/{id}/events`). Streaming (`follow=1`) is never
/// requested; the page is bounded by `limit` (default 100, max 1000) and the
/// shared response cap. Kept as an `async fn` — there is a `?` on identifier
/// validation and the token read before the dispatch await.
pub async fn get_deployment_logs(
    ctx: &VercelContext<'_>,
    args: &VercelGetDeploymentLogsArgs,
) -> Result<ControllerResponse, McpError> {
    let deployment = plain_segment(&args.deployment, "deployment")?;
    let mut qp = scoped_query(ctx, args.team_id.as_ref())?;
    qp.insert(
        "limit".into(),
        bounded_limit(args.limit, DEFAULT_LOG_LIMIT, MAX_LOG_LIMIT)?.to_string(),
    );
    let direction = trimmed(args.direction.as_ref()).map_or(Ok(LOG_DIRECTIONS[0]), |d| {
        one_of(d, &LOG_DIRECTIONS, "direction")
    })?;
    qp.insert("direction".into(), direction.to_owned());
    if args.builds.unwrap_or(true) {
        qp.insert("builds".into(), "1".into());
    }
    insert_trimmed(&mut qp, "since", args.since.as_ref());
    insert_trimmed(&mut qp, "until", args.until.as_ref());
    insert_trimmed(&mut qp, "statusCode", args.status_code.as_ref());
    let path = deployment_events_path(deployment);

    let token = ctx.vendor.token(ctx.config).await?;
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    dispatch(ctx, token, &path, &qp, args.jq.as_deref(), fmt).await
}

/// Resolve the team scope for a call: tool argument → `VERCEL_TEAM_ID` config
/// → none (personal account). The value is validated as a plain segment so a
/// crafted id cannot inject query structure.
///
/// # Errors
///
/// A 400-shaped error when the resolved id is not a plain identifier.
pub fn resolve_team_id<'a>(
    ctx: &'a VercelContext<'_>,
    arg: Option<&'a String>,
) -> Result<Option<&'a str>, McpError> {
    trimmed(arg)
        .or_else(|| ctx.vendor.default_team_id(ctx.config))
        .map(|id| plain_segment(id, "teamId"))
        .transpose()
}

/// Start a query string carrying `teamId` when a team scope resolved.
fn scoped_query(ctx: &VercelContext<'_>, arg: Option<&String>) -> Result<QueryParams, McpError> {
    let mut qp = QueryParams::new();
    if let Some(team_id) = resolve_team_id(ctx, arg)? {
        qp.insert("teamId".into(), team_id.to_owned());
    }
    Ok(qp)
}

/// Apply the default and enforce `1..=max` on a caller-supplied page size.
fn bounded_limit(limit: Option<u32>, default: u32, max: u32) -> Result<u32, McpError> {
    match limit {
        None => Ok(default),
        Some(n) if (1..=max).contains(&n) => Ok(n),
        Some(n) => Err(api_error(
            format!("`limit` must be between 1 and {max} (got {n})"),
            Some(400),
            None,
        )),
    }
}

/// Insert `key` when the optional value is non-blank after trimming.
fn insert_trimmed(qp: &mut QueryParams, key: &str, value: Option<&String>) {
    if let Some(v) = trimmed(value) {
        qp.insert(key.to_owned(), v.to_owned());
    }
}

/// Case-insensitively match `value` against `allowed`, returning the canonical
/// spelling Vercel expects.
fn one_of<'a>(value: &str, allowed: &[&'a str], what: &str) -> Result<&'a str, McpError> {
    allowed
        .iter()
        .copied()
        .find(|candidate| candidate.eq_ignore_ascii_case(value))
        .ok_or_else(|| {
            api_error(
                format!(
                    "`{what}` must be one of {} (got `{value}`)",
                    allowed.join(", ")
                ),
                Some(400),
                None,
            )
        })
}

/// Validate a comma-separated `state` filter and re-emit it in Vercel's
/// canonical upper-case spelling.
fn normalized_states(raw: &str) -> Result<String, McpError> {
    let mut out = String::with_capacity(raw.len());
    for (index, part) in raw.split(',').map(str::trim).enumerate() {
        let state = one_of(part, &DEPLOYMENT_STATES, "state")?;
        if index > 0 {
            out.push(',');
        }
        out.push_str(state);
    }
    Ok(out)
}

/// Shared tail: wrap the token as a bearer credential and dispatch through the
/// vendor-neutral pipeline. An `async fn` rather than `impl Future`: the
/// credential and handle are locals that must outlive the await, so an outer
/// state machine is unavoidable either way.
async fn dispatch(
    ctx: &VercelContext<'_>,
    token: String,
    path: &str,
    qp: &QueryParams,
    jq: Option<&str>,
    fmt: OutputFormat,
) -> Result<ControllerResponse, McpError> {
    let creds = Credentials::Bearer { token };
    let handle = HandleContext::new(ctx.client, ctx.config, ctx.vendor);
    dispatch_with_creds(
        &handle,
        &creds,
        HttpMethod::Get,
        path,
        Some(qp),
        None,
        jq,
        fmt,
    )
    .await
}

#![allow(clippy::doc_markdown)]

//! Snyk controller path.
//!
//! Four read tools sit on Snyk's REST API, all authenticated with a static
//! API token (`SNYK_TOKEN`) sent as `Authorization: token <TOKEN>` via
//! [`SnykVendor::credentials`]:
//!
//! - [`list_orgs`] — `GET /rest/orgs`: the organizations the token can see
//!   (the first call, since every other tool is org-scoped).
//! - [`list_projects`] — `GET /rest/orgs/{org}/projects`: the monitored
//!   manifests / images / IaC files in an organization.
//! - [`list_issues`] — `GET /rest/orgs/{org}/issues`: the findings, filterable
//!   by project, severity, status, type, and ignore state.
//! - [`get_project`] — `GET /rest/orgs/{org}/projects/{project}`: one project,
//!   optionally with its target expanded inline.
//!
//! Every request carries the mandatory `version` query parameter (resolved
//! by [`SnykVendor::api_version`]); every caller-supplied identifier that is
//! spliced into a path goes through [`plain_segment`] + [`encode_segment`]
//! so it cannot re-shape the endpoint. Everything after that — base-URL
//! resolution, query encoding, transport, error classification, output
//! rendering, raw-response persistence, and JMESPath filtering — is the same
//! code the other vendors use.

use crate::auth::Credentials;
use crate::config::Config;
use crate::controllers::api::{ControllerResponse, HandleContext, dispatch_with_creds};
use crate::controllers::segment::{encode_segment, plain_segment, trimmed};
use crate::error::{McpError, api_error};
use crate::format::OutputFormat;
use crate::tools::args::{
    OutputFormatArg, QueryParams, SnykGetProjectArgs, SnykListIssuesArgs, SnykListOrgsArgs,
    SnykListProjectsArgs,
};
use crate::transport::{HttpClient, HttpMethod};
use url::form_urlencoded;

use crate::vendor::snyk::{
    ORG_ISSUES_SUFFIX, ORG_PROJECTS_SUFFIX, ORGS_PATH, SnykVendor, VERSION_PARAM,
};

/// Default page size when the caller omits `limit`.
pub const DEFAULT_LIMIT: u32 = 20;

/// Largest page Snyk's REST list endpoints accept.
pub const MAX_LIMIT: u32 = 100;

/// Snyk-specific request context. Carries the concrete [`SnykVendor`] (not a
/// `&dyn Vendor`) so the token read and version / default-org resolution can
/// be driven, plus the shared client and config.
pub struct SnykContext<'a> {
    pub client: &'a HttpClient,
    pub config: &'a Config,
    pub vendor: &'a SnykVendor,
}

impl<'a> SnykContext<'a> {
    pub fn new(client: &'a HttpClient, config: &'a Config, vendor: &'a SnykVendor) -> Self {
        Self {
            client,
            config,
            vendor,
        }
    }
}

/// List the organizations visible to the token. Kept as an `async fn` — there
/// is a `?` on the credential resolution before the dispatch await, so the
/// single-tail-await `impl Future` optimisation does not apply.
pub async fn list_orgs(
    ctx: &SnykContext<'_>,
    args: &SnykListOrgsArgs,
) -> Result<ControllerResponse, McpError> {
    let (creds, mut qp) = prepare(ctx).await?;
    if let Some(group_id) = trimmed(args.group_id.as_ref()) {
        qp.insert(
            "group_id".into(),
            plain_segment(group_id, "groupId")?.to_owned(),
        );
    }
    if let Some(slug) = trimmed(args.slug.as_ref()) {
        qp.insert("slug".into(), slug.to_owned());
    }
    page_params(&mut qp, args.limit, args.starting_after.as_ref())?;

    dispatch(
        ctx,
        &creds,
        ORGS_PATH,
        &qp,
        args.jq.as_deref(),
        args.output_format,
    )
    .await
}

/// List the projects in an organization. Kept as an `async fn` for the same
/// reason as [`list_orgs`].
pub async fn list_projects(
    ctx: &SnykContext<'_>,
    args: &SnykListProjectsArgs,
) -> Result<ControllerResponse, McpError> {
    let (creds, mut qp) = prepare(ctx).await?;
    let org = resolve_org_id(ctx, args.org_id.as_ref())?;
    if let Some(names) = trimmed(args.names.as_ref()) {
        qp.insert("names".into(), names.to_owned());
    }
    if let Some(target_id) = trimmed(args.target_id.as_ref()) {
        qp.insert(
            "target_id".into(),
            plain_segment(target_id, "targetId")?.to_owned(),
        );
    }
    if let Some(types) = trimmed(args.types.as_ref()) {
        qp.insert("types".into(), types.to_owned());
    }
    if let Some(origins) = trimmed(args.origins.as_ref()) {
        qp.insert("origins".into(), origins.to_owned());
    }
    page_params(&mut qp, args.limit, args.starting_after.as_ref())?;

    let path = format!("{ORGS_PATH}/{org}/{ORG_PROJECTS_SUFFIX}");
    dispatch(
        ctx,
        &creds,
        &path,
        &qp,
        args.jq.as_deref(),
        args.output_format,
    )
    .await
}

/// List the issues (findings) in an organization, optionally scoped to one
/// project / environment and filtered by severity, status, type, ignore
/// state, and timestamps. Kept as an `async fn` for the same reason as
/// [`list_orgs`].
pub async fn list_issues(
    ctx: &SnykContext<'_>,
    args: &SnykListIssuesArgs,
) -> Result<ControllerResponse, McpError> {
    let (creds, mut qp) = prepare(ctx).await?;
    let org = resolve_org_id(ctx, args.org_id.as_ref())?;

    match (
        trimmed(args.scan_item_id.as_ref()),
        trimmed(args.scan_item_type.as_ref()),
    ) {
        (Some(id), Some(kind)) => {
            let kind = kind.to_ascii_lowercase();
            if !matches!(kind.as_str(), "project" | "environment") {
                return Err(api_error(
                    "`scanItemType` must be `project` or `environment`",
                    Some(400),
                    None,
                ));
            }
            qp.insert(
                "scan_item.id".into(),
                plain_segment(id, "scanItemId")?.to_owned(),
            );
            qp.insert("scan_item.type".into(), kind);
        }
        (None, None) => {}
        _ => {
            return Err(api_error(
                "Pass `scanItemId` and `scanItemType` together (a project or environment \
                 UUID plus its kind), or neither to list the whole organization.",
                Some(400),
                None,
            ));
        }
    }
    if let Some(levels) = trimmed(args.effective_severity_level.as_ref()) {
        qp.insert(
            "effective_severity_level".into(),
            validate_csv(
                levels,
                &["low", "medium", "high", "critical"],
                "effectiveSeverityLevel",
            )?,
        );
    }
    if let Some(status) = trimmed(args.status.as_ref()) {
        qp.insert(
            "status".into(),
            validate_csv(status, &["open", "resolved"], "status")?,
        );
    }
    if let Some(kind) = trimmed(args.r#type.as_ref()) {
        qp.insert("type".into(), kind.to_owned());
    }
    if let Some(ignored) = args.ignored {
        qp.insert("ignored".into(), ignored.to_string());
    }
    if let Some(after) = trimmed(args.updated_after.as_ref()) {
        qp.insert("updated_after".into(), after.to_owned());
    }
    if let Some(after) = trimmed(args.created_after.as_ref()) {
        qp.insert("created_after".into(), after.to_owned());
    }
    page_params(&mut qp, args.limit, args.starting_after.as_ref())?;

    let path = format!("{ORGS_PATH}/{org}/{ORG_ISSUES_SUFFIX}");
    dispatch(
        ctx,
        &creds,
        &path,
        &qp,
        args.jq.as_deref(),
        args.output_format,
    )
    .await
}

/// Fetch one project, optionally with its target expanded. Kept as an
/// `async fn` for the same reason as [`list_orgs`].
pub async fn get_project(
    ctx: &SnykContext<'_>,
    args: &SnykGetProjectArgs,
) -> Result<ControllerResponse, McpError> {
    let (creds, mut qp) = prepare(ctx).await?;
    let org = resolve_org_id(ctx, args.org_id.as_ref())?;
    let project = encode_segment(plain_segment(&args.project_id, "projectId")?);
    if let Some(expand) = trimmed(args.expand.as_ref()) {
        if !expand.eq_ignore_ascii_case("target") {
            return Err(api_error(
                "`expand` only supports `target`",
                Some(400),
                None,
            ));
        }
        qp.insert("expand".into(), "target".to_owned());
    }

    let path = format!("{ORGS_PATH}/{org}/{ORG_PROJECTS_SUFFIX}/{project}");
    dispatch(
        ctx,
        &creds,
        &path,
        &qp,
        args.jq.as_deref(),
        args.output_format,
    )
    .await
}

/// Turn a `startingAfter` argument into the bare cursor Snyk expects.
///
/// Snyk's `links.next` is a relative URL
/// (`/orgs/{id}/issues?version=…&starting_after=v1.eyJ…&limit=20`). Callers
/// are told to pass the `starting_after` value, but an LLM will often paste
/// the whole link; when the value looks like a URL, the cursor is extracted
/// from its query string instead of being sent verbatim (which Snyk would
/// reject as a malformed cursor).
pub fn resolve_cursor(raw: &str) -> Result<String, McpError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(api_error(
            "`startingAfter` must not be empty",
            Some(400),
            None,
        ));
    }
    let looks_like_link =
        value.contains('?') || value.contains('/') || value.starts_with("starting_after=");
    if !looks_like_link {
        return Ok(value.to_owned());
    }
    let query = value.rsplit_once('?').map_or(value, |(_, query)| query);
    let query = query.split('#').next().unwrap_or(query);
    form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "starting_after")
        .map(|(_, cursor)| cursor.into_owned())
        .filter(|cursor| !cursor.is_empty())
        .ok_or_else(|| {
            api_error(
                "`startingAfter` looks like a link but carries no `starting_after` cursor — \
                 pass the `starting_after` value from the previous response's `links.next`",
                Some(400),
                None,
            )
        })
}

/// Resolve credentials and seed the query with the mandatory `version`
/// parameter. Shared prologue for every tool.
async fn prepare(ctx: &SnykContext<'_>) -> Result<(Credentials, QueryParams), McpError> {
    let creds = ctx.vendor.credentials(ctx.config).await?;
    let version = ctx.vendor.api_version(ctx.config)?;
    let mut qp = QueryParams::new();
    qp.insert(VERSION_PARAM.into(), version);
    Ok((creds, qp))
}

/// Resolve the organization id (argument → `SNYK_ORG_ID`) and return it
/// validated and percent-encoded, ready to splice into a path.
fn resolve_org_id(ctx: &SnykContext<'_>, arg: Option<&String>) -> Result<String, McpError> {
    let raw = trimmed(arg)
        .or_else(|| ctx.vendor.default_org_id(ctx.config))
        .ok_or_else(|| {
            api_error(
                "orgId is required: pass `orgId` or set SNYK_ORG_ID",
                Some(400),
                None,
            )
        })?;
    Ok(encode_segment(plain_segment(raw, "orgId")?))
}

/// Validate and append `limit` / `starting_after`.
fn page_params(
    qp: &mut QueryParams,
    limit: Option<u32>,
    starting_after: Option<&String>,
) -> Result<(), McpError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(api_error(
            format!("`limit` must be between 1 and {MAX_LIMIT}"),
            Some(400),
            None,
        ));
    }
    qp.insert("limit".into(), limit.to_string());
    if let Some(cursor) = starting_after {
        qp.insert("starting_after".into(), resolve_cursor(cursor)?);
    }
    Ok(())
}

/// Validate a comma-separated enum list against `allowed` (case-insensitive)
/// and return it normalised to lowercase without stray whitespace.
fn validate_csv(raw: &str, allowed: &[&str], what: &str) -> Result<String, McpError> {
    let mut out = String::with_capacity(raw.len());
    for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let lower = item.to_ascii_lowercase();
        if !allowed.contains(&lower.as_str()) {
            return Err(api_error(
                format!(
                    "`{what}` must be a comma-separated list of {}",
                    allowed.join(" | ")
                ),
                Some(400),
                None,
            ));
        }
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&lower);
    }
    if out.is_empty() {
        return Err(api_error(
            format!(
                "`{what}` must be a comma-separated list of {}",
                allowed.join(" | ")
            ),
            Some(400),
            None,
        ));
    }
    Ok(out)
}

/// Tail dispatch shared by every tool: GET through the vendor-neutral
/// pipeline with the resolved credentials. An `async fn` rather than
/// `impl Future`: the [`HandleContext`] is a local that must outlive the
/// await, so an async block would be needed either way.
async fn dispatch(
    ctx: &SnykContext<'_>,
    creds: &Credentials,
    path: &str,
    qp: &QueryParams,
    jq: Option<&str>,
    output_format: Option<OutputFormatArg>,
) -> Result<ControllerResponse, McpError> {
    let fmt = output_format.map_or(OutputFormat::Toon, Into::into);
    let handle = HandleContext::new(ctx.client, ctx.config, ctx.vendor);
    dispatch_with_creds(
        &handle,
        creds,
        HttpMethod::Get,
        path,
        Some(qp),
        None,
        jq,
        fmt,
    )
    .await
}

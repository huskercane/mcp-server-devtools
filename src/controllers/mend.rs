//! Mend Platform API 3.0 controller path.
//!
//! Four read tools sit on Mend's 3.0 REST surface, all authenticated with the
//! JWT the vendor mints from the configured login inputs
//! ([`MendVendor::bearer`]) and injects as `Authorization: Bearer` via
//! [`Credentials::Bearer`]:
//!
//! - [`list_applications`] — the organization's applications (the former
//!   "products").
//! - [`list_projects`] — the projects of the organization or of one
//!   application.
//! - [`get_project`] — one project.
//! - [`list_findings`] — a project's SCA (dependency) security findings.
//!
//! The organization comes from `MEND_ORG_UUID`, never from a tool argument.
//! Every caller-supplied UUID is validated with [`plain_segment`] before it
//! is spliced into an endpoint path, and page sizes are bounded to
//! `1..=200`. Everything after auth — base-URL resolution, query encoding,
//! transport, error classification, output rendering, raw-response
//! persistence and JMESPath filtering — is the code the other vendors use.

use crate::auth::Credentials;
use crate::config::Config;
use crate::controllers::api::ControllerResponse;
use crate::controllers::segment::{plain_segment, trimmed};
use crate::error::{McpError, api_error};
use crate::format::OutputFormat;
use crate::tools::args::{
    MendGetProjectArgs, MendListApplicationsArgs, MendListFindingsArgs, MendListProjectsArgs,
    OutputFormatArg, QueryParams,
};
use crate::transport::{HttpClient, HttpMethod};
use crate::vendor::mend::{
    MendVendor, org_applications_path, org_projects_path, project_security_findings_path,
};

/// Default page size when `limit` is omitted.
pub const DEFAULT_LIMIT: u32 = 50;
/// Largest page size accepted; anything above is refused, not clamped, so
/// the caller learns the bound instead of silently getting less.
pub const MAX_LIMIT: u32 = 200;

/// Severities `mend_list_findings` accepts (lower-cased before comparison).
const SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];

/// Mend-specific request context. Carries the concrete [`MendVendor`] (not a
/// `&dyn Vendor`) so the login-backed bearer and the org UUID can be driven,
/// plus the shared client and config.
pub struct MendContext<'a> {
    pub client: &'a HttpClient,
    pub config: &'a Config,
    pub vendor: &'a MendVendor,
}

impl<'a> MendContext<'a> {
    pub fn new(client: &'a HttpClient, config: &'a Config, vendor: &'a MendVendor) -> Self {
        Self {
            client,
            config,
            vendor,
        }
    }
}

/// List the organization's applications (Mend 3.0's name for the former
/// "products"). Kept as an `async fn` — there are `?`s on the bearer and the
/// org UUID before the dispatch await.
pub async fn list_applications(
    ctx: &MendContext<'_>,
    args: &MendListApplicationsArgs,
) -> Result<ControllerResponse, McpError> {
    let org = ctx.vendor.org_uuid(ctx.config)?;
    let path = org_applications_path(plain_segment(&org, "MEND_ORG_UUID")?);
    let qp = paging_params(args.cursor.as_ref(), args.limit, args.search.as_ref())?;
    let token = ctx.vendor.bearer(ctx.client, ctx.config).await?;
    dispatch(
        ctx,
        token,
        &path,
        &qp,
        args.jq.as_deref(),
        args.output_format,
        None,
    )
    .await
}

/// List the projects of the organization, or of one application when
/// `applicationUuid` is given. Kept as an `async fn` — there are `?`s on the
/// bearer and the identifiers before the dispatch await.
pub async fn list_projects(
    ctx: &MendContext<'_>,
    args: &MendListProjectsArgs,
) -> Result<ControllerResponse, McpError> {
    let org = ctx.vendor.org_uuid(ctx.config)?;
    let mut path = org_projects_path(plain_segment(&org, "MEND_ORG_UUID")?);
    let body = if let Some(application) = trimmed(args.application_uuid.as_ref()) {
        let application = plain_segment(application, "applicationUuid")?;
        path.push_str("/summaries");
        Some(serde_json::json!({"applicationUuids": [application]}))
    } else {
        None
    };
    let qp = paging_params(args.cursor.as_ref(), args.limit, args.search.as_ref())?;
    let token = ctx.vendor.bearer(ctx.client, ctx.config).await?;
    dispatch(
        ctx,
        token,
        &path,
        &qp,
        args.jq.as_deref(),
        args.output_format,
        body,
    )
    .await
}

/// Fetch one project. Kept as an `async fn` — there are `?`s on the bearer
/// and the identifier before the dispatch await.
pub async fn get_project(
    ctx: &MendContext<'_>,
    args: &MendGetProjectArgs,
) -> Result<ControllerResponse, McpError> {
    let project = plain_segment(&args.project_uuid, "projectUuid")?;
    let org = ctx.vendor.org_uuid(ctx.config)?;
    let path = format!(
        "{}/summaries",
        org_projects_path(plain_segment(&org, "MEND_ORG_UUID")?)
    );
    let token = ctx.vendor.bearer(ctx.client, ctx.config).await?;
    dispatch(
        ctx,
        token,
        &path,
        &QueryParams::new(),
        args.jq.as_deref(),
        args.output_format,
        Some(serde_json::json!({"projectUuids": [project]})),
    )
    .await
}

/// List a project's SCA security findings, optionally filtered by severity
/// and status. Kept as an `async fn` — there are `?`s on the bearer, the
/// identifier and the filters before the dispatch await.
pub async fn list_findings(
    ctx: &MendContext<'_>,
    args: &MendListFindingsArgs,
) -> Result<ControllerResponse, McpError> {
    let path = project_security_findings_path(plain_segment(&args.project_uuid, "projectUuid")?);
    let mut qp = paging_params(args.cursor.as_ref(), args.limit, None)?;
    if let Some(severity) = trimmed(args.severity.as_ref()) {
        qp.insert("severity".into(), normalize_severities(severity)?);
    }
    if let Some(status) = trimmed(args.status.as_ref()) {
        qp.insert("status".into(), status.to_owned());
    }
    let token = ctx.vendor.bearer(ctx.client, ctx.config).await?;
    dispatch(
        ctx,
        token,
        &path,
        &qp,
        args.jq.as_deref(),
        args.output_format,
        None,
    )
    .await
}

/// Shared tail: wrap the JWT as a bearer and hand off to the vendor-neutral
/// dispatcher.
async fn dispatch(
    ctx: &MendContext<'_>,
    token: String,
    path: &str,
    query_params: &QueryParams,
    jq: Option<&str>,
    output_format: Option<OutputFormatArg>,
    body: Option<serde_json::Value>,
) -> Result<ControllerResponse, McpError> {
    let creds = Credentials::Bearer { token };
    let fmt = output_format.map_or(OutputFormat::Toon, Into::into);
    // These filters are explicitly page-local: the Platform endpoints do not
    // expose them as query parameters. Preserve cursor metadata after filtering.
    let mut wire_query = query_params.clone();
    for key in ["search", "severity", "status"] {
        wire_query.remove(key);
    }
    let normalized =
        crate::controllers::api::normalize_and_append(ctx.vendor, path, Some(&wire_query));
    let response = crate::transport::fetch(
        ctx.client,
        ctx.vendor,
        &creds,
        ctx.config,
        &normalized,
        crate::transport::RequestOptions {
            method: Some(if body.is_some() {
                HttpMethod::Post
            } else {
                HttpMethod::Get
            }),
            body,
            fresh: true,
            ..Default::default()
        },
    )
    .await?;
    let crate::transport::ResponseBody::Json(mut value) = response.data else {
        return Err(api_error("Invalid Mend response", Some(502), None));
    };
    if let Some(items) = value
        .get_mut("response")
        .and_then(serde_json::Value::as_array_mut)
    {
        items.retain(|item| {
            let search = query_params.get("search").is_none_or(|search| {
                item.get("name")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|name| name.to_lowercase().contains(&search.to_lowercase()))
            });
            let severity = query_params.get("severity").is_none_or(|severities| {
                item.pointer("/vulnerability/severity")
                    .or_else(|| item.get("severity"))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|severity| {
                        severities
                            .split(',')
                            .any(|allowed| allowed.eq_ignore_ascii_case(severity))
                    })
            });
            let status = query_params.get("status").is_none_or(|expected| {
                item.get("status")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|status| expected.eq_ignore_ascii_case(status))
            });
            search && severity && status
        });
    }
    let filtered = crate::format::jmespath::apply_jq_filter(&value, jq);
    Ok(ControllerResponse {
        content: crate::format::render(&filtered, fmt),
        raw_response_path: response.raw_response_path,
    })
}

/// Build the `cursor` / `limit` / `search` query parameters, validating the
/// page size. `limit` is refused (400) outside `1..=MAX_LIMIT` rather than
/// clamped so the caller learns the bound.
fn paging_params(
    cursor: Option<&String>,
    limit: Option<u32>,
    search: Option<&String>,
) -> Result<QueryParams, McpError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(api_error(
            format!("`limit` must be between 1 and {MAX_LIMIT} (default {DEFAULT_LIMIT})"),
            Some(400),
            None,
        ));
    }
    let mut qp = QueryParams::new();
    qp.insert("limit".into(), limit.to_string());
    if let Some(cursor) = trimmed(cursor) {
        qp.insert("cursor".into(), cursor.to_owned());
    }
    if let Some(search) = trimmed(search) {
        qp.insert("search".into(), search.to_owned());
    }
    Ok(qp)
}

/// Validate a comma-separated severity list against [`SEVERITIES`] and
/// return it lower-cased and de-spaced (`"Critical, HIGH"` → `"critical,high"`).
fn normalize_severities(raw: &str) -> Result<String, McpError> {
    let mut out = String::with_capacity(raw.len());
    for part in raw.split(',') {
        let value = part.trim().to_ascii_lowercase();
        if !SEVERITIES.contains(&value.as_str()) {
            return Err(api_error(
                format!(
                    "`severity` must be a comma-separated list of critical, high, medium, low \
                     (got `{}`)",
                    part.trim()
                ),
                Some(400),
                None,
            ));
        }
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&value);
    }
    Ok(out)
}

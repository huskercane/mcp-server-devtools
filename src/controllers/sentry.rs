#![allow(clippy::doc_markdown)]

//! Sentry controller path.
//!
//! Five read tools sit on Sentry's Web API, all authenticated with a static
//! auth token (`SENTRY_TOKEN`) injected as `Authorization: Bearer` via
//! [`Credentials::Bearer`]:
//!
//! - [`list_projects`] — `GET /api/0/organizations/{org}/projects/`.
//! - [`search_issues`] — `GET /api/0/organizations/{org}/issues/` with Sentry
//!   search syntax (`is:unresolved level:error …`).
//! - [`get_issue`] — `GET /api/0/organizations/{org}/issues/{id}/`.
//! - [`get_event`] — `GET /api/0/organizations/{org}/issues/{id}/events/{event}/`
//!   (`latest`, `oldest`, or a 32-hex event id).
//! - [`list_releases`] — `GET /api/0/organizations/{org}/releases/`.
//!
//! Every tool takes `organization?`, resolved as argument → `SENTRY_ORG` →
//! error, and every caller-supplied identifier spliced into a path goes
//! through [`plain_segment`] first.
//!
//! ## Cursor pagination
//!
//! Sentry paginates with a `Link` *response header*, not a body field:
//!
//! ```text
//! <…&cursor=1500000000000:0:1>; rel="previous"; results="false"; cursor="1500000000000:0:1",
//! <…&cursor=1500000000000:100:0>; rel="next"; results="true"; cursor="1500000000000:100:0"
//! ```
//!
//! The three list tools therefore call [`fetch`] directly (rather than
//! `dispatch_with_creds`, which discards headers), pull the `rel="next"`
//! cursor out with [`next_cursor`] when `results="true"`, and render
//! `{"data": <jq-filtered body>, "nextCursor": <string|null>}`. The vendor
//! disables the read cache so a cached (header-less) body can never hide a
//! next page.
//!
//! Everything else — base-URL resolution, query encoding, transport, error
//! classification, raw-response persistence, output rendering — is the same
//! code the other vendors use.

use serde_json::{Value, json};

use crate::auth::Credentials;
use crate::config::Config;
use crate::controllers::api::{
    ControllerResponse, HandleContext, dispatch_with_creds, normalize_and_append,
};
use crate::controllers::segment::{plain_segment, trimmed};
use crate::error::{McpError, api_error};
use crate::format::{OutputFormat, jmespath::apply_jq_filter, render};
use crate::tools::args::{
    QueryParams, SentryGetEventArgs, SentryGetIssueArgs, SentryListProjectsArgs,
    SentryListReleasesArgs, SentrySearchIssuesArgs,
};
use crate::transport::{HttpClient, HttpMethod, RequestOptions, ResponseBody, fetch};
use crate::vendor::sentry::{
    SentryVendor, issue_event_path, issue_path, issues_path, projects_path, releases_path,
};

/// Default page size for `sentry_search_issues`.
pub const DEFAULT_ISSUE_LIMIT: u32 = 25;
/// Sentry's own cap on `limit` for the issues endpoint.
pub const MAX_ISSUE_LIMIT: u32 = 100;
/// Default event selector for `sentry_get_event`.
pub const DEFAULT_EVENT_ID: &str = "latest";

/// Accepted `sort` values for the issues endpoint.
const ISSUE_SORTS: [&str; 5] = ["date", "new", "freq", "priority", "user"];

/// Sentry-specific request context. Carries the concrete [`SentryVendor`]
/// (not a `&dyn Vendor`) so the token read and `SENTRY_ORG` fallback can be
/// driven, plus the shared client and config.
pub struct SentryContext<'a> {
    pub client: &'a HttpClient,
    pub config: &'a Config,
    pub vendor: &'a SentryVendor,
}

impl<'a> SentryContext<'a> {
    pub fn new(client: &'a HttpClient, config: &'a Config, vendor: &'a SentryVendor) -> Self {
        Self {
            client,
            config,
            vendor,
        }
    }
}

/// List the organization's projects (one cursor page).
///
/// Kept as an `async fn`: organization resolution can fail before the
/// dispatch await, so the single-tail-await `impl Future` optimisation does
/// not apply.
pub async fn list_projects(
    ctx: &SentryContext<'_>,
    args: &SentryListProjectsArgs,
) -> Result<ControllerResponse, McpError> {
    let org = resolve_organization(ctx, args.organization.as_ref())?;
    let mut qp = QueryParams::new();
    insert_cursor(&mut qp, args.cursor.as_ref());
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    fetch_page(ctx, &projects_path(&org), &qp, args.jq.as_deref(), fmt).await
}

/// Search issues across the organization with Sentry search syntax (one
/// cursor page). `query` defaults to `is:unresolved`; `limit` is clamped to
/// Sentry's 1–100 range up front so a bad value is a 400 here, not upstream.
pub async fn search_issues(
    ctx: &SentryContext<'_>,
    args: &SentrySearchIssuesArgs,
) -> Result<ControllerResponse, McpError> {
    let org = resolve_organization(ctx, args.organization.as_ref())?;

    let limit = args.limit.unwrap_or(DEFAULT_ISSUE_LIMIT);
    if !(1..=MAX_ISSUE_LIMIT).contains(&limit) {
        return Err(api_error(
            format!(
                "`limit` must be between 1 and {MAX_ISSUE_LIMIT} (default {DEFAULT_ISSUE_LIMIT})"
            ),
            Some(400),
            None,
        ));
    }

    let mut qp = QueryParams::new();
    qp.insert(
        "query".into(),
        trimmed(args.query.as_ref())
            .unwrap_or("is:unresolved")
            .to_owned(),
    );
    qp.insert("limit".into(), limit.to_string());
    if let Some(project) = trimmed(args.project.as_ref()) {
        qp.insert("project".into(), numeric_project(project)?.to_owned());
    }
    if let Some(period) = trimmed(args.stats_period.as_ref()) {
        qp.insert("statsPeriod".into(), period.to_owned());
    }
    if let Some(environment) = trimmed(args.environment.as_ref()) {
        qp.insert("environment".into(), environment.to_owned());
    }
    if let Some(sort) = trimmed(args.sort.as_ref()) {
        if !ISSUE_SORTS.contains(&sort) {
            return Err(api_error(
                format!(
                    "`sort` must be one of {} (got `{sort}`)",
                    ISSUE_SORTS.join(", ")
                ),
                Some(400),
                None,
            ));
        }
        qp.insert("sort".into(), sort.to_owned());
    }
    insert_cursor(&mut qp, args.cursor.as_ref());

    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    fetch_page(ctx, &issues_path(&org), &qp, args.jq.as_deref(), fmt).await
}

/// One issue's metadata and aggregate stats.
pub async fn get_issue(
    ctx: &SentryContext<'_>,
    args: &SentryGetIssueArgs,
) -> Result<ControllerResponse, McpError> {
    let org = resolve_organization(ctx, args.organization.as_ref())?;
    let issue_id = plain_segment(&args.issue_id, "issueId")?;
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    dispatch_get(ctx, &issue_path(&org, issue_id), args.jq.as_deref(), fmt).await
}

/// One event of an issue — `latest` (default), `oldest`, or a 32-hex event
/// id. The body carries the full stack trace, breadcrumbs, and contexts; the
/// shared 10 MiB transport cap and the tool layer's artifact spill bound it.
/// Attachments are never fetched.
pub async fn get_event(
    ctx: &SentryContext<'_>,
    args: &SentryGetEventArgs,
) -> Result<ControllerResponse, McpError> {
    let org = resolve_organization(ctx, args.organization.as_ref())?;
    let issue_id = plain_segment(&args.issue_id, "issueId")?;
    let event_id = event_selector(trimmed(args.event_id.as_ref()))?;
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    dispatch_get(
        ctx,
        &issue_event_path(&org, issue_id, event_id),
        args.jq.as_deref(),
        fmt,
    )
    .await
}

/// List the organization's releases (one cursor page).
pub async fn list_releases(
    ctx: &SentryContext<'_>,
    args: &SentryListReleasesArgs,
) -> Result<ControllerResponse, McpError> {
    let org = resolve_organization(ctx, args.organization.as_ref())?;
    let mut qp = QueryParams::new();
    if let Some(query) = trimmed(args.query.as_ref()) {
        qp.insert("query".into(), query.to_owned());
    }
    if let Some(project) = trimmed(args.project.as_ref()) {
        qp.insert("project".into(), numeric_project(project)?.to_owned());
    }
    if let Some(sort) = trimmed(args.sort.as_ref()) {
        qp.insert("sort".into(), sort.to_owned());
    }
    insert_cursor(&mut qp, args.cursor.as_ref());
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    fetch_page(ctx, &releases_path(&org), &qp, args.jq.as_deref(), fmt).await
}

/// Extract the `rel="next"` cursor from a Sentry `Link` header, but only when
/// that entry says `results="true"` — Sentry always emits a `next` link, and
/// `results="false"` is how it signals the last page.
///
/// Entries are comma-separated; each is `<url>; param; param…` where params
/// are `key="value"` (quotes optional). The URL is skipped rather than parsed
/// because the `cursor` param carries the same value without the surrounding
/// query string. Anything malformed yields `None` — a missing next page is
/// the safe default.
#[must_use]
pub fn next_cursor(link_header: &str) -> Option<String> {
    link_entries(link_header).find_map(|entry| {
        let (_, params) = entry.split_once('>')?;
        let mut rel_next = false;
        let mut has_results = false;
        let mut cursor: Option<&str> = None;
        for param in params.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let (key, value) = param.split_once('=')?;
            let value = value.trim().trim_matches('"');
            match key.trim() {
                "rel" => rel_next = value == "next",
                "results" => has_results = value == "true",
                "cursor" => cursor = Some(value),
                _ => {}
            }
        }
        if rel_next && has_results {
            cursor.filter(|c| !c.is_empty()).map(str::to_owned)
        } else {
            None
        }
    })
}

/// Split a `Link` header into its comma-separated entries without splitting
/// inside the `<…>` URL, whose query string may itself contain commas.
fn link_entries(header: &str) -> impl Iterator<Item = &str> {
    let mut depth = 0usize;
    header
        .split(move |c: char| {
            match c {
                '<' => depth = depth.saturating_add(1),
                '>' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => return true,
                _ => {}
            }
            false
        })
        .map(str::trim)
        .filter(|entry| entry.starts_with('<'))
}

/// Resolve the organization slug: explicit argument, then `SENTRY_ORG`. The
/// result is validated as one path segment so a crafted slug cannot reshape
/// the endpoint.
fn resolve_organization(ctx: &SentryContext<'_>, arg: Option<&String>) -> Result<String, McpError> {
    let raw = trimmed(arg)
        .or_else(|| ctx.vendor.default_organization(ctx.config))
        .ok_or_else(|| {
            api_error(
                "organization is required: pass `organization` or set SENTRY_ORG",
                Some(400),
                None,
            )
        })?;
    plain_segment(raw, "organization").map(str::to_owned)
}

/// Sentry's `project` filter is a numeric project id (`-1` means "all"); a
/// slug is a different thing and gets a 400 upstream with a vague message, so
/// reject it here with a clear one.
fn numeric_project(raw: &str) -> Result<&str, McpError> {
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(api_error(
            format!(
                "`project` must be a numeric project id (see sentry_list_projects), got `{raw}`"
            ),
            Some(400),
            None,
        ));
    }
    Ok(raw)
}

/// `latest` (default) / `oldest`, or a 32-character hexadecimal event id.
fn event_selector(raw: Option<&str>) -> Result<&str, McpError> {
    let value = raw.unwrap_or(DEFAULT_EVENT_ID);
    let is_hex_id = value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit());
    if value == "latest" || value == "oldest" || is_hex_id {
        Ok(value)
    } else {
        Err(api_error(
            "`eventId` must be `latest`, `oldest`, or a 32-character hexadecimal event id",
            Some(400),
            None,
        ))
    }
}

fn insert_cursor(qp: &mut QueryParams, cursor: Option<&String>) {
    if let Some(cursor) = trimmed(cursor) {
        qp.insert("cursor".into(), cursor.to_owned());
    }
}

/// Single-resource GET through the shared dispatcher (jq + render included).
async fn dispatch_get(
    ctx: &SentryContext<'_>,
    path: &str,
    jq: Option<&str>,
    fmt: OutputFormat,
) -> Result<ControllerResponse, McpError> {
    let token = ctx.vendor.token(ctx.config).await?;
    let creds = Credentials::Bearer { token };
    let handle = HandleContext::new(ctx.client, ctx.config, ctx.vendor);
    dispatch_with_creds(&handle, &creds, HttpMethod::Get, path, None, None, jq, fmt).await
}

/// One cursor page of a list endpoint. Goes to the transport directly so the
/// `Link` response header is available, then renders
/// `{"data": <jq-filtered body>, "nextCursor": <string|null>}`.
async fn fetch_page(
    ctx: &SentryContext<'_>,
    path: &str,
    qp: &QueryParams,
    jq: Option<&str>,
    fmt: OutputFormat,
) -> Result<ControllerResponse, McpError> {
    let token = ctx.vendor.token(ctx.config).await?;
    let creds = Credentials::Bearer { token };
    let normalized = normalize_and_append(ctx.vendor, path, Some(qp));
    let response = fetch(
        ctx.client,
        ctx.vendor,
        &creds,
        ctx.config,
        &normalized,
        RequestOptions {
            fresh: true, // Pagination requires headers, which the body cache does not retain.
            method: Some(HttpMethod::Get),
            ..RequestOptions::default()
        },
    )
    .await?;

    let cursor = response
        .headers
        .get_all(http::header::LINK)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(next_cursor);
    let data = match &response.data {
        ResponseBody::Json(value) => apply_jq_filter(value, jq).into_owned(),
        ResponseBody::Text(text) => Value::String(text.clone()),
        ResponseBody::Empty => json!([]),
    };
    Ok(ControllerResponse {
        content: render(&json!({"data": data, "nextCursor": cursor}), fmt),
        raw_response_path: response.raw_response_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEXT: &str = "<https://sentry.io/api/0/organizations/acme/issues/?&cursor=1500000000000:0:1>; rel=\"previous\"; results=\"false\"; cursor=\"1500000000000:0:1\", <https://sentry.io/api/0/organizations/acme/issues/?&cursor=1500000000000:100:0>; rel=\"next\"; results=\"true\"; cursor=\"1500000000000:100:0\"";

    #[test]
    fn next_cursor_present() {
        assert_eq!(next_cursor(NEXT).as_deref(), Some("1500000000000:100:0"));
        // Order of entries and params does not matter; quotes are optional.
        let reordered = "<u?cursor=b>; cursor=b; results=true; rel=next, <u?cursor=a>; rel=\"previous\"; results=\"true\"; cursor=\"a\"";
        assert_eq!(next_cursor(reordered).as_deref(), Some("b"));
    }

    #[test]
    fn next_cursor_absent_or_last_page() {
        assert_eq!(next_cursor(""), None);
        // Only a previous link.
        assert_eq!(
            next_cursor("<u?cursor=a>; rel=\"previous\"; results=\"true\"; cursor=\"a\""),
            None
        );
        // Sentry's last-page signal: a next link with results="false".
        let last = NEXT.replace(
            "rel=\"next\"; results=\"true\"",
            "rel=\"next\"; results=\"false\"",
        );
        assert_eq!(next_cursor(&last), None);
    }

    #[test]
    fn next_cursor_malformed() {
        for bad in [
            "garbage",
            "rel=\"next\"; results=\"true\"; cursor=\"x\"", // no <url>
            "<u>; rel=\"next\"; results=\"true\"",          // no cursor param
            "<u>; rel=\"next\"; results=\"true\"; cursor=\"\"", // empty cursor
            "<u>; rel; results=\"true\"; cursor=\"x\"",     // param without `=`
            "<u; rel=\"next\"; results=\"true\"; cursor=\"x\"", // unterminated url
        ] {
            assert_eq!(next_cursor(bad), None, "{bad}");
        }
        // A comma inside the URL must not split the entry.
        let comma = "<u?project=1,2&cursor=c>; rel=\"next\"; results=\"true\"; cursor=\"c\"";
        assert_eq!(next_cursor(comma).as_deref(), Some("c"));
    }

    #[test]
    fn selectors_validate() {
        assert_eq!(event_selector(None).unwrap(), "latest");
        assert_eq!(event_selector(Some("oldest")).unwrap(), "oldest");
        let hex = "a1b2c3d4e5f60718a9b0c1d2e3f40516";
        assert_eq!(event_selector(Some(hex)).unwrap(), hex);
        for bad in ["newest", "a1b2", "g1b2c3d4e5f60718a9b0c1d2e3f40516", "../x"] {
            assert_eq!(
                event_selector(Some(bad)).unwrap_err().status_code,
                Some(400)
            );
        }
        assert_eq!(
            numeric_project("4507000000000001").unwrap(),
            "4507000000000001"
        );
        assert_eq!(numeric_project("-1").unwrap(), "-1");
        for bad in ["my-project", "-", "12a", ""] {
            assert_eq!(numeric_project(bad).unwrap_err().status_code, Some(400));
        }
    }
}

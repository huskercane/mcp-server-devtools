//! The read-only pages (WP D.1): each is one admin API response rendered.
//! Templates receive view structs only — never a session, never a token.
//!
//! Forms carry `hx-*` attributes for an in-place refresh of one section
//! (`hx-select` pulls that section out of the full page the handler always
//! renders), and plain `method`/`action` so the page works without the
//! script. `HX-Request` is never consulted: the same handler answers both.

use std::{collections::BTreeMap, sync::Arc};

use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Console, Page, Session};
use crate::ports::{
    AdminMethod, AdminRequest, AdminResponse,
    activity_reports::ActivityRow,
    rollup_store::{GroupRow, Report, TimelineRow, Totals},
};

/// One admin call's outcome from a page's point of view: its `data`, or
/// the boundary's status and error code (a session-ending 401 never
/// reaches here; [`Console::api`] answers it).
enum Answer {
    Data(Value),
    Refused { status: u16, code: String },
}

fn answer(response: AdminResponse) -> Answer {
    if response.is_success() {
        let mut body = response.body;
        Answer::Data(body["data"].take())
    } else {
        Answer::Refused {
            status: response.status,
            code: response.body["error"]
                .as_str()
                .unwrap_or("error")
                .to_owned(),
        }
    }
}

fn refusal(status: u16, code: &str) -> String {
    match code {
        "admin_backend_unavailable" => "Not available from this process (admin_backend_unavailable): the backend lives in a co-located `all` process, not here.".to_owned(),
        "approvals_off" => "Two-person approval is off (`MCP_ADMIN_APPROVALS`); there are no proposals to show.".to_owned(),
        "admin_busy" => "The admin API is at its task budget (429 admin_busy); try again.".to_owned(),
        _ => format!("The admin API answered {status} {code}."),
    }
}

/// A page that could not be rendered: the API's non-success answer, or a
/// response that did not decode.
fn error_from(status: u16, code: &str) -> Response {
    let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    Console::error_page(status_code, "Admin API error", &refusal(status, code), true)
}

fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Option<T> {
    serde_json::from_value(value).ok()
}

// ---------------------------------------------------------------- policy

#[derive(Deserialize, Default, Clone)]
pub(super) struct ExplainForm {
    #[serde(default)]
    tool: String,
    #[serde(default)]
    arguments: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    groups: String,
    #[serde(default)]
    scopes: String,
    #[serde(default)]
    tenant: String,
    #[serde(default)]
    environment: String,
}

impl ExplainForm {
    fn blank() -> Self {
        Self {
            arguments: "{}".to_owned(),
            ..Self::default()
        }
    }

    /// The `POST /admin/policy/explain` body, or why the form is not one.
    fn body(&self) -> Result<Value, String> {
        let tool = self.tool.trim();
        if tool.is_empty() {
            return Err("A tool name is required.".to_owned());
        }
        let arguments: Value = serde_json::from_str(if self.arguments.trim().is_empty() {
            "{}"
        } else {
            &self.arguments
        })
        .map_err(|error| format!("Arguments are not JSON: {error}"))?;
        if !arguments.is_object() {
            return Err("Arguments must be a JSON object.".to_owned());
        }
        let list =
            |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_owned).collect() };
        let mut body = json!({"tool": tool, "arguments": arguments});
        for (key, value) in [
            ("subject", &self.subject),
            ("tenant", &self.tenant),
            ("environment", &self.environment),
        ] {
            if !value.trim().is_empty() {
                body[key] = Value::String(value.trim().to_owned());
            }
        }
        if !self.groups.trim().is_empty() {
            body["groups"] = json!(list(&self.groups));
        }
        if !self.scopes.trim().is_empty() {
            body["scopes"] = json!(list(&self.scopes));
        }
        Ok(body)
    }
}

pub(super) struct RuleView {
    id: String,
    effect: String,
    mark: &'static str,
    note: String,
}

/// The explanation, in the words `policy explain` prints.
pub(super) struct ExplainView {
    verdict: &'static str,
    verdict_class: &'static str,
    reason: String,
    policy_version: String,
    tool: String,
    vendor: String,
    environment: String,
    action: String,
    risk: String,
    resource_type: String,
    resource_scope: String,
    overridden: bool,
    configured_environment: String,
    subject: String,
    groups: String,
    scopes: String,
    tenant: String,
    upstream_label: String,
    upstream_authority: String,
    unclassified: bool,
    rules: Vec<RuleView>,
}

fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn joined(value: &Value) -> String {
    value
        .as_array()
        .map(|items| items.iter().map(text).collect::<Vec<_>>().join(", "))
        .unwrap_or_default()
}

impl ExplainView {
    fn from_data(data: &Value, overridden: bool) -> Self {
        let action = &data["action"];
        let decision = &data["explanation"]["decision"];
        let allow = decision["effect"] == "allow";
        let unclassified = data["explanation"]["unclassified"] == true;
        let rules = data["explanation"]["rules"]
            .as_array()
            .map(|rules| {
                rules
                    .iter()
                    .map(|rule| {
                        let decisive = rule["decisive"] == true;
                        let (mark, note) = match rule["mismatch"].as_str() {
                            Some(key) => ("✗", format!("fails on `{key}`")),
                            None if decisive => ("✓", "decisive".to_owned()),
                            None if unclassified => (
                                "✓",
                                "matched, not decisive (unclassified calls are denied before rules)"
                                    .to_owned(),
                            ),
                            None => ("✓", "matched, not decisive".to_owned()),
                        };
                        RuleView {
                            id: text(&rule["id"]),
                            effect: text(&rule["effect"]),
                            mark,
                            note,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            verdict: if allow { "ALLOW" } else { "DENY" },
            verdict_class: if allow { "allow" } else { "deny" },
            reason: text(&decision["reason"]),
            policy_version: data["policy_version"]
                .as_str()
                .unwrap_or("unversioned")
                .to_owned(),
            tool: text(&action["tool_name"]),
            vendor: text(&action["vendor"]),
            environment: text(&action["environment"]),
            action: text(&action["normalized_action"]),
            risk: text(&action["request_risk"]),
            resource_type: text(&action["resource_type"]),
            resource_scope: action["resource_scope"].to_string(),
            overridden,
            configured_environment: text(&data["configured_environment"]),
            subject: text(&action["principal"]["subject"]),
            groups: joined(&action["principal"]["groups"]),
            scopes: joined(&action["principal"]["scopes"]),
            tenant: text(&action["principal"]["tenant"]),
            upstream_label: text(&action["upstream_identity"]["label"]),
            upstream_authority: text(&action["upstream_identity"]["authority"]),
            unclassified,
            rules,
        }
    }
}

#[derive(Template)]
#[template(path = "policy.html")]
pub(super) struct PolicyPage {
    page: Page,
    version: String,
    signature: String,
    document: String,
    form: ExplainForm,
    result: Option<ExplainView>,
    error: Option<String>,
}

async fn policy_document(
    console: &Console,
    session: &Session,
) -> Result<(String, String, String), Response> {
    let response = console
        .api(
            session,
            AdminRequest {
                method: AdminMethod::Get,
                operation: "policy",
                body: None,
            },
        )
        .await?;
    match answer(response) {
        Answer::Data(data) => Ok((
            text(&data["version"]),
            match &data["signature"] {
                Value::Null => "none".to_owned(),
                other => other.to_string(),
            },
            text(&data["document"]),
        )),
        Answer::Refused { status, code } => Err(error_from(status, &code)),
    }
}

pub(super) async fn policy(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let session = console.session(&headers)?;
    let (version, signature, document) = policy_document(&console, &session).await?;
    Ok(Console::render(&PolicyPage {
        page: Page::signed_in("Policy", "policy"),
        version,
        signature,
        document,
        form: ExplainForm::blank(),
        result: None,
        error: None,
    }))
}

pub(super) async fn explain(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Form(form): Form<ExplainForm>,
) -> Result<Response, Response> {
    let session = console.session(&headers)?;
    let (version, signature, document) = policy_document(&console, &session).await?;
    let (result, error) = match form.body() {
        Err(error) => (None, Some(error)),
        Ok(body) => {
            let response = console
                .api(
                    &session,
                    AdminRequest {
                        method: AdminMethod::Post,
                        operation: "policy/explain",
                        body: Some(&body),
                    },
                )
                .await?;
            match answer(response) {
                Answer::Data(data) => (
                    Some(ExplainView::from_data(
                        &data,
                        !form.environment.trim().is_empty(),
                    )),
                    None,
                ),
                Answer::Refused { status: 400, code } => (
                    None,
                    Some(format!(
                        "The admin API refused the call ({code}): an unknown tool, or an environment that is not prod, staging, qa, or dev."
                    )),
                ),
                Answer::Refused { status, code } => (None, Some(refusal(status, &code))),
            }
        }
    };
    Ok(Console::render(&PolicyPage {
        page: Page::signed_in("Policy", "policy"),
        version,
        signature,
        document,
        form,
        result,
        error,
    }))
}

// -------------------------------------------------------------- activity

#[derive(Deserialize, Default, Clone)]
pub struct ActivityQuery {
    #[serde(default)]
    pub since: String,
    #[serde(default)]
    pub until: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub vendor: String,
}

impl ActivityQuery {
    fn body(&self) -> Value {
        let mut body = json!({});
        for (key, value) in [
            ("since", &self.since),
            ("until", &self.until),
            ("subject", &self.subject),
            ("vendor", &self.vendor),
        ] {
            if !value.trim().is_empty() {
                body[key] = Value::String(value.trim().to_owned());
            }
        }
        body
    }
}

/// The activity page. Public so the allocation probe can render it at
/// 1,000 rows (stage −1f, plan §3.10.2).
#[derive(Template)]
#[template(path = "activity.html")]
pub struct ActivityPage {
    page: Page,
    filter: ActivityQuery,
    rows: Vec<ActivityRow>,
    records_read: u64,
    stopped: Option<String>,
    unavailable: Option<String>,
}

impl ActivityPage {
    /// A complete result for `rows`, as the handler builds one.
    #[must_use]
    pub fn complete(filter: ActivityQuery, rows: Vec<ActivityRow>, records_read: u64) -> Self {
        Self {
            page: Page::signed_in("Activity", "activity"),
            filter,
            rows,
            records_read,
            stopped: None,
            unavailable: None,
        }
    }
}

#[derive(Deserialize)]
struct ActivityData {
    rows: Vec<ActivityRow>,
    records_read: u64,
    stopped: Option<String>,
}

pub(super) async fn activity(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Query(filter): Query<ActivityQuery>,
) -> Result<Response, Response> {
    let session = console.session(&headers)?;
    let body = filter.body();
    let response = console
        .api(
            &session,
            AdminRequest {
                method: AdminMethod::Post,
                operation: "reports/activity",
                body: Some(&body),
            },
        )
        .await?;
    let mut page = ActivityPage::complete(filter, vec![], 0);
    match answer(response) {
        Answer::Data(data) => {
            let data: ActivityData = decode(data).ok_or_else(|| {
                Console::error_page(
                    StatusCode::BAD_GATEWAY,
                    "Admin API error",
                    "The activity report did not decode.",
                    true,
                )
            })?;
            page.rows = data.rows;
            page.records_read = data.records_read;
            page.stopped = data.stopped;
        }
        Answer::Refused { status: 400, .. } => {
            page.unavailable = Some(
                "Refused (invalid_request): `since` and `until` must be RFC 3339 instants."
                    .to_owned(),
            );
        }
        Answer::Refused { status, code } => page.unavailable = Some(refusal(status, &code)),
    }
    Ok(Console::render(&page))
}

// --------------------------------------------------------- access review

#[derive(Deserialize, Default)]
pub(super) struct AccessReviewForm {
    #[serde(default)]
    tenant: String,
    #[serde(default)]
    groups: String,
}

pub(super) struct AccessRowView {
    subject: String,
    groups: String,
    rule_id: String,
    effect: String,
    matches: String,
}

#[derive(Deserialize)]
struct AccessRowData {
    subject: String,
    groups: Vec<String>,
    rule_id: String,
    effect: String,
    matches: BTreeMap<String, Vec<String>>,
}

#[derive(Template)]
#[template(path = "access_review.html")]
pub(super) struct AccessReviewPage {
    page: Page,
    tenant: String,
    groups: String,
    rows: Option<Vec<AccessRowView>>,
    error: Option<String>,
}

pub(super) async fn access_review_form(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    console.session(&headers)?;
    Ok(Console::render(&AccessReviewPage {
        page: Page::signed_in("Access review", "access-review"),
        tenant: String::new(),
        groups: "{\n  \"SRE\": [\"alice@example\"]\n}".to_owned(),
        rows: None,
        error: None,
    }))
}

pub(super) async fn access_review(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Form(form): Form<AccessReviewForm>,
) -> Result<Response, Response> {
    let session = console.session(&headers)?;
    let mut page = AccessReviewPage {
        page: Page::signed_in("Access review", "access-review"),
        tenant: form.tenant.trim().to_owned(),
        groups: form.groups.clone(),
        rows: None,
        error: None,
    };
    let groups: Result<BTreeMap<String, Vec<String>>, _> = serde_json::from_str(&form.groups);
    match groups {
        Err(error) => {
            page.error = Some(format!(
                "The group snapshot is not a JSON object of string arrays: {error}"
            ));
        }
        Ok(groups) if page.tenant.is_empty() => {
            drop(groups);
            page.error = Some("A tenant is required.".to_owned());
        }
        Ok(groups) => {
            let body = json!({"groups": groups, "tenant": page.tenant});
            let response = console
                .api(
                    &session,
                    AdminRequest {
                        method: AdminMethod::Post,
                        operation: "reports/access-review",
                        body: Some(&body),
                    },
                )
                .await?;
            match answer(response) {
                Answer::Data(mut data) => {
                    let rows: Option<Vec<AccessRowData>> = decode(data["rows"].take());
                    page.rows = Some(
                        rows.unwrap_or_default()
                            .into_iter()
                            .map(|row| AccessRowView {
                                subject: row.subject,
                                groups: row.groups.join(", "),
                                rule_id: row.rule_id,
                                effect: row.effect,
                                matches: row
                                    .matches
                                    .iter()
                                    .map(|(key, values)| format!("{key}={}", values.join("|")))
                                    .collect::<Vec<_>>()
                                    .join(" "),
                            })
                            .collect(),
                    );
                }
                Answer::Refused { status, code } => page.error = Some(refusal(status, &code)),
            }
        }
    }
    Ok(Console::render(&page))
}

// ----------------------------------------------------------------- usage

const REPORTS: &[(&str, &str)] = &[
    ("totals", "Totals"),
    ("by_principal", "By principal"),
    ("by_vendor", "By vendor"),
    ("by_tool", "By tool"),
    ("denials_by_environment", "Denials by environment"),
    ("timeline", "Timeline"),
];

#[derive(Deserialize, Default)]
pub(super) struct UsageQuery {
    #[serde(default)]
    report: String,
    #[serde(default)]
    since: String,
    #[serde(default)]
    until: String,
    #[serde(default)]
    bucket: String,
}

#[derive(Template)]
#[template(path = "usage.html")]
pub(super) struct UsagePage {
    page: Page,
    reports: &'static [(&'static str, &'static str)],
    query: UsageQuery,
    totals: Option<Totals>,
    groups: Option<Vec<GroupRow>>,
    timeline: Option<Vec<TimelineRow>>,
    unavailable: Option<String>,
}

pub(super) async fn usage(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Query(mut query): Query<UsageQuery>,
) -> Result<Response, Response> {
    let session = console.session(&headers)?;
    if !REPORTS.iter().any(|(value, _)| *value == query.report) {
        "totals".clone_into(&mut query.report);
    }
    if query.bucket != "hour" {
        "day".clone_into(&mut query.bucket);
    }
    let mut window = json!({});
    for (key, value) in [("since", &query.since), ("until", &query.until)] {
        if !value.trim().is_empty() {
            window[key] = Value::String(value.trim().to_owned());
        }
    }
    let mut body = json!({"report": query.report, "window": window});
    if query.report == "timeline" {
        body["bucket"] = Value::String(query.bucket.clone());
    }
    let response = console
        .api(
            &session,
            AdminRequest {
                method: AdminMethod::Post,
                operation: "usage",
                body: Some(&body),
            },
        )
        .await?;
    let mut page = UsagePage {
        page: Page::signed_in("Usage", "usage"),
        reports: REPORTS,
        query,
        totals: None,
        groups: None,
        timeline: None,
        unavailable: None,
    };
    match answer(response) {
        Answer::Data(data) => match decode::<Report>(data) {
            Some(Report::Totals(totals)) => page.totals = Some(totals),
            Some(Report::Groups { rows }) => page.groups = Some(rows),
            Some(Report::Timeline { rows }) => page.timeline = Some(rows),
            None => page.unavailable = Some("The usage report did not decode.".to_owned()),
        },
        Answer::Refused { status: 400, .. } => {
            page.unavailable =
                Some("Refused (invalid_request): check the window's RFC 3339 instants.".to_owned());
        }
        Answer::Refused { status, code } => page.unavailable = Some(refusal(status, &code)),
    }
    Ok(Console::render(&page))
}

// ------------------------------------------------- sessions and artifacts

pub(super) struct InventoryRow {
    id: String,
    owner: String,
    size: String,
    content_type: String,
}

#[derive(Template)]
#[template(path = "inventory.html")]
pub(super) struct InventoryPage {
    page: Page,
    artifacts: bool,
    scope: String,
    rows: Vec<InventoryRow>,
    unavailable: Option<String>,
}

async fn inventory(
    console: &Console,
    headers: &HeaderMap,
    artifacts: bool,
) -> Result<Response, Response> {
    let session = console.session(headers)?;
    let (operation, title, active) = if artifacts {
        ("artifacts", "Artifacts", "artifacts")
    } else {
        ("sessions", "Sessions", "sessions")
    };
    let response = console
        .api(
            &session,
            AdminRequest {
                method: AdminMethod::Get,
                operation,
                body: None,
            },
        )
        .await?;
    let mut page = InventoryPage {
        page: Page::signed_in(title, active),
        artifacts,
        scope: String::new(),
        rows: vec![],
        unavailable: None,
    };
    match answer(response) {
        Answer::Data(data) => {
            page.scope = text(&data["scope"]);
            page.rows = data["rows"]
                .as_array()
                .map(|rows| {
                    rows.iter()
                        .map(|row| InventoryRow {
                            id: text(&row["id"]),
                            owner: match &row["owner"] {
                                Value::Null => "—".to_owned(),
                                other => other.to_string(),
                            },
                            size: text(&row["size"]),
                            content_type: text(&row["content_type"]),
                        })
                        .collect()
                })
                .unwrap_or_default();
        }
        Answer::Refused { status, code } => page.unavailable = Some(refusal(status, &code)),
    }
    Ok(Console::render(&page))
}

pub(super) async fn sessions(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    inventory(&console, &headers, false).await
}

pub(super) async fn artifacts(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    inventory(&console, &headers, true).await
}

// ------------------------------------------------------------- proposals

pub(super) struct ProposalView {
    pub(super) id: String,
    pub(super) operation: String,
    pub(super) target: String,
    pub(super) proposer: String,
    pub(super) created: String,
    pub(super) expires: String,
    pub(super) state_label: &'static str,
    pub(super) state_class: &'static str,
    pub(super) pending: bool,
    pub(super) incomplete: bool,
    pub(super) decided_by: String,
    pub(super) reason: String,
    pub(super) applied_seq: String,
    pub(super) digest: String,
}

impl ProposalView {
    pub(super) fn from_data(row: &Value) -> Self {
        let state = row["state"].as_str().unwrap_or_default();
        let applied = row["applied_seq"].as_u64().is_some();
        let (state_label, state_class) = match (state, applied) {
            ("approved", true) => ("Applied", "ok"),
            ("approved", false) => ("Approved · incomplete", "warn"),
            ("pending", _) => ("Pending review", "warn"),
            ("rejected", _) => ("Rejected", "deny"),
            ("expired", _) => ("Expired", "neutral"),
            _ => ("Unknown", "neutral"),
        };
        Self {
            id: text(&row["id"]),
            operation: text(&row["operation"]),
            target: text(&row["target"]),
            proposer: party(&row["proposer"]),
            created: text(&row["created"]),
            expires: text(&row["expires"]),
            state_label,
            state_class,
            pending: state == "pending",
            incomplete: state == "approved" && !applied,
            decided_by: party(&row["decided_by"]),
            reason: text(&row["reason"]),
            applied_seq: text(&row["applied_seq"]),
            digest: text(&row["candidate_digest"]),
        }
    }
}

#[derive(Template)]
#[template(path = "proposals.html")]
pub(super) struct ProposalsPage {
    page: Page,
    rows: Vec<ProposalView>,
    unavailable: Option<String>,
}

fn party(value: &Value) -> String {
    match value {
        Value::Null => "—".to_owned(),
        other => format!("{} ({})", text(&other["subject"]), text(&other["tenant"])),
    }
}

pub(super) async fn proposals(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let session = console.session(&headers)?;
    let response = console
        .api(
            &session,
            AdminRequest {
                method: AdminMethod::Get,
                operation: "proposals",
                body: None,
            },
        )
        .await?;
    let mut page = ProposalsPage {
        page: Page::signed_in("Proposals", "proposals"),
        rows: vec![],
        unavailable: None,
    };
    match answer(response) {
        Answer::Data(data) => {
            page.rows = data["rows"]
                .as_array()
                .map(|rows| rows.iter().map(ProposalView::from_data).collect())
                .unwrap_or_default();
        }
        Answer::Refused { status, code } => page.unavailable = Some(refusal(status, &code)),
    }
    Ok(Console::render(&page))
}

// ---------------------------------------------------------------- health

#[derive(Template)]
#[template(path = "health.html")]
pub(super) struct HealthPage {
    page: Page,
    ok: bool,
    banner: String,
}

pub(super) async fn health(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    console.session(&headers)?;
    let banner = (console.health)();
    Ok(Console::render(&HealthPage {
        page: Page::signed_in("Health", "health"),
        ok: banner.ok,
        banner: banner.text,
    }))
}

#[cfg(test)]
mod proposal_view_tests {
    use super::ProposalView;
    use serde_json::json;

    #[test]
    fn approval_without_application_evidence_is_never_presented_as_applied() {
        for evidence in [serde_json::Value::Null, json!("42")] {
            let view = ProposalView::from_data(&json!({
                "state": "approved", "applied_seq": evidence,
            }));
            assert_eq!(view.state_label, "Approved · incomplete");
            assert!(view.incomplete);
            assert!(!view.pending);
        }
        let applied = ProposalView::from_data(&json!({"state": "approved", "applied_seq": 42}));
        assert_eq!(applied.state_label, "Applied");
        assert!(!applied.incomplete);
        assert!(!applied.pending);
        let unknown = ProposalView::from_data(&json!({"state": "unexpected"}));
        assert!(!unknown.pending);
        assert_eq!(unknown.state_label, "Unknown");
    }
}

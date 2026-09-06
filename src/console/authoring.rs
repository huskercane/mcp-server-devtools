//! Policy authoring and proposal decisions through the same authenticated
//! `AdminClient` as the CLI. No policy parsing, signature checks or gate
//! decisions live here; every effect belongs to the admin boundary.
use std::sync::Arc;

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Console, Page, Session};
use crate::ports::{AdminMethod, AdminRequest, AdminResponse};

#[derive(Deserialize)]
pub(super) struct CandidateForm {
    document: String,
}

#[derive(Template)]
#[template(path = "authoring.html")]
struct Editor {
    page: Page,
    document: String,
    validation: String,
    diff: String,
}

async fn call(
    console: &Console,
    session: &Session,
    method: AdminMethod,
    operation: &str,
    body: Option<&Value>,
) -> Result<AdminResponse, Response> {
    console
        .api(
            session,
            AdminRequest {
                method,
                operation,
                body,
            },
        )
        .await
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

fn editor(document: String, validation: String, diff: String) -> Response {
    Console::render(&Editor {
        page: Page::signed_in("Author policy", "policy"),
        document,
        validation,
        diff,
    })
}

pub(super) async fn edit(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let session = console.session(&headers)?;
    let response = call(&console, &session, AdminMethod::Get, "policy", None).await?;
    if !response.is_success() {
        return Ok(result(&response));
    }
    let Some(document) = response.body["data"]["document"].as_str() else {
        return Ok(Console::error_page(
            StatusCode::BAD_GATEWAY,
            "Invalid response",
            "Policy document missing from admin response.",
            true,
        ));
    };
    Ok(editor(document.to_owned(), String::new(), String::new()))
}

pub(super) async fn preview(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Form(form): Form<CandidateForm>,
) -> Result<Response, Response> {
    let session = console.session(&headers)?;
    let body = json!({"document": form.document});
    let validation = call(
        &console,
        &session,
        AdminMethod::Post,
        "policy/validate",
        Some(&body),
    )
    .await?;
    let diff = if validation.is_success() {
        let response = call(
            &console,
            &session,
            AdminMethod::Post,
            "policy/diff",
            Some(&body),
        )
        .await?;
        pretty(&response.body)
    } else {
        "Diff unavailable until validation succeeds.".to_owned()
    };
    // Preview errors are rendered in the checked section, including on an
    // htmx refresh. They never enable installation or imply signature proof.
    Ok(editor(form.document, pretty(&validation.body), diff))
}

pub(super) async fn download(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Form(form): Form<CandidateForm>,
) -> Result<Response, Response> {
    let session = console.session(&headers)?;
    let body = json!({"document": form.document});
    let validation = call(
        &console,
        &session,
        AdminMethod::Post,
        "policy/validate",
        Some(&body),
    )
    .await?;
    if !validation.is_success() {
        return Ok(result(&validation));
    }
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=policy-candidate.yaml",
            ),
        ],
        form.document,
    )
        .into_response())
}

#[derive(Deserialize)]
pub(super) struct UploadForm {
    bundle: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedBundle {
    document: String,
    signature: String,
}

pub(super) async fn upload(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Form(form): Form<UploadForm>,
) -> Result<Response, Response> {
    let session = console.session(&headers)?;
    let Ok(bundle) = serde_json::from_str::<SignedBundle>(&form.bundle) else {
        return Ok(Console::error_page(
            StatusCode::BAD_REQUEST,
            "Invalid signed bundle",
            "Supply a JSON object with document and signature strings.",
            true,
        ));
    };
    let body = json!({"document": bundle.document, "signature": bundle.signature});
    Ok(result(
        &call(&console, &session, AdminMethod::Put, "policy", Some(&body)).await?,
    ))
}

#[derive(Template)]
#[template(path = "mutation_result.html")]
struct MutationResult {
    page: Page,
    status: u16,
    body: String,
    deferred: bool,
}

fn result(response: &AdminResponse) -> Response {
    let mut rendered = Console::render(&MutationResult {
        page: Page::signed_in("Admin API result", "policy"),
        status: response.status,
        body: pretty(&response.body),
        deferred: response.status == 202,
    });
    *rendered.status_mut() =
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
    rendered
}

#[derive(Template)]
#[template(path = "proposal.html")]
struct ProposalPage {
    page: Page,
    id: String,
    body: String,
}

// Prevent a decoded path segment from becoming another AdminClient operation.
fn valid_id(id: &str) -> bool {
    id.len() == 18 && id.starts_with("p-") && id[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

pub(super) async fn proposal(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Response> {
    let session = console.session(&headers)?;
    if !valid_id(&id) {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let response = call(
        &console,
        &session,
        AdminMethod::Get,
        &format!("proposals/{id}"),
        None,
    )
    .await?;
    if !response.is_success() {
        return Ok(result(&response));
    }
    Ok(Console::render(&ProposalPage {
        page: Page::signed_in("Review proposal", "proposals"),
        id,
        body: pretty(&response.body),
    }))
}

async fn decide(
    console: &Console,
    headers: &HeaderMap,
    id: &str,
    decision: &str,
    body: &Value,
) -> Result<Response, Response> {
    let session = console.session(headers)?;
    if !valid_id(id) {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    Ok(result(
        &call(
            console,
            &session,
            AdminMethod::Post,
            &format!("proposals/{id}/{decision}"),
            Some(body),
        )
        .await?,
    ))
}

pub(super) async fn approve(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Response> {
    decide(&console, &headers, &id, "approve", &json!({})).await
}

#[derive(Deserialize)]
pub(super) struct RejectionForm {
    reason: String,
}

pub(super) async fn reject(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<RejectionForm>,
) -> Result<Response, Response> {
    decide(
        &console,
        &headers,
        &id,
        "reject",
        &json!({"reason": form.reason}),
    )
    .await
}

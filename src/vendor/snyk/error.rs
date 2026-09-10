#![allow(clippy::doc_markdown)]

//! Parse Snyk REST API error response bodies into typed [`McpError`] values.
//!
//! The REST API speaks JSON:API, so its error envelope is
//! `{"errors": [{"status": "401", "title": "...", "detail": "...", ...}]}` —
//! an array, because one response can report several problems. We join every
//! entry's `title: detail` (or whichever of the two is present) with `; ` so
//! nothing is dropped. A few older / edge endpoints answer with a flat
//! `{"message": "..."}` instead, so that key is accepted as a fallback. The
//! typed error is keyed off the HTTP status, mirroring the SonarQube / Grafana
//! classifiers.

use http::StatusCode;
use serde_json::Value;

use crate::error::{McpError, OriginalError, api_error, auth_invalid};

/// Map a non-2xx HTTP status + body to the correct [`McpError`] factory,
/// preserving the upstream payload as `original`.
pub fn classify(status: StatusCode, body_text: &str) -> McpError {
    let parsed = parse_error_body(body_text);
    let message = parsed.message.unwrap_or_else(|| {
        let reason = status.canonical_reason().unwrap_or("Snyk API error");
        format!("{} {reason}", status.as_u16())
    });
    let original = parsed.original;

    match status.as_u16() {
        401 => finalize(
            auth_invalid(format!(
                "Authentication failed — check SNYK_TOKEN (sent as `Authorization: token`). \
                 Snyk API: {message}"
            )),
            Some(401),
            original,
        ),
        403 => finalize(
            auth_invalid(format!(
                "Insufficient permissions for this organization or resource. Snyk API: {message}"
            )),
            Some(403),
            original,
        ),
        404 => api_error(
            format!("Resource not found. Snyk API: {message}"),
            Some(404),
            original,
        ),
        429 => api_error(
            format!("Rate limit exceeded — retry later. Snyk API: {message}"),
            Some(429),
            original,
        ),
        s if s >= 500 => api_error(
            format!("Snyk server error. Detail: {message}"),
            Some(s),
            original,
        ),
        s => api_error(
            format!("Snyk API request failed. Detail: {message}"),
            Some(s),
            original,
        ),
    }
}

/// Attach the HTTP status and original payload to an already-built error.
fn finalize(mut err: McpError, status: Option<u16>, original: Option<OriginalError>) -> McpError {
    if let Some(s) = status {
        err.status_code = Some(s);
    }
    err.original = original;
    err
}

/// Narrow-view parse result. `original` is what gets attached to the
/// `McpError` so downstream MCP consumers see the vendor payload.
#[derive(Debug, Default)]
pub struct ParsedError {
    pub message: Option<String>,
    pub original: Option<OriginalError>,
}

pub fn parse_error_body(body_text: &str) -> ParsedError {
    let trimmed = body_text.trim();
    if trimmed.is_empty() {
        return ParsedError::default();
    }

    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return ParsedError {
            message: Some(trimmed.to_owned()),
            original: Some(OriginalError::String(body_text.to_owned())),
        };
    }

    let Ok(parsed) = serde_json::from_str::<Value>(trimmed) else {
        return ParsedError {
            message: Some(trimmed.to_owned()),
            original: Some(OriginalError::String(body_text.to_owned())),
        };
    };

    // JSON:API `errors: [{title, detail}]` first; flat `message` as fallback.
    let message = parsed
        .get("errors")
        .and_then(Value::as_array)
        .map(|errs| {
            let mut message = String::new();
            for description in errs.iter().filter_map(describe_json_api_error) {
                if !message.is_empty() {
                    message.push_str("; ");
                }
                message.push_str(&description);
            }
            message
        })
        .filter(|s| !s.is_empty())
        .or_else(|| {
            parsed
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .filter(|s| !s.is_empty());

    ParsedError {
        message,
        original: Some(OriginalError::Json(parsed)),
    }
}

/// One JSON:API error object → `title: detail`, `detail`, or `title`.
fn describe_json_api_error(entry: &Value) -> Option<String> {
    let title = entry
        .get("title")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let detail = entry
        .get("detail")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match (title, detail) {
        (Some(title), Some(detail)) => Some(format!("{title}: {detail}")),
        (None, Some(text)) | (Some(text), None) => Some(text.to_owned()),
        (None, None) => None,
    }
}

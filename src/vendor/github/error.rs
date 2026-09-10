#![allow(clippy::doc_markdown)]

//! Parse GitHub REST API error bodies into typed [`McpError`] values.
//!
//! GitHub's envelope is `{"message": "…", "documentation_url": "…",
//! "errors": [{"resource", "field", "code", "message"?}, …]}`. `message` is
//! the human-readable line; `errors` is only populated on `422 Unprocessable
//! Entity` (validation) and is folded into the message so the caller sees
//! which field was rejected without opening `original`.
//!
//! Status mapping mirrors the other bearer-token vendors: `401` and `403`
//! become [`auth_invalid`] (a `403` is also what GitHub sends for a primary or
//! secondary rate limit and for a fine-grained token that lacks the required
//! permission — the upstream `message` is preserved so those are
//! distinguishable), everything else keys off the status.

use http::StatusCode;
use serde_json::Value;

use crate::error::{McpError, OriginalError, api_error, auth_invalid};

/// Map a non-2xx HTTP status + body to the correct [`McpError`] factory,
/// preserving the upstream payload as `original`.
pub fn classify(status: StatusCode, body_text: &str) -> McpError {
    let parsed = parse_error_body(body_text);
    let message = parsed.message.unwrap_or_else(|| {
        let reason = status.canonical_reason().unwrap_or("GitHub API error");
        format!("{} {reason}", status.as_u16())
    });
    let original = parsed.original;

    match status.as_u16() {
        401 => finalize(
            auth_invalid(format!("Authentication failed. GitHub API: {message}")),
            None,
            original,
        ),
        403 => {
            let prefix = if message.to_ascii_lowercase().contains("rate limit") {
                "Rate limit exceeded"
            } else {
                "Insufficient permissions"
            };
            finalize(
                auth_invalid(format!("{prefix}. GitHub API: {message}")),
                Some(403),
                original,
            )
        }
        404 => api_error(
            format!("Resource not found. GitHub API: {message}"),
            Some(404),
            original,
        ),
        422 => api_error(
            format!("Validation failed. GitHub API: {message}"),
            Some(422),
            original,
        ),
        429 => api_error(
            format!("Rate limit exceeded. GitHub API: {message}"),
            Some(429),
            original,
        ),
        s if s >= 500 => api_error(
            format!("GitHub server error. Detail: {message}"),
            Some(s),
            original,
        ),
        s => api_error(
            format!("GitHub API request failed. Detail: {message}"),
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

    let mut message = parsed
        .get("message")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    // Validation detail (`422`): `errors[]` names the resource/field/code.
    // Fold it into the message so the rejected field is visible up front.
    if let Some(details) = parsed.get("errors").and_then(Value::as_array) {
        let mut joined = String::new();
        for entry in details {
            describe_error(entry, &mut joined);
        }
        if !joined.is_empty() {
            message = Some(match message {
                Some(m) => format!("{m} ({joined})"),
                None => joined,
            });
        }
    }

    ParsedError {
        message,
        original: Some(OriginalError::Json(parsed)),
    }
}

/// Append one `errors[]` entry to `out` as `resource.field: code — message`,
/// using whichever of those keys are present and `; ` between entries.
/// GitHub sends either a bare string (rare, older endpoints) or the
/// structured object.
fn describe_error(entry: &Value, out: &mut String) {
    let start = out.len();
    if !out.is_empty() {
        out.push_str("; ");
    }
    if let Some(s) = entry.as_str() {
        out.push_str(s);
        return;
    }
    let mut wrote = false;
    for key in ["resource", "field"] {
        if let Some(part) = entry.get(key).and_then(Value::as_str) {
            if wrote {
                out.push('.');
            }
            out.push_str(part);
            wrote = true;
        }
    }
    if let Some(code) = entry.get("code").and_then(Value::as_str) {
        if wrote {
            out.push_str(": ");
        }
        out.push_str(code);
        wrote = true;
    }
    if let Some(detail) = entry.get("message").and_then(Value::as_str) {
        if wrote {
            out.push_str(" — ");
        }
        out.push_str(detail);
        wrote = true;
    }
    if !wrote {
        // Nothing usable in this entry: drop the separator we added.
        out.truncate(start);
    }
}

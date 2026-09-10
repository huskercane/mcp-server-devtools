//! Parse Mend Platform API 3.0 error response bodies into typed
//! [`McpError`] values.
//!
//! Mend wraps API responses as `{"retVal": …, "supportToken": "…"}` and, on
//! failure, adds an `errorMessage` (some endpoints put the text in `retVal`
//! itself, or reply with the plainer `{"error": …, "message": …}` shape). The
//! human-readable text is surfaced with the `supportToken` appended — Mend
//! support asks for it — and the typed error is keyed off the HTTP status,
//! mirroring the `SonarQube` / Zoom classifiers.

use http::StatusCode;
use serde_json::Value;

use crate::error::{McpError, OriginalError, api_error, auth_invalid};

/// Map a non-2xx HTTP status + body to the correct [`McpError`] factory,
/// preserving the upstream payload as `original`.
pub fn classify(status: StatusCode, body_text: &str) -> McpError {
    let parsed = parse_error_body(body_text);
    let message = parsed.message.unwrap_or_else(|| {
        let reason = status.canonical_reason().unwrap_or("Mend API error");
        format!("{} {reason}", status.as_u16())
    });
    let original = parsed.original;

    match status.as_u16() {
        401 => finalize(
            auth_invalid(format!(
                "Authentication failed. Mend API: {message}. The JWT may have been \
                 revoked or the account lost access to the organization."
            )),
            Some(401),
            original,
        ),
        403 => finalize(
            auth_invalid(format!("Insufficient permissions. Mend API: {message}")),
            Some(403),
            original,
        ),
        404 => api_error(
            format!("Resource not found. Mend API: {message}"),
            Some(404),
            original,
        ),
        429 => api_error(
            format!("Rate limit exceeded. Mend API: {message}"),
            Some(429),
            original,
        ),
        s if s >= 500 => api_error(
            format!("Mend server error. Detail: {message}"),
            Some(s),
            original,
        ),
        s => api_error(
            format!("Mend API request failed. Detail: {message}"),
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

/// Extract the message from a Mend error body. Non-JSON bodies are surfaced
/// verbatim (trimmed).
pub fn parse_error_body(body_text: &str) -> ParsedError {
    let trimmed = body_text.trim();
    if trimmed.is_empty() {
        return ParsedError::default();
    }

    let Ok(parsed) = serde_json::from_str::<Value>(trimmed) else {
        return ParsedError {
            message: Some(trimmed.to_owned()),
            original: Some(OriginalError::String(body_text.to_owned())),
        };
    };

    let message = envelope_message(&parsed).map(|text| {
        match parsed.get("supportToken").and_then(Value::as_str) {
            Some(token) if !token.is_empty() => format!("{text} (supportToken: {token})"),
            _ => text.to_owned(),
        }
    });

    ParsedError {
        message,
        original: Some(OriginalError::Json(parsed)),
    }
}

/// The first non-empty message string in the envelope, in order of how
/// specific the field is: `errorMessage`, `message`, a string `error`, a
/// string `retVal`, then `retVal.errorMessage` / `retVal.message`.
fn envelope_message(parsed: &Value) -> Option<&str> {
    let direct = ["errorMessage", "message", "error", "retVal"]
        .into_iter()
        .find_map(|key| parsed.get(key).and_then(Value::as_str));
    direct
        .or_else(|| {
            let ret = parsed.get("retVal")?;
            ["errorMessage", "message"]
                .into_iter()
                .find_map(|key| ret.get(key).and_then(Value::as_str))
        })
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

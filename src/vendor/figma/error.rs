//! Parse Figma REST API error bodies into typed [`McpError`] values.
//!
//! Figma's error envelope is `{"status": 403, "err": "Invalid token"}` — a
//! numeric status echo plus a human-readable `err`. A few endpoints (and the
//! rate limiter) instead return `{"message": "..."}`, so that key is accepted
//! as a fallback. We surface the text and key the typed error off the HTTP
//! status, mirroring the SonarQube/Grafana classifiers.
//!
//! Status semantics worth spelling out for the caller:
//! - `401`/`403` → `AuthInvalid`. Figma answers a bad or revoked PAT, *and* a
//!   PAT lacking the endpoint's scope, with 403; both are credential problems.
//! - `404` → the file key is wrong, or the file is not shared with the token
//!   owner (Figma does not distinguish these).
//! - `429` → rate limited. The transport does not honour `Retry-After`; the
//!   caller must back off and retry.

use http::StatusCode;
use serde_json::Value;

use crate::error::{McpError, OriginalError, api_error, auth_invalid};

/// Map a non-2xx HTTP status + body to the correct [`McpError`] factory,
/// preserving the upstream payload as `original`.
pub fn classify(status: StatusCode, body_text: &str) -> McpError {
    let parsed = parse_error_body(body_text);
    let message = parsed.message.unwrap_or_else(|| {
        let reason = status.canonical_reason().unwrap_or("Figma API error");
        format!("{} {reason}", status.as_u16())
    });
    let original = parsed.original;

    match status.as_u16() {
        401 => finalize(
            auth_invalid(format!(
                "Authentication failed. Figma API: {message}. Check FIGMA_TOKEN."
            )),
            Some(401),
            original,
        ),
        403 => finalize(
            auth_invalid(format!(
                "Authentication failed or insufficient token scope. Figma API: {message}. \
                 Check FIGMA_TOKEN and that the token has the scope this endpoint needs \
                 (file_content:read, file_comments:read, file_metadata:read, or \
                 library_content:read)."
            )),
            Some(403),
            original,
        ),
        404 => api_error(
            format!(
                "Resource not found. Figma API: {message}. The file key may be wrong, or \
                 the file is not shared with the token owner."
            ),
            Some(404),
            original,
        ),
        429 => api_error(
            format!(
                "Rate limit exceeded. Figma API: {message}. Retry-After is not honored \
                 automatically — wait and retry."
            ),
            Some(429),
            original,
        ),
        s if s >= 500 => api_error(
            format!("Figma server error. Detail: {message}"),
            Some(s),
            original,
        ),
        s => api_error(
            format!("Figma API request failed. Detail: {message}"),
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

/// Extract the human-readable message from a Figma error body. Accepts the
/// canonical `{"status", "err"}` envelope, the `{"message"}` variant, and
/// falls back to the raw text for non-JSON bodies (proxies, HTML error pages).
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

    let message = ["err", "message", "error"]
        .iter()
        .find_map(|key| parsed.get(key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    ParsedError {
        message,
        original: Some(OriginalError::Json(parsed)),
    }
}

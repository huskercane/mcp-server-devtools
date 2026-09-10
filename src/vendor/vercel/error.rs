//! Parse Vercel error response bodies into typed [`McpError`] values.
//!
//! Vercel's REST API error envelope is `{"error": {"code": "<str>", "message":
//! "<str>"}}`. The `message` is the human-readable text; `code` (`forbidden`,
//! `not_found`, `rate_limited`, …) is a stable machine key, so it is appended
//! to the message when present. The typed error is keyed off the HTTP status,
//! mirroring the `CircleCI` / Grafana / `SonarQube` classifiers.
//!
//! Scope is the classic Vercel mistake: a token that is valid for a team but
//! used without `teamId` is answered with `403`/`404` against the personal
//! account. The 401/403/404 messages therefore point at `teamId` /
//! `VERCEL_TEAM_ID` so the caller can fix the call instead of the token.

use http::StatusCode;
use serde_json::Value;

use crate::error::{McpError, OriginalError, api_error, auth_invalid};

/// Map a non-2xx HTTP status + body to the correct [`McpError`] factory,
/// preserving the upstream payload as `original`.
pub fn classify(status: StatusCode, body_text: &str) -> McpError {
    let parsed = parse_error_body(body_text);
    let message = parsed.message.unwrap_or_else(|| {
        let reason = status.canonical_reason().unwrap_or("Vercel API error");
        format!("{} {reason}", status.as_u16())
    });
    let original = parsed.original;

    match status.as_u16() {
        401 => finalize(
            auth_invalid(format!(
                "Authentication failed. Vercel API: {message}. Check VERCEL_TOKEN \
                 (Account Settings → Tokens) and that the token's scope covers the team \
                 you are addressing (`teamId` / VERCEL_TEAM_ID)."
            )),
            None,
            original,
        ),
        403 => finalize(
            auth_invalid(format!(
                "Insufficient permissions. Vercel API: {message}. Team-owned projects and \
                 deployments require `teamId` (or VERCEL_TEAM_ID); without it the request is \
                 scoped to the personal account, and the token must be scoped to that team."
            )),
            Some(403),
            original,
        ),
        404 => api_error(
            format!(
                "Resource not found. Vercel API: {message}. If the resource belongs to a \
                 team, pass `teamId` (or set VERCEL_TEAM_ID) — without it Vercel searches \
                 the personal account only."
            ),
            Some(404),
            original,
        ),
        429 => api_error(
            format!("Rate limit exceeded. Vercel API: {message}"),
            Some(429),
            original,
        ),
        s if s >= 500 => api_error(
            format!("Vercel server error. Detail: {message}"),
            Some(s),
            original,
        ),
        s => api_error(
            format!("Vercel API request failed. Detail: {message}"),
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

/// Extract the human-readable message from a Vercel error body. JSON bodies
/// yield `error.message` (with `error.code` appended when present); a bare
/// top-level `message` is accepted as a fallback. Non-JSON bodies are passed
/// through verbatim.
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

    let envelope = parsed.get("error");
    let text = envelope
        .and_then(|e| e.get("message"))
        .or_else(|| parsed.get("message"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let code = envelope
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let message = match (text, code) {
        (Some(text), Some(code)) => Some(format!("{text} (code: {code})")),
        (Some(text), None) => Some(text.to_owned()),
        (None, Some(code)) => Some(code.to_owned()),
        (None, None) => None,
    };

    ParsedError {
        message,
        original: Some(OriginalError::Json(parsed)),
    }
}

#![allow(clippy::doc_markdown)]

//! Parse Sentry error response bodies into typed [`McpError`] values.
//!
//! Sentry's Web API error envelope is `{"detail": "<str>"}` — a single
//! human-readable message. Field validation errors on write endpoints come
//! back as `{"<field>": ["<msg>", …]}` instead, but this adapter is read-only,
//! so `detail` is the only key we look for; anything else is surfaced as the
//! raw JSON. The typed error is keyed off the HTTP status, mirroring the
//! SonarQube / CircleCI classifiers.

use http::StatusCode;
use serde_json::Value;

use crate::error::{McpError, OriginalError, api_error, auth_invalid};

/// Scopes the read tools need; named in the 401/403 message so the fix is
/// obvious from the error alone.
const REQUIRED_SCOPES: &str = "`org:read`, `project:read`, `event:read`";

/// Map a non-2xx HTTP status + body to the correct [`McpError`] factory,
/// preserving the upstream payload as `original`.
pub fn classify(status: StatusCode, body_text: &str) -> McpError {
    let parsed = parse_error_body(body_text);
    let message = parsed.message.unwrap_or_else(|| {
        let reason = status.canonical_reason().unwrap_or("Sentry API error");
        format!("{} {reason}", status.as_u16())
    });
    let original = parsed.original;

    match status.as_u16() {
        401 => finalize(
            auth_invalid(format!(
                "Authentication failed. Check SENTRY_TOKEN and that it carries the \
                 {REQUIRED_SCOPES} scopes. Sentry API: {message}"
            )),
            Some(401),
            original,
        ),
        403 => finalize(
            auth_invalid(format!(
                "Insufficient permissions. The token needs the {REQUIRED_SCOPES} scopes \
                 and membership of the organization. Sentry API: {message}"
            )),
            Some(403),
            original,
        ),
        404 => api_error(
            format!("Resource not found. Sentry API: {message}"),
            Some(404),
            original,
        ),
        429 => api_error(
            format!("Rate limit exceeded. Sentry API: {message}"),
            Some(429),
            original,
        ),
        s if s >= 500 => api_error(
            format!("Sentry server error. Detail: {message}"),
            Some(s),
            original,
        ),
        s => api_error(
            format!("Sentry API request failed. Detail: {message}"),
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

    let message = parsed
        .get("detail")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    ParsedError {
        message,
        original: Some(OriginalError::Json(parsed)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    #[test]
    fn detail_envelope_is_surfaced_and_status_drives_kind() {
        let err = classify(StatusCode::UNAUTHORIZED, r#"{"detail":"Invalid token"}"#);
        assert_eq!(err.kind, ErrorKind::AuthInvalid);
        assert_eq!(err.status_code, Some(401));
        assert!(err.message.contains("Invalid token"));
        assert!(err.message.contains("event:read"));

        let err = classify(
            StatusCode::NOT_FOUND,
            r#"{"detail":"The requested resource does not exist"}"#,
        );
        assert_eq!(err.kind, ErrorKind::ApiError);
        assert_eq!(err.status_code, Some(404));
        assert!(err.message.contains("does not exist"));
    }

    #[test]
    fn non_json_and_empty_bodies_fall_back_gracefully() {
        let err = classify(StatusCode::BAD_GATEWAY, "<html>upstream</html>");
        assert_eq!(err.status_code, Some(502));
        assert!(err.message.contains("<html>upstream</html>"));
        assert!(matches!(err.original, Some(OriginalError::String(_))));

        let err = classify(StatusCode::TOO_MANY_REQUESTS, "");
        assert_eq!(err.status_code, Some(429));
        assert!(err.message.contains("429 Too Many Requests"));
        assert!(err.original.is_none());

        // JSON without `detail` keeps the payload but uses the status reason.
        let err = classify(StatusCode::BAD_REQUEST, r#"{"query":["invalid"]}"#);
        assert!(err.message.contains("400 Bad Request"));
        assert!(matches!(err.original, Some(OriginalError::Json(_))));
    }
}

#![allow(clippy::doc_markdown)]

//! Parse GitLab REST error bodies into typed [`McpError`] values.
//!
//! GitLab's envelope is `{"message": ...}` where `message` is usually a string
//! (`"404 Project Not Found"`, `"401 Unauthorized"`) but is an object of
//! attribute → messages on validation failures (`{"title": ["can't be
//! blank"]}`). A few paths (OAuth-style and some 4xx from the router) use
//! `{"error": "...", "error_description": "..."}` instead. We surface the
//! human-readable text and key the typed error off the HTTP status, mirroring
//! the SonarQube and CircleCI classifiers.

use http::StatusCode;
use serde_json::Value;

use crate::error::{McpError, OriginalError, api_error, auth_invalid};

/// Map a non-2xx HTTP status + body to the correct [`McpError`] factory,
/// preserving the upstream payload as `original`.
pub fn classify(status: StatusCode, body_text: &str) -> McpError {
    let parsed = parse_error_body(body_text);
    let message = parsed.message.unwrap_or_else(|| {
        let reason = status.canonical_reason().unwrap_or("GitLab API error");
        format!("{} {reason}", status.as_u16())
    });
    let original = parsed.original;

    match status.as_u16() {
        401 => finalize(
            auth_invalid(format!(
                "Authentication failed. GitLab API: {message}. Check that GITLAB_TOKEN is \
                 a valid, unexpired access token."
            )),
            None,
            original,
        ),
        403 => finalize(
            auth_invalid(format!(
                "Insufficient permissions. GitLab API: {message}. The token needs the \
                 `read_api` scope (plus `read_repository` for file reads) and access to \
                 the project."
            )),
            Some(403),
            original,
        ),
        404 => api_error(
            format!(
                "Resource not found. GitLab API: {message}. GitLab also answers 404 for \
                 projects the token cannot see."
            ),
            Some(404),
            original,
        ),
        429 => api_error(
            format!("Rate limit exceeded. GitLab API: {message}"),
            Some(429),
            original,
        ),
        s if s >= 500 => api_error(
            format!("GitLab server error. Detail: {message}"),
            Some(s),
            original,
        ),
        s => api_error(
            format!("GitLab API request failed. Detail: {message}"),
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

    let Ok(parsed) = serde_json::from_str::<Value>(trimmed) else {
        return ParsedError {
            message: Some(trimmed.to_owned()),
            original: Some(OriginalError::String(body_text.to_owned())),
        };
    };

    let message = parsed
        .get("message")
        .and_then(render_message)
        .or_else(|| {
            let error = parsed.get("error").and_then(Value::as_str)?;
            Some(
                parsed
                    .get("error_description")
                    .and_then(Value::as_str)
                    .map_or_else(|| error.to_owned(), |desc| format!("{error}: {desc}")),
            )
        })
        .filter(|s| !s.is_empty());

    ParsedError {
        message,
        original: Some(OriginalError::Json(parsed)),
    }
}

/// Flatten GitLab's `message` value: a string verbatim; an attribute → messages
/// object as `attr: msg1, msg2; attr2: ...`; an array joined with `; `.
fn render_message(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => Some(crate::format::join_strings(
            items.iter().filter_map(Value::as_str),
            "; ",
        )),
        Value::Object(map) => {
            let mut out = String::new();
            for (key, val) in map {
                if !out.is_empty() {
                    out.push_str("; ");
                }
                out.push_str(key);
                out.push_str(": ");
                match val {
                    Value::Array(items) => {
                        out.push_str(&crate::format::join_strings(
                            items.iter().filter_map(Value::as_str),
                            ", ",
                        ));
                    }
                    Value::String(s) => out.push_str(s),
                    other => out.push_str(&other.to_string()),
                }
            }
            Some(out)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_string_object_and_error_envelopes() {
        assert_eq!(
            parse_error_body(r#"{"message":"404 Project Not Found"}"#).message,
            Some("404 Project Not Found".into())
        );
        assert_eq!(
            parse_error_body(r#"{"message":{"title":["can't be blank","too short"],"ref":"bad"}}"#)
                .message,
            Some("title: can't be blank, too short; ref: bad".into())
        );
        assert_eq!(
            parse_error_body(r#"{"error":"invalid_token","error_description":"expired"}"#).message,
            Some("invalid_token: expired".into())
        );
        assert_eq!(
            parse_error_body("<html>gateway</html>").message,
            Some("<html>gateway</html>".into())
        );
        assert!(parse_error_body("  ").message.is_none());
    }
}

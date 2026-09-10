#![allow(clippy::doc_markdown)]

//! PostgreSQL error classification, shared by every Postgres-backed vendor.
//!
//! Failures arrive as [`tokio_postgres::Error`] rather than an HTTP response.
//! This module maps them onto the same [`McpError`] envelope the HTTP vendors
//! produce, so tool output is consistent:
//!
//! - **Server-side (db) errors** carry a SQLSTATE code. Authentication failures
//!   (bad password / role) become [`auth_invalid`]; missing schema/table/column
//!   and syntax/privilege/timeout errors become [`api_error`] with the HTTP
//!   status the equivalent REST failure would have used (404 / 400 / 403 / 504)
//!   so `McpError::mcp_code` classifies them the same way.
//! - **Client-side errors** (TLS handshake, connection refused, I/O) have no
//!   SQLSTATE and become a generic [`api_error`] connection failure.
//!
//! `detail` and `hint` are appended to the server's message wherever Postgres
//! supplies them: on a rejected query they are usually the only part that says
//! what to do about it.

use tokio_postgres::error::SqlState;

use crate::error::{McpError, OriginalError, api_error, auth_invalid};

use super::PgVendor;

/// Map a [`tokio_postgres::Error`] (from connect or query) onto an [`McpError`],
/// naming `vendor` in the message.
pub fn classify(vendor: PgVendor, err: &tokio_postgres::Error) -> McpError {
    let name = vendor.name;
    let Some(db) = err.as_db_error() else {
        // No SQLSTATE: TLS / connection / I/O failure raised client-side.
        return api_error(
            format!("{name} connection failed: {err}"),
            None,
            Some(OriginalError::String(err.to_string())),
        );
    };

    let code = db.code();
    let mut message = db.message().to_owned();
    if let Some(detail) = db.detail() {
        message.push_str(" — ");
        message.push_str(detail);
    }
    if let Some(hint) = db.hint() {
        message.push_str(" (hint: ");
        message.push_str(hint);
        message.push(')');
    }

    if code == &SqlState::INVALID_PASSWORD || code == &SqlState::INVALID_AUTHORIZATION_SPECIFICATION
    {
        return auth_invalid(format!("{name} authentication failed: {message}"));
    }
    // A write attempted against a read-only session is a permission outcome,
    // not a syntax problem: report it like any other denial rather than letting
    // it fall through to the generic branch.
    if code == &SqlState::INSUFFICIENT_PRIVILEGE || code == &SqlState::READ_ONLY_SQL_TRANSACTION {
        return api_error(format!("{name} access denied: {message}"), Some(403), None);
    }
    if code == &SqlState::UNDEFINED_TABLE
        || code == &SqlState::UNDEFINED_COLUMN
        || code == &SqlState::UNDEFINED_OBJECT
        || code == &SqlState::UNDEFINED_FUNCTION
        || code == &SqlState::INVALID_SCHEMA_NAME
    {
        return api_error(format!("{name}: {message}"), Some(404), None);
    }
    if code == &SqlState::QUERY_CANCELED {
        return api_error(
            format!(
                "{name} query canceled ({}-second statement timeout exceeded)",
                vendor.statement_timeout.as_secs()
            ),
            Some(504),
            None,
        );
    }
    // Syntax errors and other access-rule violations are caller-fixable input
    // problems → 400, mirroring how the REST vendors surface a bad request.
    if code.code().starts_with("42") {
        return api_error(format!("{name} query rejected: {message}"), Some(400), None);
    }

    api_error(
        format!("{name} query failed: {message}"),
        None,
        Some(OriginalError::String(format!("SQLSTATE {}", code.code()))),
    )
}

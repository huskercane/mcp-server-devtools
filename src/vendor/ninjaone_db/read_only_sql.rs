//! The read-only SQL guard for caller-supplied NinjaOne queries.
//!
//! This is policy, not plumbing: it decides what a tool caller is allowed to
//! ask for, and it does so without any knowledge of Postgres connections, TLS,
//! or configuration. It lives in its own module for that reason — it is the
//! highest-consequence logic in this vendor and must be testable, and
//! reviewable, on its own.
//!
//! The guard is one of three independent layers. The session is pinned
//! read-only and the query runs inside a read-only transaction, so a write that
//! somehow got past this check would still be refused by the server; and the
//! account itself should be read-only. This layer exists so the refusal is a
//! clear, actionable tool error rather than a SQLSTATE.

use crate::error::McpError;

use super::invalid_input;

/// Keywords that can only appear in a statement that changes something, or that
/// smuggle a second statement in. `into` catches `SELECT ... INTO table`;
/// `set` catches `SET` outside the session setup this module never sees.
const WRITE_KEYWORDS: &[&str] = &[
    "alter", "analyze", "call", "cluster", "comment", "copy", "create", "delete", "do", "drop",
    "grant", "insert", "into", "merge", "refresh", "reindex", "revoke", "security", "set",
    "truncate", "update", "vacuum",
];

/// Reject anything except one SELECT or WITH ... SELECT statement. Quoted
/// strings/identifiers and comments are ignored while scanning, preventing a
/// keyword inside a literal from producing a false write classification.
pub fn validate(sql: &str) -> Result<(), McpError> {
    let mut tokens = tokenize(sql)?;
    if tokens.last().is_some_and(|token| token == ";") {
        tokens.pop();
    }
    if tokens.is_empty() || tokens.iter().any(|token| token == ";") {
        return Err(invalid_input("SQL must contain exactly one statement"));
    }

    if let Some(keyword) = tokens
        .iter()
        .find(|token| WRITE_KEYWORDS.contains(&token.as_str()))
    {
        return Err(invalid_input(format!(
            "SQL keyword `{keyword}` is not allowed; only read-only SELECT queries are accepted"
        )));
    }

    match tokens.first().map(String::as_str) {
        Some("select") => Ok(()),
        Some("with") => {
            let mut depth = 0_u32;
            for token in tokens.iter().skip(1) {
                match token.as_str() {
                    "(" => depth = depth.saturating_add(1),
                    ")" => depth = depth.saturating_sub(1),
                    "select" if depth == 0 => return Ok(()),
                    _ => {}
                }
            }
            Err(invalid_input("WITH query must end in a top-level SELECT"))
        }
        _ => Err(invalid_input(
            "SQL must begin with SELECT or WITH and end in a SELECT",
        )),
    }
}

/// Lex just enough of Postgres' grammar to classify keywords safely: quoted
/// strings and identifiers, line and block comments, and dollar-quoted bodies
/// are skipped wholesale so nothing inside them is mistaken for a keyword.
/// Everything else reduces to lowercase word tokens plus the three punctuation
/// marks the validator reasons about.
fn tokenize(sql: &str) -> Result<Vec<String>, McpError> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => {
                let quote = bytes[index];
                index += 1;
                loop {
                    if index >= bytes.len() {
                        return Err(invalid_input("SQL contains an unterminated quoted value"));
                    }
                    if bytes[index] == quote {
                        if bytes.get(index + 1) == Some(&quote) {
                            index += 2;
                        } else {
                            index += 1;
                            break;
                        }
                    } else {
                        index += 1;
                    }
                }
            }
            b'-' if bytes.get(index + 1) == Some(&b'-') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let Some(end) = sql[index + 2..].find("*/") else {
                    return Err(invalid_input("SQL contains an unterminated block comment"));
                };
                index += end + 4;
            }
            b'$' => {
                let tag_end = bytes[index + 1..].iter().position(|byte| {
                    *byte == b'$' || !(byte.is_ascii_alphanumeric() || *byte == b'_')
                });
                if let Some(offset) = tag_end
                    && bytes[index + 1 + offset] == b'$'
                {
                    let delimiter_end = index + offset + 2;
                    let delimiter = &sql[index..delimiter_end];
                    let Some(end) = sql[delimiter_end..].find(delimiter) else {
                        return Err(invalid_input("SQL contains an unterminated dollar quote"));
                    };
                    index = delimiter_end + end + delimiter.len();
                } else {
                    index += 1;
                }
            }
            b'(' | b')' | b';' => {
                tokens.push(char::from(bytes[index]).to_string());
                index += 1;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                tokens.push(sql[start..index].to_ascii_lowercase());
            }
            _ => index += 1,
        }
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_single_select_and_read_only_cte() {
        for sql in [
            "SELECT * FROM device",
            " -- why\n SELECT 'delete; drop' AS words;",
            "WITH chosen AS (SELECT uid FROM division) SELECT * FROM chosen",
            "SELECT $$ update users $$ AS text",
        ] {
            validate(sql).unwrap();
        }
    }

    #[test]
    fn rejects_writes_data_changing_ctes_and_multiple_statements() {
        for sql in [
            "UPDATE device SET name = 'x'",
            "WITH changed AS (DELETE FROM device RETURNING *) SELECT * FROM changed",
            "SELECT 1; SELECT 2",
            "DROP TABLE device",
            "WITH picked AS (SELECT 1) VALUES (1)",
            "SELECT * INTO copied FROM device",
        ] {
            assert!(validate(sql).is_err(), "accepted {sql}");
        }
    }

    #[test]
    fn rejects_unterminated_quotes_and_comments() {
        for sql in [
            "SELECT 'unterminated",
            "SELECT 1 /* unterminated",
            "SELECT $$ unterminated",
        ] {
            assert!(validate(sql).is_err(), "accepted {sql}");
        }
    }
}

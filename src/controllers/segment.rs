//! Path-segment helpers shared by the purpose-built vendor controllers.
//!
//! A purpose-built tool splices caller-supplied identifiers (a repository
//! name, a GitLab project path, a file path) into a fixed endpoint template.
//! Two things must hold before that string goes to the canonicalizer:
//!
//! - an identifier that is meant to be **one** segment must not be able to
//!   add or remove segments (`owner/../admin`, `a/b`), and
//! - a value that legitimately contains reserved characters (GitLab's
//!   `group/project`, a file path with spaces) must be percent-encoded so the
//!   canonicalizer keeps it as the single escaped segment the API expects
//!   (`%2F` survives canonicalization; a raw `/` would split the segment).
//!
//! [`plain_segment`] enforces the first; [`encode_segment`] does the second.

use crate::error::{McpError, api_error};

/// Percent-encode `raw` as a single path segment: every byte outside RFC 3986
/// `unreserved` (`ALPHA / DIGIT / "-" / "." / "_" / "~"`) becomes `%XX`, so
/// `/`, spaces, `?`, `#`, and non-ASCII are all escaped. The canonicalizer
/// preserves escapes of reserved bytes, so the wire form is exactly this.
#[must_use]
pub fn encode_segment(raw: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(raw.len() + 8);
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0F)] as char);
        }
    }
    out
}

/// Percent-encode a slash-separated path (a file path inside a repository)
/// segment by segment, keeping the `/` separators. Empty segments, `.`, and
/// `..` are rejected so a caller cannot climb out of the templated prefix.
///
/// # Errors
///
/// A 400-shaped [`McpError`] naming `what` when the path is empty or contains
/// an empty / `.` / `..` segment.
pub fn encode_path(raw: &str, what: &str) -> Result<String, McpError> {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        return Err(api_error(
            format!("`{what}` must not be empty"),
            Some(400),
            None,
        ));
    }
    let mut out = String::with_capacity(trimmed.len() + 8);
    for (index, segment) in trimmed.split('/').enumerate() {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(api_error(
                format!("`{what}` must not contain empty, `.` or `..` segments"),
                Some(400),
                None,
            ));
        }
        if index > 0 {
            out.push('/');
        }
        out.push_str(&encode_segment(segment));
    }
    Ok(out)
}

/// Validate that `raw` is one plain identifier segment: non-empty after
/// trimming, not `.` or `..`, and free of `/`, `?`, `#`, `%`, whitespace, and
/// control characters. Returns the trimmed value. Use it for identifiers the
/// upstream API defines as opaque tokens (a repository slug, an issue id, an
/// organization key) so a crafted value cannot re-shape the endpoint.
///
/// # Errors
///
/// A 400-shaped [`McpError`] naming `what` when the value is not a plain
/// segment.
pub fn plain_segment<'a>(raw: &'a str, what: &str) -> Result<&'a str, McpError> {
    let trimmed = raw.trim();
    let bad = trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed
            .bytes()
            .any(|b| b < 0x21 || b == 0x7F || matches!(b, b'/' | b'\\' | b'?' | b'#' | b'%'));
    if bad {
        return Err(api_error(
            format!("`{what}` must be a single identifier (no `/`, whitespace, `?`, `#`, or `%`)"),
            Some(400),
            None,
        ));
    }
    Ok(trimmed)
}

/// Treat an absent or whitespace-only optional string as "not provided".
#[must_use]
pub fn trimmed(opt: Option<&String>) -> Option<&str> {
    opt.map(|s| s.trim()).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_segment_escapes_everything_but_unreserved() {
        assert_eq!(encode_segment("group/sub project"), "group%2Fsub%20project");
        assert_eq!(encode_segment("a-b.c_d~e"), "a-b.c_d~e");
        assert_eq!(encode_segment("ü"), "%C3%BC");
        assert_eq!(encode_segment("?#%"), "%3F%23%25");
    }

    #[test]
    fn encode_path_keeps_separators_and_rejects_climbing() {
        assert_eq!(
            encode_path("/src/my dir/file.rs/", "path").unwrap(),
            "src/my%20dir/file.rs"
        );
        for bad in ["", "/", "a//b", "a/./b", "../etc"] {
            assert_eq!(encode_path(bad, "path").unwrap_err().status_code, Some(400));
        }
    }

    #[test]
    fn plain_segment_accepts_identifiers_and_rejects_structure() {
        assert_eq!(plain_segment("  my-repo ", "repo").unwrap(), "my-repo");
        for bad in [
            "", " ", ".", "..", "a/b", "a?b", "a#b", "a%2Fb", "a b", "a\tb",
        ] {
            assert_eq!(
                plain_segment(bad, "repo").unwrap_err().status_code,
                Some(400)
            );
        }
    }
}

//! `multipart/form-data` uploads over the shared vendor transport.
//!
//! Two pieces, both vendor-neutral:
//!
//! - [`MultipartBody`] encodes file parts into an RFC 7578 body. It is a
//!   pure function of its inputs (no I/O, no HTTP client), so the exact wire
//!   bytes are locked by tests without a network. The form field name and
//!   any extra request headers are the caller's, because the vendors differ:
//!   Bitbucket Downloads wants repeated `files` fields, while Jira and
//!   Confluence attachments want `file` plus `X-Atlassian-Token: no-check`.
//! - [`post_multipart`] sends one body through the same pipeline as
//!   [`fetch`](super::fetch): egress policy, credential header, timeout,
//!   response-size cap, vendor error classification, cache invalidation,
//!   and raw-response persistence. It deliberately has **no retry**: an
//!   upload that timed out after the body was sent may have succeeded, and
//!   a blind retry replaces whatever landed. Callers decide what a caller
//!   should verify.
//!
//! The body is built with a hand-rolled encoder rather than `reqwest`'s
//! `multipart` feature. That keeps the pinned dependency graph unchanged
//! (the feature pulls `mime_guess` into the cargo-deny gate), and gives
//! byte-exact control over part headers, which the tests then pin.
//!
//! File contents never reach a log line: the only per-request diagnostics
//! are the part count, the encoded byte total, and the sanitised URL.

use std::time::Duration;

use http::header::{ACCEPT, CONTENT_TYPE, HeaderName, HeaderValue};
use serde_json::Value;
use tracing::debug;

use super::{
    CacheMetadata, Config, Credentials, HttpCallLog, HttpClient, HttpMethod, McpError,
    ResponseBody, TransportResponse, Vendor, canonical_target, classify_body,
    enforce_content_length_cap, log_http_status_failure, log_http_transport_failure,
    map_transport_error, raw_response, report_attempt, resolve_timeout, response_cache, unexpected,
    validate_auth,
};

/// One file part of a multipart body. Borrowed throughout so encoding is
/// the only copy of the file bytes.
#[derive(Debug, Clone, Copy)]
pub struct FilePart<'a> {
    /// Form field name: `files` for Bitbucket Downloads, `file` for Jira and
    /// Confluence attachments.
    pub field: &'a str,
    /// Filename sent in the `Content-Disposition` header. Quotes and line
    /// breaks are percent-escaped the way browsers do; everything else is
    /// sent verbatim, so callers validate names against their vendor's
    /// rules before encoding.
    pub filename: &'a str,
    /// Part `Content-Type`. Sent verbatim.
    pub content_type: &'a str,
    /// Raw file bytes.
    pub bytes: &'a [u8],
}

/// An encoded `multipart/form-data` body plus its boundary.
#[derive(Debug, Clone)]
pub struct MultipartBody {
    boundary: String,
    bytes: Vec<u8>,
}

const BOUNDARY_PREFIX: &str = "----mcp-devtools-";
const CRLF: &[u8] = b"\r\n";

impl MultipartBody {
    /// Encode `parts` behind a fresh random boundary.
    #[must_use]
    pub fn encode(parts: &[FilePart<'_>]) -> Self {
        Self::encode_with_boundary(random_boundary(), parts)
    }

    /// Encode `parts` behind a caller-supplied boundary. Exposed so tests
    /// can pin exact bytes; production uses [`Self::encode`].
    ///
    /// # Panics
    ///
    /// Panics if `boundary` is empty, longer than the 70 characters RFC 2046
    /// allows, or contains a byte outside the `bchars` set. A boundary is
    /// program-generated, so a bad one is a bug, not input.
    #[must_use]
    pub fn encode_with_boundary(boundary: String, parts: &[FilePart<'_>]) -> Self {
        assert!(
            !boundary.is_empty()
                && boundary.len() <= 70
                && boundary.bytes().all(is_boundary_byte)
                && !boundary.ends_with(' '),
            "multipart boundary must be 1-70 RFC 2046 bchars: {boundary:?}"
        );

        // Escape once, then size the buffer exactly: the encoded body is
        // the single largest allocation on the upload path.
        let escaped: Vec<(String, String)> = parts
            .iter()
            .map(|part| (escape_quoted(part.field), escape_quoted(part.filename)))
            .collect();
        let capacity = parts
            .iter()
            .zip(&escaped)
            .map(|(part, (field, filename))| {
                2 + boundary.len()
                    + 2
                    + b"Content-Disposition: form-data; name=\"\"; filename=\"\"\r\n".len()
                    + field.len()
                    + filename.len()
                    + b"Content-Type: \r\n\r\n".len()
                    + part.content_type.len()
                    + part.bytes.len()
                    + 2
            })
            .sum::<usize>()
            + 2
            + boundary.len()
            + 4;

        let mut bytes = Vec::with_capacity(capacity);
        for (part, (field, filename)) in parts.iter().zip(&escaped) {
            bytes.extend_from_slice(b"--");
            bytes.extend_from_slice(boundary.as_bytes());
            bytes.extend_from_slice(CRLF);
            bytes.extend_from_slice(b"Content-Disposition: form-data; name=\"");
            bytes.extend_from_slice(field.as_bytes());
            bytes.extend_from_slice(b"\"; filename=\"");
            bytes.extend_from_slice(filename.as_bytes());
            bytes.extend_from_slice(b"\"\r\nContent-Type: ");
            bytes.extend_from_slice(part.content_type.as_bytes());
            bytes.extend_from_slice(b"\r\n\r\n");
            bytes.extend_from_slice(part.bytes);
            bytes.extend_from_slice(CRLF);
        }
        bytes.extend_from_slice(b"--");
        bytes.extend_from_slice(boundary.as_bytes());
        bytes.extend_from_slice(b"--\r\n");
        debug_assert_eq!(bytes.len(), capacity, "multipart capacity estimate drifted");

        Self { boundary, bytes }
    }

    /// The `Content-Type` request header value for this body.
    #[must_use]
    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encoded length in bytes, including part headers and the boundaries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// RFC 2046 `bchars`: `DIGIT / ALPHA / "'" / "(" / ")" / "+" / "_" / ","
/// / "-" / "." / "/" / ":" / "=" / "?" / " "`.
fn is_boundary_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&byte)
}

/// A boundary that cannot collide with any realistic payload: 128 random
/// bits behind a fixed prefix, 49 characters in total.
fn random_boundary() -> String {
    use std::fmt::Write as _;
    let mut random = [0u8; 16];
    rand::fill(&mut random);
    let mut boundary = String::with_capacity(BOUNDARY_PREFIX.len() + random.len() * 2);
    boundary.push_str(BOUNDARY_PREFIX);
    for byte in random {
        let _ = write!(boundary, "{byte:02x}");
    }
    boundary
}

/// Percent-escape the three bytes that would break a quoted
/// `Content-Disposition` parameter, exactly as the WHATWG
/// `multipart/form-data` encoder does: `"` → `%22`, CR → `%0D`, LF → `%0A`.
/// Everything else (including non-ASCII, sent as UTF-8) passes through.
fn escape_quoted(value: &str) -> String {
    if !value.contains(['"', '\r', '\n']) {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("%22"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            other => out.push(other),
        }
    }
    out
}

/// One multipart upload to dispatch through [`post_multipart`].
#[derive(Debug)]
pub struct MultipartRequest<'a> {
    /// Vendor-relative path, already normalised by the caller (for
    /// Bitbucket that means it carries the `/2.0` prefix).
    pub path: &'a str,
    /// The encoded body.
    pub body: MultipartBody,
    /// Extra request headers, e.g. Jira's `X-Atlassian-Token: no-check`.
    pub headers: &'a [(HeaderName, HeaderValue)],
    /// Non-secret description of the upload (names, sizes, types) offered
    /// to the egress policy in place of a JSON body. Never file contents.
    pub manifest: Option<&'a Value>,
}

/// Grace added to the configured request timeout for the bytes on the
/// wire: one second per 100 KiB keeps a 1 Mbit/s uplink inside the
/// deadline without raising the default for every other call.
const UPLOAD_GRACE_BYTES_PER_SECOND: u64 = 100 * 1024;

fn upload_timeout(base: Duration, body_len: usize) -> Duration {
    let grace = u64::try_from(body_len).unwrap_or(u64::MAX) / UPLOAD_GRACE_BYTES_PER_SECOND;
    base.saturating_add(Duration::from_secs(grace))
}

/// Send a `multipart/form-data` POST with the vendor's credentials.
///
/// Mirrors [`fetch`](super::fetch) for a write: the target is canonicalised
/// and authorised, cached reads under the vendor are dropped, non-2xx
/// bodies go through [`Vendor::classify_error`], and a JSON success body is
/// persisted as a raw response (with no request body recorded, so file
/// contents never land on disk twice). Exactly one attempt is made.
pub async fn post_multipart(
    client: &HttpClient,
    vendor: &dyn Vendor,
    credentials: &Credentials,
    config: &Config,
    request: MultipartRequest<'_>,
) -> Result<TransportResponse, McpError> {
    let base = vendor.base_url(config)?;
    let target = canonical_target(request.path)?;
    let ticket =
        crate::policy::authorize_egress(vendor.name(), HttpMethod::Post, &target, request.manifest)
            .await?;
    let url = target.url_under(&base);
    let (auth_name, auth_header) = validate_auth(credentials)?;
    let body_len = request.body.len();
    let timeout = upload_timeout(resolve_timeout(config, None), body_len);
    let deadline = tokio::time::Instant::now() + timeout;
    let content_type = HeaderValue::from_str(&request.body.content_type())
        .map_err(|_| unexpected("multipart boundary produced an invalid header", None))?;

    // A write, like every non-GET through `fetch`: whatever was cached for
    // this vendor may now be stale.
    response_cache::invalidate_namespace(vendor.name(), &base);

    let mut req = client
        .post(&url)
        .timeout(timeout)
        .header(auth_name, auth_header)
        .header(ACCEPT, HeaderValue::from_static("application/json"))
        .header(CONTENT_TYPE, content_type);
    for (name, value) in request.headers {
        req = req.header(name.clone(), value.clone());
    }

    debug!(
        %url,
        vendor = vendor.name(),
        bytes = body_len,
        "dispatching multipart upload"
    );

    let call = HttpCallLog::new(vendor.name(), "POST", &url);
    let start = call.started;
    let response = req
        .body(request.body.into_bytes())
        .send()
        .await
        .map_err(|error| {
            report_attempt(ticket.as_ref(), None, Some("transport_error"));
            log_http_transport_failure(call, &error, false);
            map_transport_error(&error, &url)
        })?;
    let duration = start.elapsed();

    let status = response.status();
    report_attempt(ticket.as_ref(), Some(status.as_u16()), None);
    if !status.is_success() {
        log_http_status_failure(call, status, false);
    }
    enforce_content_length_cap(&response)?;
    if !status.is_success() {
        let delay = super::retry::parse(response.headers(), std::time::SystemTime::now());
        let policy = super::StreamingPolicy::new(
            super::MAX_RESPONSE_SIZE as u64,
            super::MAX_RESPONSE_SIZE as u64,
        );
        let body_text = super::bounded_body(response, &policy, deadline).await?;
        return Err(super::retry::metadata(
            vendor.classify_error(status, &body_text),
            delay,
        ));
    }

    let headers = response.headers().clone();
    let body = classify_body(response).await?;
    if let ResponseBody::Json(value) = &body
        && let Some(err) = vendor.classify_success_json(value)
    {
        return Err(err);
    }

    let raw_response_path = if let ResponseBody::Json(value) = &body {
        raw_response::save(&url, "POST", None, value, status.as_u16(), duration).await
    } else {
        None
    };

    Ok(TransportResponse {
        data: body,
        cache: CacheMetadata {
            hit: false,
            age_ms: 0,
            fetched_at: crate::logger::iso_timestamp(),
        },
        raw_response_path,
        headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_boundaries_are_valid_and_distinct() {
        let first = random_boundary();
        let second = random_boundary();
        assert_ne!(first, second);
        assert_eq!(first.len(), BOUNDARY_PREFIX.len() + 32);
        assert!(first.bytes().all(is_boundary_byte));
    }

    #[test]
    fn escape_quoted_only_touches_quote_and_line_breaks() {
        assert_eq!(escape_quoted("plain-name.json"), "plain-name.json");
        assert_eq!(escape_quoted("a\"b\r\nc"), "a%22b%0D%0Ac");
        assert_eq!(escape_quoted("naïve ✓.txt"), "naïve ✓.txt");
    }

    #[test]
    fn upload_timeout_grows_with_body_size() {
        let base = Duration::from_secs(30);
        assert_eq!(upload_timeout(base, 0), base);
        assert_eq!(upload_timeout(base, 100 * 1024 - 1), base);
        assert_eq!(
            upload_timeout(base, 25 * 1024 * 1024),
            base + Duration::from_secs(256)
        );
    }

    #[test]
    #[should_panic(expected = "multipart boundary must be")]
    fn rejects_boundary_outside_bchars() {
        let _ = MultipartBody::encode_with_boundary("bad\"boundary".to_owned(), &[]);
    }
}

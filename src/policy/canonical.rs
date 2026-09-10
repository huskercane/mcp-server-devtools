//! Outbound request canonicalization (plan §3.5, WP A.6).
//!
//! Policy and audit must see **one** canonical form of every upstream
//! request, and the request that actually goes on the wire must be that same
//! form — otherwise a caller can present one path to the policy engine and a
//! differently-spelled path to the vendor. This module is the single place
//! that form is produced. The transport builds the outbound URL from a
//! [`CanonicalTarget`], and the extractors in [`super::extractors`] accept
//! only a [`CanonicalPath`], a newtype that nothing outside this module can
//! construct. That is what turns "the extractor is only as sound as the
//! canonicalizer in front of it" (carry-forward CF-5) from a caveat into a
//! type-checked fact.
//!
//! ## What "canonical" means here
//!
//! RFC 3986 §6.2.2 syntax-based normalization, plus the structural rules the
//! plan lists:
//!
//! - **scheme, host, and port never come from the request.** The input is a
//!   path-and-query that is always joined onto the configured base, so it
//!   cannot name a host; anything shaped like an absolute URL (`scheme://`)
//!   is rejected outright rather than sent as a nonsense path. A leading
//!   `//` is a doubled slash, not a network-path reference — there is no
//!   reference resolution here, only concatenation — and collapses like any
//!   other. User-info is therefore unrepresentable rather than merely
//!   rejected.
//! - **percent-decoded once — for unreserved characters only.** `%41` is `A`
//!   and `%2E` is `.`, so `%2E%2E` is a dot-segment and is removed like one.
//!   Escapes of *reserved* characters are kept as escapes with their hex
//!   uppercased: `%2F` stays `%2F`. Decoding it would turn one path segment
//!   into two, which is not what a vendor does (Bitbucket branch names carry
//!   `%2F` inside a single segment) and would let the policy engine classify a
//!   different request than the one sent. Double encoding (`%252E`) decodes
//!   to `%2E` upstream at most, never to `.`, and is not treated as a dot
//!   segment here either.
//! - **dot-segments removed** (`.` and `..`, RFC 3986 §5.2.4, so `/a/b/..`
//!   is `/a/`), duplicate slashes collapsed, case preserved — vendors are
//!   case-sensitive. A trailing slash is normalized to *at most one* and
//!   otherwise **kept**: Django-style APIs (edX) treat `/courses/x/` and
//!   `/courses/x` as different resources, and since the canonical form is
//!   what is sent, stripping it would turn a valid request into a 404. It
//!   never changes a classification — extractors ignore empty segments.
//! - **query decoded and sorted by key**, stably, so repeated keys keep their
//!   relative order. Only allowlisted keys reach policy; that filter lives in
//!   the extractors, which see the decoded pairs.
//! - **re-encoded** so the canonical path is pure ASCII in the `pchar` set:
//!   bytes outside it (space, quotes, non-ASCII UTF-8, …) become `%XX`.
//!
//! Redirects and DNS pinning are transport properties, not guarantees of this
//! canonicalizer. Shared API transports disable implicit redirects and authorize
//! each GET hop with its destination origin; cross-origin hops require the
//! configured download allowlist and shed credentials. DNS pinning remains
//! outside this canonicalizer. See `docs/integration-expansion-status.md`.
//!
//! ## Budget
//!
//! §8 allows 30 µs for context build plus canonicalization. This is a single
//! byte-level pass with one output allocation for the path and one `Vec` for
//! the query pairs; no regex, no intermediate segment vectors.
//!
//! ## Testing
//!
//! `fuzz/fuzz_targets/canonicalize.rs` is the libFuzzer target (nightly to
//! *run*, stable code); `tests/canonicalization_tests.rs` runs the same
//! invariants over a seeded pseudo-random corpus on stable, in CI.

use std::fmt;

/// Longest path-and-query accepted. Beyond it the answer is an error, not an
/// unbounded pass over caller-controlled bytes on the request path.
pub const MAX_TARGET_BYTES: usize = 16 * 1024;

/// Why a target could not be canonicalized. Each is a refusal: the request
/// is not sent, because there is no canonical form to evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanonicalizeError {
    /// The input carried a scheme (`https://…`). The host comes from
    /// configuration, never from the request.
    AbsoluteUrl,
    /// A `%` not followed by two hex digits.
    InvalidPercentEncoding,
    /// A control byte (`0x00`–`0x1F`, `0x7F`) in the path or query.
    ControlCharacter,
    /// A query key or value that does not decode to UTF-8.
    InvalidUtf8,
    /// Longer than [`MAX_TARGET_BYTES`].
    TooLong,
}

impl fmt::Display for CanonicalizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AbsoluteUrl => "request path must be relative to the configured vendor base URL",
            Self::InvalidPercentEncoding => "request path contains an invalid percent-escape",
            Self::ControlCharacter => "request path contains a control character",
            Self::InvalidUtf8 => "request query does not decode to UTF-8",
            Self::TooLong => "request path is too long",
        })
    }
}

impl std::error::Error for CanonicalizeError {}

/// A path in canonical form. Only this module can construct one, so a
/// function taking `&CanonicalPath` is guaranteed the §3.5 normalization has
/// already happened — there is no way to hand an extractor a raw path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalPath(String);

impl CanonicalPath {
    /// Canonicalize a bare path (no query, no fragment expected — both are
    /// handled, and dropped, if present). Prefer [`CanonicalTarget::parse`]
    /// when the query matters.
    ///
    /// # Errors
    ///
    /// See [`CanonicalizeError`].
    pub fn parse(path: &str) -> Result<Self, CanonicalizeError> {
        CanonicalTarget::parse(path).map(|target| target.path)
    }

    /// Build a canonical path from segments that are already known to be
    /// plain: every byte unreserved (`ALPHA / DIGIT / "-" / "." / "_" / "~"`)
    /// and no segment equal to `.` or `..`. Returns `None` otherwise. This is
    /// the zero-cost path for purpose-built tools that have validated their
    /// own segments (the Grafana datasource UID), and it cannot produce
    /// anything [`Self::parse`] would not.
    #[must_use]
    pub fn from_plain_segments(segments: &[&str]) -> Option<Self> {
        let mut out = String::with_capacity(
            segments
                .iter()
                .map(|segment| segment.len() + 1)
                .sum::<usize>()
                + 1,
        );
        for segment in segments {
            if segment.is_empty()
                || *segment == "."
                || *segment == ".."
                || !segment.bytes().all(is_unreserved)
            {
                return None;
            }
            out.push('/');
            out.push_str(segment);
        }
        if out.is_empty() {
            out.push('/');
        }
        Some(Self(out))
    }

    /// The root path, `/`. Infallible, so total fallbacks need no `expect`.
    #[must_use]
    pub fn root() -> Self {
        Self("/".to_owned())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the underlying string (for audit records that own it).
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for CanonicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for CanonicalPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A canonical path plus its decoded, key-sorted query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTarget {
    path: CanonicalPath,
    query: Vec<(String, String)>,
}

impl CanonicalTarget {
    /// Canonicalize a path-and-query as a tool supplied it (after the
    /// vendor's own prefixing, e.g. Bitbucket's `/2.0`).
    ///
    /// # Errors
    ///
    /// See [`CanonicalizeError`].
    pub fn parse(path_and_query: &str) -> Result<Self, CanonicalizeError> {
        if path_and_query.len() > MAX_TARGET_BYTES {
            return Err(CanonicalizeError::TooLong);
        }
        let without_fragment = path_and_query
            .split_once('#')
            .map_or(path_and_query, |(before, _)| before);
        let (raw_path, raw_query) = match without_fragment.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (without_fragment, None),
        };
        if looks_absolute(raw_path) {
            return Err(CanonicalizeError::AbsoluteUrl);
        }
        let path = canonical_path(raw_path)?;
        let query = raw_query.map_or_else(|| Ok(Vec::new()), canonical_query)?;
        Ok(Self {
            path: CanonicalPath(path),
            query,
        })
    }

    #[must_use]
    pub fn path(&self) -> &CanonicalPath {
        &self.path
    }

    /// Decoded query pairs, sorted by key (stable).
    #[must_use]
    pub fn query(&self) -> &[(String, String)] {
        &self.query
    }

    /// Borrowed view of the query for the extractors, which take
    /// `&[(&str, &str)]`.
    #[must_use]
    pub fn query_pairs(&self) -> Vec<(&str, &str)> {
        self.query
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    }

    /// The URL to put on the wire: the configured base joined with the
    /// canonical path and the re-encoded canonical query. This is the only
    /// way the transport builds an upstream URL, so what policy evaluated is
    /// what is sent.
    #[must_use]
    pub fn url_under(&self, base: &str) -> String {
        let base = base.trim_end_matches('/');
        let mut url = String::with_capacity(base.len() + self.path.0.len() + 1);
        url.push_str(base);
        url.push_str(&self.path.0);
        if !self.query.is_empty() {
            url.push('?');
            let encoded = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(
                    self.query
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str())),
                )
                .finish();
            url.push_str(&encoded);
        }
        url
    }

    /// Split back into parts (for callers that want to own both).
    #[must_use]
    pub fn into_parts(self) -> (CanonicalPath, Vec<(String, String)>) {
        (self.path, self.query)
    }
}

/// `scheme://…` — the request tried to name a host.
fn looks_absolute(raw_path: &str) -> bool {
    let bytes = raw_path.as_bytes();
    // RFC 3986 scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"
    let Some(first) = bytes.first() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    let scheme_len = bytes
        .iter()
        .position(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')))
        .unwrap_or(bytes.len());
    bytes[scheme_len..].starts_with(b"://")
}

const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// RFC 3986 `pchar` minus the escapes: unreserved / sub-delims / ":" / "@".
const fn is_pchar(byte: u8) -> bool {
    is_unreserved(byte)
        || matches!(
            byte,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn push_escaped(out: &mut String, byte: u8) {
    out.push('%');
    out.push(HEX_UPPER[usize::from(byte >> 4)] as char);
    out.push(HEX_UPPER[usize::from(byte & 0x0F)] as char);
}

/// Decode the three-byte escape starting at `bytes[index]` (which is `%`).
fn read_escape(bytes: &[u8], index: usize) -> Result<u8, CanonicalizeError> {
    let (Some(high), Some(low)) = (
        bytes.get(index + 1).copied().and_then(hex_value),
        bytes.get(index + 2).copied().and_then(hex_value),
    ) else {
        return Err(CanonicalizeError::InvalidPercentEncoding);
    };
    Ok((high << 4) | low)
}

/// One pass: decode unreserved escapes, re-encode what must be encoded, and
/// resolve segments (dot removal, duplicate-slash collapse) as they close.
fn canonical_path(raw: &str) -> Result<String, CanonicalizeError> {
    let bytes = raw.as_bytes();
    // Output holds `/segment/segment…`. Segment starts are tracked as byte
    // offsets into `out` so `..` can pop the previous segment without a
    // segment vector.
    let mut out = String::with_capacity(bytes.len() + 1);
    let mut index = 0usize;

    // A path always begins with a segment boundary.
    out.push('/');
    let mut segment_start = out.len();

    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'/' {
            close_segment(&mut out, &mut segment_start);
            index += 1;
            continue;
        }
        if byte < 0x20 || byte == 0x7F {
            return Err(CanonicalizeError::ControlCharacter);
        }
        if byte == b'%' {
            let decoded = read_escape(bytes, index)?;
            if is_unreserved(decoded) {
                out.push(decoded as char);
            } else {
                push_escaped(&mut out, decoded);
            }
            index += 3;
            continue;
        }
        if is_pchar(byte) {
            out.push(byte as char);
        } else {
            push_escaped(&mut out, byte);
        }
        index += 1;
    }

    // The final segment. A real one closes without a trailing slash; an
    // empty one means the input ended in `/` (kept, see the module docs);
    // `.` and `..` resolve to a trailing slash per RFC 3986 §5.2.4.
    let last_is_real = !matches!(&out[segment_start..], "" | "." | "..");
    close_segment(&mut out, &mut segment_start);
    if last_is_real {
        out.pop();
    }
    Ok(out)
}

/// Resolve the segment that just ended at `out.len()`: drop it if empty
/// (duplicate slash) or `.`, pop the previous one if `..`, otherwise keep it
/// and open the next.
fn close_segment(out: &mut String, segment_start: &mut usize) {
    let segment = &out[*segment_start..];
    match segment {
        "" => {}
        "." => out.truncate(*segment_start),
        ".." => {
            out.truncate(*segment_start);
            // Pop the previous segment: `out` is `/a/b/` shaped, so strip
            // the trailing `/` then everything back to the previous `/`.
            if out.len() > 1 {
                out.pop();
                let previous = out.rfind('/').map_or(0, |at| at + 1);
                out.truncate(previous);
            }
        }
        _ => out.push('/'),
    }
    *segment_start = out.len();
}

fn decode_component(raw: &str) -> Result<String, CanonicalizeError> {
    let bytes = raw.as_bytes();
    let mut decoded: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b'%' => {
                decoded.push(read_escape(bytes, index)?);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            0x00..=0x1F | 0x7F => return Err(CanonicalizeError::ControlCharacter),
            _ => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| CanonicalizeError::InvalidUtf8)
}

fn canonical_query(raw: &str) -> Result<Vec<(String, String)>, CanonicalizeError> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        pairs.push((decode_component(key)?, decode_component(value)?));
    }
    // Stable: repeated keys keep their relative order.
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(pairs)
}

/// The properties every canonical form satisfies, as one checker shared by
/// the libFuzzer target (`fuzz/fuzz_targets/canonicalize.rs`) and the
/// stable seeded-corpus test (`tests/canonicalization_tests.rs`), so the two
/// cannot drift. Panics describe the violated property.
pub mod invariants {
    use super::{CanonicalTarget, CanonicalizeError, MAX_TARGET_BYTES, is_pchar};

    /// Run every invariant against `input`. Never panics on a *rejected*
    /// input; panics only when an accepted input's canonical form is wrong.
    pub fn check(input: &str) {
        let target = match CanonicalTarget::parse(input) {
            Ok(target) => target,
            Err(CanonicalizeError::TooLong) => {
                assert!(input.len() > MAX_TARGET_BYTES, "TooLong for a short input");
                return;
            }
            Err(_) => return,
        };
        let path = target.path().as_str();

        // Shape: absolute, no empty segments, no dot segments, no trailing
        // slash except the root, nothing that would re-split the URL.
        assert!(path.starts_with('/'), "path must be absolute: {path:?}");
        assert!(!path.contains("//"), "duplicate slash survived: {path:?}");
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            assert!(segment != "." && segment != "..", "dot segment in {path:?}");
        }
        assert!(
            !path.contains(['?', '#']),
            "query/fragment leaked into path: {path:?}"
        );

        // Encoding: pure ASCII pchar, every escape well-formed, uppercase,
        // and never an escape of an unreserved byte (those are decoded).
        let bytes = path.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b'%' => {
                    let hex = &bytes[index + 1..index + 3];
                    assert!(
                        hex.len() == 2 && hex.iter().all(u8::is_ascii_hexdigit),
                        "malformed escape in {path:?}"
                    );
                    assert!(
                        hex.iter().all(|byte| !byte.is_ascii_lowercase()),
                        "lowercase escape in {path:?}"
                    );
                    let decoded = u8::from_str_radix(std::str::from_utf8(hex).unwrap(), 16)
                        .expect("hex checked above");
                    assert!(
                        !super::is_unreserved(decoded),
                        "unreserved byte left encoded in {path:?}"
                    );
                    index += 3;
                }
                b'/' => index += 1,
                byte => {
                    assert!(is_pchar(byte), "non-pchar byte {byte:#04x} in {path:?}");
                    index += 1;
                }
            }
        }

        // Query: sorted by key, stably.
        let query = target.query();
        assert!(
            query.windows(2).all(|pair| pair[0].0 <= pair[1].0),
            "query keys not sorted: {query:?}"
        );

        // Idempotence: the wire form canonicalizes to itself.
        let wire = target.url_under("");
        let again = CanonicalTarget::parse(&wire)
            .unwrap_or_else(|error| panic!("canonical form {wire:?} rejected: {error}"));
        assert_eq!(
            again, target,
            "canonicalization is not idempotent for {input:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn path(input: &str) -> String {
        CanonicalPath::parse(input).unwrap().into_string()
    }

    #[test]
    fn plain_paths_pass_through_with_a_leading_slash() {
        assert_eq!(path("/rest/api/3/issue/PLAT-1"), "/rest/api/3/issue/PLAT-1");
        assert_eq!(path("rest/api/3/issue/PLAT-1"), "/rest/api/3/issue/PLAT-1");
        assert_eq!(path(""), "/");
        assert_eq!(path("/"), "/");
        assert_eq!(path("///"), "/");
    }

    #[test]
    fn duplicate_slashes_collapse_and_a_trailing_slash_is_kept_once() {
        assert_eq!(
            path("//rest//api/3//issue/PLAT-1/"),
            "/rest/api/3/issue/PLAT-1/"
        );
        assert_eq!(path("/a/b//"), "/a/b/");
        // Django-style APIs distinguish these; the canonical form is what
        // is sent, so the distinction must survive.
        assert_ne!(path("/courses/x/"), path("/courses/x"));
    }

    #[test]
    fn dot_segments_are_removed_including_encoded_ones() {
        assert_eq!(path("/a/./b/../c"), "/a/c");
        assert_eq!(path("/a/b/../../c"), "/c");
        assert_eq!(path("/../../etc/passwd"), "/etc/passwd");
        assert_eq!(path("/a/%2e%2e/b"), "/b");
        assert_eq!(path("/a/%2E/b"), "/a/b");
        // RFC 3986 §5.2.4: a trailing `.` or `..` resolves to a directory.
        assert_eq!(path("/a/b/.."), "/a/");
        assert_eq!(path("/a/."), "/a/");
        assert_eq!(path("/a/.."), "/");
        assert_eq!(path("/.."), "/");
        assert_eq!(path("/a/..."), "/a/...");
    }

    #[test]
    fn reserved_escapes_are_kept_and_uppercased_unreserved_ones_decoded() {
        // `%2F` inside a segment is one segment on the wire and stays so.
        assert_eq!(
            path("/refs/branches/feature%2fx"),
            "/refs/branches/feature%2Fx"
        );
        assert_eq!(path("/a/%41%7e%2d"), "/a/A~-");
        // Double encoding does not collapse to a dot segment: `%25` is an
        // escaped `%`, and the `2e` after it is literal text, so it stays
        // exactly as written (only escape hex is uppercased).
        assert_eq!(path("/a/%252e%252e/b"), "/a/%252e%252e/b");
        assert_eq!(path("/a/%2e%2e%2fb"), "/a/..%2Fb");
    }

    #[test]
    fn bytes_outside_pchar_are_percent_encoded() {
        assert_eq!(path("/a b"), "/a%20b");
        assert_eq!(path("/a\"b"), "/a%22b");
        assert_eq!(path("/caf\u{e9}"), "/caf%C3%A9");
        assert_eq!(path("/a\\b"), "/a%5Cb");
        // Sub-delims and `:`/`@` are legal path characters.
        assert_eq!(path("/user@example.com:1"), "/user@example.com:1");
    }

    #[test]
    fn invalid_input_is_refused_not_guessed() {
        assert_eq!(
            CanonicalPath::parse("/a/%zz").unwrap_err(),
            CanonicalizeError::InvalidPercentEncoding
        );
        assert_eq!(
            CanonicalPath::parse("/a/%2").unwrap_err(),
            CanonicalizeError::InvalidPercentEncoding
        );
        assert_eq!(
            CanonicalPath::parse("/a/%").unwrap_err(),
            CanonicalizeError::InvalidPercentEncoding
        );
        assert_eq!(
            CanonicalPath::parse("/a\u{0}b").unwrap_err(),
            CanonicalizeError::ControlCharacter
        );
        assert_eq!(
            CanonicalPath::parse("/a\nb").unwrap_err(),
            CanonicalizeError::ControlCharacter
        );
        assert_eq!(
            CanonicalPath::parse(&"a".repeat(MAX_TARGET_BYTES + 1)).unwrap_err(),
            CanonicalizeError::TooLong
        );
    }

    #[test]
    fn absolute_urls_are_refused_and_doubled_leading_slashes_collapse() {
        for hostile in [
            "https://evil.example/x",
            "http://evil.example",
            "HTTPS://evil.example/x",
            "custom+scheme.v1://x",
        ] {
            assert_eq!(
                CanonicalTarget::parse(hostile).unwrap_err(),
                CanonicalizeError::AbsoluteUrl,
                "{hostile}"
            );
        }
        // No reference resolution happens here — the path is concatenated
        // onto the configured base — so `//host` is a doubled slash on our
        // host, not a network-path reference.
        assert_eq!(path("//evil.example/x"), "/evil.example/x");
        // A colon that is not a scheme is just a path character.
        assert_eq!(path("/a:b/c"), "/a:b/c");
        assert_eq!(path("a:b"), "/a:b");
    }

    #[test]
    fn query_is_decoded_sorted_stably_and_fragment_dropped() {
        let target =
            CanonicalTarget::parse("/search?jql=project+%3D+PLAT&fields=b&fields=a&x#frag")
                .unwrap();
        assert_eq!(target.path().as_str(), "/search");
        assert_eq!(
            target.query(),
            &[
                ("fields".to_owned(), "b".to_owned()),
                ("fields".to_owned(), "a".to_owned()),
                ("jql".to_owned(), "project = PLAT".to_owned()),
                ("x".to_owned(), String::new()),
            ]
        );
        assert_eq!(
            target.url_under("https://x.example/"),
            "https://x.example/search?fields=b&fields=a&jql=project+%3D+PLAT&x="
        );
        assert_eq!(
            CanonicalTarget::parse("/a?b=%ff").unwrap_err(),
            CanonicalizeError::InvalidUtf8
        );
    }

    #[test]
    fn canonicalization_is_idempotent() {
        for input in [
            "/a/./b/../c?z=1&a=2",
            "/refs/branches/feature%2fx",
            "/caf\u{e9}/a b",
            "//x//y/",
            "/%2e%2e/%2e",
        ] {
            let once = CanonicalTarget::parse(input).unwrap();
            let again = CanonicalTarget::parse(&once.url_under("")).unwrap();
            assert_eq!(once, again, "{input}");
        }
    }

    #[test]
    fn plain_segments_build_the_same_form_parse_would() {
        let built =
            CanonicalPath::from_plain_segments(&["api", "datasources", "loki-prod"]).unwrap();
        assert_eq!(
            built,
            CanonicalPath::parse("/api/datasources/loki-prod").unwrap()
        );
        assert_eq!(
            CanonicalPath::from_plain_segments(&[]).unwrap().as_str(),
            "/"
        );
        for bad in [
            &["a", ".."][..],
            &["a/b"],
            &["a%2Fb"],
            &[""],
            &["."],
            &["a b"],
        ] {
            assert!(
                CanonicalPath::from_plain_segments(bad).is_none(),
                "{bad:?} is not plain"
            );
        }
    }
}

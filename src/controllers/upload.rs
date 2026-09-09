//! Vendor-neutral upload input handling.
//!
//! An MCP client cannot hand the server a local path: over a remote
//! transport the path means nothing here. Files therefore arrive either
//! inline as base64, or as the id of a server-side temporary artifact that
//! another tool produced (the `artifact_read` store). This module turns
//! either form into validated bytes and refuses anything that would breach
//! the operator's limits **before** a byte leaves the process.
//!
//! Vendor adapters (Bitbucket Downloads today; Jira and Confluence
//! attachments later) call [`prepare_files`] and then encode the result
//! with [`crate::transport::multipart`]. What differs per vendor — the
//! target path, form field name, collision semantics, result shape — stays
//! in the vendor's own controller.
//!
//! Nothing here logs file contents. Diagnostics carry counts and sizes.

use std::collections::HashSet;

use base64::alphabet;
use base64::engine::{DecodePaddingMode, Engine as _, GeneralPurpose, GeneralPurposeConfig};
use tokio::io::AsyncReadExt as _;

use crate::config::Config;
use crate::constants::data_limits::MAX_UPLOAD_FILES;
use crate::error::{McpError, api_error};
use crate::policy::OwnerKey;
use crate::tools::args::UploadFileArg;
use crate::transport::raw_response::pin_artifact;

/// Operator-configurable ceilings for one upload call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadLimits {
    /// Decoded bytes per file.
    pub max_file_bytes: u64,
    /// Decoded bytes across every file in the call.
    pub max_total_bytes: u64,
    /// Files per call.
    pub max_files: usize,
}

impl UploadLimits {
    /// Limits for `vendor`, read through the config cascade so a vendor
    /// section can tighten them (`UPLOAD_MAX_FILE_BYTES`,
    /// `UPLOAD_MAX_TOTAL_BYTES`). The file count is a fixed constant.
    #[must_use]
    pub fn from_config(config: &Config, vendor: &str) -> Self {
        Self {
            max_file_bytes: config.upload_max_file_bytes(vendor),
            max_total_bytes: config.upload_max_total_bytes(vendor),
            max_files: MAX_UPLOAD_FILES,
        }
    }
}

/// One validated, decoded file ready to encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedFile {
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

/// Longest filename accepted, in bytes. Matches the common filesystem
/// limit so a downloaded artifact can always be saved under its own name.
pub const MAX_FILENAME_BYTES: usize = 255;

/// Default part type when the caller gives none and no artifact supplies one.
pub const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

/// Standard alphabet, padding optional: model-generated base64 frequently
/// drops the trailing `=`, and refusing it would only cost a round trip.
const LENIENT_STANDARD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Validate and decode every file in `files` against `limits`.
///
/// Fails on the first problem with a `400`-shaped error naming the file,
/// `413` for a size breach, or `404` for an artifact id that is unknown,
/// expired, or owned by another principal. Nothing is returned partially:
/// a rejected call has cost no upstream request.
pub async fn prepare_files(
    files: &[UploadFileArg],
    limits: &UploadLimits,
) -> Result<Vec<PreparedFile>, McpError> {
    if files.is_empty() {
        return Err(rejected("at least one file is required"));
    }
    if files.len() > limits.max_files {
        return Err(rejected(format!(
            "{} files supplied; at most {} per call",
            files.len(),
            limits.max_files
        )));
    }

    let mut seen: HashSet<String> = HashSet::with_capacity(files.len());
    let mut prepared = Vec::with_capacity(files.len());
    let mut total: u64 = 0;
    for file in files {
        validate_filename(&file.filename)?;
        // Case-insensitive: two names that differ only by case would map to
        // one artifact on a case-folding store and are a mistake either way.
        if !seen.insert(file.filename.to_lowercase()) {
            return Err(rejected(format!(
                "filename {:?} appears more than once (names are compared case-insensitively)",
                file.filename
            )));
        }

        let (bytes, artifact_type) = match (&file.content_base64, &file.artifact_id) {
            (Some(_), Some(_)) => {
                return Err(rejected(format!(
                    "{:?}: give either contentBase64 or artifactId, not both",
                    file.filename
                )));
            }
            (None, None) => {
                return Err(rejected(format!(
                    "{:?}: contentBase64 or artifactId is required (the server cannot read client-local paths)",
                    file.filename
                )));
            }
            (Some(encoded), None) => (
                decode_inline(&file.filename, encoded, limits.max_file_bytes)?,
                None,
            ),
            (None, Some(id)) => read_artifact(&file.filename, id, limits.max_file_bytes).await?,
        };

        total = total.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if total > limits.max_total_bytes {
            return Err(too_large(format!(
                "decoded upload total exceeds the {} limit",
                describe_bytes(limits.max_total_bytes)
            )));
        }

        let content_type = match file.mime_type.as_deref() {
            Some(explicit) => validate_content_type(&file.filename, explicit)?,
            None => artifact_type.unwrap_or_else(|| DEFAULT_CONTENT_TYPE.to_owned()),
        };
        prepared.push(PreparedFile {
            filename: file.filename.clone(),
            content_type,
            bytes,
        });
    }
    Ok(prepared)
}

/// One path segment that is safe in a URL, in a `Content-Disposition`
/// header, and as a filename on every platform a download lands on.
pub fn validate_filename(name: &str) -> Result<(), McpError> {
    if name.is_empty() {
        return Err(rejected("filename must not be empty"));
    }
    if name.len() > MAX_FILENAME_BYTES {
        return Err(rejected(format!(
            "filename {:?} is longer than {MAX_FILENAME_BYTES} bytes",
            truncate_for_message(name)
        )));
    }
    if name == "." || name == ".." {
        return Err(rejected(format!("filename {name:?} is not a file name")));
    }
    if name.trim() != name {
        return Err(rejected(format!(
            "filename {name:?} has leading or trailing whitespace"
        )));
    }
    if let Some(bad) = name.chars().find(|ch| {
        ch.is_control() || matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    }) {
        return Err(rejected(format!(
            "filename {name:?} contains {bad:?}; use one path segment without / \\ : * ? \" < > | or control characters"
        )));
    }
    Ok(())
}

/// `type/subtype` in printable ASCII, no quoting or parameter separators
/// (a part `Content-Type` is written verbatim into the multipart body).
fn validate_content_type(filename: &str, raw: &str) -> Result<String, McpError> {
    let value = raw.trim();
    let valid = !value.is_empty()
        && value.len() <= 127
        && value.bytes().all(|byte| byte.is_ascii_graphic())
        && !value.contains(['"', '\\', ';', ',', '(', ')'])
        && value.split_once('/').is_some_and(|(kind, subtype)| {
            !kind.is_empty() && !subtype.is_empty() && !subtype.contains('/')
        });
    if !valid {
        return Err(rejected(format!(
            "{filename:?}: mimeType {raw:?} is not a type/subtype media type"
        )));
    }
    Ok(value.to_ascii_lowercase())
}

/// Decode inline base64, refusing before decoding when the encoded length
/// alone proves the file is over the limit.
fn decode_inline(filename: &str, encoded: &str, max_file_bytes: u64) -> Result<Vec<u8>, McpError> {
    if encoded.trim_start().starts_with("data:") {
        return Err(rejected(format!(
            "{filename:?}: contentBase64 must be raw base64, not a data: URL"
        )));
    }
    // Wrapped base64 (line breaks every 76 characters) is common; the
    // decoder itself rejects whitespace, so strip it in one pass first.
    let compact: Vec<u8> = encoded
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if compact.is_empty() {
        return Err(rejected(format!("{filename:?}: contentBase64 is empty")));
    }
    let estimate = base64::decoded_len_estimate(compact.len());
    if u64::try_from(estimate).unwrap_or(u64::MAX) > max_file_bytes.saturating_add(2) {
        return Err(file_too_large(filename, max_file_bytes));
    }
    let bytes = LENIENT_STANDARD.decode(&compact).map_err(|error| {
        rejected(format!(
            "{filename:?}: contentBase64 is not valid standard base64 ({error})"
        ))
    })?;
    if bytes.is_empty() {
        return Err(rejected(format!("{filename:?}: decoded content is empty")));
    }
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_file_bytes {
        return Err(file_too_large(filename, max_file_bytes));
    }
    Ok(bytes)
}

/// Read a server-side artifact the current principal owns. The pin is held
/// across the read so a retention sweep cannot reclaim the file underneath
/// it; the artifact's own content type is returned for the caller to use
/// as a default.
async fn read_artifact(
    filename: &str,
    id: &str,
    max_file_bytes: u64,
) -> Result<(Vec<u8>, Option<String>), McpError> {
    let Some(pin) = pin_artifact(id, &OwnerKey::current()) else {
        return Err(api_error(
            format!("{filename:?}: artifact {id:?} not found or expired"),
            Some(404),
            None,
        ));
    };
    let metadata = pin.metadata();
    if metadata.size > max_file_bytes {
        return Err(file_too_large(filename, max_file_bytes));
    }
    if metadata.size == 0 {
        return Err(rejected(format!("{filename:?}: artifact {id:?} is empty")));
    }
    // Bounded by the registered size, which the limit check above vetted.
    let expected =
        usize::try_from(metadata.size).map_err(|_| file_too_large(filename, max_file_bytes))?;
    let mut bytes = Vec::with_capacity(expected);
    let file = tokio::fs::File::open(&metadata.path)
        .await
        .map_err(|error| {
            api_error(
                format!("{filename:?}: artifact {id:?} could not be opened ({error})"),
                Some(404),
                None,
            )
        })?;
    file.take(metadata.size)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| {
            crate::error::unexpected(
                format!("{filename:?}: failed to read artifact {id:?}: {error}"),
                None,
            )
        })?;
    if bytes.len() != expected {
        return Err(crate::error::unexpected(
            format!(
                "{filename:?}: artifact {id:?} is {} bytes on disk but {} were registered",
                bytes.len(),
                metadata.size
            ),
            None,
        ));
    }
    let content_type = metadata
        .content_type
        .split(';')
        .next()
        .map(str::trim)
        .filter(|kind| !kind.is_empty() && kind.contains('/'))
        .map(str::to_ascii_lowercase);
    drop(pin);
    Ok((bytes, content_type))
}

fn rejected(detail: impl Into<String>) -> McpError {
    api_error(
        format!("Upload rejected: {}", detail.into()),
        Some(400),
        None,
    )
}

fn too_large(detail: impl Into<String>) -> McpError {
    api_error(
        format!("Upload rejected: {}", detail.into()),
        Some(413),
        None,
    )
}

fn file_too_large(filename: &str, max_file_bytes: u64) -> McpError {
    too_large(format!(
        "{filename:?} exceeds the {} per-file limit",
        describe_bytes(max_file_bytes)
    ))
}

/// Human-readable size for error text: whole MiB or KiB when exact, bytes
/// otherwise.
pub(crate) fn describe_bytes(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    if bytes >= MIB && bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else if bytes >= KIB && bytes.is_multiple_of(KIB) {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{bytes} bytes")
    }
}

fn truncate_for_message(name: &str) -> String {
    let mut shown: String = name.chars().take(40).collect();
    if shown.len() < name.len() {
        shown.push('…');
    }
    shown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames_are_single_safe_segments() {
        for ok in ["postman.json", "report-2026.09.pdf", "naïve ✓.txt", "a b"] {
            assert!(validate_filename(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            ".",
            "..",
            "../etc",
            "a/b",
            "a\\b",
            "c:d",
            "a*b",
            "a?b",
            "a\"b",
            "<a>",
            "a|b",
            "tab\tname",
            " lead",
            "trail ",
            "nul\0",
        ] {
            assert!(validate_filename(bad).is_err(), "{bad:?}");
        }
        assert!(validate_filename(&"x".repeat(256)).is_err());
        assert!(validate_filename(&"x".repeat(255)).is_ok());
    }

    #[test]
    fn content_types_are_normalised_or_rejected() {
        assert_eq!(
            validate_content_type("f", " Application/JSON ").unwrap(),
            "application/json"
        );
        for bad in [
            "",
            "json",
            "/json",
            "text/",
            "a/b/c",
            "text/plain; x=1",
            "te xt/plain",
        ] {
            assert!(validate_content_type("f", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn describe_bytes_prefers_round_units() {
        assert_eq!(describe_bytes(10 * 1024 * 1024), "10 MiB");
        assert_eq!(describe_bytes(64 * 1024), "64 KiB");
        assert_eq!(describe_bytes(1000), "1000 bytes");
    }
}

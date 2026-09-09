//! Bitbucket repository **Downloads** uploads (`bb_upload`).
//!
//! Target: `POST /2.0/repositories/{workspace}/{repo_slug}/downloads` as a
//! `multipart/form-data` body with one or more `files` fields. The official
//! API reference documents two facts this controller is built around:
//!
//! - a `201` with no body is the success shape, so the result returned to
//!   the caller is assembled here (name, size, download URLs), not parsed
//!   from upstream;
//! - "when a file is uploaded with the same name as an existing artifact,
//!   then the existing file will be replaced" — silently. Collisions are
//!   therefore detected **before** the upload by listing the repository's
//!   artifacts with the cache bypassed, and refused unless the caller
//!   opted into `onConflict: "replace"`. The check is a read followed by a
//!   write, not a transaction: an artifact created by someone else between
//!   the two is still replaced. That window is stated in the tool text.
//!
//! This is the Downloads API only. Pull-request attachments are a
//! different Bitbucket surface with a different API and are not assumed to
//! behave like this.
//!
//! No automatic retry anywhere on this path. A `429`, `403`, or `4xx` is
//! returned as the typed error the vendor classifier produces; a timeout,
//! connection failure, or `5xx` after the body was sent is reported as an
//! *unknown* outcome with the exact listing call to make before retrying,
//! because retrying replaces whatever did land.

use serde::Serialize;
use serde_json::{Value, json};
use tracing::debug;

use crate::auth::Credentials;
use crate::config::VENDOR_BITBUCKET;
use crate::controllers::api::{BitbucketContext, ControllerResponse};
use crate::controllers::upload::{PreparedFile, UploadLimits, prepare_files};
use crate::error::{ErrorKind, McpError, api_error};
use crate::format::{OutputFormat, render};
use crate::tools::args::{ConflictPolicy, UploadArgs};
use crate::transport::multipart::{FilePart, MultipartBody, MultipartRequest, post_multipart};
use crate::transport::{HttpMethod, RequestOptions, ResponseBody, fetch};
use crate::workspace::resolve_default_workspace;

/// Form field Bitbucket reads uploaded files from.
const FILES_FIELD: &str = "files";

/// Web host that serves artifact downloads to browsers (the API host only
/// redirects there).
const WEB_BASE_URL: &str = "https://bitbucket.org";

/// Page size for the collision listing (Bitbucket's maximum).
const LISTING_PAGE_LEN: u32 = 100;

/// Upper bound on listing pages walked for the collision check. Past this
/// the check is refused rather than skipped: a repository with more than
/// 5000 artifacts gets an explicit error, never a blind overwrite.
const MAX_LISTING_PAGES: u32 = 50;

/// One artifact as reported back to the caller.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UploadedArtifact {
    pub name: String,
    pub size: u64,
    pub mime_type: String,
    /// API link: `GET` here answers `302` to the file contents.
    pub download_url: String,
    /// Link for humans and PR comments.
    pub browser_url: String,
    /// `true` when an artifact of the same name existed before this call.
    pub replaced: bool,
}

/// What `bb_upload` reports on success.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DownloadsUploadOutcome {
    pub workspace: String,
    pub repo_slug: String,
    /// Browser page listing every artifact of the repository.
    pub downloads_url: String,
    pub files: Vec<UploadedArtifact>,
}

/// Upload `args.files` to the repository's Downloads section.
pub async fn upload_downloads(
    ctx: &BitbucketContext<'_>,
    args: &UploadArgs,
) -> Result<ControllerResponse, McpError> {
    let handle = ctx.handle();
    validate_segment("repoSlug", &args.repo_slug)?;
    if let Some(explicit) = args.workspace_slug.as_deref()
        && !explicit.is_empty()
    {
        validate_segment("workspaceSlug", explicit)?;
    }

    // Everything that can fail on the caller's input fails here, before a
    // credential is touched or a request is made.
    let limits = UploadLimits::from_config(handle.config, VENDOR_BITBUCKET);
    let files = prepare_files(&args.files, &limits).await?;

    let creds = Credentials::require_for_async(handle.config, handle.vendor.name()).await?;
    let workspace = resolve_workspace(ctx, args.workspace_slug.as_deref()).await?;
    validate_segment("workspaceSlug", &workspace)?;

    let downloads_path = format!("/2.0/repositories/{workspace}/{}/downloads", args.repo_slug);
    let policy = args.on_conflict.unwrap_or_default();
    let existing = existing_artifact_names(ctx, &creds, &downloads_path).await?;
    let colliding: Vec<&str> = files
        .iter()
        .filter(|file| existing.iter().any(|name| name == &file.filename))
        .map(|file| file.filename.as_str())
        .collect();
    if policy == ConflictPolicy::Fail && !colliding.is_empty() {
        return Err(api_error(
            format!(
                "Upload refused: {} already exist(s) in {workspace}/{} Downloads. Bitbucket replaces \
                 same-name artifacts silently, so choose different filenames or pass \
                 onConflict: \"replace\" to overwrite deliberately. Nothing was uploaded.",
                colliding
                    .iter()
                    .map(|name| format!("{name:?}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                args.repo_slug
            ),
            Some(409),
            None,
        ));
    }

    let parts: Vec<FilePart<'_>> = files
        .iter()
        .map(|file| FilePart {
            field: FILES_FIELD,
            filename: &file.filename,
            content_type: &file.content_type,
            bytes: &file.bytes,
        })
        .collect();
    let manifest = manifest(&files, policy);
    let body = MultipartBody::encode(&parts);
    debug!(
        workspace = %workspace,
        repo = %args.repo_slug,
        files = files.len(),
        replacing = colliding.len(),
        encoded_bytes = body.len(),
        "bitbucket downloads: uploading"
    );

    let response = post_multipart(
        handle.client,
        handle.vendor,
        &creds,
        handle.config,
        MultipartRequest {
            path: &downloads_path,
            body,
            headers: &[],
            manifest: Some(&manifest),
        },
    )
    .await
    .map_err(|err| explain_upload_failure(err, &downloads_path))?;

    let base = handle.vendor.base_url(handle.config)?;
    let outcome = build_outcome(&base, workspace, &args.repo_slug, &files, &colliding)?;

    let format = args.output_format.map_or(OutputFormat::Toon, Into::into);
    let value = serde_json::to_value(&outcome)
        .map_err(|error| crate::error::unexpected(error.to_string(), None))?;
    Ok(ControllerResponse {
        content: render(&value, format),
        raw_response_path: response.raw_response_path,
    })
}

/// Assemble the caller-facing result. Bitbucket answers the upload with an
/// empty `201`, so every field here is derived from what was sent.
fn build_outcome(
    base: &str,
    workspace: String,
    repo_slug: &str,
    files: &[PreparedFile],
    colliding: &[&str],
) -> Result<DownloadsUploadOutcome, McpError> {
    let uploaded = files
        .iter()
        .map(|file| {
            Ok(UploadedArtifact {
                name: file.filename.clone(),
                size: u64::try_from(file.bytes.len()).unwrap_or(u64::MAX),
                mime_type: file.content_type.clone(),
                download_url: join_url(
                    base,
                    &[
                        "2.0",
                        "repositories",
                        &workspace,
                        repo_slug,
                        "downloads",
                        &file.filename,
                    ],
                )?,
                browser_url: join_url(
                    WEB_BASE_URL,
                    &[&workspace, repo_slug, "downloads", &file.filename],
                )?,
                replaced: colliding.contains(&file.filename.as_str()),
            })
        })
        .collect::<Result<Vec<_>, McpError>>()?;
    Ok(DownloadsUploadOutcome {
        downloads_url: join_url(WEB_BASE_URL, &[&workspace, repo_slug, "downloads"])?,
        files: uploaded,
        workspace,
        repo_slug: repo_slug.to_owned(),
    })
}

/// Names of every artifact currently in the repository, read fresh.
///
/// Walks `page=1..` rather than following `next` links so the request
/// never leaves the vendor's configured base URL. Every page is fetched
/// with `fresh: true`: a collision decision made from a cached listing
/// would be a decision made from stale data.
async fn existing_artifact_names(
    ctx: &BitbucketContext<'_>,
    creds: &Credentials,
    downloads_path: &str,
) -> Result<Vec<String>, McpError> {
    let handle = ctx.handle();
    let mut names = Vec::new();
    for page in 1..=MAX_LISTING_PAGES {
        let path = format!("{downloads_path}?pagelen={LISTING_PAGE_LEN}&page={page}");
        let response = fetch(
            handle.client,
            handle.vendor,
            creds,
            handle.config,
            &path,
            RequestOptions {
                fresh: true,
                method: Some(HttpMethod::Get),
                ..RequestOptions::default()
            },
        )
        .await
        .map_err(|err| explain_listing_failure(err, downloads_path))?;
        let ResponseBody::Json(value) = &response.data else {
            return Err(api_error(
                format!(
                    "Cannot verify artifact names: GET {downloads_path} did not return JSON. \
                     Nothing was uploaded."
                ),
                Some(502),
                None,
            ));
        };
        let values = value
            .get("values")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                api_error(
                    format!(
                        "Cannot verify artifact names: GET {downloads_path} returned no \
                         `values` array. Nothing was uploaded."
                    ),
                    Some(502),
                    None,
                )
            })?;
        names.extend(
            values
                .iter()
                .filter_map(|artifact| artifact.get("name").and_then(Value::as_str))
                .map(str::to_owned),
        );
        let has_next = value.get("next").and_then(Value::as_str).is_some();
        if values.is_empty() || !has_next {
            return Ok(names);
        }
    }
    Err(api_error(
        format!(
            "Cannot verify artifact names: {downloads_path} holds more than {} artifacts. \
             Delete unused artifacts first, or pass onConflict: \"replace\" only if \
             overwriting is acceptable. Nothing was uploaded.",
            LISTING_PAGE_LEN * MAX_LISTING_PAGES
        ),
        Some(409),
        None,
    ))
}

/// Non-secret upload summary handed to the egress policy in place of a
/// JSON body: names, sizes, and types, never contents.
fn manifest(files: &[PreparedFile], policy: ConflictPolicy) -> Value {
    json!({
        "upload": "bitbucket-downloads",
        "onConflict": match policy {
            ConflictPolicy::Fail => "fail",
            ConflictPolicy::Replace => "replace",
        },
        "files": files
            .iter()
            .map(|file| json!({
                "name": file.filename,
                "size": file.bytes.len(),
                "mimeType": file.content_type,
            }))
            .collect::<Vec<_>>(),
    })
}

/// The listing failed before any upload: say so, and keep the vendor's own
/// classification (permission, not-found, rate limit) intact.
fn explain_listing_failure(mut err: McpError, downloads_path: &str) -> McpError {
    err.message = format!(
        "{} (while listing {downloads_path} to check for name collisions; nothing was uploaded)",
        err.message
    );
    err
}

/// Distinguish a definite refusal from an unknown outcome. The vendor
/// classifier already names permission and rate-limit failures; this adds
/// the one instruction that matters for each: whether a retry is safe.
fn explain_upload_failure(mut err: McpError, downloads_path: &str) -> McpError {
    let status = err.status_code;
    let unknown_outcome = matches!(err.kind, ErrorKind::UnexpectedError)
        || status == Some(408)
        || status.is_some_and(|code| code >= 500);
    if unknown_outcome {
        err.message = format!(
            "Upload outcome unknown: {}. The request may have reached Bitbucket before it \
             failed. Run bb_get on {downloads_path} to see which artifacts exist before \
             retrying; a retry replaces any artifact that did upload.",
            err.message
        );
    } else if status == Some(429) {
        err.message = format!(
            "{}. This tool does not retry automatically; wait for the rate-limit window and \
             call it again (nothing was uploaded).",
            err.message
        );
    } else if status.is_some_and(|code| (400..500).contains(&code)) {
        err.message = format!("{} (nothing was uploaded)", err.message);
    }
    err
}

async fn resolve_workspace(
    ctx: &BitbucketContext<'_>,
    explicit: Option<&str>,
) -> Result<String, McpError> {
    if let Some(slug) = explicit
        && !slug.is_empty()
    {
        return Ok(slug.to_owned());
    }
    resolve_default_workspace(ctx).await.ok_or_else(|| {
        api_error(
            "No default workspace found. Please provide a workspace slug.",
            Some(400),
            None,
        )
    })
}

/// A workspace or repository identifier: a slug (`[A-Za-z0-9._-]`) or a
/// brace-wrapped UUID, as the API accepts for both path parameters. Nothing
/// that could add a segment or a query reaches the URL.
fn validate_segment(what: &str, value: &str) -> Result<(), McpError> {
    let slug = value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'));
    let uuid = value.len() > 2
        && value.starts_with('{')
        && value.ends_with('}')
        && value[1..value.len() - 1]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() || ch == '-');
    if value.is_empty() || value == "." || value == ".." || !(slug || uuid) {
        return Err(api_error(
            format!(
                "Upload rejected: {what} {value:?} must be a slug (letters, digits, '.', '-', '_') \
                 or a {{uuid}}"
            ),
            Some(400),
            None,
        ));
    }
    Ok(())
}

/// `base` plus percent-encoded path segments, so an artifact name with a
/// space or a non-ASCII character yields a link that resolves.
fn join_url(base: &str, segments: &[&str]) -> Result<String, McpError> {
    let mut url = url::Url::parse(base)
        .map_err(|error| crate::error::unexpected(format!("invalid base URL: {error}"), None))?;
    url.path_segments_mut()
        .map_err(|()| crate::error::unexpected("base URL cannot carry a path", None))?
        .pop_if_empty()
        .extend(segments);
    Ok(url.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_accept_slugs_and_braced_uuids_only() {
        for ok in [
            "myteam",
            "project-api",
            "a.b_c",
            "{4f9c5a1e-1234-abcd-0000-ffffffffffff}",
        ] {
            assert!(validate_segment("repoSlug", ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a?b",
            "a#b",
            "{}",
            "{not hex}",
            "a b",
            "{abc",
        ] {
            assert!(validate_segment("repoSlug", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn urls_percent_encode_artifact_names() {
        assert_eq!(
            join_url(
                "https://api.bitbucket.org",
                &[
                    "2.0",
                    "repositories",
                    "ws",
                    "repo",
                    "downloads",
                    "my collection ✓.json"
                ]
            )
            .unwrap(),
            "https://api.bitbucket.org/2.0/repositories/ws/repo/downloads/my%20collection%20%E2%9C%93.json"
        );
        assert_eq!(
            join_url("http://127.0.0.1:9/", &["ws", "repo", "downloads"]).unwrap(),
            "http://127.0.0.1:9/ws/repo/downloads"
        );
    }

    #[test]
    fn failures_after_send_are_reported_as_unknown_outcome() {
        for err in [
            api_error("timeout", Some(408), None),
            api_error("service error", Some(503), None),
            crate::error::unexpected("connection reset", None),
        ] {
            let explained = explain_upload_failure(err, "/2.0/repositories/ws/repo/downloads");
            assert!(explained.message.starts_with("Upload outcome unknown"));
            assert!(explained.message.contains("bb_get"));
        }
        let denied = explain_upload_failure(api_error("Permission denied", Some(403), None), "/p");
        assert_eq!(denied.message, "Permission denied (nothing was uploaded)");
        assert_eq!(denied.status_code, Some(403));
        let limited =
            explain_upload_failure(api_error("Rate limit exceeded", Some(429), None), "/p");
        assert!(limited.message.contains("does not retry automatically"));
    }
}

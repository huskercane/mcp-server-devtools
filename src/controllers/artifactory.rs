#![allow(clippy::doc_markdown)]

//! JFrog Artifactory controller path.
//!
//! Five read tools sit on Artifactory's REST API, all authenticated with a
//! static access token (`ARTIFACTORY_TOKEN`) injected as
//! `Authorization: Bearer` via [`Credentials::Bearer`]:
//!
//! - [`list_repositories`] — `GET /api/repositories`: the repositories the
//!   token can see, optionally filtered by class (`local`, `remote`, …) and
//!   package type.
//! - [`search`] — `POST /api/search/aql`: structured filters compiled by
//!   [`build_aql`] into a bounded `items.find(...)` query and sent as a
//!   `text/plain` body (AQL is a POST despite being a read).
//! - [`get_file_info`] — `GET /api/storage/{repo}/{path}`: metadata for a
//!   file (size, checksums, timestamps) or the `children` of a folder.
//! - [`get_build_info`] — `GET /api/build/{name}/{number}`: the published
//!   build information.
//!
//! Every caller-supplied identifier spliced into a path goes through
//! [`crate::controllers::segment`] so a crafted value cannot re-shape the
//! endpoint; every value embedded in AQL is emitted through
//! `serde_json::to_string`, never concatenated raw.
//!
//! Everything after auth — base-URL resolution (including the `/artifactory`
//! context rule), query encoding, transport, error classification, output
//! rendering, raw-response persistence, and JMESPath filtering — is the same
//! code the other vendors use.

use std::fmt::Write as _;

use crate::auth::Credentials;
use crate::config::Config;
use crate::controllers::api::{
    ControllerResponse, HandleContext, dispatch_with_creds, dispatch_with_options,
    normalize_and_append,
};
use crate::controllers::segment::{encode_path, encode_segment, plain_segment, trimmed};
use crate::error::{McpError, api_error};
use crate::format::OutputFormat;
use crate::tools::args::{
    ArtifactoryGetBuildInfoArgs, ArtifactoryGetFileInfoArgs, ArtifactoryListRepositoriesArgs,
    ArtifactorySearchArgs, QueryParams,
};
use crate::transport::{HttpClient, HttpMethod, RequestOptions};
use crate::vendor::artifactory::{
    AQL_SEARCH_PATH, ArtifactoryVendor, BUILD_PATH_PREFIX, REPOSITORIES_PATH, STORAGE_PATH_PREFIX,
};

/// Upper bound on `artifactory_search` results per call. AQL itself accepts
/// any `limit`, but an LLM-facing tool must stay bounded.
pub const SEARCH_LIMIT_MAX: u32 = 500;

/// Default `artifactory_search` result count when `limit` is omitted.
pub const SEARCH_LIMIT_DEFAULT: u32 = 100;

/// Repository classes accepted by `artifactory_list_repositories` (`type`).
const REPO_TYPES: [&str; 5] = ["local", "remote", "virtual", "federated", "distribution"];

/// Item kinds accepted by `artifactory_search` (`type`).
const ITEM_TYPES: [&str; 3] = ["file", "folder", "any"];

/// Sort fields accepted by `artifactory_search` (`sortBy`).
const SORT_FIELDS: [&str; 4] = ["name", "modified", "size", "path"];

/// Fields requested from AQL for every hit. Fixed so the result shape is
/// predictable for the LLM and small enough to stay within token budgets.
const AQL_INCLUDE: &str =
    r#".include("repo","path","name","type","size","modified","created","sha256","actual_sha1")"#;

/// Artifactory-specific request context. Carries the concrete
/// [`ArtifactoryVendor`] (not a `&dyn Vendor`) so the token read can be
/// driven, plus the shared client and config.
pub struct ArtifactoryContext<'a> {
    pub client: &'a HttpClient,
    pub config: &'a Config,
    pub vendor: &'a ArtifactoryVendor,
}

impl<'a> ArtifactoryContext<'a> {
    pub fn new(client: &'a HttpClient, config: &'a Config, vendor: &'a ArtifactoryVendor) -> Self {
        Self {
            client,
            config,
            vendor,
        }
    }
}

/// List repositories, optionally filtered by class and package type. Kept as
/// an `async fn` — there are `?`s (validation, token) before the dispatch
/// await, so the single-tail-await `impl Future` optimisation does not apply.
pub async fn list_repositories(
    ctx: &ArtifactoryContext<'_>,
    args: &ArtifactoryListRepositoriesArgs,
) -> Result<ControllerResponse, McpError> {
    let mut qp = QueryParams::new();
    if let Some(repo_type) = trimmed(args.repo_type.as_ref()) {
        let repo_type = one_of(repo_type, &REPO_TYPES, "type")?;
        qp.insert("type".into(), repo_type.to_owned());
    }
    if let Some(package_type) = trimmed(args.package_type.as_ref()) {
        qp.insert("packageType".into(), package_type.to_ascii_lowercase());
    }

    let token = ctx.vendor.token(ctx.config).await?;
    let creds = Credentials::Bearer { token };
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    let handle = HandleContext::new(ctx.client, ctx.config, ctx.vendor);
    dispatch_with_creds(
        &handle,
        &creds,
        HttpMethod::Get,
        REPOSITORIES_PATH,
        Some(&qp),
        None,
        args.jq.as_deref(),
        fmt,
    )
    .await
}

/// Search items with structured filters compiled to AQL and sent as a
/// `text/plain` POST body. Kept as an `async fn` — the AQL compilation and
/// token resolution both `?` before the dispatch await.
pub async fn search(
    ctx: &ArtifactoryContext<'_>,
    args: &ArtifactorySearchArgs,
) -> Result<ControllerResponse, McpError> {
    let aql = build_aql(args)?;
    let token = ctx.vendor.token(ctx.config).await?;
    let creds = Credentials::Bearer { token };
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    let handle = HandleContext::new(ctx.client, ctx.config, ctx.vendor);
    let normalized = normalize_and_append(ctx.vendor, AQL_SEARCH_PATH, None);
    let opts = RequestOptions {
        method: Some(HttpMethod::Post),
        text_body: Some(aql),
        ..RequestOptions::default()
    };
    dispatch_with_options(&handle, &creds, &normalized, args.jq.as_deref(), fmt, opts).await
}

/// Item storage info for a file or folder. Kept as an `async fn` — the
/// segment validation and token resolution both `?` before the dispatch
/// await.
pub async fn get_file_info(
    ctx: &ArtifactoryContext<'_>,
    args: &ArtifactoryGetFileInfoArgs,
) -> Result<ControllerResponse, McpError> {
    let repo = plain_segment(&args.repo, "repo")?;
    let path = encode_path(&args.path, "path")?;
    let endpoint = format!("{STORAGE_PATH_PREFIX}/{repo}/{path}");

    let token = ctx.vendor.token(ctx.config).await?;
    let creds = Credentials::Bearer { token };
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    let handle = HandleContext::new(ctx.client, ctx.config, ctx.vendor);
    dispatch_with_creds(
        &handle,
        &creds,
        HttpMethod::Get,
        &endpoint,
        None,
        None,
        args.jq.as_deref(),
        fmt,
    )
    .await
}

/// Published build information for one build run. Kept as an `async fn` —
/// the segment validation and token resolution both `?` before the dispatch
/// await.
pub async fn get_build_info(
    ctx: &ArtifactoryContext<'_>,
    args: &ArtifactoryGetBuildInfoArgs,
) -> Result<ControllerResponse, McpError> {
    let name = build_segment(&args.build_name, "buildName")?;
    let number = build_segment(&args.build_number, "buildNumber")?;
    let endpoint = format!(
        "{BUILD_PATH_PREFIX}/{}/{}",
        encode_segment(name),
        encode_segment(number)
    );
    let mut qp = QueryParams::new();
    if let Some(project) = trimmed(args.project.as_ref()) {
        qp.insert("project".into(), project.to_owned());
    }

    let token = ctx.vendor.token(ctx.config).await?;
    let creds = Credentials::Bearer { token };
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    let handle = HandleContext::new(ctx.client, ctx.config, ctx.vendor);
    dispatch_with_creds(
        &handle,
        &creds,
        HttpMethod::Get,
        &endpoint,
        Some(&qp),
        None,
        args.jq.as_deref(),
        fmt,
    )
    .await
}

/// Compile the structured search arguments into one bounded AQL query:
///
/// ```text
/// items.find({"repo":"libs-release","name":{"$match":"*.jar"},"type":"file"})
///      .include("repo","path","name","type","size","modified","created","sha256","actual_sha1")
///      .sort({"$desc":["modified"]})
///      .limit(100)
/// ```
///
/// Rules:
/// - `name` / `path` containing `*` become `{"$match": …}`; otherwise exact.
/// - `type` defaults to `file`; `any` is passed through as AQL's `"any"`.
/// - `modifiedAfter` becomes `"modified": {"$gt": …}`.
/// - `sha256` is lower-cased and must be 64 hex characters.
/// - `limit` defaults to [`SEARCH_LIMIT_DEFAULT`], capped at
///   [`SEARCH_LIMIT_MAX`].
/// - At least one of `repo`, `name`, `path`, `sha256` is required so a call
///   cannot enumerate the whole instance.
///
/// Every user value is emitted via `serde_json::to_string`, so quotes,
/// backslashes and control characters are escaped and cannot break out of
/// the criteria object.
///
/// # Errors
///
/// A 400-shaped [`McpError`] for a missing filter, an unknown enum value, an
/// out-of-range `limit`, a malformed `sha256` / `modifiedAfter`, or
/// `sortOrder` without `sortBy`.
pub fn build_aql(args: &ArtifactorySearchArgs) -> Result<String, McpError> {
    let repo = trimmed(args.repo.as_ref());
    let name = trimmed(args.name.as_ref());
    let path = trimmed(args.path.as_ref()).map(|p| p.trim_matches('/'));
    let sha256 = trimmed(args.sha256.as_ref());

    if repo.is_none() && name.is_none() && path.is_none() && sha256.is_none() {
        return Err(bad_request(
            "At least one of `repo`, `name`, `path`, or `sha256` is required so the \
             search stays bounded.",
        ));
    }

    let item_type = match trimmed(args.item_type.as_ref()) {
        Some(t) => one_of(t, &ITEM_TYPES, "type")?,
        None => "file",
    };
    let limit = args.limit.unwrap_or(SEARCH_LIMIT_DEFAULT);
    if limit == 0 || limit > SEARCH_LIMIT_MAX {
        return Err(bad_request(format!(
            "`limit` must be between 1 and {SEARCH_LIMIT_MAX} (default {SEARCH_LIMIT_DEFAULT})."
        )));
    }
    let sort_by = trimmed(args.sort_by.as_ref())
        .map(|s| one_of(s, &SORT_FIELDS, "sortBy"))
        .transpose()?;
    let sort_order = trimmed(args.sort_order.as_ref())
        .map(|s| one_of(s, &["asc", "desc"], "sortOrder"))
        .transpose()?;
    if sort_order.is_some() && sort_by.is_none() {
        return Err(bad_request("`sortOrder` requires `sortBy`."));
    }
    let sha256 = sha256
        .map(|s| {
            if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
                Ok(s.to_ascii_lowercase())
            } else {
                Err(bad_request("`sha256` must be 64 hexadecimal characters."))
            }
        })
        .transpose()?;
    let modified_after = trimmed(args.modified_after.as_ref())
        .map(|s| {
            if looks_like_iso_date(s) {
                Ok(s)
            } else {
                Err(bad_request(
                    "`modifiedAfter` must be an ISO-8601 timestamp such as \
                     `2024-06-01T00:00:00.000Z`.",
                ))
            }
        })
        .transpose()?;

    // Criteria object, built into one pre-sized buffer. `write!` into a
    // `String` is infallible, so its result is discarded.
    let mut aql = String::with_capacity(256);
    aql.push_str("items.find({");
    let mut first = true;
    let mut criterion = |aql: &mut String, key: &str, value: &str| {
        if !first {
            aql.push(',');
        }
        first = false;
        aql.push_str(key);
        aql.push(':');
        aql.push_str(value);
    };
    if let Some(repo) = repo {
        criterion(&mut aql, "\"repo\"", &quote(repo));
    }
    if let Some(name) = name {
        criterion(&mut aql, "\"name\"", &exact_or_match(name));
    }
    if let Some(path) = path {
        criterion(&mut aql, "\"path\"", &exact_or_match(path));
    }
    criterion(&mut aql, "\"type\"", &quote(item_type));
    if let Some(modified_after) = modified_after {
        let clause = format!("{{\"$gt\":{}}}", quote(modified_after));
        criterion(&mut aql, "\"modified\"", &clause);
    }
    if let Some(sha256) = sha256.as_deref() {
        criterion(&mut aql, "\"sha256\"", &quote(sha256));
    }
    aql.push_str("})");
    aql.push_str(AQL_INCLUDE);
    if let Some(field) = sort_by {
        let direction = if sort_order == Some("desc") {
            "$desc"
        } else {
            "$asc"
        };
        let _ = write!(aql, ".sort({{\"{direction}\":[{}]}})", quote(field));
    }
    let _ = write!(aql, ".limit({limit})");
    Ok(aql)
}

/// `{"$match": "<pattern>"}` when the value carries a `*` wildcard, otherwise
/// the quoted exact value.
fn exact_or_match(value: &str) -> String {
    if value.contains('*') {
        format!("{{\"$match\":{}}}", quote(value))
    } else {
        quote(value)
    }
}

/// JSON-quote a string for embedding in AQL. `serde_json::to_string` on a
/// `&str` cannot fail, but the signature is `Result`, so the fallback keeps
/// the function total without introducing a panic path.
fn quote(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

/// Cheap shape check for `modifiedAfter`: `YYYY-MM-DD` followed by nothing or
/// a `T…` time part. AQL does the real parsing; this only rejects values that
/// are obviously not timestamps (so a typo is caught here, not as an opaque
/// upstream 400).
fn looks_like_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 10 {
        return false;
    }
    let date_ok = bytes[..10].iter().enumerate().all(|(i, b)| match i {
        4 | 7 => *b == b'-',
        _ => b.is_ascii_digit(),
    });
    date_ok && (bytes.len() == 10 || bytes[10] == b'T')
}

/// Validate a case-insensitive enum argument and return its canonical
/// (lower-case) spelling from `allowed`.
fn one_of<'a>(value: &str, allowed: &[&'a str], what: &str) -> Result<&'a str, McpError> {
    allowed
        .iter()
        .copied()
        .find(|candidate| candidate.eq_ignore_ascii_case(value))
        .ok_or_else(|| bad_request(format!("`{what}` must be one of: {}.", allowed.join(", "))))
}

/// A build name / number is one path segment that may legitimately contain
/// spaces and other reserved characters (percent-encoded by the caller), but
/// must not be empty or a dot-segment.
fn build_segment<'a>(raw: &'a str, what: &str) -> Result<&'a str, McpError> {
    let value = raw.trim();
    if value.is_empty() || value == "." || value == ".." {
        return Err(bad_request(format!(
            "`{what}` must be a non-empty build identifier."
        )));
    }
    Ok(value)
}

fn bad_request(message: impl Into<String>) -> McpError {
    api_error(message, Some(400), None)
}

/// Download a repository item as an opaque, checksum-verified artifact.
pub async fn download(
    ctx: &ArtifactoryContext<'_>,
    args: &crate::tools::args::ArtifactoryDownloadArgs,
) -> Result<ControllerResponse, McpError> {
    let repo = plain_segment(&args.repo, "repo")?;
    let path = encode_path(&args.path, "path")?;
    let policy = super::download::policy(args.max_bytes)?;
    let credentials = Credentials::Bearer {
        token: ctx.vendor.token(ctx.config).await?,
    };
    let artifact = crate::transport::fetch_streamed_artifact_with_policy(
        ctx.vendor,
        &credentials,
        ctx.config,
        &format!("/{repo}/{path}"),
        crate::transport::RequestOptions::default(),
        "artifactory-download",
        "bin",
        "application/octet-stream",
        policy,
    )
    .await?;
    Ok(super::download::response(&super::download::metadata(
        &artifact, ctx.config,
    )))
}

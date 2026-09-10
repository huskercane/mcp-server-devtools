//! Figma controller path.
//!
//! Five read tools sit on Figma's REST API, all authenticated with a static
//! personal access token (`FIGMA_TOKEN`) injected as `X-Figma-Token` via
//! [`Credentials::ApiKeyHeader`]:
//!
//! - [`get_file`] — `GET /v1/files/{key}`: the document tree, bounded by
//!   `depth`, plus the file's component/style metadata.
//! - [`get_nodes`] — `GET /v1/files/{key}/nodes?ids=…`: explicit subtrees.
//! - [`list_components`] — `GET /v1/files/{key}/components`: components
//!   published from the file.
//! - [`list_comments`] — `GET /v1/files/{key}/comments`: comment threads.
//!
//! The one piece of domain logic is [`parse_file_key`]: every tool accepts
//! either a bare file key or a Figma URL, and the key is the only
//! caller-supplied value spliced into a path — it is validated to a strict
//! `[A-Za-z0-9]+` alphabet before it gets near the canonicalizer. Node ids
//! travel as a query parameter and are validated by [`parse_node_ids`].
//!
//! Everything after that — base-URL resolution, query encoding, transport,
//! error classification, output rendering, raw-response persistence, and
//! JMESPath filtering — is the same code the other vendors use.

use url::Url;

use crate::auth::Credentials;
use crate::config::Config;
use crate::controllers::api::{ControllerResponse, HandleContext, dispatch_with_creds};
use crate::controllers::segment::trimmed;
use crate::error::{McpError, api_error};
use crate::format::OutputFormat;
use crate::tools::args::{
    FigmaGetFileArgs, FigmaGetNodesArgs, FigmaListCommentsArgs, FigmaListComponentsArgs,
    OutputFormatArg, QueryParams,
};
use crate::transport::{HttpClient, HttpMethod};
use crate::vendor::figma::{
    DEFAULT_DEPTH, FigmaVendor, MAX_DEPTH, MAX_NODE_IDS, TOKEN_HEADER, comments_path,
    components_path, file_path, nodes_path,
};

/// Figma-specific request context. Carries the concrete [`FigmaVendor`] (not
/// a `&dyn Vendor`) so the token read can be driven, plus the shared client
/// and config.
pub struct FigmaContext<'a> {
    pub client: &'a HttpClient,
    pub config: &'a Config,
    pub vendor: &'a FigmaVendor,
}

impl<'a> FigmaContext<'a> {
    pub fn new(client: &'a HttpClient, config: &'a Config, vendor: &'a FigmaVendor) -> Self {
        Self {
            client,
            config,
            vendor,
        }
    }
}

/// Hosts a Figma URL may carry. Anything else is refused rather than guessed
/// at, so a look-alike domain cannot smuggle a key through.
const FIGMA_HOSTS: [&str; 2] = ["www.figma.com", "figma.com"];

/// URL path kinds whose second segment is the file key.
const FIGMA_URL_KINDS: [&str; 4] = ["file", "design", "proto", "board"];

/// Extract and validate a Figma file key from either a bare key or a Figma
/// URL (`https://www.figma.com/(file|design|proto|board)/<key>/...`).
///
/// A file key is an opaque `[A-Za-z0-9]+` token (currently 22 characters,
/// but the length is not something Figma documents, so only the alphabet is
/// enforced). Because the result is spliced straight into `/v1/files/{key}`,
/// the alphabet check is what keeps a crafted value from reshaping the path.
///
/// # Errors
///
/// A 400-shaped [`McpError`] when the value is empty, is a URL on a non-Figma
/// host or of an unrecognised kind, or contains anything outside the key
/// alphabet.
pub fn parse_file_key(raw: &str) -> Result<String, McpError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(invalid_file(
            "`file` must not be empty; pass a Figma file key or a Figma file URL",
        ));
    }
    if value.contains("://") {
        return key_from_url(value);
    }
    if is_file_key(value) {
        Ok(value.to_owned())
    } else {
        Err(invalid_file(
            "`file` must be a Figma file key (letters and digits only, e.g. \
             \"AbC123dEf456GhI789jKl0\") or a Figma file URL such as \
             https://www.figma.com/design/<key>/...",
        ))
    }
}

fn key_from_url(value: &str) -> Result<String, McpError> {
    let parsed = Url::parse(value)
        .map_err(|_| invalid_file("`file` looks like a URL but could not be parsed"))?;
    if parsed.scheme() != "https" {
        return Err(invalid_file("`file` URL must use https"));
    }
    let host = parsed.host_str().unwrap_or_default();
    if !FIGMA_HOSTS.contains(&host) {
        return Err(invalid_file(
            "`file` URL must be on figma.com (https://www.figma.com/design/<key>/...)",
        ));
    }
    let mut segments = parsed.path_segments().into_iter().flatten();
    let kind = segments.next().unwrap_or_default();
    if !FIGMA_URL_KINDS.contains(&kind) {
        return Err(invalid_file(
            "`file` URL must be a Figma file, design, proto, or board URL \
             (https://www.figma.com/design/<key>/...)",
        ));
    }
    let key = segments.next().unwrap_or_default();
    if is_file_key(key) {
        Ok(key.to_owned())
    } else {
        Err(invalid_file(
            "`file` URL does not contain a valid file key after the /design/ (or \
             /file/, /proto/, /board/) segment",
        ))
    }
}

/// True when `value` is non-empty and entirely ASCII letters and digits.
fn is_file_key(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn invalid_file(message: &str) -> McpError {
    api_error(message, Some(400), None)
}

/// Validate a comma-separated list of node ids (`1:2,3:4`) and return it
/// re-joined with single commas and no whitespace. Each id must be non-empty
/// and match `^[0-9A-Za-z:;-]+$`; at most [`MAX_NODE_IDS`] are accepted.
///
/// # Errors
///
/// A 400-shaped [`McpError`] when the list is empty, too long, or any id is
/// malformed.
pub fn parse_node_ids(raw: &str) -> Result<String, McpError> {
    let mut out = String::with_capacity(raw.len());
    let mut count = 0usize;
    for id in raw.split(',').map(str::trim) {
        if id.is_empty() {
            return Err(api_error(
                "`ids` must be a comma-separated list of node ids with no empty entries, \
                 e.g. \"1:2,3:4\"",
                Some(400),
                None,
            ));
        }
        if !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b';' | b'-'))
        {
            return Err(api_error(
                format!(
                    "`ids` entry {id:?} is not a valid Figma node id (letters, digits, \
                     `:`, `;` and `-` only, e.g. \"1:2\")"
                ),
                Some(400),
                None,
            ));
        }
        count += 1;
        if count > MAX_NODE_IDS {
            return Err(api_error(
                format!("`ids` lists more than {MAX_NODE_IDS} node ids; split the request"),
                Some(400),
                None,
            ));
        }
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(id);
    }
    Ok(out)
}

/// Resolve the effective tree depth: [`DEFAULT_DEPTH`] when absent, capped at
/// [`MAX_DEPTH`]. Zero is rejected (Figma requires `depth >= 1`).
///
/// # Errors
///
/// A 400-shaped [`McpError`] for `depth == 0`.
pub fn bounded_depth(depth: Option<u32>) -> Result<u32, McpError> {
    match depth {
        None => Ok(DEFAULT_DEPTH),
        Some(0) => Err(api_error(
            format!("`depth` must be between 1 and {MAX_DEPTH}"),
            Some(400),
            None,
        )),
        Some(d) => Ok(d.min(MAX_DEPTH)),
    }
}

/// Fetch the document tree of a file, bounded by `depth` and optionally
/// restricted to `ids`. Kept as an `async fn` — there are `?`s on the token
/// resolution and argument validation before the dispatch await.
pub async fn get_file(
    ctx: &FigmaContext<'_>,
    args: &FigmaGetFileArgs,
) -> Result<ControllerResponse, McpError> {
    let token = ctx.vendor.token(ctx.config).await?;
    let key = parse_file_key(&args.file)?;
    let depth = bounded_depth(args.depth)?;

    let mut qp = QueryParams::new();
    qp.insert("depth".into(), depth.to_string());
    if let Some(ids) = trimmed(args.ids.as_ref()) {
        qp.insert("ids".into(), parse_node_ids(ids)?);
    }
    if let Some(version) = trimmed(args.version.as_ref()) {
        qp.insert("version".into(), version.to_owned());
    }
    if args.branch_data == Some(true) {
        qp.insert("branch_data".into(), "true".into());
    }

    dispatch(
        ctx,
        token,
        &file_path(&key),
        &qp,
        args.jq.as_deref(),
        args.output_format,
    )
    .await
}

/// Fetch explicit subtrees of a file by node id. Kept as an `async fn` —
/// there are `?`s on the token resolution and argument validation before the
/// dispatch await.
pub async fn get_nodes(
    ctx: &FigmaContext<'_>,
    args: &FigmaGetNodesArgs,
) -> Result<ControllerResponse, McpError> {
    let token = ctx.vendor.token(ctx.config).await?;
    let key = parse_file_key(&args.file)?;
    let depth = bounded_depth(args.depth)?;

    let mut qp = QueryParams::new();
    qp.insert("ids".into(), parse_node_ids(&args.ids)?);
    qp.insert("depth".into(), depth.to_string());
    if let Some(version) = trimmed(args.version.as_ref()) {
        qp.insert("version".into(), version.to_owned());
    }

    dispatch(
        ctx,
        token,
        &nodes_path(&key),
        &qp,
        args.jq.as_deref(),
        args.output_format,
    )
    .await
}

/// List the components published from a file. Kept as an `async fn` — there
/// are `?`s on the token resolution and key validation before the dispatch
/// await.
pub async fn list_components(
    ctx: &FigmaContext<'_>,
    args: &FigmaListComponentsArgs,
) -> Result<ControllerResponse, McpError> {
    let token = ctx.vendor.token(ctx.config).await?;
    let key = parse_file_key(&args.file)?;
    dispatch(
        ctx,
        token,
        &components_path(&key),
        &QueryParams::new(),
        args.jq.as_deref(),
        args.output_format,
    )
    .await
}

/// List a file's comment threads, optionally rendered as Markdown. Kept as an
/// `async fn` — there are `?`s on the token resolution and key validation
/// before the dispatch await.
pub async fn list_comments(
    ctx: &FigmaContext<'_>,
    args: &FigmaListCommentsArgs,
) -> Result<ControllerResponse, McpError> {
    let token = ctx.vendor.token(ctx.config).await?;
    let key = parse_file_key(&args.file)?;
    let mut qp = QueryParams::new();
    if args.as_md == Some(true) {
        qp.insert("as_md".into(), "true".into());
    }
    dispatch(
        ctx,
        token,
        &comments_path(&key),
        &qp,
        args.jq.as_deref(),
        args.output_format,
    )
    .await
}

/// Shared tail: wrap the PAT as an `X-Figma-Token` credential and hand off to
/// the vendor-neutral dispatcher. An `async fn` rather than `impl Future`:
/// `dispatch_with_creds` borrows the credential and handle, so they must live
/// inside the future either way.
async fn dispatch(
    ctx: &FigmaContext<'_>,
    token: String,
    path: &str,
    query: &QueryParams,
    jq: Option<&str>,
    output_format: Option<OutputFormatArg>,
) -> Result<ControllerResponse, McpError> {
    let creds = Credentials::ApiKeyHeader {
        header_name: TOKEN_HEADER.to_owned(),
        key: token,
    };
    let fmt = output_format.map_or(OutputFormat::Toon, Into::into);
    let handle = HandleContext::new(ctx.client, ctx.config, ctx.vendor);
    dispatch_with_creds(
        &handle,
        &creds,
        HttpMethod::Get,
        path,
        Some(query),
        None,
        jq,
        fmt,
    )
    .await
}

/// Render explicit nodes as PNG files, with bounded transfers and metadata-only output.
pub async fn export_images(
    ctx: &FigmaContext<'_>,
    args: &crate::tools::args::FigmaExportImagesArgs,
) -> Result<ControllerResponse, McpError> {
    let key = parse_file_key(&args.file)?;
    let ids = parse_node_ids(&args.ids)?;
    if ids.split(',').count() > 10 {
        return Err(api_error(
            "At most 10 nodes may be exported",
            Some(400),
            None,
        ));
    }
    let scale = args.scale.unwrap_or(1.0);
    if !scale.is_finite() || !(0.01..=4.0).contains(&scale) {
        return Err(api_error(
            "scale must be between 0.01 and 4",
            Some(400),
            None,
        ));
    }
    let mut policy = super::download::policy(args.max_bytes)?;
    policy.aggregate = Some(std::sync::Arc::new(
        crate::transport::StreamingAggregateQuota::new(
            policy.max_encoded_bytes,
            policy.max_decoded_bytes,
        ),
    ));
    let deadline = tokio::time::Instant::now() + policy.total_deadline;
    let credentials = Credentials::ApiKeyHeader {
        header_name: TOKEN_HEADER.to_owned(),
        key: ctx.vendor.token(ctx.config).await?,
    };
    let mut query = QueryParams::new();
    query.insert("ids".into(), ids.clone());
    query.insert("format".into(), "png".into());
    query.insert("scale".into(), scale.to_string());
    if let Some(version) = args.version.as_ref() {
        query.insert("version".into(), version.clone());
    }
    let endpoint = crate::controllers::api::normalize_and_append(
        ctx.vendor,
        &format!("/v1/images/{key}"),
        Some(&query),
    );
    let result = crate::transport::fetch(
        ctx.client,
        ctx.vendor,
        &credentials,
        ctx.config,
        &endpoint,
        crate::transport::RequestOptions {
            fresh: true,
            sensitive_response: true,
            ..Default::default()
        },
    )
    .await?;
    let crate::transport::ResponseBody::Json(body) = result.data else {
        return Err(api_error("Invalid render response", Some(502), None));
    };
    let images = body
        .get("images")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| api_error("Render response has no images", Some(502), None))?;
    let mut results = Vec::with_capacity(ids.split(',').count());
    for id in ids.split(',') {
        let Some(url) = images.get(id).and_then(serde_json::Value::as_str) else {
            results.push(
                serde_json::json!({"nodeId": id, "complete": false, "error": "Render unavailable"}),
            );
            continue;
        };
        policy.total_deadline = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| api_error("Image export exceeded total deadline", Some(408), None))?;
        let artifact = crate::transport::fetch_streamed_url(
            "figma",
            ctx.config,
            url,
            "figma-render",
            "png",
            "image/png",
            policy.clone(),
        )
        .await?;
        if let Err(error) = validate_png(&artifact.artifact.path).await {
            crate::transport::raw_response::remove_artifact(&artifact.artifact.path)
                .await
                .map_err(|_| api_error("Invalid render; cleanup failed", Some(502), None))?;
            return Err(error);
        }
        let mut metadata = super::download::metadata(&artifact, ctx.config);
        metadata["nodeId"] = serde_json::json!(id);
        results.push(metadata);
    }
    Ok(super::download::response(
        &serde_json::json!({"images": results}),
    ))
}

async fn validate_png(path: &std::path::Path) -> Result<(), McpError> {
    use tokio::io::AsyncReadExt as _;
    let mut header = [0_u8; 24];
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|_| api_error("Cannot read render", Some(502), None))?;
    file.read_exact(&mut header)
        .await
        .map_err(|_| api_error("Truncated PNG header", Some(502), None))?;
    if &header[..8] != b"\x89PNG\r\n\x1a\n" || &header[12..16] != b"IHDR" {
        return Err(api_error("Render is not a PNG", Some(415), None));
    }
    let width = u32::from_be_bytes(header[16..20].try_into().expect("four bytes"));
    let height = u32::from_be_bytes(header[20..24].try_into().expect("four bytes"));
    if width == 0
        || height == 0
        || width > 32768
        || height > 32768
        || u64::from(width) * u64::from(height) > 32_000_000
    {
        return Err(api_error(
            "PNG dimensions exceed render limits",
            Some(413),
            None,
        ));
    }
    Ok(())
}

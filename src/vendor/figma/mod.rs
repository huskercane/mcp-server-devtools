//! Figma REST API vendor implementation.
//!
//! Figma's REST API is a single fixed host (`https://api.figma.com`) — there is
//! no self-hosted variant — so unlike SonarQube/TeamCity there is no URL config
//! key; only [`FigmaVendor::with_base_url`] (tests → wiremock) can move it.
//!
//! Authentication is a **personal access token** (`FIGMA_TOKEN`) carried in the
//! custom `X-Figma-Token` header (not `Authorization`), which maps onto
//! [`Credentials::ApiKeyHeader`](crate::auth::Credentials::ApiKeyHeader) the
//! same way Postman's `X-API-Key` does. The token is read from config per
//! request via [`FigmaVendor::token`]; the shared Atlassian resolver is never
//! consulted, and a missing token surfaces as `AuthMissing` at tool-call time
//! so a deployment without Figma still boots.
//!
//! Every endpoint in the first work package is a read under
//! `/v1/files/{file_key}`; the path builders below are the only place that
//! prefix is spelled. The `file_key` they receive has already been validated
//! by the controller ([`crate::controllers::figma::parse_file_key`]) to be a
//! bare `[A-Za-z0-9]+` token, so it can be spliced without further escaping.

pub mod error;

use http::StatusCode;

use crate::config::{Config, VENDOR_FIGMA};
use crate::error::{McpError, auth_missing};
use crate::vendor::Vendor;

/// Production API base. Fixed; [`FigmaVendor::with_base_url`] points tests at
/// a wiremock instead. There is deliberately no config key for it.
pub const DEFAULT_API_BASE: &str = "https://api.figma.com";

/// Header the personal access token is sent under. Figma does not use the
/// `Authorization` header for PATs.
pub const TOKEN_HEADER: &str = "X-Figma-Token";

/// Common prefix of every file-scoped endpoint.
pub const FILES_PATH: &str = "/v1/files";

/// Default `depth` for `GET /v1/files/{key}` and `.../nodes`: the document's
/// pages only (`1`), which keeps the response small. Deeper trees are fetched
/// explicitly.
pub const DEFAULT_DEPTH: u32 = 1;

/// Upper bound on `depth`. A full Figma document tree can run to tens of
/// megabytes; the transport refuses bodies over 10 MiB, so anything past this
/// should go through `figma_get_nodes` on a subtree instead.
pub const MAX_DEPTH: u32 = 4;

/// Upper bound on the number of node ids accepted per `figma_get_nodes` call.
/// Each id fetches a full subtree, so the count is bounded independently of
/// `depth`.
pub const MAX_NODE_IDS: usize = 100;

/// `GET /v1/files/{key}` — the document tree (bounded by `depth`), plus
/// component/style metadata used in the file.
#[must_use]
pub fn file_path(file_key: &str) -> String {
    format!("{FILES_PATH}/{file_key}")
}

/// `GET /v1/files/{key}/nodes` — specific subtrees by node id.
#[must_use]
pub fn nodes_path(file_key: &str) -> String {
    format!("{FILES_PATH}/{file_key}/nodes")
}

/// `GET /v1/files/{key}/components` — components *published* from the file.
#[must_use]
pub fn components_path(file_key: &str) -> String {
    format!("{FILES_PATH}/{file_key}/components")
}

/// `GET /v1/files/{key}/comments` — the file's comment threads.
#[must_use]
pub fn comments_path(file_key: &str) -> String {
    format!("{FILES_PATH}/{file_key}/comments")
}

/// Figma REST API [`Vendor`] strategy.
///
/// Cheap to clone: it holds only an optional base-URL override. There is no
/// token cache — the PAT is static and read from config per request.
#[derive(Debug, Clone, Default)]
pub struct FigmaVendor {
    /// Optional API base override (tests → wiremock). `None` resolves to
    /// [`DEFAULT_API_BASE`].
    base_url_override: Option<String>,
}

impl FigmaVendor {
    /// Production constructor: talks to [`DEFAULT_API_BASE`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the API base (tests → wiremock).
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url_override: Some(base_url.into()),
        }
    }

    /// Resolve the personal access token from the `figma` config section.
    /// This is the Figma credential entry point — the shared Atlassian
    /// resolver is never consulted. Errors with a clear, actionable message at
    /// tool-call time when the token is absent.
    pub async fn token(&self, config: &Config) -> Result<String, McpError> {
        crate::auth::vendor_secret(config, VENDOR_FIGMA, "FIGMA_TOKEN")
            .await?
            .ok_or_else(|| {
                auth_missing(
                    "FIGMA_TOKEN is required for figma_* tools. Set a Figma personal access \
                     token (Settings → Security → Personal access tokens) under the `figma` \
                     section of ~/.mcp/configs.json or in the environment.",
                )
            })
    }
}

impl Vendor for FigmaVendor {
    fn name(&self) -> &'static str {
        VENDOR_FIGMA
    }

    /// The fixed production host unless a test override is set. A trailing
    /// slash is trimmed so the appended `/v1/...` path never produces a double
    /// slash. Infallible: there is no config key to be missing.
    fn base_url(&self, _config: &Config) -> Result<String, McpError> {
        Ok(self
            .base_url_override
            .as_deref()
            .unwrap_or(DEFAULT_API_BASE)
            .trim_end_matches('/')
            .to_owned())
    }

    /// Verbatim passthrough — the controller supplies the full `/v1/...`
    /// path. We only ensure a leading `/`, matching the other single-host
    /// vendors.
    fn normalize_path(&self, path: &str) -> String {
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        }
    }

    fn classify_error(&self, status: StatusCode, body: &str) -> McpError {
        error::classify(status, body)
    }
}

// The field-level doc strings below travel as the JSON Schema descriptions
// published to MCP clients.
#![allow(clippy::doc_markdown)]

//! Argument DTOs for the `artifactory_*` tools.
//!
//! Four read-only tools: repository discovery, structured search (compiled to
//! AQL by the controller), item storage metadata, and build information.
//! Every struct carries `jq` and `outputFormat` so the shared rendering
//! pipeline applies uniformly.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::OutputFormatArg;

/// Arguments for `artifactory_list_repositories`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactoryListRepositoriesArgs {
    /// Repository class to list: `local`, `remote`, `virtual`, `federated`,
    /// or `distribution`. Omit for every repository the token can see.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub repo_type: Option<String>,

    /// Package type filter, e.g. `maven`, `npm`, `docker`, `pypi`, `generic`,
    /// `nuget`, `helm`. Omit for all package types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_type: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "[*].{key: key, type: type, packageType: packageType}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `artifactory_search`. Structured filters that the server
/// compiles into a bounded AQL `items.find(...)` query. At least one of
/// `repo`, `name`, `path`, or `sha256` is required.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactorySearchArgs {
    /// Restrict to one repository by key, e.g. `libs-release-local`. Exact
    /// match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,

    /// Item name (file name) to find, e.g. `my-app-1.4.2.jar`. A value
    /// containing `*` is a wildcard pattern (`*.jar`, `my-app-*`); without
    /// `*` it is an exact match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Folder path inside the repository (no leading slash), e.g.
    /// `com/example/my-app/1.4.2`. A value containing `*` is a wildcard
    /// pattern (`com/example/*`); without `*` it is an exact match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Item kind: `file` (default), `folder`, or `any`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub item_type: Option<String>,

    /// Only items modified after this ISO-8601 timestamp, e.g.
    /// `2024-06-01T00:00:00.000Z`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_after: Option<String>,

    /// Find the item(s) with this exact SHA-256 checksum (64 hex characters).
    /// Useful to locate where a known binary is stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    /// Maximum number of results, 1–500. Default 100. Results beyond the
    /// limit are not returned; narrow the filters or sort to find them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Sort field: `name`, `modified`, `size`, or `path`. Omit for
    /// Artifactory's natural order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<String>,

    /// Sort direction: `asc` (default when `sortBy` is set) or `desc`. Use
    /// `sortBy: "modified", sortOrder: "desc"` for the newest items first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort_order: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "results[*].{repo: repo, path: path, name: name, size: size}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `artifactory_get_file_info`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactoryGetFileInfoArgs {
    /// Repository key, e.g. `libs-release-local`.
    pub repo: String,

    /// Path of the file or folder inside the repository, e.g.
    /// `com/example/my-app/1.4.2/my-app-1.4.2.jar` or `com/example/my-app`.
    /// A leading slash is optional.
    pub path: String,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "{size: size, sha256: checksums.sha256, modified: lastModified}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `artifactory_get_build_info`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactoryGetBuildInfoArgs {
    /// Build name as published to Artifactory, e.g. `my-app-release`. Spaces
    /// are allowed.
    pub build_name: String,

    /// Build number (or build id string), e.g. `142` or `2024.06.01-3`.
    pub build_number: String,

    /// JFrog project key the build belongs to. Omit for the default (global)
    /// project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "buildInfo.modules[*].{id: id, artifacts: artifacts[*].name}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Explicit bounded download; returns an owner-scoped artifact, never inline bytes.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactoryDownloadArgs {
    pub repo: String,
    pub path: String,
    /// Maximum transferred bytes, default 32 MiB, hard maximum 512 MiB.
    pub max_bytes: Option<u64>,
}

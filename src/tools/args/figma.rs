//! Argument DTOs for the `figma_*` tools.
//!
//! Every tool takes a `file` reference — a bare file key or a Figma URL — and
//! the shared `jq` / `outputFormat` pair. The field doc strings travel as the
//! JSON Schema descriptions published to MCP clients, so they are written for
//! an LLM: what the field is, an example, and its constraints.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::OutputFormatArg;

/// Arguments for `figma_get_file`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FigmaGetFileArgs {
    /// The Figma file: either the bare file key (e.g. "AbC123dEf456GhI789jKl0")
    /// or a Figma URL such as
    /// "https://www.figma.com/design/AbC123dEf456GhI789jKl0/My-Design?node-id=1-2".
    /// `file`, `design`, `proto`, and `board` URLs are accepted; the key is
    /// extracted from the URL.
    pub file: String,

    /// How many levels of the document tree to return. Default 1 (pages only);
    /// maximum 4. Each extra level multiplies the response size — for a deep
    /// subtree use `figma_get_nodes` with explicit `ids` instead of raising
    /// this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,

    /// Comma-separated node ids to restrict the document tree to, e.g. "1:2,3:4"
    /// (the `node-id=1-2` in a Figma URL is node "1:2"). Only these nodes, their
    /// ancestors, and their children (to `depth`) are returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ids: Option<String>,

    /// A specific version id from the file's version history. Omit for the
    /// current version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Set true to include branch metadata (`branches[]`) in the response.
    /// Default false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_data: Option<bool>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "document.children[*].{id: id, name: name, type: type}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `figma_get_nodes`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FigmaGetNodesArgs {
    /// The Figma file: either the bare file key (e.g. "AbC123dEf456GhI789jKl0")
    /// or a Figma URL such as
    /// "https://www.figma.com/design/AbC123dEf456GhI789jKl0/My-Design?node-id=1-2".
    pub file: String,

    /// Comma-separated node ids to fetch, e.g. "1:2,3:4". Required. The
    /// `node-id=1-2` in a Figma URL is node "1:2". Ids may contain letters,
    /// digits, `:`, `;` and `-`; at most 100 per call.
    pub ids: String,

    /// How many levels below each requested node to return. Default 1;
    /// maximum 4. Omit for the node and its direct children.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,

    /// A specific version id from the file's version history. Omit for the
    /// current version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "nodes.*.document.{name: name, type: type, children: children[*].name}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `figma_list_components`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FigmaListComponentsArgs {
    /// The Figma file: either the bare file key (e.g. "AbC123dEf456GhI789jKl0")
    /// or a Figma URL such as
    /// "https://www.figma.com/design/AbC123dEf456GhI789jKl0/My-Design".
    pub file: String,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "meta.components[*].{key: key, name: name, node: node_id}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `figma_list_comments`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FigmaListCommentsArgs {
    /// The Figma file: either the bare file key (e.g. "AbC123dEf456GhI789jKl0")
    /// or a Figma URL such as
    /// "https://www.figma.com/design/AbC123dEf456GhI789jKl0/My-Design".
    pub file: String,

    /// Set true to return comment bodies as Markdown (`message` rendered with
    /// Figma's rich-text formatting) instead of plain text. Default false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_md: Option<bool>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "comments[?resolved_at==null].{id: id, by: user.handle, msg: message}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Explicit bounded download; returns an owner-scoped artifact, never inline bytes.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FigmaExportImagesArgs {
    pub file: String,
    /// Comma-separated explicit node IDs; at most 10 per export.
    pub ids: String,
    /// PNG render scale, 0.01 through 4; default 1.
    pub scale: Option<f64>,
    pub version: Option<String>,
    /// Maximum transferred bytes, default 32 MiB, hard maximum 512 MiB.
    pub max_bytes: Option<u64>,
}

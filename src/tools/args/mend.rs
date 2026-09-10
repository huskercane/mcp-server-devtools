//! Argument DTOs for the `mend_*` tools (Mend Platform API 3.0).
//!
//! The organization UUID is never a tool argument — it comes from
//! `MEND_ORG_UUID` in config, so an LLM cannot point the tools at a different
//! organization than the operator configured. Page sizes are bounded by the
//! controller (`limit` 1..=200, default 50).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::OutputFormatArg;

/// Arguments for `mend_list_applications`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MendListApplicationsArgs {
    /// Opaque page cursor from a previous response's `additionalData.cursor`.
    /// Omit for the first page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,

    /// Page size, 1..=200 (default 50). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Free-text filter on the application name, e.g. `payments`. Omit for all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: `response[*].{uuid: uuid, name: name}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `mend_list_projects`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MendListProjectsArgs {
    /// Restrict to the projects of one application (former "product"), by
    /// its UUID as returned by `mend_list_applications`, e.g.
    /// `4c5a1b2e-9d3f-4a6b-8c7d-0e1f2a3b4c5d`. Omit to list every project in
    /// the organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_uuid: Option<String>,

    /// Opaque page cursor from a previous response's `additionalData.cursor`.
    /// Omit for the first page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,

    /// Page size, 1..=200 (default 50). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Free-text filter on the project name, e.g. `api-gateway`. Omit for all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: `response[*].{uuid: uuid, name: name, lastScan: lastScan}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `mend_get_project`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MendGetProjectArgs {
    /// Project UUID as returned by `mend_list_projects`, e.g.
    /// `7f2c9e10-3b4d-4e5f-a6b7-c8d9e0f1a2b3`.
    pub project_uuid: String,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: `response.{name: name, lastScan: lastScan}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `mend_list_findings`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MendListFindingsArgs {
    /// Project UUID as returned by `mend_list_projects`, e.g.
    /// `7f2c9e10-3b4d-4e5f-a6b7-c8d9e0f1a2b3`.
    pub project_uuid: String,

    /// Local page filter: comma-separated severities to include: `critical`, `high`, `medium`,
    /// `low` (case-insensitive), e.g. `critical,high`. Omit for all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,

    /// Local status filter on the returned page, e.g. `ACTIVE`. Omit for all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// Opaque page cursor from a previous response's `additionalData.cursor`.
    /// Omit for the first page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,

    /// Page size, 1..=200 (default 50). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: `response[*].{cve: vulnerability.name, severity: vulnerability.severity, lib: component.name}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

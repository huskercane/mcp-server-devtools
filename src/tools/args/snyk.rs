// The field-level doc strings below travel as the JSON Schema descriptions
// published to MCP clients.
#![allow(clippy::doc_markdown)]

//! Argument DTOs for the `snyk_*` tools.
//!
//! Every org-scoped tool takes an optional `orgId`; when it is omitted the
//! controller falls back to `SNYK_ORG_ID`. List tools share the same
//! cursor-pagination pair (`limit`, `startingAfter`) that Snyk's JSON:API
//! surface exposes as `limit` / `starting_after`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::OutputFormatArg;

/// Arguments for `snyk_list_orgs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnykListOrgsArgs {
    /// Restrict to organizations in one Snyk group (group UUID, e.g.
    /// "0d3728ec-eebf-484d-9c8d-3b6d3b1b7c9a"). Omit for every organization
    /// the token can see.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,

    /// Restrict to the organization with this slug (the URL-safe name shown
    /// in the Snyk UI, e.g. "my-company"). Omit for all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,

    /// Page size, 1-100 (default 20). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Pagination cursor for the next page: the `starting_after` value from
    /// the previous response's `links.next`. Pasting the whole `links.next`
    /// URL is accepted; the cursor is extracted from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starting_after: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "data[*].{id: id, name: attributes.name, slug: attributes.slug}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `snyk_list_projects`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnykListProjectsArgs {
    /// Organization UUID (Snyk UI: Org Settings → General → Organization ID).
    /// Omit to use `SNYK_ORG_ID` from the server configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,

    /// Comma-separated project names to match exactly, e.g.
    /// "my-org/api:package.json,my-org/web:package-lock.json". Omit for all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<String>,

    /// Restrict to projects belonging to one target (target UUID — a target is
    /// the imported repository / container image / cloud account).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,

    /// Comma-separated project types, e.g. "npm,maven,dockerfile,terraformconfig".
    /// Omit for all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<String>,

    /// Comma-separated integration origins, e.g. "github,gitlab,cli,ecr".
    /// Omit for all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origins: Option<String>,

    /// Page size, 1-100 (default 20). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Pagination cursor for the next page: the `starting_after` value from
    /// the previous response's `links.next`. Pasting the whole `links.next`
    /// URL is accepted; the cursor is extracted from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starting_after: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "data[*].{id: id, name: attributes.name, type: attributes.type, origin: attributes.origin}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `snyk_list_issues`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnykListIssuesArgs {
    /// Organization UUID (Snyk UI: Org Settings → General → Organization ID).
    /// Omit to use `SNYK_ORG_ID` from the server configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,

    /// Restrict to issues on one scan item — a project UUID (from
    /// `snyk_list_projects`) or an environment UUID. Requires `scanItemType`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_item_id: Option<String>,

    /// Kind of `scanItemId`: "project" or "environment". Required together
    /// with `scanItemId`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_item_type: Option<String>,

    /// Comma-separated effective severities to include: "low", "medium",
    /// "high", "critical" (e.g. "high,critical"). Omit for all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_severity_level: Option<String>,

    /// Issue status: "open" or "resolved". Omit for both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// Comma-separated issue types, e.g. "package_vulnerability,license,
    /// code,config,cloud". Omit for all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,

    /// `true` for ignored issues only, `false` to exclude ignored issues.
    /// Omit for both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignored: Option<bool>,

    /// Only issues updated after this RFC 3339 timestamp, e.g.
    /// "2026-08-01T00:00:00Z".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_after: Option<String>,

    /// Only issues created after this RFC 3339 timestamp, e.g.
    /// "2026-08-01T00:00:00Z".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_after: Option<String>,

    /// Page size, 1-100 (default 20). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Pagination cursor for the next page: the `starting_after` value from
    /// the previous response's `links.next`. Pasting the whole `links.next`
    /// URL is accepted; the cursor is extracted from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starting_after: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "data[*].{title: attributes.title, severity: attributes.effective_severity_level, pkg: attributes.coordinates[0].representations[0].dependency.package_name}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `snyk_get_project`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnykGetProjectArgs {
    /// Organization UUID (Snyk UI: Org Settings → General → Organization ID).
    /// Omit to use `SNYK_ORG_ID` from the server configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,

    /// Project UUID, e.g. "331ede0a-de94-456f-b788-166caeca58bf" (the `id` of
    /// a `snyk_list_projects` entry).
    pub project_id: String,

    /// Include the related target (repository / image) inline: pass "target".
    /// Omit for the project alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expand: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: always
    /// use this to extract only needed fields and reduce token costs.
    /// Example: "data.attributes.{name: name, type: type, status: status, tags: tags}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

// The field-level doc strings below travel as the JSON Schema descriptions
// published to MCP clients.
#![allow(clippy::doc_markdown)]

//! Argument DTOs for the `sentry_*` tools.
//!
//! Every organization-scoped tool takes `organization?`; the controller
//! resolves it as argument → `SENTRY_ORG` → error. The three list tools take
//! `cursor?` (Sentry's opaque `Link`-header cursor) and return `nextCursor`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::OutputFormatArg;

/// Arguments for `sentry_list_projects`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SentryListProjectsArgs {
    /// Organization slug, e.g. "acme-corp". Omit to use `SENTRY_ORG`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,

    /// Opaque pagination cursor from a previous call's `nextCursor`, e.g.
    /// "1500000000000:100:0". Omit for the first page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,

    /// JMESPath expression applied to the page's `data` array before it is
    /// wrapped with `nextCursor`. IMPORTANT: use this to keep only needed
    /// fields and reduce token costs. Example: "[*].{id: id, slug: slug, platform: platform}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `sentry_search_issues`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SentrySearchIssuesArgs {
    /// Organization slug, e.g. "acme-corp". Omit to use `SENTRY_ORG`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,

    /// Sentry issue search query (the same syntax as the Issues page search
    /// bar), e.g. "is:unresolved level:error release:1.4.2" or
    /// "is:unresolved assigned:me". Defaults to "is:unresolved".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,

    /// Numeric project id to restrict the search to, e.g. "4507000000000001"
    /// (from `sentry_list_projects`). Omit for all projects the token can see.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,

    /// Relative time window, e.g. "24h", "7d", "14d". Omit for Sentry's
    /// default (the organization's retention window).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats_period: Option<String>,

    /// Environment name to filter on, e.g. "production".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,

    /// Sort order: "date" (last seen, default), "new" (first seen), "freq"
    /// (event count), "priority", or "user" (affected users).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,

    /// Page size, 1-100 (default 25). Keep small to reduce token costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,

    /// Opaque pagination cursor from a previous call's `nextCursor`. Omit for
    /// the first page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,

    /// JMESPath expression applied to the page's `data` array before it is
    /// wrapped with `nextCursor`. IMPORTANT: use this to keep only needed
    /// fields and reduce token costs. Example:
    /// "[*].{id: id, title: title, count: count, lastSeen: lastSeen}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `sentry_get_issue`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SentryGetIssueArgs {
    /// Organization slug, e.g. "acme-corp". Omit to use `SENTRY_ORG`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,

    /// Numeric issue id, e.g. "5432109876" (the `id` field from
    /// `sentry_search_issues`, not the short id like "PROJ-1A2").
    pub issue_id: String,

    /// JMESPath expression to filter/transform the response. IMPORTANT: use
    /// this to keep only needed fields and reduce token costs. Example:
    /// "{title: title, culprit: culprit, count: count, firstSeen: firstSeen}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `sentry_get_event`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SentryGetEventArgs {
    /// Organization slug, e.g. "acme-corp". Omit to use `SENTRY_ORG`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,

    /// Numeric issue id the event belongs to, e.g. "5432109876".
    pub issue_id: String,

    /// Which event: "latest" (default), "oldest", or a 32-character
    /// hexadecimal event id, e.g. "a1b2c3d4e5f60718a9b0c1d2e3f40516".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,

    /// JMESPath expression to filter/transform the response. IMPORTANT: event
    /// bodies are large — always narrow them. Examples:
    /// "entries[?type=='exception'].data.values[].{type: type, value: value}"
    /// or "{message: message, tags: tags, contexts: contexts}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

/// Arguments for `sentry_list_releases`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SentryListReleasesArgs {
    /// Organization slug, e.g. "acme-corp". Omit to use `SENTRY_ORG`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,

    /// Filter releases whose version contains this text, e.g. "1.4" or a
    /// commit SHA prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,

    /// Numeric project id to restrict to, e.g. "4507000000000001". Omit for
    /// all projects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,

    /// Sort order: "date" (default), "sessions", "users", "crash_free_users",
    /// or "crash_free_sessions".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,

    /// Opaque pagination cursor from a previous call's `nextCursor`. Omit for
    /// the first page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,

    /// JMESPath expression applied to the page's `data` array before it is
    /// wrapped with `nextCursor`. IMPORTANT: use this to keep only needed
    /// fields and reduce token costs. Example:
    /// "[*].{version: version, dateCreated: dateCreated, newGroups: newGroups}".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jq: Option<String>,

    /// Output format: "toon" (default, 30-60% fewer tokens) or "json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_format: Option<OutputFormatArg>,
}

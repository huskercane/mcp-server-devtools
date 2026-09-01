// Tool descriptions in `descriptions/*.md` are LLM-facing MCP payloads that we
// surface verbatim from the TS reference implementations. Clippy's doc-markdown
// lint is a poor fit here — it would rewrite the prompts we need to keep stable.
#![allow(clippy::doc_markdown)]

//! MCP tool registration for the unified developer-tools surface.
//!
//! [`DevtoolsServer`] hosts the vendor `#[tool_router]` impl blocks on the same
//! handler type, then combines them in an inherent
//! [`DevtoolsServer::tool_router`] so [`#[tool_handler]`](rmcp::tool_handler)
//! sees a single `ToolRouter` containing every tool:
//!
//! - **`bb_*`** (six tools — five generic verbs + `bb_clone`) — Bitbucket
//!   Cloud, ported from `@aashari/mcp-server-atlassian-bitbucket`. Path
//!   normalisation auto-prepends `/2.0`.
//! - **`jira_*`** (five generic verbs) — Jira Cloud, ported from
//!   `@aashari/mcp-server-atlassian-jira`. Paths are passed through
//!   verbatim (callers supply `/rest/api/3/...`). The base URL is derived
//!   per-request from `ATLASSIAN_SITE_NAME`; Bitbucket-only deployments
//!   are unaffected — Jira tools surface a clear configuration error at
//!   tool-call time only when the env var is missing.
//! - **`conf_*`** (five generic verbs) — Confluence Cloud, ported from
//!   `@aashari/mcp-server-atlassian-confluence`. Paths are passed through
//!   verbatim (callers supply `/wiki/api/v2/...` or `/wiki/rest/api/...`).
//!   Same `ATLASSIAN_SITE_NAME`-derived base URL as Jira.

pub mod args;
mod prelude;

mod artifact;
mod bitbucket;
mod circleci;
mod confluence;
mod edx;
mod grafana;
mod jira;
mod newrelic;
mod ninjaone;
#[cfg(feature = "ninjaone-db")]
mod ninjaone_db;
mod postman;
mod slack;
mod sonarqube;
mod splunk;
#[cfg(feature = "wrds")]
mod wrds;
mod zoom;

use std::sync::Arc;

use rmcp::{
    ErrorData as RmcpError, ServerHandler,
    handler::server::router::tool::ToolRouter,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock as Content,
        Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    tool_handler,
};

use crate::bootstrap::{Components, ServerBuilder};
use crate::config::Config;
use crate::constants::{PACKAGE_NAME, VERSION};
use crate::controllers::api::{BitbucketContext, HandleContext};
use crate::controllers::circleci::CircleCiContext;
use crate::controllers::edx::EdxContext;
use crate::controllers::grafana::GrafanaContext;
use crate::controllers::newrelic::NewRelicContext;
use crate::controllers::ninjaone::NinjaOneContext;
#[cfg(feature = "ninjaone-db")]
use crate::controllers::ninjaone_db::NinjaOneDbContext;
use crate::controllers::postman::PostmanContext;
use crate::controllers::slack::SlackContext;
use crate::controllers::sonarqube::SonarqubeContext;
use crate::controllers::splunk::SplunkContext;
#[cfg(feature = "wrds")]
use crate::controllers::wrds::WrdsContext;
use crate::controllers::zoom::ZoomContext;
use crate::error::format_error_for_mcp_tool;
use crate::format::truncation::truncate_for_ai;
#[derive(Clone)]
pub struct DevtoolsServer {
    components: Arc<Components>,
    // The `#[tool_handler]` macro references this field by name at expansion
    // time; the rustc reference tracker doesn't see that, so we silence the
    // dead-code lint explicitly.
    #[allow(dead_code)]
    tool_router: ToolRouter<DevtoolsServer>,
}

impl DevtoolsServer {
    /// Standard constructor: the environment cascade, a fresh HTTP client, the
    /// default vendor set, and the live config watcher.
    ///
    /// Vendors are constructed eagerly but do not resolve their base URLs here
    /// — `JiraVendor` defers the `ATLASSIAN_SITE_NAME` lookup to request time,
    /// so a Bitbucket-only deployment boots without Jira config.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::McpError`] when the HTTP client cannot be built.
    pub fn new() -> Result<Self, crate::error::McpError> {
        ServerBuilder::new().watch_config(true).build()
    }

    /// Adopt an already-assembled dependency graph. This is the seam the
    /// composition root builds through; prefer [`ServerBuilder`] over calling
    /// it directly.
    #[must_use]
    pub fn from_components(components: Arc<Components>) -> Self {
        Self {
            components,
            tool_router: Self::tool_router(),
        }
    }

    /// Combined router that drives `#[tool_handler]`. Stitches together
    /// the three vendor-scoped routers via the `Add` impl on
    /// [`ToolRouter`](rmcp::handler::server::router::tool::ToolRouter).
    /// Naming this method `tool_router` (the macro's default) lets
    /// `#[tool_handler]` find it without a custom `router = …` attr.
    fn tool_router() -> ToolRouter<Self> {
        let router = Self::bitbucket_router()
            + Self::jira_router()
            + Self::confluence_router()
            + Self::zoom_router()
            + Self::circleci_router()
            + Self::artifact_router()
            + Self::slack_router()
            + Self::postman_router()
            + Self::edx_discussion_router()
            + Self::newrelic_router()
            + Self::grafana_router()
            + Self::sonarqube_router()
            + Self::splunk_router();
        let router = router + Self::ninjaone_router();
        // The NinjaOne database tools ride their own feature so a deployment
        // without QA/dev Postgres access drops them and the driver entirely.
        #[cfg(feature = "ninjaone-db")]
        let router = router + Self::ninjaone_db_router();
        // WRDS tools only exist when the `wrds` feature is on (default).
        #[cfg(feature = "wrds")]
        let router = router + Self::wrds_router();
        router
    }

    /// Snapshot the current config. Returns an `Arc` so a tool call costs one
    /// atomic increment instead of deep-cloning the credential maps; `&Arc<Config>`
    /// deref-coerces to the `&Config` every context factory takes.
    fn config(&self) -> Arc<Config> {
        self.components.config()
    }

    fn bitbucket_ctx<'a>(&'a self, config: &'a Config) -> HandleContext<'a> {
        HandleContext::new(
            &self.components.client,
            config,
            &self.components.vendors.bitbucket,
        )
    }

    /// Bitbucket-only typed context for `bb_clone` and any future
    /// Bitbucket-specific operation. Carries the workspace cache so
    /// `resolve_default_workspace` lookups stay scoped to this server
    /// instance.
    fn bitbucket_typed_ctx<'a>(&'a self, config: &'a Config) -> BitbucketContext<'a> {
        BitbucketContext::new(
            &self.components.client,
            config,
            &self.components.vendors.bitbucket,
            &self.components.workspace_cache,
        )
    }

    fn jira_ctx<'a>(&'a self, config: &'a Config) -> HandleContext<'a> {
        HandleContext::new(
            &self.components.client,
            config,
            &self.components.vendors.jira,
        )
    }

    fn confluence_ctx<'a>(&'a self, config: &'a Config) -> HandleContext<'a> {
        HandleContext::new(
            &self.components.client,
            config,
            &self.components.vendors.confluence,
        )
    }

    /// Zoom-specific context. Unlike the Atlassian vendors, Zoom carries its
    /// own credential lifecycle (Server-to-Server OAuth bearer), so it uses a
    /// dedicated [`ZoomContext`] rather than the vendor-neutral
    /// [`HandleContext`].
    fn zoom_ctx<'a>(&'a self, config: &'a Config) -> ZoomContext<'a> {
        ZoomContext::new(
            &self.components.client,
            config,
            &self.components.vendors.zoom,
        )
    }

    /// CircleCI-specific context. Like Zoom, CircleCI carries its own
    /// credential lookup (a static Bearer token from config), so it uses a
    /// dedicated [`CircleCiContext`] rather than the vendor-neutral
    /// [`HandleContext`].
    fn circleci_ctx<'a>(&'a self, config: &'a Config) -> CircleCiContext<'a> {
        CircleCiContext::new(
            &self.components.client,
            config,
            &self.components.vendors.circleci,
        )
    }

    /// Slack-specific context. Like CircleCI, Slack carries its own credential
    /// lookup (a static OAuth token from config), so it uses a dedicated
    /// [`SlackContext`] rather than the vendor-neutral [`HandleContext`].
    fn slack_ctx<'a>(&'a self, config: &'a Config) -> SlackContext<'a> {
        SlackContext::new(
            &self.components.client,
            config,
            &self.components.vendors.slack,
        )
    }

    /// Postman-specific context. Carries its own credential lookup (a static
    /// API key from config) and is the one vendor that authenticates via a
    /// custom `X-API-Key` header, so it uses a dedicated [`PostmanContext`].
    fn postman_ctx<'a>(&'a self, config: &'a Config) -> PostmanContext<'a> {
        PostmanContext::new(
            &self.components.client,
            config,
            &self.components.vendors.postman,
        )
    }

    fn edx_ctx<'a>(&'a self, config: &'a Config) -> EdxContext<'a> {
        EdxContext::new(
            &self.components.client,
            config,
            &self.components.vendors.edx,
        )
    }

    /// New Relic-specific context. Carries its own credential lookup (a static
    /// User API key from config) and authenticates via the custom `API-Key`
    /// header, so it uses a dedicated [`NewRelicContext`].
    fn newrelic_ctx<'a>(&'a self, config: &'a Config) -> NewRelicContext<'a> {
        NewRelicContext::new(
            &self.components.client,
            config,
            &self.components.vendors.newrelic,
        )
    }

    /// Grafana-specific context. Carries its own credential lookup (a static
    /// service-account token from config) and authenticates via
    /// `Authorization: Bearer`, so it uses a dedicated [`GrafanaContext`].
    fn grafana_ctx<'a>(&'a self, config: &'a Config) -> GrafanaContext<'a> {
        GrafanaContext::new(
            &self.components.client,
            config,
            &self.components.vendors.grafana,
        )
    }

    /// SonarQube-specific context. Like CircleCI/Grafana, Sonar carries its own
    /// credential lookup (a static user token from config) and authenticates via
    /// `Authorization: Bearer`, so it uses a dedicated [`SonarqubeContext`].
    fn sonarqube_ctx<'a>(&'a self, config: &'a Config) -> SonarqubeContext<'a> {
        SonarqubeContext::new(
            &self.components.client,
            config,
            &self.components.vendors.sonarqube,
        )
    }

    fn splunk_ctx<'a>(&'a self, config: &'a Config) -> SplunkContext<'a> {
        SplunkContext::new(
            &self.components.client,
            config,
            &self.components.vendors.splunk,
        )
    }

    fn ninjaone_ctx<'a>(&'a self, config: &'a Config) -> NinjaOneContext<'a> {
        NinjaOneContext::new(
            &self.components.client,
            config,
            &self.components.vendors.ninjaone,
        )
    }

    /// WRDS-specific context. WRDS is PostgreSQL, not HTTP, so this context
    /// carries no `reqwest::Client` — just config and the Postgres vendor.
    #[cfg(feature = "wrds")]
    fn wrds_ctx<'a>(&'a self, config: &'a Config) -> WrdsContext<'a> {
        WrdsContext::new(config, &self.components.vendors.wrds)
    }

    /// NinjaOne database context. Like WRDS this is a direct Postgres path, so
    /// it carries config and the vendor only.
    #[cfg(feature = "ninjaone-db")]
    fn ninjaone_db_ctx<'a>(&'a self, config: &'a Config) -> NinjaOneDbContext<'a> {
        NinjaOneDbContext::new(config, &self.components.vendors.ninjaone_db)
    }
}

// ============================================================================
// Bitbucket tools
// ============================================================================

// ============================================================================
// edX discussion tools
// ============================================================================

// ============================================================================
// Jira tools
// ============================================================================

// ============================================================================
// Confluence tools
// ============================================================================

// ============================================================================
// Zoom tools
// ============================================================================

// ============================================================================
// CircleCI tools
// ============================================================================

// ============================================================================
// Slack tools
// ============================================================================

// ============================================================================
// Postman tools
// ============================================================================

// ============================================================================
// New Relic tools
// ============================================================================

// ============================================================================
// Grafana tools
// ============================================================================

// ============================================================================
// SonarQube tools
// ============================================================================

// ============================================================================
// Splunk tools
// ============================================================================

// ============================================================================
// NinjaOne tools
// ============================================================================

// ============================================================================
// WRDS tools (feature = "wrds")
// ============================================================================

#[tool_handler]
impl ServerHandler for DevtoolsServer {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<CallToolResponse, RmcpError> {
        let client = context.client_info();
        let audit = crate::audit::AuditCall::start(
            request.name.as_ref(),
            context.id.to_string(),
            client.as_ref().map(|value| value.name.clone()),
            client.as_ref().map(|value| value.version.clone()),
        );
        let tool_context =
            rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        let result = audit.scope(self.tool_router.call(tool_context)).await;
        let outcome = match &result {
            Ok(CallToolResponse::Complete(value)) if value.is_error == Some(true) => "error",
            Ok(CallToolResponse::Complete(_)) => "success",
            Ok(CallToolResponse::InputRequired(_)) => "input_required",
            Ok(CallToolResponse::Task(_)) => "task_created",
            Ok(_) => "other",
            Err(_) => "protocol_error",
        };
        audit.complete(outcome);
        result
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, RmcpError> {
        let mut tools = self.tool_router.list_all();
        // MCP 2026-07-28 recommends deterministic ordering so clients can
        // reuse prompt caches. The list is build-static and principal-agnostic,
        // making a short public cache safe.
        tools.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(rmcp::model::ListToolsResult::with_all_items(tools)
            .with_ttl_ms(300_000)
            .with_cache_scope(rmcp::model::CacheScope::Public))
    }

    fn get_info(&self) -> ServerInfo {
        let mut implementation = Implementation::default();
        PACKAGE_NAME.clone_into(&mut implementation.name);
        VERSION.clone_into(&mut implementation.version);

        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::LATEST;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = implementation;
        info
    }
}

// ---- helpers ----

pub(crate) fn success_response(resp: &crate::controllers::ControllerResponse) -> CallToolResult {
    let text = truncate_for_ai(&resp.content, resp.raw_response_path.as_deref());
    CallToolResult::success(vec![Content::text(text)])
}

pub(crate) fn error_to_result(err: &crate::error::McpError) -> CallToolResult {
    let formatted = format_error_for_mcp_tool(err);
    let text = formatted
        .content
        .into_iter()
        .next()
        .map_or_else(String::new, |c| c.text);
    CallToolResult::error(vec![Content::text(text)])
}

#[cfg(test)]
mod config_snapshot_tests {
    use std::collections::HashMap;

    use super::*;

    /// Every tool call snapshots the config. That snapshot must be a shared
    /// `Arc`, not a deep copy of the credential maps — 64 tools multiplied by
    /// a `HashMap` + `BTreeMap<String, HashMap>` clone per call is pure waste.
    /// Reverting `config()` to `.clone()` on the inner `Config` fails here.
    #[test]
    fn config_snapshots_share_one_allocation() {
        let mut values = HashMap::new();
        values.insert("ATLASSIAN_API_TOKEN".to_owned(), "tok".to_owned());
        let server = server_with_config(Config::from_map(values));

        let first = server.config();
        let second = server.config();

        assert!(
            Arc::ptr_eq(&first, &second),
            "config() deep-copied the snapshot instead of sharing it"
        );
    }

    fn server_with_config(config: Config) -> DevtoolsServer {
        ServerBuilder::new().config(config).build().unwrap()
    }
}

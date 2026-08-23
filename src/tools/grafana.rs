//! MCP inbound adapter for Grafana.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Split out of `tools::mod`,
//! which had grown to hold every integration at once alongside the server
//! type itself.

use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = grafana_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/grafana_query_logs.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn grafana_query_logs(
        &self,
        Parameters(args): Parameters<GrafanaQueryLogsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_grafana_query_logs(self, &args).await)
    }

    #[doc = include_str!("descriptions/grafana_list_datasources.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn grafana_list_datasources(
        &self,
        Parameters(args): Parameters<GrafanaListDatasourcesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_grafana_list_datasources(self, &args).await)
    }
}

async fn run_grafana_query_logs(
    server: &DevtoolsServer,
    args: &GrafanaQueryLogsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::grafana::query_logs(&server.grafana_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_grafana_list_datasources(
    server: &DevtoolsServer,
    args: &GrafanaListDatasourcesArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::grafana::list_datasources(&server.grafana_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

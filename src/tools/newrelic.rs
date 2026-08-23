//! MCP inbound adapter for New Relic.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Split out of `tools::mod`,
//! which had grown to hold every integration at once alongside the server
//! type itself.

use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = newrelic_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/newrelic_query.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn newrelic_query(
        &self,
        Parameters(args): Parameters<NewRelicQueryArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_newrelic_query(self, &args).await)
    }
}

async fn run_newrelic_query(server: &DevtoolsServer, args: &NewRelicQueryArgs) -> CallToolResult {
    let config = server.config();
    match crate::controllers::newrelic::query(&server.newrelic_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

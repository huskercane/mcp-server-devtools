//! MCP inbound adapter for the NinjaOne QA/dev database tools.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the `run_*`
//! helpers its tools dispatch through, matching the layout every other
//! integration uses.
//!
//! All three tools are read-only by construction — the vendor rejects anything
//! but a single `SELECT`, pins the session read-only, and runs inside a
//! read-only transaction — so each is annotated `read_only_hint`.

use super::prelude::*;

#[cfg(feature = "ninjaone-db")]
#[tool_router(vis = "pub(crate)", router = ninjaone_db_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/ninjaone_db_resolve_division.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn ninjaone_db_resolve_division(
        &self,
        Parameters(args): Parameters<ResolveDivisionArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_resolve_division(self, &args).await)
    }

    #[doc = include_str!("descriptions/ninjaone_db_query_division.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn ninjaone_db_query_division(
        &self,
        Parameters(args): Parameters<QueryDivisionDbArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_query_division_db(self, &args).await)
    }

    #[doc = include_str!("descriptions/ninjaone_db_query_central.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn ninjaone_db_query_central(
        &self,
        Parameters(args): Parameters<QueryCentralDbArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_query_central_db(self, &args).await)
    }
}

#[cfg(feature = "ninjaone-db")]
async fn run_resolve_division(
    server: &DevtoolsServer,
    args: &ResolveDivisionArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::ninjaone_db::resolve_division(&server.ninjaone_db_ctx(&config), args)
        .await
    {
        Ok(response) => success_response(&response),
        Err(error) => error_to_result(&error),
    }
}

#[cfg(feature = "ninjaone-db")]
async fn run_query_division_db(
    server: &DevtoolsServer,
    args: &QueryDivisionDbArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::ninjaone_db::query_division_db(&server.ninjaone_db_ctx(&config), args)
        .await
    {
        Ok(response) => success_response(&response),
        Err(error) => error_to_result(&error),
    }
}

#[cfg(feature = "ninjaone-db")]
async fn run_query_central_db(
    server: &DevtoolsServer,
    args: &QueryCentralDbArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::ninjaone_db::query_central_db(&server.ninjaone_db_ctx(&config), args)
        .await
    {
        Ok(response) => success_response(&response),
        Err(error) => error_to_result(&error),
    }
}

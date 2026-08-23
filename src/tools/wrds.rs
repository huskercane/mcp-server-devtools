//! MCP inbound adapter for WRDS.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Split out of `tools::mod`,
//! which had grown to hold every integration at once alongside the server
//! type itself.

use super::prelude::*;

#[cfg(feature = "wrds")]
#[tool_router(vis = "pub(crate)", router = wrds_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/wrds_query.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn wrds_query(
        &self,
        Parameters(args): Parameters<WrdsQueryArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_wrds_query(self, &args).await)
    }

    #[doc = include_str!("descriptions/wrds_list_libraries.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn wrds_list_libraries(
        &self,
        Parameters(args): Parameters<WrdsListLibrariesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_wrds_list_libraries(self, &args).await)
    }

    #[doc = include_str!("descriptions/wrds_list_tables.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn wrds_list_tables(
        &self,
        Parameters(args): Parameters<WrdsListTablesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_wrds_list_tables(self, &args).await)
    }

    #[doc = include_str!("descriptions/wrds_describe_table.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn wrds_describe_table(
        &self,
        Parameters(args): Parameters<WrdsDescribeTableArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_wrds_describe_table(self, &args).await)
    }
}

#[cfg(feature = "wrds")]
async fn run_wrds_query(server: &DevtoolsServer, args: &WrdsQueryArgs) -> CallToolResult {
    let config = server.config();
    match crate::controllers::wrds::query(&server.wrds_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

#[cfg(feature = "wrds")]
async fn run_wrds_list_libraries(
    server: &DevtoolsServer,
    args: &WrdsListLibrariesArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::wrds::list_libraries(&server.wrds_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

#[cfg(feature = "wrds")]
async fn run_wrds_list_tables(
    server: &DevtoolsServer,
    args: &WrdsListTablesArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::wrds::list_tables(&server.wrds_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

#[cfg(feature = "wrds")]
async fn run_wrds_describe_table(
    server: &DevtoolsServer,
    args: &WrdsDescribeTableArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::wrds::describe_table(&server.wrds_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

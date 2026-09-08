//! MCP inbound adapter for NinjaOne.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Split out of `tools::mod`,
//! which had grown to hold every integration at once alongside the server
//! type itself.

use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = ninjaone_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/ninjaone_login.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn ninjaone_login(
        &self,
        Parameters(args): Parameters<NinjaOneLoginArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_ninjaone_login(self, &args).await)
    }

    #[doc = include_str!("descriptions/ninjaone_get.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn ninjaone_get(
        &self,
        Parameters(args): Parameters<NinjaOneReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_read_ninjaone(self, HttpMethod::Get, &args).await)
    }

    #[doc = include_str!("descriptions/ninjaone_post.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn ninjaone_post(
        &self,
        Parameters(args): Parameters<NinjaOneWriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_ninjaone(self, HttpMethod::Post, &args).await)
    }

    #[doc = include_str!("descriptions/ninjaone_put.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn ninjaone_put(
        &self,
        Parameters(args): Parameters<NinjaOneWriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_ninjaone(self, HttpMethod::Put, &args).await)
    }

    #[doc = include_str!("descriptions/ninjaone_patch.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn ninjaone_patch(
        &self,
        Parameters(args): Parameters<NinjaOneWriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_ninjaone(self, HttpMethod::Patch, &args).await)
    }

    #[doc = include_str!("descriptions/ninjaone_delete.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn ninjaone_delete(
        &self,
        Parameters(args): Parameters<NinjaOneReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_read_ninjaone(self, HttpMethod::Delete, &args).await)
    }
}

async fn run_ninjaone_login(server: &DevtoolsServer, args: &NinjaOneLoginArgs) -> CallToolResult {
    let config = server.config();
    match crate::controllers::ninjaone::login(&server.ninjaone_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_read_ninjaone(
    server: &DevtoolsServer,
    method: HttpMethod,
    args: &NinjaOneReadArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::ninjaone::handle_read(&server.ninjaone_ctx(&config), method, args)
        .await
    {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_write_ninjaone(
    server: &DevtoolsServer,
    method: HttpMethod,
    args: &NinjaOneWriteArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::ninjaone::handle_write(&server.ninjaone_ctx(&config), method, args)
        .await
    {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

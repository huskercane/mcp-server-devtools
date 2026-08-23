//! MCP inbound adapter for Confluence Cloud.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Split out of `tools::mod`,
//! which had grown to hold every integration at once alongside the server
//! type itself.

use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = confluence_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/conf_get.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn conf_get(
        &self,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_read_confluence(self, HttpMethod::Get, &args).await)
    }

    #[doc = include_str!("descriptions/conf_post.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn conf_post(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_confluence(self, HttpMethod::Post, &args).await)
    }

    #[doc = include_str!("descriptions/conf_put.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn conf_put(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_confluence(self, HttpMethod::Put, &args).await)
    }

    #[doc = include_str!("descriptions/conf_patch.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn conf_patch(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_confluence(self, HttpMethod::Patch, &args).await)
    }

    #[doc = include_str!("descriptions/conf_delete.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn conf_delete(
        &self,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_read_confluence(self, HttpMethod::Delete, &args).await)
    }
}

async fn run_read_confluence(
    server: &DevtoolsServer,
    method: HttpMethod,
    args: &ReadArgs,
) -> CallToolResult {
    let config = server.config();
    match handle_read(&server.confluence_ctx(&config), method, args).await {
        Ok(resp) => {
            let text = truncate_for_ai(&resp.content, resp.raw_response_path.as_deref());
            CallToolResult::success(vec![Content::text(text)])
        }
        Err(err) => error_to_result(&err),
    }
}

async fn run_write_confluence(
    server: &DevtoolsServer,
    method: HttpMethod,
    args: &WriteArgs,
) -> CallToolResult {
    let config = server.config();
    match handle_write(&server.confluence_ctx(&config), method, args).await {
        Ok(resp) => {
            let text = truncate_for_ai(&resp.content, resp.raw_response_path.as_deref());
            CallToolResult::success(vec![Content::text(text)])
        }
        Err(err) => error_to_result(&err),
    }
}

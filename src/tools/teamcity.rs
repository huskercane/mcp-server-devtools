//! MCP inbound adapter for TeamCity.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Split out of `tools::mod`,
//! which had grown to hold every integration at once alongside the server
//! type itself.

use super::args::{TeamcityReadArgs, TeamcityWriteArgs};
use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = teamcity_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/teamcity_get.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn teamcity_get(
        &self,
        Parameters(args): Parameters<TeamcityReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_read_teamcity(self, HttpMethod::Get, &args).await)
    }

    #[doc = include_str!("descriptions/teamcity_post.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn teamcity_post(
        &self,
        Parameters(args): Parameters<TeamcityWriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_teamcity(self, HttpMethod::Post, &args).await)
    }

    #[doc = include_str!("descriptions/teamcity_put.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn teamcity_put(
        &self,
        Parameters(args): Parameters<TeamcityWriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_teamcity(self, HttpMethod::Put, &args).await)
    }

    #[doc = include_str!("descriptions/teamcity_delete.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn teamcity_delete(
        &self,
        Parameters(args): Parameters<TeamcityReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_read_teamcity(self, HttpMethod::Delete, &args).await)
    }
}

async fn run_read_teamcity(
    server: &DevtoolsServer,
    method: HttpMethod,
    args: &TeamcityReadArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::teamcity::handle_read(&server.teamcity_ctx(&config), method, args)
        .await
    {
        Ok(resp) => {
            let text = truncate_for_ai(&resp.content, resp.raw_response_path.as_deref());
            CallToolResult::success(vec![Content::text(text)])
        }
        Err(err) => error_to_result(&err),
    }
}

async fn run_write_teamcity(
    server: &DevtoolsServer,
    method: HttpMethod,
    args: &TeamcityWriteArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::teamcity::handle_write(&server.teamcity_ctx(&config), method, args)
        .await
    {
        Ok(resp) => {
            let text = truncate_for_ai(&resp.content, resp.raw_response_path.as_deref());
            CallToolResult::success(vec![Content::text(text)])
        }
        Err(err) => error_to_result(&err),
    }
}

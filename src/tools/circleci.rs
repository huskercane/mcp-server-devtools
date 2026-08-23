//! MCP inbound adapter for CircleCI.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Split out of `tools::mod`,
//! which had grown to hold every integration at once alongside the server
//! type itself.

use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = circleci_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/circleci_get.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn circleci_get(
        &self,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_read_circleci(self, HttpMethod::Get, &args).await)
    }

    #[doc = include_str!("descriptions/circleci_logs.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn circleci_logs(
        &self,
        Parameters(args): Parameters<CircleCiLogsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_circleci_logs(self, &args).await)
    }

    #[doc = include_str!("descriptions/circleci_post.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn circleci_post(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_circleci(self, HttpMethod::Post, &args).await)
    }

    #[doc = include_str!("descriptions/circleci_put.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn circleci_put(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_circleci(self, HttpMethod::Put, &args).await)
    }

    #[doc = include_str!("descriptions/circleci_patch.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn circleci_patch(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_circleci(self, HttpMethod::Patch, &args).await)
    }

    #[doc = include_str!("descriptions/circleci_delete.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn circleci_delete(
        &self,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_read_circleci(self, HttpMethod::Delete, &args).await)
    }
}

async fn run_read_circleci(
    server: &DevtoolsServer,
    method: HttpMethod,
    args: &ReadArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::circleci::handle_read(&server.circleci_ctx(&config), method, args)
        .await
    {
        Ok(resp) => {
            let text = truncate_for_ai(&resp.content, resp.raw_response_path.as_deref());
            CallToolResult::success(vec![Content::text(text)])
        }
        Err(err) => error_to_result(&err),
    }
}

async fn run_write_circleci(
    server: &DevtoolsServer,
    method: HttpMethod,
    args: &WriteArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::circleci::handle_write(&server.circleci_ctx(&config), method, args)
        .await
    {
        Ok(resp) => {
            let text = truncate_for_ai(&resp.content, resp.raw_response_path.as_deref());
            CallToolResult::success(vec![Content::text(text)])
        }
        Err(err) => error_to_result(&err),
    }
}

async fn run_circleci_logs(server: &DevtoolsServer, args: &CircleCiLogsArgs) -> CallToolResult {
    let config = server.config();
    match crate::controllers::circleci::handle_logs(&server.circleci_ctx(&config), args).await {
        Ok(resp) => {
            let text = truncate_for_ai(&resp.content, resp.raw_response_path.as_deref());
            CallToolResult::success(vec![Content::text(text)])
        }
        Err(err) => error_to_result(&err),
    }
}

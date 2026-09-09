//! MCP inbound adapter for Bitbucket Cloud.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Split out of `tools::mod`,
//! which had grown to hold every integration at once alongside the server
//! type itself.

use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = bitbucket_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/bb_get.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn bb_get(
        &self,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_read_bb(self, HttpMethod::Get, &args).await)
    }

    #[doc = include_str!("descriptions/bb_post.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn bb_post(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_bb(self, HttpMethod::Post, &args).await)
    }

    #[doc = include_str!("descriptions/bb_put.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn bb_put(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_bb(self, HttpMethod::Put, &args).await)
    }

    #[doc = include_str!("descriptions/bb_patch.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn bb_patch(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_bb(self, HttpMethod::Patch, &args).await)
    }

    #[doc = include_str!("descriptions/bb_delete.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn bb_delete(
        &self,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_read_bb(self, HttpMethod::Delete, &args).await)
    }

    #[doc = include_str!("descriptions/bb_clone.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn bb_clone(
        &self,
        Parameters(args): Parameters<CloneArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_clone(self, &args).await)
    }

    #[doc = include_str!("descriptions/bb_upload.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn bb_upload(
        &self,
        Parameters(args): Parameters<UploadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_upload(self, &args).await)
    }
}

async fn run_read_bb(
    server: &DevtoolsServer,
    method: HttpMethod,
    args: &ReadArgs,
) -> CallToolResult {
    let config = server.config();
    match handle_read(&server.bitbucket_ctx(&config), method, args).await {
        Ok(resp) => {
            let text = truncate_for_ai(&resp.content, resp.raw_response_path.as_deref());
            CallToolResult::success(vec![Content::text(text)])
        }
        Err(err) => error_to_result(&err),
    }
}

async fn run_write_bb(
    server: &DevtoolsServer,
    method: HttpMethod,
    args: &WriteArgs,
) -> CallToolResult {
    let config = server.config();
    match handle_write(&server.bitbucket_ctx(&config), method, args).await {
        Ok(resp) => {
            let text = truncate_for_ai(&resp.content, resp.raw_response_path.as_deref());
            CallToolResult::success(vec![Content::text(text)])
        }
        Err(err) => error_to_result(&err),
    }
}

async fn run_clone(server: &DevtoolsServer, args: &CloneArgs) -> CallToolResult {
    let config = server.config();
    match handle_clone(
        &server.bitbucket_typed_ctx(&config),
        &SystemCommandRunner,
        args,
    )
    .await
    {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_upload(server: &DevtoolsServer, args: &UploadArgs) -> CallToolResult {
    let config = server.config();
    match upload_downloads(&server.bitbucket_typed_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

//! MCP inbound adapter for Slack.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Split out of `tools::mod`,
//! which had grown to hold every integration at once alongside the server
//! type itself.

use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = slack_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/slack_get.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn slack_get(
        &self,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_read_slack(self, HttpMethod::Get, &args).await)
    }

    #[doc = include_str!("descriptions/slack_post.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn slack_post(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_slack(self, HttpMethod::Post, &args).await)
    }

    #[doc = include_str!("descriptions/slack_put.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn slack_put(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_slack(self, HttpMethod::Put, &args).await)
    }

    #[doc = include_str!("descriptions/slack_patch.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn slack_patch(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_write_slack(self, HttpMethod::Patch, &args).await)
    }

    #[doc = include_str!("descriptions/slack_list_channels.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn slack_list_channels(
        &self,
        Parameters(args): Parameters<SlackListChannelsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(purpose_built(
            crate::controllers::slack::list_channels(&self.slack_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/slack_channel_info.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn slack_channel_info(
        &self,
        Parameters(args): Parameters<SlackChannelInfoArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(purpose_built(
            crate::controllers::slack::channel_info(&self.slack_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/slack_channel_history.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn slack_channel_history(
        &self,
        Parameters(args): Parameters<SlackChannelHistoryArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(purpose_built(
            crate::controllers::slack::channel_history(&self.slack_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/slack_thread_replies.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn slack_thread_replies(
        &self,
        Parameters(args): Parameters<SlackThreadRepliesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(purpose_built(
            crate::controllers::slack::thread_replies(&self.slack_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/slack_search_messages.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn slack_search_messages(
        &self,
        Parameters(args): Parameters<SlackSearchMessagesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(purpose_built(
            crate::controllers::slack::search_messages(&self.slack_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/slack_delete.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn slack_delete(
        &self,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_read_slack(self, HttpMethod::Delete, &args).await)
    }
}

/// Render a purpose-built read's response the way the passthrough tools do.
fn purpose_built(
    result: Result<crate::controllers::api::ControllerResponse, crate::error::McpError>,
) -> CallToolResult {
    match result {
        Ok(resp) => {
            let text = truncate_for_ai(&resp.content, resp.raw_response_path.as_deref());
            CallToolResult::success(vec![Content::text(text)])
        }
        Err(err) => error_to_result(&err),
    }
}

async fn run_read_slack(
    server: &DevtoolsServer,
    method: HttpMethod,
    args: &ReadArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::slack::handle_read(&server.slack_ctx(&config), method, args).await {
        Ok(resp) => {
            let text = truncate_for_ai(&resp.content, resp.raw_response_path.as_deref());
            CallToolResult::success(vec![Content::text(text)])
        }
        Err(err) => error_to_result(&err),
    }
}

async fn run_write_slack(
    server: &DevtoolsServer,
    method: HttpMethod,
    args: &WriteArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::slack::handle_write(&server.slack_ctx(&config), method, args).await {
        Ok(resp) => {
            let text = truncate_for_ai(&resp.content, resp.raw_response_path.as_deref());
            CallToolResult::success(vec![Content::text(text)])
        }
        Err(err) => error_to_result(&err),
    }
}

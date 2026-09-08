//! MCP inbound adapter for edX discussions.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Split out of `tools::mod`,
//! which had grown to hold every integration at once alongside the server
//! type itself.

use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = edx_discussion_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/edx_discussion_course.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn edx_discussion_course(
        &self,
        Parameters(args): Parameters<EdxDiscussionCourseArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_edx_discussion_course(self, &args).await)
    }

    #[doc = include_str!("descriptions/edx_discussion_topics.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn edx_discussion_topics(
        &self,
        Parameters(args): Parameters<EdxDiscussionTopicsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_edx_discussion_topics(self, &args).await)
    }

    #[doc = include_str!("descriptions/edx_discussion_threads.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn edx_discussion_threads(
        &self,
        Parameters(args): Parameters<EdxDiscussionThreadsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_edx_discussion_threads(self, &args).await)
    }

    #[doc = include_str!("descriptions/edx_discussion_thread_create.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn edx_discussion_thread_create(
        &self,
        Parameters(args): Parameters<EdxDiscussionThreadCreateArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_edx_discussion_thread_create(self, &args).await)
    }

    #[doc = include_str!("descriptions/edx_discussion_comments.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn edx_discussion_comments(
        &self,
        Parameters(args): Parameters<EdxDiscussionCommentsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_edx_discussion_comments(self, &args).await)
    }

    #[doc = include_str!("descriptions/edx_discussion_comment_create.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn edx_discussion_comment_create(
        &self,
        Parameters(args): Parameters<EdxDiscussionCommentCreateArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_edx_discussion_comment_create(self, &args).await)
    }
}

async fn run_edx_discussion_course(
    server: &DevtoolsServer,
    args: &EdxDiscussionCourseArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::edx::course(&server.edx_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_edx_discussion_topics(
    server: &DevtoolsServer,
    args: &EdxDiscussionTopicsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::edx::topics(&server.edx_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_edx_discussion_threads(
    server: &DevtoolsServer,
    args: &EdxDiscussionThreadsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::edx::threads(&server.edx_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_edx_discussion_thread_create(
    server: &DevtoolsServer,
    args: &EdxDiscussionThreadCreateArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::edx::create_thread(&server.edx_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_edx_discussion_comments(
    server: &DevtoolsServer,
    args: &EdxDiscussionCommentsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::edx::comments(&server.edx_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_edx_discussion_comment_create(
    server: &DevtoolsServer,
    args: &EdxDiscussionCommentCreateArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::edx::create_comment(&server.edx_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

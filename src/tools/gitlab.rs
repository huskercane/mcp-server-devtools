//! MCP inbound adapter for GitLab.
//!
//! Hosts the `#[tool_router]` impl block for this integration. Each tool is a
//! thin shim: build the request context, call the matching controller
//! function, and convert the outcome with [`finish`]. Everything with any
//! logic in it (identifier validation, pagination bounds, base64 decoding)
//! lives in `controllers::gitlab` so it is testable without an MCP session.

use super::args::{
    GitlabGetFileArgs, GitlabGetIssueArgs, GitlabGetJobTraceArgs, GitlabGetMergeRequestArgs,
    GitlabGetMergeRequestDiffArgs, GitlabListIssuesArgs, GitlabListMergeRequestsArgs,
    GitlabListPipelineJobsArgs, GitlabListPipelinesArgs, GitlabListProjectsArgs,
};
use super::prelude::*;
use crate::controllers::ControllerResponse;
use crate::controllers::gitlab as ctrl;
use crate::error::McpError;

#[tool_router(vis = "pub(crate)", router = gitlab_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/gitlab_list_projects.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn gitlab_list_projects(
        &self,
        Parameters(args): Parameters<GitlabListProjectsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(finish(
            ctrl::list_projects(&self.gitlab_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/gitlab_get_file.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn gitlab_get_file(
        &self,
        Parameters(args): Parameters<GitlabGetFileArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(finish(
            ctrl::get_file(&self.gitlab_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/gitlab_list_merge_requests.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn gitlab_list_merge_requests(
        &self,
        Parameters(args): Parameters<GitlabListMergeRequestsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(finish(
            ctrl::list_merge_requests(&self.gitlab_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/gitlab_get_merge_request.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn gitlab_get_merge_request(
        &self,
        Parameters(args): Parameters<GitlabGetMergeRequestArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(finish(
            ctrl::get_merge_request(&self.gitlab_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/gitlab_get_merge_request_diff.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn gitlab_get_merge_request_diff(
        &self,
        Parameters(args): Parameters<GitlabGetMergeRequestDiffArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(finish(
            ctrl::get_merge_request_diff(&self.gitlab_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/gitlab_list_issues.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn gitlab_list_issues(
        &self,
        Parameters(args): Parameters<GitlabListIssuesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(finish(
            ctrl::list_issues(&self.gitlab_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/gitlab_get_issue.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn gitlab_get_issue(
        &self,
        Parameters(args): Parameters<GitlabGetIssueArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(finish(
            ctrl::get_issue(&self.gitlab_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/gitlab_list_pipelines.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn gitlab_list_pipelines(
        &self,
        Parameters(args): Parameters<GitlabListPipelinesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(finish(
            ctrl::list_pipelines(&self.gitlab_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/gitlab_list_pipeline_jobs.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn gitlab_list_pipeline_jobs(
        &self,
        Parameters(args): Parameters<GitlabListPipelineJobsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(finish(
            ctrl::list_pipeline_jobs(&self.gitlab_ctx(&config), &args).await,
        ))
    }

    #[doc = include_str!("descriptions/gitlab_get_job_trace.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn gitlab_get_job_trace(
        &self,
        Parameters(args): Parameters<GitlabGetJobTraceArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(finish(
            ctrl::get_job_trace(&self.gitlab_ctx(&config), &args).await,
        ))
    }
}

/// Convert a controller outcome into the MCP result: successes are bounded
/// (and spilled to an artifact when large) by `success_response`, errors get
/// the shared error envelope.
fn finish(result: Result<ControllerResponse, McpError>) -> CallToolResult {
    match result {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

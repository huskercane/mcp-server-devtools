//! MCP inbound adapter for GitHub.
//!
//! Hosts the `#[tool_router]` impl block for this integration. Every tool is a
//! read: it builds a `GithubContext`, calls the matching controller function,
//! and turns the result into a `CallToolResult` through the shared
//! `success_response` / `error_to_result` helpers.

use super::args::{
    GithubGetFileArgs, GithubGetIssueArgs, GithubGetPullRequestArgs, GithubGetPullRequestDiffArgs,
    GithubListIssuesArgs, GithubListPullRequestsArgs, GithubListRepositoriesArgs,
    GithubListWorkflowJobsArgs, GithubListWorkflowRunsArgs,
};
use super::prelude::*;
use crate::controllers::github as controller;

/// Build the context, run one controller function, and render the result.
/// A macro rather than a generic fn because each controller function has its
/// own argument type and there is no closure-friendly async trait to unify
/// them without boxing.
macro_rules! run_github {
    ($server:expr, $handler:ident, $args:expr) => {{
        let config = $server.config();
        match controller::$handler(&$server.github_ctx(&config), $args).await {
            Ok(resp) => success_response(&resp),
            Err(err) => error_to_result(&err),
        }
    }};
}

#[tool_router(vis = "pub(crate)", router = github_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/github_get_job_logs.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true
    ))]
    async fn github_get_job_logs(
        &self,
        Parameters(args): Parameters<crate::tools::args::GithubGetJobLogsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(
            match crate::controllers::github::get_job_logs(&self.github_ctx(&config), &args).await {
                Ok(response) => success_response(&response),
                Err(error) => error_to_result(&error),
            },
        )
    }

    #[doc = include_str!("descriptions/github_list_repositories.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn github_list_repositories(
        &self,
        Parameters(args): Parameters<GithubListRepositoriesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_github!(self, list_repositories, &args))
    }

    #[doc = include_str!("descriptions/github_get_file.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn github_get_file(
        &self,
        Parameters(args): Parameters<GithubGetFileArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_github!(self, get_file, &args))
    }

    #[doc = include_str!("descriptions/github_list_pull_requests.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn github_list_pull_requests(
        &self,
        Parameters(args): Parameters<GithubListPullRequestsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_github!(self, list_pull_requests, &args))
    }

    #[doc = include_str!("descriptions/github_get_pull_request.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn github_get_pull_request(
        &self,
        Parameters(args): Parameters<GithubGetPullRequestArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_github!(self, get_pull_request, &args))
    }

    #[doc = include_str!("descriptions/github_get_pull_request_diff.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn github_get_pull_request_diff(
        &self,
        Parameters(args): Parameters<GithubGetPullRequestDiffArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_github!(self, get_pull_request_diff, &args))
    }

    #[doc = include_str!("descriptions/github_list_issues.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn github_list_issues(
        &self,
        Parameters(args): Parameters<GithubListIssuesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_github!(self, list_issues, &args))
    }

    #[doc = include_str!("descriptions/github_get_issue.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn github_get_issue(
        &self,
        Parameters(args): Parameters<GithubGetIssueArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_github!(self, get_issue, &args))
    }

    #[doc = include_str!("descriptions/github_list_workflow_runs.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn github_list_workflow_runs(
        &self,
        Parameters(args): Parameters<GithubListWorkflowRunsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_github!(self, list_workflow_runs, &args))
    }

    #[doc = include_str!("descriptions/github_list_workflow_jobs.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn github_list_workflow_jobs(
        &self,
        Parameters(args): Parameters<GithubListWorkflowJobsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_github!(self, list_workflow_jobs, &args))
    }
}

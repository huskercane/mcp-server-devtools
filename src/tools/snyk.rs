//! MCP inbound adapter for Snyk.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Four read-only tools over the
//! Snyk REST API: organizations, projects, issues, and one project.

use super::args::{SnykGetProjectArgs, SnykListIssuesArgs, SnykListOrgsArgs, SnykListProjectsArgs};
use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = snyk_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/snyk_list_orgs.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn snyk_list_orgs(
        &self,
        Parameters(args): Parameters<SnykListOrgsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_snyk_list_orgs(self, &args).await)
    }

    #[doc = include_str!("descriptions/snyk_list_projects.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn snyk_list_projects(
        &self,
        Parameters(args): Parameters<SnykListProjectsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_snyk_list_projects(self, &args).await)
    }

    #[doc = include_str!("descriptions/snyk_list_issues.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn snyk_list_issues(
        &self,
        Parameters(args): Parameters<SnykListIssuesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_snyk_list_issues(self, &args).await)
    }

    #[doc = include_str!("descriptions/snyk_get_project.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn snyk_get_project(
        &self,
        Parameters(args): Parameters<SnykGetProjectArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_snyk_get_project(self, &args).await)
    }
}

async fn run_snyk_list_orgs(server: &DevtoolsServer, args: &SnykListOrgsArgs) -> CallToolResult {
    let config = server.config();
    match crate::controllers::snyk::list_orgs(&server.snyk_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_snyk_list_projects(
    server: &DevtoolsServer,
    args: &SnykListProjectsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::snyk::list_projects(&server.snyk_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_snyk_list_issues(
    server: &DevtoolsServer,
    args: &SnykListIssuesArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::snyk::list_issues(&server.snyk_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_snyk_get_project(
    server: &DevtoolsServer,
    args: &SnykGetProjectArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::snyk::get_project(&server.snyk_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

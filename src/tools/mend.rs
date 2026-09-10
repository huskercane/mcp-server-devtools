//! MCP inbound adapter for Mend (Platform API 3.0).
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. All four tools are read-only;
//! the organization is fixed by `MEND_ORG_UUID`, so none of them takes an org
//! argument.

use super::args::{
    MendGetProjectArgs, MendListApplicationsArgs, MendListFindingsArgs, MendListProjectsArgs,
};
use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = mend_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/mend_list_applications.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn mend_list_applications(
        &self,
        Parameters(args): Parameters<MendListApplicationsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_mend_list_applications(self, &args).await)
    }

    #[doc = include_str!("descriptions/mend_list_projects.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn mend_list_projects(
        &self,
        Parameters(args): Parameters<MendListProjectsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_mend_list_projects(self, &args).await)
    }

    #[doc = include_str!("descriptions/mend_get_project.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn mend_get_project(
        &self,
        Parameters(args): Parameters<MendGetProjectArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_mend_get_project(self, &args).await)
    }

    #[doc = include_str!("descriptions/mend_list_findings.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn mend_list_findings(
        &self,
        Parameters(args): Parameters<MendListFindingsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_mend_list_findings(self, &args).await)
    }
}

async fn run_mend_list_applications(
    server: &DevtoolsServer,
    args: &MendListApplicationsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::mend::list_applications(&server.mend_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_mend_list_projects(
    server: &DevtoolsServer,
    args: &MendListProjectsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::mend::list_projects(&server.mend_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_mend_get_project(
    server: &DevtoolsServer,
    args: &MendGetProjectArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::mend::get_project(&server.mend_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_mend_list_findings(
    server: &DevtoolsServer,
    args: &MendListFindingsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::mend::list_findings(&server.mend_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

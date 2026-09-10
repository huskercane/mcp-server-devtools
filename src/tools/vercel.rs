//! MCP inbound adapter for Vercel.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. All four tools are reads:
//! project discovery, deployment history, one deployment, and its bounded
//! build/runtime log.

use super::args::{
    VercelGetDeploymentArgs, VercelGetDeploymentLogsArgs, VercelListDeploymentsArgs,
    VercelListProjectsArgs,
};
use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = vercel_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/vercel_list_projects.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn vercel_list_projects(
        &self,
        Parameters(args): Parameters<VercelListProjectsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_vercel_list_projects(self, &args).await)
    }

    #[doc = include_str!("descriptions/vercel_list_deployments.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn vercel_list_deployments(
        &self,
        Parameters(args): Parameters<VercelListDeploymentsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_vercel_list_deployments(self, &args).await)
    }

    #[doc = include_str!("descriptions/vercel_get_deployment.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn vercel_get_deployment(
        &self,
        Parameters(args): Parameters<VercelGetDeploymentArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_vercel_get_deployment(self, &args).await)
    }

    #[doc = include_str!("descriptions/vercel_get_deployment_logs.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn vercel_get_deployment_logs(
        &self,
        Parameters(args): Parameters<VercelGetDeploymentLogsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_vercel_get_deployment_logs(self, &args).await)
    }
}

async fn run_vercel_list_projects(
    server: &DevtoolsServer,
    args: &VercelListProjectsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::vercel::list_projects(&server.vercel_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_vercel_list_deployments(
    server: &DevtoolsServer,
    args: &VercelListDeploymentsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::vercel::list_deployments(&server.vercel_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_vercel_get_deployment(
    server: &DevtoolsServer,
    args: &VercelGetDeploymentArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::vercel::get_deployment(&server.vercel_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_vercel_get_deployment_logs(
    server: &DevtoolsServer,
    args: &VercelGetDeploymentLogsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::vercel::get_deployment_logs(&server.vercel_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

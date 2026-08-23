//! MCP inbound adapter for SonarQube.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Split out of `tools::mod`,
//! which had grown to hold every integration at once alongside the server
//! type itself.

use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = sonarqube_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/sonarqube_quality_gate.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn sonarqube_quality_gate(
        &self,
        Parameters(args): Parameters<SonarqubeQualityGateArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_sonarqube_quality_gate(self, &args).await)
    }

    #[doc = include_str!("descriptions/sonarqube_search_issues.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn sonarqube_search_issues(
        &self,
        Parameters(args): Parameters<SonarqubeSearchIssuesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_sonarqube_search_issues(self, &args).await)
    }

    #[doc = include_str!("descriptions/sonarqube_get.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn sonarqube_get(
        &self,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_sonarqube_get(self, &args).await)
    }
}

async fn run_sonarqube_quality_gate(
    server: &DevtoolsServer,
    args: &SonarqubeQualityGateArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::sonarqube::quality_gate(&server.sonarqube_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_sonarqube_search_issues(
    server: &DevtoolsServer,
    args: &SonarqubeSearchIssuesArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::sonarqube::search_issues(&server.sonarqube_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_sonarqube_get(server: &DevtoolsServer, args: &ReadArgs) -> CallToolResult {
    let config = server.config();
    match crate::controllers::sonarqube::get(&server.sonarqube_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

//! MCP inbound adapter for Splunk.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Split out of `tools::mod`,
//! which had grown to hold every integration at once alongside the server
//! type itself.

use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = splunk_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/splunk_search.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn splunk_search(
        &self,
        Parameters(args): Parameters<SplunkSearchArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_splunk_search(self, &args).await)
    }

    #[doc = include_str!("descriptions/splunk_create_job.md")]
    #[tool(annotations(
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true,
    ))]
    async fn splunk_create_job(
        &self,
        Parameters(args): Parameters<SplunkCreateJobArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_splunk_create_job(self, &args).await)
    }

    #[doc = include_str!("descriptions/splunk_job_results.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn splunk_job_results(
        &self,
        Parameters(args): Parameters<SplunkJobResultsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_splunk_job_results(self, &args).await)
    }

    #[doc = include_str!("descriptions/splunk_list_saved_searches.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn splunk_list_saved_searches(
        &self,
        Parameters(args): Parameters<SplunkListSavedSearchesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_splunk_list_saved_searches(self, &args).await)
    }
}

async fn run_splunk_search(server: &DevtoolsServer, args: &SplunkSearchArgs) -> CallToolResult {
    let config = server.config();
    match crate::controllers::splunk::search(&server.splunk_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_splunk_create_job(
    server: &DevtoolsServer,
    args: &SplunkCreateJobArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::splunk::create_job(&server.splunk_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_splunk_job_results(
    server: &DevtoolsServer,
    args: &SplunkJobResultsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::splunk::job_results(&server.splunk_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_splunk_list_saved_searches(
    server: &DevtoolsServer,
    args: &SplunkListSavedSearchesArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::splunk::list_saved_searches(&server.splunk_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

//! MCP inbound adapter for JFrog Artifactory.
//!
//! Hosts the read-only discovery, structured search, metadata and streamed
//! download tools. Writes remain outside this integration's initial scope.

use super::args::{
    ArtifactoryGetBuildInfoArgs, ArtifactoryGetFileInfoArgs, ArtifactoryListRepositoriesArgs,
    ArtifactorySearchArgs,
};
use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = artifactory_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/artifactory_download.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true
    ))]
    async fn artifactory_download(
        &self,
        Parameters(args): Parameters<crate::tools::args::ArtifactoryDownloadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(
            match crate::controllers::artifactory::download(&self.artifactory_ctx(&config), &args)
                .await
            {
                Ok(response) => success_response(&response),
                Err(error) => error_to_result(&error),
            },
        )
    }

    #[doc = include_str!("descriptions/artifactory_list_repositories.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn artifactory_list_repositories(
        &self,
        Parameters(args): Parameters<ArtifactoryListRepositoriesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_artifactory_list_repositories(self, &args).await)
    }

    #[doc = include_str!("descriptions/artifactory_search.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn artifactory_search(
        &self,
        Parameters(args): Parameters<ArtifactorySearchArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_artifactory_search(self, &args).await)
    }

    #[doc = include_str!("descriptions/artifactory_get_file_info.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn artifactory_get_file_info(
        &self,
        Parameters(args): Parameters<ArtifactoryGetFileInfoArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_artifactory_get_file_info(self, &args).await)
    }

    #[doc = include_str!("descriptions/artifactory_get_build_info.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn artifactory_get_build_info(
        &self,
        Parameters(args): Parameters<ArtifactoryGetBuildInfoArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_artifactory_get_build_info(self, &args).await)
    }
}

async fn run_artifactory_list_repositories(
    server: &DevtoolsServer,
    args: &ArtifactoryListRepositoriesArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::artifactory::list_repositories(&server.artifactory_ctx(&config), args)
        .await
    {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_artifactory_search(
    server: &DevtoolsServer,
    args: &ArtifactorySearchArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::artifactory::search(&server.artifactory_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_artifactory_get_file_info(
    server: &DevtoolsServer,
    args: &ArtifactoryGetFileInfoArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::artifactory::get_file_info(&server.artifactory_ctx(&config), args)
        .await
    {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_artifactory_get_build_info(
    server: &DevtoolsServer,
    args: &ArtifactoryGetBuildInfoArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::artifactory::get_build_info(&server.artifactory_ctx(&config), args)
        .await
    {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

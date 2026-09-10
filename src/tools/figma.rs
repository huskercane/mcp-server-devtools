//! MCP inbound adapter for Figma.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. All four tools are reads on a
//! single Figma file, identified by key or URL.

use super::args::{
    FigmaGetFileArgs, FigmaGetNodesArgs, FigmaListCommentsArgs, FigmaListComponentsArgs,
};
use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = figma_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/figma_export_images.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true
    ))]
    async fn figma_export_images(
        &self,
        Parameters(args): Parameters<crate::tools::args::FigmaExportImagesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(
            match crate::controllers::figma::export_images(&self.figma_ctx(&config), &args).await {
                Ok(response) => success_response(&response),
                Err(error) => error_to_result(&error),
            },
        )
    }

    #[doc = include_str!("descriptions/figma_get_file.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn figma_get_file(
        &self,
        Parameters(args): Parameters<FigmaGetFileArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_figma_get_file(self, &args).await)
    }

    #[doc = include_str!("descriptions/figma_get_nodes.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn figma_get_nodes(
        &self,
        Parameters(args): Parameters<FigmaGetNodesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_figma_get_nodes(self, &args).await)
    }

    #[doc = include_str!("descriptions/figma_list_components.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn figma_list_components(
        &self,
        Parameters(args): Parameters<FigmaListComponentsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_figma_list_components(self, &args).await)
    }

    #[doc = include_str!("descriptions/figma_list_comments.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn figma_list_comments(
        &self,
        Parameters(args): Parameters<FigmaListCommentsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        Ok(run_figma_list_comments(self, &args).await)
    }
}

async fn run_figma_get_file(server: &DevtoolsServer, args: &FigmaGetFileArgs) -> CallToolResult {
    let config = server.config();
    match crate::controllers::figma::get_file(&server.figma_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_figma_get_nodes(server: &DevtoolsServer, args: &FigmaGetNodesArgs) -> CallToolResult {
    let config = server.config();
    match crate::controllers::figma::get_nodes(&server.figma_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_figma_list_components(
    server: &DevtoolsServer,
    args: &FigmaListComponentsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::figma::list_components(&server.figma_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

async fn run_figma_list_comments(
    server: &DevtoolsServer,
    args: &FigmaListCommentsArgs,
) -> CallToolResult {
    let config = server.config();
    match crate::controllers::figma::list_comments(&server.figma_ctx(&config), args).await {
        Ok(resp) => success_response(&resp),
        Err(err) => error_to_result(&err),
    }
}

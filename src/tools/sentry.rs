//! MCP inbound adapter for Sentry.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Five read-only tools; the
//! controller (`controllers::sentry`) owns organization resolution, cursor
//! extraction, and validation.

use super::args::{
    SentryGetEventArgs, SentryGetIssueArgs, SentryListProjectsArgs, SentryListReleasesArgs,
    SentrySearchIssuesArgs,
};
use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = sentry_router)]
impl DevtoolsServer {
    #[doc = include_str!("descriptions/sentry_list_projects.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn sentry_list_projects(
        &self,
        Parameters(args): Parameters<SentryListProjectsArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(
            match crate::controllers::sentry::list_projects(&self.sentry_ctx(&config), &args).await
            {
                Ok(resp) => success_response(&resp),
                Err(err) => error_to_result(&err),
            },
        )
    }

    #[doc = include_str!("descriptions/sentry_search_issues.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn sentry_search_issues(
        &self,
        Parameters(args): Parameters<SentrySearchIssuesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(
            match crate::controllers::sentry::search_issues(&self.sentry_ctx(&config), &args).await
            {
                Ok(resp) => success_response(&resp),
                Err(err) => error_to_result(&err),
            },
        )
    }

    #[doc = include_str!("descriptions/sentry_get_issue.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn sentry_get_issue(
        &self,
        Parameters(args): Parameters<SentryGetIssueArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(
            match crate::controllers::sentry::get_issue(&self.sentry_ctx(&config), &args).await {
                Ok(resp) => success_response(&resp),
                Err(err) => error_to_result(&err),
            },
        )
    }

    #[doc = include_str!("descriptions/sentry_get_event.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn sentry_get_event(
        &self,
        Parameters(args): Parameters<SentryGetEventArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(
            match crate::controllers::sentry::get_event(&self.sentry_ctx(&config), &args).await {
                Ok(resp) => success_response(&resp),
                Err(err) => error_to_result(&err),
            },
        )
    }

    #[doc = include_str!("descriptions/sentry_list_releases.md")]
    #[tool(annotations(
        read_only_hint = true,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true,
    ))]
    async fn sentry_list_releases(
        &self,
        Parameters(args): Parameters<SentryListReleasesArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        let config = self.config();
        Ok(
            match crate::controllers::sentry::list_releases(&self.sentry_ctx(&config), &args).await
            {
                Ok(resp) => success_response(&resp),
                Err(err) => error_to_result(&err),
            },
        )
    }
}

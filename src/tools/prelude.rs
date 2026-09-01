//! Shared imports for the per-integration inbound adapter modules.
//!
//! Each `tools::<integration>` module hosts one `#[tool_router]` impl block for
//! [`DevtoolsServer`] plus the `run_*` helpers those tools dispatch through.
//! They all need the same handful of rmcp types, the shared response helpers,
//! and the argument DTOs, so those are gathered here rather than restated
//! fifteen times.
//!
//! The per-vendor `*Context` types are deliberately absent: they are named only
//! by the context factories on [`DevtoolsServer`], which stay in `tools::mod`.
//! Adapter modules just call `server.<vendor>_ctx(&config)`.
//!
//! A glob import is deliberate: clippy's `wildcard_imports` (pedantic, denied
//! in this crate) exempts paths containing `prelude`, which is exactly the
//! case this module exists to serve.

pub(crate) use rmcp::{
    ErrorData as RmcpError, handler::server::wrapper::Parameters, model::CallToolResult,
    model::ContentBlock as Content, tool, tool_router,
};

pub(crate) use super::{DevtoolsServer, error_to_result, success_response};
pub(crate) use crate::format::truncation::truncate_for_ai;
pub(crate) use crate::shell::SystemCommandRunner;
pub(crate) use crate::transport::HttpMethod;

pub(crate) use crate::controllers::api::{handle_read, handle_write};
pub(crate) use crate::controllers::handle_clone;

pub(crate) use super::args::{
    ArtifactReadArgs, CircleCiLogsArgs, CloneArgs, EdxDiscussionCommentCreateArgs,
    EdxDiscussionCommentsArgs, EdxDiscussionCourseArgs, EdxDiscussionThreadCreateArgs,
    EdxDiscussionThreadsArgs, EdxDiscussionTopicsArgs, GrafanaListDatasourcesArgs,
    GrafanaQueryLogsArgs, NewRelicQueryArgs, NinjaOneLoginArgs, NinjaOneReadArgs,
    NinjaOneWriteArgs, ReadArgs, SonarqubeQualityGateArgs, SonarqubeSearchIssuesArgs,
    SplunkCreateJobArgs, SplunkJobResultsArgs, SplunkListSavedSearchesArgs, SplunkSearchArgs,
    WriteArgs,
};
#[cfg(feature = "ninjaone-db")]
pub(crate) use super::args::{QueryCentralDbArgs, QueryDivisionDbArgs, ResolveDivisionArgs};
#[cfg(feature = "wrds")]
pub(crate) use super::args::{
    WrdsDescribeTableArgs, WrdsListLibrariesArgs, WrdsListTablesArgs, WrdsQueryArgs,
};

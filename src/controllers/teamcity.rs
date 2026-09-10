//! `TeamCity` orchestration through the shared HTTP transport.

use crate::transport::HttpClient;
use serde_json::Value;

use crate::auth::Credentials;
use crate::config::Config;
use crate::controllers::api::{ControllerResponse, HandleContext, dispatch_with_creds};
use crate::error::McpError;
use crate::format::OutputFormat;
use crate::tools::args::{QueryParams, TeamcityReadArgs, TeamcityWriteArgs};
use crate::transport::HttpMethod;
use crate::vendor::teamcity::TeamcityVendor;

/// Teamcity-specific request context. Carries the concrete [`TeamcityVendor`]
/// (not a `&dyn Vendor`) so the token read can be driven, plus the shared client
/// and config.
pub struct TeamcityContext<'a> {
    pub client: &'a HttpClient,
    pub config: &'a Config,
    pub vendor: &'a TeamcityVendor,
}

impl<'a> TeamcityContext<'a> {
    pub fn new(client: &'a HttpClient, config: &'a Config, vendor: &'a TeamcityVendor) -> Self {
        Self {
            client,
            config,
            vendor,
        }
    }
}

/// Resolve the access token, then dispatch the request. Kept as an `async fn` —
/// there is a `?` on the token resolution before the dispatch await, so the
/// single-tail-await `impl Future` optimisation does not apply.
pub async fn handle_request(
    ctx: &TeamcityContext<'_>,
    method: HttpMethod,
    path: &str,
    query_params: Option<&QueryParams>,
    body: Option<Value>,
    jq: Option<&str>,
    output_format: OutputFormat,
) -> Result<ControllerResponse, McpError> {
    let token = ctx.vendor.token(ctx.config).await?;
    let creds = Credentials::Bearer { token };
    let handle = HandleContext::new(ctx.client, ctx.config, ctx.vendor);
    dispatch_with_creds(
        &handle,
        &creds,
        method,
        path,
        query_params,
        body,
        jq,
        output_format,
    )
    .await
}

/// Read-shaped convenience wrapper (no body).
pub async fn handle_read(
    ctx: &TeamcityContext<'_>,
    method: HttpMethod,
    args: &TeamcityReadArgs,
) -> Result<ControllerResponse, McpError> {
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    handle_request(
        ctx,
        method,
        &args.path,
        args.query_params.as_ref(),
        None,
        args.jq.as_deref(),
        fmt,
    )
    .await
}

/// Write-shaped convenience wrapper (POST / PUT).
pub async fn handle_write(
    ctx: &TeamcityContext<'_>,
    method: HttpMethod,
    args: &TeamcityWriteArgs,
) -> Result<ControllerResponse, McpError> {
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    handle_request(
        ctx,
        method,
        &args.path,
        args.query_params.as_ref(),
        Some(args.body.clone()),
        args.jq.as_deref(),
        fmt,
    )
    .await
}

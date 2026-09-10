//! Controller for allowlisted, read-only NinjaOne PostgreSQL tools.

use serde_json::Value;

use crate::config::Config;
use crate::controllers::api::ControllerResponse;
use crate::error::McpError;
use crate::format::{OutputFormat, jmespath::apply_jq_filter, render};
use crate::tools::args::{QueryCentralDbArgs, QueryDivisionDbArgs, ResolveDivisionArgs};
use crate::vendor::ninjaone_db::{NinjaOneDbVendor, clamp_row_limit};

pub struct NinjaOneDbContext<'a> {
    pub config: &'a Config,
    pub vendor: &'a NinjaOneDbVendor,
}

impl<'a> NinjaOneDbContext<'a> {
    pub fn new(config: &'a Config, vendor: &'a NinjaOneDbVendor) -> Self {
        Self { config, vendor }
    }
}

fn respond(data: &Value, jq: Option<&str>, output_format: OutputFormat) -> ControllerResponse {
    let filtered = apply_jq_filter(data, jq);
    ControllerResponse {
        content: render(&filtered, output_format),
        raw_response_path: None,
    }
}

pub async fn resolve_division(
    ctx: &NinjaOneDbContext<'_>,
    args: &ResolveDivisionArgs,
) -> Result<ControllerResponse, McpError> {
    let data = ctx
        .vendor
        .resolve_division(ctx.config, &args.environment, &args.division)
        .await?;
    Ok(respond(
        &data,
        args.jq.as_deref(),
        args.output_format.map_or(OutputFormat::Toon, Into::into),
    ))
}

pub async fn query_division_db(
    ctx: &NinjaOneDbContext<'_>,
    args: &QueryDivisionDbArgs,
) -> Result<ControllerResponse, McpError> {
    let data = ctx
        .vendor
        .query_division(
            ctx.config,
            &args.environment,
            args.db_host.as_deref(),
            &args.db_name,
            &args.sql,
            clamp_row_limit(args.row_limit),
        )
        .await?;
    Ok(respond(
        &data,
        args.jq.as_deref(),
        args.output_format.map_or(OutputFormat::Toon, Into::into),
    ))
}

pub async fn query_central_db(
    ctx: &NinjaOneDbContext<'_>,
    args: &QueryCentralDbArgs,
) -> Result<ControllerResponse, McpError> {
    let data = ctx
        .vendor
        .query_central(
            ctx.config,
            &args.environment,
            &args.sql,
            clamp_row_limit(args.row_limit),
        )
        .await?;
    Ok(respond(
        &data,
        args.jq.as_deref(),
        args.output_format.map_or(OutputFormat::Toon, Into::into),
    ))
}

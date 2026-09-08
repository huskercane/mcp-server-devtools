#![allow(clippy::doc_markdown)]

//! Slack controller path.
//!
//! Slack reads its static OAuth token from config (via
//! [`SlackVendor::token`](crate::vendor::slack::SlackVendor::token)) and injects
//! a [`Credentials::Bearer`] into the shared dispatch path
//! ([`dispatch_with_creds`]) — exactly like CircleCI. Everything after auth —
//! path normalisation, query encoding, transport, error classification (both
//! the non-2xx and the `ok: false` channels), output rendering — is the same
//! code the Atlassian vendors use.
//!
//! The purpose-built read tools (WP B.1: [`list_channels`], [`channel_info`],
//! [`channel_history`], [`thread_replies`], [`search_messages`]) are thin:
//! they validate the channel id against the same predicate the policy
//! extractor uses (`extractors::slack::is_valid_channel_id`), build the
//! query, and go through [`handle_request`]. Enterprise policy sees them
//! through the extractor as channel-scoped reads; the passthrough `slack_get`
//! reaches the same endpoints and is classified the same way.

use reqwest::Client;
use serde_json::Value;

use crate::auth::Credentials;
use crate::config::Config;
use crate::controllers::api::{ControllerResponse, HandleContext, dispatch_with_creds};
use crate::error::McpError;
use crate::format::OutputFormat;
use crate::policy::extractors::slack::{is_valid_channel_id, is_valid_message_ts};
use crate::tools::args::{
    QueryParams, ReadArgs, SlackChannelHistoryArgs, SlackChannelInfoArgs, SlackListChannelsArgs,
    SlackSearchMessagesArgs, SlackThreadRepliesArgs, WriteArgs,
};
use crate::transport::HttpMethod;
use crate::vendor::slack::SlackVendor;

/// Slack-specific request context. Carries the concrete [`SlackVendor`] (not a
/// `&dyn Vendor`) so the token read can be driven, plus the shared client and
/// config.
pub struct SlackContext<'a> {
    pub client: &'a Client,
    pub config: &'a Config,
    pub vendor: &'a SlackVendor,
}

impl<'a> SlackContext<'a> {
    pub fn new(client: &'a Client, config: &'a Config, vendor: &'a SlackVendor) -> Self {
        Self {
            client,
            config,
            vendor,
        }
    }
}

/// Resolve the OAuth token, then dispatch the request. Kept as an `async fn` —
/// there is a `?` on the token resolution before the dispatch await, so the
/// single-tail-await `impl Future` optimisation does not apply.
pub async fn handle_request(
    ctx: &SlackContext<'_>,
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
    ctx: &SlackContext<'_>,
    method: HttpMethod,
    args: &ReadArgs,
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

fn channel_param(channel_id: &str) -> Result<(), McpError> {
    if is_valid_channel_id(channel_id) {
        return Ok(());
    }
    Err(crate::error::api_error(
        "channelId must be a Slack channel id (uppercase letters and digits, 1-64 characters, \
         e.g. C0123ABCDEF); find it with slack_list_channels",
        Some(400),
        None,
    ))
}

fn insert_opt(qp: &mut QueryParams, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        qp.insert(key.to_owned(), value.to_owned());
    }
}

fn insert_num(qp: &mut QueryParams, key: &str, value: Option<u16>) {
    if let Some(value) = value {
        qp.insert(key.to_owned(), value.to_string());
    }
}

fn insert_flag(qp: &mut QueryParams, key: &str, value: Option<bool>) {
    if let Some(value) = value {
        qp.insert(key.to_owned(), value.to_string());
    }
}

/// `slack_list_channels`: `GET /conversations.list`.
pub async fn list_channels(
    ctx: &SlackContext<'_>,
    args: &SlackListChannelsArgs,
) -> Result<ControllerResponse, McpError> {
    let mut qp = QueryParams::new();
    insert_opt(&mut qp, "types", args.types.as_deref());
    insert_flag(&mut qp, "exclude_archived", args.exclude_archived);
    insert_num(&mut qp, "limit", args.limit);
    insert_opt(&mut qp, "cursor", args.cursor.as_deref());
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    handle_request(
        ctx,
        HttpMethod::Get,
        "/conversations.list",
        Some(&qp),
        None,
        args.jq.as_deref(),
        fmt,
    )
    .await
}

/// `slack_channel_info`: `GET /conversations.info?channel=`.
pub async fn channel_info(
    ctx: &SlackContext<'_>,
    args: &SlackChannelInfoArgs,
) -> Result<ControllerResponse, McpError> {
    channel_param(&args.channel_id)?;
    let mut qp = QueryParams::new();
    qp.insert("channel".to_owned(), args.channel_id.clone());
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    handle_request(
        ctx,
        HttpMethod::Get,
        "/conversations.info",
        Some(&qp),
        None,
        args.jq.as_deref(),
        fmt,
    )
    .await
}

/// `slack_channel_history`: `GET /conversations.history?channel=`.
pub async fn channel_history(
    ctx: &SlackContext<'_>,
    args: &SlackChannelHistoryArgs,
) -> Result<ControllerResponse, McpError> {
    channel_param(&args.channel_id)?;
    let mut qp = QueryParams::new();
    qp.insert("channel".to_owned(), args.channel_id.clone());
    insert_opt(&mut qp, "oldest", args.oldest.as_deref());
    insert_opt(&mut qp, "latest", args.latest.as_deref());
    insert_flag(&mut qp, "inclusive", args.inclusive);
    insert_num(&mut qp, "limit", args.limit);
    insert_opt(&mut qp, "cursor", args.cursor.as_deref());
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    handle_request(
        ctx,
        HttpMethod::Get,
        "/conversations.history",
        Some(&qp),
        None,
        args.jq.as_deref(),
        fmt,
    )
    .await
}

/// `slack_thread_replies`: `GET /conversations.replies?channel=&ts=`.
pub async fn thread_replies(
    ctx: &SlackContext<'_>,
    args: &SlackThreadRepliesArgs,
) -> Result<ControllerResponse, McpError> {
    channel_param(&args.channel_id)?;
    if !is_valid_message_ts(&args.thread_ts) {
        return Err(crate::error::api_error(
            "threadTs must be a Slack message timestamp (digits with one decimal point, e.g. \
             1700000000.123456)",
            Some(400),
            None,
        ));
    }
    let mut qp = QueryParams::new();
    qp.insert("channel".to_owned(), args.channel_id.clone());
    qp.insert("ts".to_owned(), args.thread_ts.clone());
    insert_opt(&mut qp, "oldest", args.oldest.as_deref());
    insert_opt(&mut qp, "latest", args.latest.as_deref());
    insert_flag(&mut qp, "inclusive", args.inclusive);
    insert_num(&mut qp, "limit", args.limit);
    insert_opt(&mut qp, "cursor", args.cursor.as_deref());
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    handle_request(
        ctx,
        HttpMethod::Get,
        "/conversations.replies",
        Some(&qp),
        None,
        args.jq.as_deref(),
        fmt,
    )
    .await
}

/// `slack_search_messages`: `GET /search.messages?query=`.
pub async fn search_messages(
    ctx: &SlackContext<'_>,
    args: &SlackSearchMessagesArgs,
) -> Result<ControllerResponse, McpError> {
    if args.query.trim().is_empty() {
        return Err(crate::error::api_error(
            "query must not be empty",
            Some(400),
            None,
        ));
    }
    let mut qp = QueryParams::new();
    qp.insert("query".to_owned(), args.query.clone());
    insert_num(&mut qp, "count", args.count);
    insert_num(&mut qp, "page", args.page);
    insert_opt(&mut qp, "sort", args.sort.as_deref());
    insert_opt(&mut qp, "sort_dir", args.sort_dir.as_deref());
    let fmt = args.output_format.map_or(OutputFormat::Toon, Into::into);
    handle_request(
        ctx,
        HttpMethod::Get,
        "/search.messages",
        Some(&qp),
        None,
        args.jq.as_deref(),
        fmt,
    )
    .await
}

/// Write-shaped convenience wrapper (POST / PUT / PATCH).
pub async fn handle_write(
    ctx: &SlackContext<'_>,
    method: HttpMethod,
    args: &WriteArgs,
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

//! Jira image attachment retrieval.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rmcp::model::ContentBlock;

use super::api::HandleContext;
use crate::auth::Credentials;
use crate::error::{McpError, api_error};
use crate::transport::image::fetch_image;

pub async fn get_attachment(
    ctx: &HandleContext<'_>,
    attachment_id: &str,
) -> Result<ContentBlock, McpError> {
    if attachment_id.is_empty() || !attachment_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(api_error(
            "attachmentId must be a numeric Jira attachment ID from fields.attachment, not a media UUID or blob URL",
            Some(400),
            None,
        ));
    }
    let credentials = Credentials::require_for_async(ctx.config, ctx.vendor.name()).await?;
    let path = format!("/rest/api/3/attachment/content/{attachment_id}?redirect=false");
    let (bytes, mime) =
        fetch_image(ctx.client, ctx.vendor, &credentials, ctx.config, &path).await?;
    Ok(ContentBlock::image(STANDARD.encode(bytes), mime))
}

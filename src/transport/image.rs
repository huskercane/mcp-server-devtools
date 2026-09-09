//! Bounded image downloads that never decode binary bodies as text.

use super::{
    CONTENT_TYPE, Config, Credentials, HttpCallLog, HttpClient, HttpMethod, McpError, Vendor,
    api_error, canonical_target, log_http_status_failure, log_http_transport_failure,
    map_transport_error, report_attempt, resolve_timeout, validate_auth,
};

/// Maximum unencoded image size (base64 adds roughly one third).
pub const MAX_IMAGE_BYTES: usize = 5 * 1024 * 1024;

pub async fn fetch_image(
    client: &HttpClient,
    vendor: &dyn Vendor,
    credentials: &Credentials,
    config: &Config,
    path: &str,
) -> Result<(Vec<u8>, String), McpError> {
    let base = vendor.base_url(config)?;
    let target = canonical_target(path)?;
    let ticket =
        crate::policy::authorize_egress(vendor.name(), HttpMethod::Get, &target, None).await?;
    let url = target.url_under(&base);
    let (auth_name, auth) = validate_auth(credentials)?;
    let call = HttpCallLog::new(vendor.name(), "GET", &url);
    let mut response = client
        .get(&url)
        .header(auth_name, auth)
        // The Jira gateway negotiates JSON before streaming attachment bytes.
        .header("Accept", "*/*")
        .timeout(resolve_timeout(config, None))
        .send()
        .await
        .map_err(|error| {
            report_attempt(ticket.as_ref(), None, Some("transport_error"));
            log_http_transport_failure(call, &error, false);
            map_transport_error(&error, &url)
        })?;
    let status = response.status();
    report_attempt(ticket.as_ref(), Some(status.as_u16()), None);
    if !status.is_success() {
        log_http_status_failure(call, status, false);
    }
    let mime = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if status.is_success()
        && !matches!(
            mime.as_str(),
            "image/png" | "image/jpeg" | "image/gif" | "image/webp"
        )
    {
        return Err(api_error(
            format!(
                "Attachment is not a supported image (Content-Type: {mime:?}). Supported: PNG, JPEG, GIF, WebP."
            ),
            Some(415),
            None,
        ));
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_IMAGE_BYTES as u64)
    {
        return Err(image_too_large());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| map_transport_error(&error, &url))?
    {
        if chunk.len() > MAX_IMAGE_BYTES - bytes.len() {
            return Err(image_too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        return Err(vendor.classify_error(status, &String::from_utf8_lossy(&bytes)));
    }
    if bytes.is_empty() {
        return Err(api_error("Attachment image is empty", Some(502), None));
    }
    Ok((bytes, mime))
}

fn image_too_large() -> McpError {
    api_error("Attachment exceeds the 5 MiB image limit", Some(413), None)
}

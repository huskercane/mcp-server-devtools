//! Explicit, bounded GET redirects. Cross-origin requests carry no API headers.
use std::collections::HashSet;

use super::*;

pub(super) fn destination(value: &str) -> Result<url::Url, McpError> {
    let url = url::Url::parse(value)
        .map_err(|_| api_error("Invalid destination URL", Some(400), None))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(api_error("Unsupported destination URL", Some(400), None));
    }
    Ok(url)
}

pub(super) fn allowed(config: &Config, vendor: &str, url: &url::Url) -> bool {
    config
        .get_for(vendor, "MCP_DOWNLOAD_ALLOWED_ORIGINS")
        .is_some_and(|origins| {
            origins
                .split(',')
                .filter_map(|origin| destination(origin.trim()).ok())
                .any(|allowed| {
                    allowed.path() == "/"
                        && allowed.query().is_none()
                        && allowed.origin() == url.origin()
                })
        })
}

pub(super) async fn authorize(
    vendor: &str,
    url: &url::Url,
) -> Result<Option<crate::policy::EgressTicket>, McpError> {
    let target = canonical_target(&url[url::Position::BeforePath..url::Position::AfterQuery])?;
    if target.path().as_str() != url.path() {
        return Err(api_error("Download path is not canonical", Some(400), None));
    }
    crate::policy::authorize_download_egress(vendor, &target, url).await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn follow(
    client: &HttpClient,
    vendor: &str,
    config: &Config,
    initial: &str,
    mut response: HttpResponse,
    method: HttpMethod,
    options: &RequestOptions,
    auth: Option<(&HeaderName, &HeaderValue)>,
    deadline: tokio::time::Instant,
    cancellation: &CancellationToken,
) -> Result<HttpResponse, McpError> {
    let original = destination(initial)?;
    let mut current = original.clone();
    let mut seen = HashSet::with_capacity(6);
    seen.insert(current.clone());
    let mut credential_allowed = auth.is_some();
    for _ in 0..5 {
        if !response.status().is_redirection() {
            return Ok(response);
        }
        if method != HttpMethod::Get
            || !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308)
        {
            return Err(api_error(
                "Unsupported redirect for this request",
                Some(502),
                None,
            ));
        }
        let location = response
            .headers()
            .get(http::header::LOCATION)
            .and_then(|header| header.to_str().ok())
            .ok_or_else(|| api_error("Redirect has no valid Location", Some(502), None))?;
        let next = current
            .join(location)
            .map_err(|_| api_error("Invalid redirect Location", Some(502), None))?;
        let next = destination(next.as_str())?;
        if current.scheme() == "https" && next.scheme() != "https" {
            return Err(api_error("Redirect downgrade denied", Some(403), None));
        }
        let ticket = authorize(vendor, &next).await?;
        if next.origin() != original.origin() && !allowed(config, vendor, &next) {
            return Err(api_error(
                "Redirect origin is not in MCP_DOWNLOAD_ALLOWED_ORIGINS",
                Some(403),
                None,
            ));
        }
        if !seen.insert(next.clone()) {
            return Err(api_error("Redirect loop", Some(502), None));
        }
        if let Some(delay) = retry::parse(response.headers(), std::time::SystemTime::now()) {
            let mut timing = StreamingPolicy::new(0, 0);
            timing.cancellation = cancellation.clone();
            retry_stream_attempt(0, &timing, deadline, Some(delay)).await?;
        }
        drop(response);
        credential_allowed &= next.origin() == current.origin();
        let remaining = remaining_until(deadline)?;
        let request = if credential_allowed && let Some((name, value)) = auth {
            build_request(
                client,
                method,
                next.as_str(),
                name,
                value,
                options,
                remaining,
            )
        } else {
            // Rebuild from scratch: no cookies, custom tokens, or caller headers.
            client.get(next.as_str()).timeout(remaining)
        };
        response = tokio::select! {
            () = cancellation.cancelled() => {
                report_attempt(ticket.as_ref(), None, Some("cancelled"));
                return Err(api_error("redirect cancelled", Some(499), None));
            },
            result = request.send() => result.map_err(|_| {
                report_attempt(ticket.as_ref(), None, Some("transport_error"));
                api_error("Redirect request failed", Some(502), None)
            })?,
        };
        report_attempt(ticket.as_ref(), Some(response.status().as_u16()), None);
        current = next;
    }
    if response.status().is_redirection() {
        Err(api_error("Redirect hop limit exceeded", Some(502), None))
    } else {
        Ok(response)
    }
}

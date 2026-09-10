//! `TeamCity` REST API adapter with per-request bearer-token resolution.

use crate::config::{Config, VENDOR_TEAMCITY};
use crate::error::{McpError, OriginalError, api_error, auth_invalid, auth_missing};
use crate::vendor::Vendor;
use http::StatusCode;

/// `TeamCity` server connection. The URL includes any deployment context path.
#[derive(Debug, Clone, Default)]
pub struct TeamcityVendor {
    base_url_override: Option<String>,
}

impl TeamcityVendor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url_override: Some(base_url.into()),
        }
    }

    pub async fn token(&self, config: &Config) -> Result<String, McpError> {
        crate::auth::vendor_secret(config, VENDOR_TEAMCITY, "TEAMCITY_TOKEN")
            .await?
            .ok_or_else(|| auth_missing("TEAMCITY_TOKEN is required for teamcity_* tools. Set a personal access token in the `teamcity` config section or environment."))
    }
}

impl Vendor for TeamcityVendor {
    fn name(&self) -> &'static str {
        VENDOR_TEAMCITY
    }

    fn base_url(&self, config: &Config) -> Result<String, McpError> {
        let url = self.base_url_override.as_deref()
            .or_else(|| config.get_for(VENDOR_TEAMCITY, "TEAMCITY_URL"))
            .map(str::trim).filter(|url| !url.is_empty())
            .ok_or_else(|| auth_missing("TEAMCITY_URL is required for teamcity_* tools. Set the server URL (e.g. https://ci.example.com/teamcity), without /app/rest, in the `teamcity` config section or environment."))?;
        Ok(url.trim_end_matches('/').to_owned())
    }

    fn normalize_path(&self, path: &str) -> String {
        let path = path.trim_start_matches('/');
        if path == "app/rest" || path.starts_with("app/rest/") || path.starts_with("app/rest?") {
            format!("/{path}")
        } else if path.is_empty() {
            "/app/rest".to_owned()
        } else {
            format!("/app/rest/{path}")
        }
    }

    fn classify_error(&self, status: StatusCode, body: &str) -> McpError {
        let message = if body.trim().is_empty() {
            status.canonical_reason().unwrap_or("TeamCity API error")
        } else {
            body.trim()
        };
        let message = format!("TeamCity API: {message}");
        let original = (!body.is_empty()).then(|| {
            serde_json::from_str(body).map_or_else(
                |_| OriginalError::String(body.to_owned()),
                OriginalError::Json,
            )
        });
        if matches!(status.as_u16(), 401 | 403) {
            let mut error = auth_invalid(message);
            error.status_code = Some(status.as_u16());
            error.original = original;
            error
        } else {
            api_error(message, Some(status.as_u16()), original)
        }
    }
}

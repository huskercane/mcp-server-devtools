//! HTTP forwarder: Splunk HTTP Event Collector, or a generic JSON endpoint
//! (WP C.3, the second `AuditForwarder` adapter).
//!
//! Selected by `MCP_AUDIT_FORWARD_URL=https://…`. The format is inferred
//! from the path — `/services/collector` is Splunk HEC — and can be forced
//! with `MCP_AUDIT_FORWARD_FORMAT=hec|json`.
//!
//! - **Splunk HEC.** `POST` with `Authorization: Splunk <token>` and a body
//!   of one HEC event per record, newline-separated: `time` from the
//!   record's timestamp, `host` from `MCP_AUDIT_FORWARD_ORIGIN`,
//!   `source: mcp-devtools`, `sourcetype: mcp-devtools:audit`, and the
//!   journal line itself under `event`. A `2xx` acknowledges the batch;
//!   HEC checks the whole body before it answers, so a `2xx` is all or
//!   nothing.
//! - **Generic JSON.** `POST` a JSON array of the journal lines, with
//!   `Authorization: Bearer <token>` when a token is configured. A `2xx`
//!   acknowledges.
//!
//! The record bytes are spliced into the body as they are; nothing is
//! re-parsed or re-serialised, so the receiver holds the journal's lines.
//!
//! `https` is required, or `http` on a loopback host (a local collector, a
//! test). The token is a header, never part of the URL, and appears in no
//! error or log line.
//!
//! The token is read from its [`TokenSource`] for **each** delivery, not
//! copied once at startup: when `MCP_AUDIT_FORWARD_TOKEN` is a secret
//! reference, the refresher swaps a new snapshot in and the next batch
//! carries the rotated value, so a receiver that revoked the old token
//! stops rejecting without a restart.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::ports::{AuditForwarder, DeliverFuture, ForwardError, ForwardRecord};

/// Which body the receiver expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFormat {
    SplunkHec,
    Json,
}

impl HttpFormat {
    /// Parse `MCP_AUDIT_FORWARD_FORMAT`.
    ///
    /// # Errors
    ///
    /// For anything but `hec` or `json`.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "hec" | "splunk" | "splunk-hec" => Ok(Self::SplunkHec),
            "json" => Ok(Self::Json),
            other => Err(format!(
                "{}: {other:?} is not a format (expected `hec` or `json`)",
                super::FORMAT_KEY
            )),
        }
    }

    /// The format a URL implies: HEC when its path names the collector.
    #[must_use]
    pub fn infer(url: &url::Url) -> Self {
        if url.path().contains("/services/collector") {
            Self::SplunkHec
        } else {
            Self::Json
        }
    }
}

/// Where the token comes from at delivery time. Returns the configured
/// value as it stands now; `None` when none is configured.
pub type TokenSource = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// The HTTP adapter.
pub struct HttpForwarder {
    client: crate::transport::HttpClient,
    url: url::Url,
    format: HttpFormat,
    token: TokenSource,
    origin: String,
}

/// Never the token.
impl std::fmt::Debug for HttpForwarder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpForwarder")
            .field("url", &self.url.as_str())
            .field("format", &self.format)
            .field("token", &normalize((self.token)()).map(|_| "<redacted>"))
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl HttpForwarder {
    /// Build the adapter with a fixed token. No network I/O.
    ///
    /// # Errors
    ///
    /// As [`Self::with_token_source`].
    pub fn new(
        url: &str,
        format: Option<HttpFormat>,
        token: Option<String>,
        origin: String,
        ca_file: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self, String> {
        let token = normalize(token);
        Self::with_token_source(
            url,
            format,
            Arc::new(move || token.clone()),
            origin,
            ca_file,
            timeout,
        )
    }

    /// Build the adapter, reading the token from `token` at each delivery.
    /// No network I/O.
    ///
    /// # Errors
    ///
    /// When the URL is not `https` (or `http` on loopback), carries
    /// user-info, or HEC is selected without a token configured right now;
    /// when the CA file cannot be read; when the client cannot be built.
    pub fn with_token_source(
        url: &str,
        format: Option<HttpFormat>,
        token: TokenSource,
        origin: String,
        ca_file: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self, String> {
        let url = url::Url::parse(url.trim()).map_err(|error| format!("{url:?}: {error}"))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(format!(
                "{url}: user-info in the receiver URL is not allowed"
            ));
        }
        let host = url.host_str().ok_or_else(|| format!("{url}: no host"))?;
        match url.scheme() {
            "https" => {}
            "http" if super::syslog::is_loopback_host(host) => {}
            "http" => {
                return Err(format!(
                    "{url}: the receiver must be reached over https (http is allowed on \
                     loopback only)"
                ));
            }
            other => return Err(format!("{url}: no HTTP forwarder for `{other}://`")),
        }
        let format = format.unwrap_or_else(|| HttpFormat::infer(&url));
        if format == HttpFormat::SplunkHec && normalize(token()).is_none() {
            return Err(format!(
                "{}: Splunk HEC needs the collector token",
                super::TOKEN_KEY
            ));
        }
        let mut builder = crate::transport::HttpClient::builder()
            .crate_user_agent()
            .timeout(timeout)
            .no_redirects();
        if let Some(path) = ca_file {
            let pem = std::fs::read(path).map_err(|error| {
                format!(
                    "{}: cannot read {}: {}",
                    super::CA_FILE_KEY,
                    path.display(),
                    error.kind()
                )
            })?;
            builder = builder.add_root_certificate_pem(&pem).map_err(|_| {
                format!(
                    "{}: {} is not a PEM certificate",
                    super::CA_FILE_KEY,
                    path.display()
                )
            })?;
        }
        let client = builder
            .build()
            .map_err(|_| "cannot build the forwarder's HTTP client".to_owned())?;
        Ok(Self {
            client,
            url,
            format,
            token,
            origin,
        })
    }

    #[must_use]
    pub fn format(&self) -> HttpFormat {
        self.format
    }

    /// The request body for `batch`.
    #[must_use]
    pub fn body(&self, batch: &[ForwardRecord<'_>]) -> Vec<u8> {
        let mut body = Vec::with_capacity(batch.iter().map(|record| record.json.len() + 128).sum());
        match self.format {
            HttpFormat::SplunkHec => {
                let host = serde_json::to_string(&self.origin).unwrap_or_else(|_| "\"-\"".into());
                for (index, record) in batch.iter().enumerate() {
                    if index > 0 {
                        body.push(b'\n');
                    }
                    body.extend_from_slice(b"{");
                    if let Some(time) = record.timestamp.and_then(hec_time) {
                        body.extend_from_slice(b"\"time\":");
                        body.extend_from_slice(time.as_bytes());
                        body.push(b',');
                    }
                    body.extend_from_slice(b"\"host\":");
                    body.extend_from_slice(host.as_bytes());
                    body.extend_from_slice(
                        b",\"source\":\"mcp-devtools\",\"sourcetype\":\"mcp-devtools:audit\",\"event\":",
                    );
                    body.extend_from_slice(record.json);
                    body.push(b'}');
                }
            }
            HttpFormat::Json => {
                body.push(b'[');
                for (index, record) in batch.iter().enumerate() {
                    if index > 0 {
                        body.push(b',');
                    }
                    body.extend_from_slice(record.json);
                }
                body.push(b']');
            }
        }
        body
    }
}

/// A configured token, trimmed; `None` when absent or blank.
fn normalize(token: Option<String>) -> Option<String> {
    let mut token = token?;
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() != token.len() {
        token = trimmed.to_owned();
    }
    Some(token)
}

/// `seconds.millis` for HEC's `time`, from the journal's RFC 3339 stamp.
fn hec_time(timestamp: &str) -> Option<String> {
    let parsed = chrono::DateTime::parse_from_rfc3339(timestamp).ok()?;
    Some(format!(
        "{}.{:03}",
        parsed.timestamp(),
        parsed.timestamp_subsec_millis()
    ))
}

impl AuditForwarder for HttpForwarder {
    fn name(&self) -> &'static str {
        match self.format {
            HttpFormat::SplunkHec => "splunk-hec",
            HttpFormat::Json => "http-json",
        }
    }

    fn deliver<'a>(&'a self, batch: &'a [ForwardRecord<'a>]) -> DeliverFuture<'a> {
        Box::pin(async move {
            // The token as configured *now*, so a rotation reaches the
            // receiver on the next batch rather than the next restart.
            let token = normalize((self.token)());
            if self.format == HttpFormat::SplunkHec && token.is_none() {
                return Err(ForwardError::new(
                    ForwardError::REJECTED,
                    "collector token is no longer configured",
                ));
            }
            let body = self.body(batch);
            let mut request = self
                .client
                .post(self.url.clone())
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(body);
            if let Some(token) = token {
                let value = match self.format {
                    HttpFormat::SplunkHec => format!("Splunk {token}"),
                    HttpFormat::Json => format!("Bearer {token}"),
                };
                request = request.header(http::header::AUTHORIZATION, value);
            }
            let response = request.send().await.map_err(|error| {
                let category = if error.is_timeout() {
                    ForwardError::TIMEOUT
                } else if error.is_connect() {
                    ForwardError::UNREACHABLE
                } else {
                    ForwardError::INTERRUPTED
                };
                // The transport error text can quote the URL; the URL holds
                // no credential (user-info is refused), so that is fine,
                // but keep it to the kind.
                ForwardError::new(category, describe(&error))
            })?;
            let status = response.status();
            if status.is_success() {
                return Ok(());
            }
            // HEC answers `{"text":"Invalid token","code":4}`; keep `text`,
            // which is a fixed vocabulary, never the request.
            let text = response
                .bytes()
                .await
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .and_then(|value| {
                    value
                        .get("text")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                });
            Err(ForwardError::new(
                ForwardError::REJECTED,
                match text {
                    Some(text) => format!("http {}: {text}", status.as_u16()),
                    None => format!("http {}", status.as_u16()),
                },
            ))
        })
    }
}

fn describe(error: &crate::transport::HttpError) -> String {
    if error.is_timeout() {
        "request timed out".to_owned()
    } else if error.is_connect() {
        "connection failed".to_owned()
    } else if error.is_request() {
        "request failed".to_owned()
    } else {
        "response failed".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(seq: u64, json: &[u8]) -> ForwardRecord<'_> {
        ForwardRecord {
            seq,
            kind: "tool_call_intent",
            timestamp: Some("2026-09-04T12:00:00.123Z"),
            adverse: false,
            json,
        }
    }

    #[test]
    fn hec_is_inferred_from_the_collector_path_and_needs_a_token() {
        assert_eq!(
            HttpFormat::infer(
                &url::Url::parse("https://splunk:8088/services/collector/event").unwrap()
            ),
            HttpFormat::SplunkHec
        );
        assert_eq!(
            HttpFormat::infer(&url::Url::parse("https://siem.example/ingest").unwrap()),
            HttpFormat::Json
        );
        let error = HttpForwarder::new(
            "https://splunk:8088/services/collector",
            None,
            None,
            "o".into(),
            None,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("collector token"), "{error}");
    }

    #[test]
    fn plaintext_http_is_loopback_only_and_user_info_is_refused() {
        assert!(
            HttpForwarder::new(
                "http://127.0.0.1:1/x",
                None,
                None,
                "o".into(),
                None,
                Duration::from_secs(1)
            )
            .is_ok()
        );
        assert!(
            HttpForwarder::new(
                "http://siem.example/x",
                None,
                None,
                "o".into(),
                None,
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            HttpForwarder::new(
                "https://u:p@siem.example/x",
                None,
                None,
                "o".into(),
                None,
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            HttpForwarder::new(
                "ftp://siem.example/x",
                None,
                None,
                "o".into(),
                None,
                Duration::from_secs(1)
            )
            .is_err()
        );
    }

    #[test]
    fn hec_body_wraps_each_record_with_time_host_and_sourcetype() {
        let forwarder = HttpForwarder::new(
            "https://splunk:8088/services/collector",
            None,
            Some("tok".into()),
            "gateway-0".into(),
            None,
            Duration::from_secs(1),
        )
        .unwrap();
        let body = forwarder.body(&[record(1, b"{\"seq\":1}"), record(2, b"{\"seq\":2}")]);
        let text = String::from_utf8(body).unwrap();
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "{\"time\":1788523200.123,\"host\":\"gateway-0\",\"source\":\"mcp-devtools\",\"sourcetype\":\"mcp-devtools:audit\",\"event\":{\"seq\":1}}"
        );
        let parsed: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed["event"]["seq"], 2);
    }

    #[test]
    fn json_body_is_an_array_of_the_records() {
        let forwarder = HttpForwarder::new(
            "https://siem.example/ingest",
            None,
            None,
            "o".into(),
            None,
            Duration::from_secs(1),
        )
        .unwrap();
        let body = forwarder.body(&[record(1, b"{\"seq\":1}"), record(2, b"{\"seq\":2}")]);
        assert_eq!(body, b"[{\"seq\":1},{\"seq\":2}]");
        assert_eq!(forwarder.name(), "http-json");
    }
}

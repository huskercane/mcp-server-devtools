//! Syslog forwarder: RFC 5424 messages, RFC 5425 octet-counted framing,
//! over TLS (WP C.3, the first `AuditForwarder` adapter).
//!
//! Selected by `MCP_AUDIT_FORWARD_URL=syslog+tls://host[:6514]`. Plaintext
//! syslog (`syslog://`, `syslog+tcp://`, UDP) is refused: the stream is a
//! copy of the security journal, and a receiver that cannot do TLS is a
//! receiver to fix, not a mode to add.
//!
//! ## Message shape
//!
//! ```text
//! <110>1 2026-09-04T12:00:00.123Z gateway-0 mcp-devtools - tool_call_intent - BOM{…the journal line…}
//! ```
//!
//! - `PRI` is facility 13 (log audit) with severity *informational* for a
//!   record and *warning* for a denial or refusal, so a receiver's
//!   severity filter sees denials without parsing JSON;
//! - `TIMESTAMP` is the record's own `timestamp` (the journal writes
//!   RFC 3339 UTC with milliseconds, which RFC 5424 accepts), or `-` for a
//!   record without one;
//! - `HOSTNAME` is `MCP_AUDIT_FORWARD_ORIGIN`, `APP-NAME` is `mcp-devtools`,
//!   `MSGID` is the record's `kind`;
//! - no structured data (`-`): the journal line already is structured, and
//!   an SD-ID needs a registered enterprise number this project does not
//!   hold;
//! - `MSG` is the UTF-8 BOM followed by the exact journal line without its
//!   newline — the bytes `audit verify` hashes, not a rendering of them.
//!
//! Each message is framed as `MSG-LEN SP SYSLOG-MSG` (RFC 5425 §4.3), so a
//! record containing a newline inside a JSON string can never split a
//! message; this is what every TLS syslog receiver (rsyslog `imtcp`,
//! syslog-ng `syslog()`, Splunk, Elastic) expects on port 6514.
//!
//! ## Acknowledgement
//!
//! TCP syslog has no application-level acknowledgement (that is what RELP
//! adds, and it is not built). What this adapter can know is whether the
//! peer is still there, so it checks in three places: **before** a batch
//! on a reused connection, a zero-wait read that turns a connection the
//! peer already closed into a reconnect rather than a write into a dead
//! socket; **after** writing and flushing, a short grace read
//! ([`POST_WRITE_GRACE`]) that catches a peer which closed — or sent a TLS
//! alert, as a receiver refusing an absent client certificate does — as
//! the bytes arrived; and the write itself. A batch is acknowledged when
//! the bytes were flushed and the peer stayed silent through the grace.
//! Anything else is `delivery_interrupted`, the connection is dropped,
//! and the shipper re-sends the batch on a fresh one: a receiver may see
//! a batch twice after a broken connection, never not at all.
//!
//! The residual gap is a receiver that takes the bytes and dies after the
//! grace, before writing them anywhere; that batch was acknowledged here
//! and is not re-sent. It is inherent to TCP syslog, which is why the
//! receiver should be a **local relay with a disk queue** (rsyslog,
//! syslog-ng) that forwards on to the SIEM with its own retries, rather
//! than the SIEM across a WAN — the runbook says so, and CF-32 records
//! RELP as the adapter that would close it.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::ports::{AuditForwarder, DeliverFuture, ForwardError, ForwardRecord};

/// The default TLS syslog port (RFC 5425).
pub const DEFAULT_PORT: u16 = 6514;
/// How long to listen for the peer closing (or objecting) after a batch
/// is flushed, before calling it delivered. On a loopback or LAN relay a
/// close arrives well inside this; the cost is paid once per batch on a
/// background task.
pub const POST_WRITE_GRACE: Duration = Duration::from_millis(50);
/// RFC 5424 facility 13: log audit.
const FACILITY_LOG_AUDIT: u8 = 13;
const SEVERITY_WARNING: u8 = 4;
const SEVERITY_INFORMATIONAL: u8 = 6;
const APP_NAME: &str = "mcp-devtools";

/// The certificate material the connection trusts and presents.
#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    /// A PEM bundle appended to the system trust store.
    pub ca_file: Option<PathBuf>,
    /// A PEM client certificate (chain) for mutual TLS, with its key.
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
}

/// Where and as whom to send.
#[derive(Debug, Clone)]
pub struct SyslogSettings {
    pub host: String,
    pub port: u16,
    pub origin: String,
    pub timeout: Duration,
}

impl SyslogSettings {
    /// Parse `syslog+tls://host[:port]`. Anything else — another scheme, a
    /// path, a query, user-info — is refused with the reason.
    ///
    /// # Errors
    ///
    /// A message naming what was wrong with the URL.
    pub fn parse_url(url: &str, origin: String, timeout: Duration) -> Result<Self, String> {
        let parsed = url::Url::parse(url.trim()).map_err(|error| format!("{url:?}: {error}"))?;
        if parsed.scheme() != "syslog+tls" {
            return Err(format!(
                "{url:?}: the syslog forwarder takes `syslog+tls://host[:port]`; plaintext \
                 syslog is not supported"
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(format!(
                "{url:?}: user-info in the receiver URL is not allowed"
            ));
        }
        if parsed.path() != "/" && !parsed.path().is_empty() || parsed.query().is_some() {
            return Err(format!(
                "{url:?}: a syslog receiver is a host and a port; no path or query"
            ));
        }
        let host = parsed
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| format!("{url:?}: no host"))?
            .trim_matches(['[', ']'])
            .to_owned();
        Ok(Self {
            host,
            port: parsed.port().unwrap_or(DEFAULT_PORT),
            origin,
            timeout,
        })
    }
}

/// Build the rustls client configuration: the system trust store plus
/// `ca_file`, and a client certificate when both halves are given.
///
/// # Errors
///
/// When a file cannot be read or is not the PEM object expected, when only
/// one half of the client credential is given, or when no trust anchor at
/// all is available.
pub fn client_config(options: &TlsOptions) -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }
    if let Some(path) = &options.ca_file {
        let mut added = 0usize;
        for cert in CertificateDer::pem_file_iter(path)
            .map_err(|error| format!("{}: cannot read as PEM: {error}", path.display()))?
        {
            let cert = cert
                .map_err(|error| format!("{}: not a PEM certificate: {error}", path.display()))?;
            roots
                .add(cert)
                .map_err(|error| format!("{}: certificate rejected: {error}", path.display()))?;
            added += 1;
        }
        if added == 0 {
            return Err(format!("{}: holds no certificate", path.display()));
        }
    }
    if roots.is_empty() {
        return Err(format!(
            "no trust anchors: the system trust store yielded none ({}) and no CA file was \
             given",
            native
                .errors
                .first()
                .map_or_else(|| "empty".to_owned(), ToString::to_string)
        ));
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("TLS setup failed: {error}"))?
        .with_root_certificates(roots);
    match (&options.client_cert, &options.client_key) {
        (None, None) => Ok(builder.with_no_client_auth()),
        (Some(cert_path), Some(key_path)) => {
            let certs = CertificateDer::pem_file_iter(cert_path)
                .map_err(|error| format!("{}: cannot read as PEM: {error}", cert_path.display()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    format!("{}: not a PEM certificate: {error}", cert_path.display())
                })?;
            if certs.is_empty() {
                return Err(format!("{}: holds no certificate", cert_path.display()));
            }
            let key = PrivateKeyDer::from_pem_file(key_path).map_err(|error| {
                format!("{}: not a PEM private key: {error}", key_path.display())
            })?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|error| format!("client certificate rejected: {error}"))
        }
        _ => Err(format!(
            "{} and {} must be given together",
            super::CLIENT_CERT_KEY,
            super::CLIENT_KEY_KEY
        )),
    }
}

/// The syslog adapter.
pub struct SyslogForwarder {
    settings: SyslogSettings,
    connector: TlsConnector,
    server_name: ServerName<'static>,
    /// One stream, reused across batches. A `tokio` mutex because it is
    /// held across the write; deliveries are serial by construction (one
    /// shipper), so it never contends.
    stream: tokio::sync::Mutex<Option<TlsStream<TcpStream>>>,
}

impl std::fmt::Debug for SyslogForwarder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyslogForwarder")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl SyslogForwarder {
    /// Build the adapter. No network I/O: the first delivery connects.
    ///
    /// # Errors
    ///
    /// When the TLS material cannot be loaded, or the host is not a valid
    /// TLS server name.
    pub fn new(settings: SyslogSettings, tls: &TlsOptions) -> Result<Self, String> {
        let config = client_config(tls)?;
        let server_name = ServerName::try_from(settings.host.clone())
            .map_err(|_| format!("{:?} is not a valid TLS server name", settings.host))?;
        Ok(Self {
            settings,
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
            stream: tokio::sync::Mutex::new(None),
        })
    }

    /// Frame one record as an RFC 5425 octet-counted RFC 5424 message,
    /// appended to `out`.
    pub fn frame(record: &ForwardRecord<'_>, origin: &str, out: &mut Vec<u8>) {
        use std::io::Write as _;
        let severity = if record.adverse {
            SEVERITY_WARNING
        } else {
            SEVERITY_INFORMATIONAL
        };
        let pri = FACILITY_LOG_AUDIT * 8 + severity;
        // Header fields are printable US-ASCII without spaces; anything
        // else becomes `_`, and the bounds are RFC 5424's.
        let hostname = sanitised(origin, 255);
        let msgid = sanitised(record.kind, 32);
        let timestamp = record
            .timestamp
            .filter(|value| value.len() <= 48 && value.bytes().all(|byte| byte.is_ascii_graphic()))
            .unwrap_or("-");
        // HEADER SP SD SP MSG, then the length prefix; the message is built
        // into `out` past a reserved prefix so nothing is copied twice.
        let header_len = 3
            + 2
            + 2
            + timestamp.len()
            + 1
            + hostname.len()
            + 1
            + APP_NAME.len()
            + 3
            + msgid.len()
            + 3
            + 1
            + 3
            + record.json.len();
        let start = out.len();
        // Longest decimal length prefix for a u32-sized frame plus the space.
        out.reserve(header_len + 12);
        let _ = write!(out, "{}", header_len + 3);
        // The frame length counts the BOM; recompute exactly below and fix
        // the prefix if the estimate differs (it never does, but a wrong
        // octet count desynchronises the stream for good).
        let prefix_end = out.len();
        out.push(b' ');
        let message_start = out.len();
        let _ = write!(
            out,
            "<{pri}>1 {timestamp} {hostname} {APP_NAME} - {msgid} - "
        );
        out.extend_from_slice("\u{feff}".as_bytes());
        out.extend_from_slice(record.json);
        let actual = out.len() - message_start;
        let written: usize = std::str::from_utf8(&out[start..prefix_end])
            .ok()
            .and_then(|digits| digits.parse().ok())
            .unwrap_or(0);
        if written != actual {
            let message = out.split_off(message_start);
            out.truncate(start);
            let _ = write!(out, "{actual} ");
            out.extend_from_slice(&message);
        }
    }

    async fn connect(&self) -> Result<TlsStream<TcpStream>, ForwardError> {
        let address = (self.settings.host.as_str(), self.settings.port);
        let tcp =
            match tokio::time::timeout(self.settings.timeout, TcpStream::connect(address)).await {
                Ok(Ok(tcp)) => tcp,
                Ok(Err(error)) => {
                    return Err(ForwardError::new(
                        ForwardError::UNREACHABLE,
                        format!(
                            "connect to {}:{}: {}",
                            self.settings.host,
                            self.settings.port,
                            error.kind()
                        ),
                    ));
                }
                Err(_) => {
                    return Err(ForwardError::new(
                        ForwardError::TIMEOUT,
                        format!(
                            "connect to {}:{} timed out",
                            self.settings.host, self.settings.port
                        ),
                    ));
                }
            };
        let _ = tcp.set_nodelay(true);
        match tokio::time::timeout(
            self.settings.timeout,
            self.connector.connect(self.server_name.clone(), tcp),
        )
        .await
        {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(error)) => Err(ForwardError::new(
                ForwardError::UNREACHABLE,
                format!("TLS handshake with {}: {error}", self.settings.host),
            )),
            Err(_) => Err(ForwardError::new(
                ForwardError::TIMEOUT,
                format!("TLS handshake with {} timed out", self.settings.host),
            )),
        }
    }
}

impl AuditForwarder for SyslogForwarder {
    fn name(&self) -> &'static str {
        "syslog"
    }

    fn deliver<'a>(&'a self, batch: &'a [ForwardRecord<'a>]) -> DeliverFuture<'a> {
        Box::pin(async move {
            let mut frame =
                Vec::with_capacity(batch.iter().map(|record| record.json.len() + 96).sum());
            for record in batch {
                Self::frame(record, &self.settings.origin, &mut frame);
            }
            let mut guard = self.stream.lock().await;
            // A reused connection the peer has since closed is a reconnect,
            // not a delivery failure: check before writing into it.
            if let Some(stream) = guard.as_mut()
                && peer_closed(stream, Duration::ZERO).await
            {
                *guard = None;
            }
            if guard.is_none() {
                *guard = Some(self.connect().await?);
            }
            let stream = guard.as_mut().expect("connected above");
            let written = tokio::time::timeout(self.settings.timeout, async {
                stream.write_all(&frame).await?;
                stream.flush().await
            })
            .await;
            match written {
                Ok(Ok(())) => {
                    if peer_closed(stream, POST_WRITE_GRACE).await {
                        *guard = None;
                        return Err(ForwardError::new(
                            ForwardError::INTERRUPTED,
                            "receiver closed the connection while the batch was in flight",
                        ));
                    }
                    Ok(())
                }
                Ok(Err(error)) => {
                    *guard = None;
                    Err(ForwardError::new(
                        ForwardError::INTERRUPTED,
                        format!("write: {}", error.kind()),
                    ))
                }
                Err(_) => {
                    *guard = None;
                    Err(ForwardError::new(ForwardError::TIMEOUT, "write timed out"))
                }
            }
        })
    }
}

/// Whether the peer has closed or objected: a read that completes within
/// `wait` — end of stream, an error, or a TLS alert surfacing as one. A
/// syslog receiver never sends application data, so any completed read
/// means the connection is over; a read still pending after `wait` means
/// the peer is there.
async fn peer_closed(stream: &mut TlsStream<TcpStream>, wait: Duration) -> bool {
    use tokio::io::AsyncReadExt as _;
    let mut byte = [0u8; 1];
    !matches!(
        tokio::time::timeout(wait, stream.read(&mut byte)).await,
        Err(_elapsed)
    )
}

/// Printable US-ASCII without spaces, bounded; `-` when nothing is left.
fn sanitised(value: &str, max: usize) -> String {
    let mut out: String = value
        .chars()
        .take(max)
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .collect();
    if out.is_empty() {
        out.push('-');
    }
    out
}

/// Whether `host` is a loopback address or name (for the plaintext rule
/// the HTTP adapter applies; kept here beside the other host checks).
#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The path given for a key file, for messages.
#[must_use]
pub fn display(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record<'a>(seq: u64, kind: &'a str, json: &'a [u8], adverse: bool) -> ForwardRecord<'a> {
        ForwardRecord {
            seq,
            kind,
            timestamp: Some("2026-09-04T12:00:00.123Z"),
            adverse,
            json,
        }
    }

    #[test]
    fn frames_an_rfc_5424_message_with_octet_counting() {
        let mut out = Vec::new();
        SyslogForwarder::frame(
            &record(
                7,
                "tool_call_intent",
                br#"{"seq":7,"kind":"tool_call_intent"}"#,
                false,
            ),
            "gateway-0",
            &mut out,
        );
        let text = String::from_utf8(out).unwrap();
        let (len, message) = text.split_once(' ').unwrap();
        assert_eq!(len.parse::<usize>().unwrap(), message.len());
        assert_eq!(
            message,
            "<110>1 2026-09-04T12:00:00.123Z gateway-0 mcp-devtools - tool_call_intent - \u{feff}{\"seq\":7,\"kind\":\"tool_call_intent\"}"
        );
    }

    #[test]
    fn adverse_records_are_warnings_and_headers_are_sanitised() {
        let mut out = Vec::new();
        SyslogForwarder::frame(
            &ForwardRecord {
                seq: 1,
                kind: "egress_decision",
                timestamp: None,
                adverse: true,
                json: b"{}",
            },
            "host name\u{e9}",
            &mut out,
        );
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("<108>1 - host_name_ mcp-devtools - egress_decision - "),
            "{text}"
        );
    }

    #[test]
    fn two_frames_concatenate_without_ambiguity() {
        let mut out = Vec::new();
        SyslogForwarder::frame(&record(1, "a", b"{\"n\":1}", false), "h", &mut out);
        SyslogForwarder::frame(&record(2, "b", b"{\"n\":2}", false), "h", &mut out);
        let text = String::from_utf8(out).unwrap();
        let (len, rest) = text.split_once(' ').unwrap();
        let first_len: usize = len.parse().unwrap();
        let second = &rest[first_len..];
        assert!(second.starts_with(|c: char| c.is_ascii_digit()));
        assert!(second.contains("<110>1"));
    }

    #[test]
    fn url_parsing_accepts_only_syslog_tls_host_port() {
        let settings = SyslogSettings::parse_url(
            "syslog+tls://siem.example:6515",
            "o".into(),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            (settings.host.as_str(), settings.port),
            ("siem.example", 6515)
        );
        let default = SyslogSettings::parse_url(
            "syslog+tls://siem.example",
            "o".into(),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(default.port, DEFAULT_PORT);
        for bad in [
            "syslog://siem.example",
            "syslog+tcp://siem.example:514",
            "syslog+tls://user:pw@siem.example",
            "syslog+tls://siem.example/path",
            "syslog+tls://siem.example?x=1",
            "syslog+tls://",
        ] {
            assert!(
                SyslogSettings::parse_url(bad, "o".into(), Duration::from_secs(1)).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn client_certificate_halves_must_come_together() {
        let error = client_config(&TlsOptions {
            ca_file: None,
            client_cert: Some("/nonexistent".into()),
            client_key: None,
        })
        .unwrap_err();
        assert!(error.contains("must be given together"), "{error}");
    }

    #[test]
    fn loopback_hosts() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("siem.example"));
        assert!(!is_loopback_host("10.0.0.1"));
    }
}

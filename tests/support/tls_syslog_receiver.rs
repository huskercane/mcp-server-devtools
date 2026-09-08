//! An in-process RFC 5425 (octet-counted syslog over TLS) receiver, for
//! the syslog adapter's conformance run and the shipper tests. Speaks TLS
//! with the fixture certificate in `tests/fixtures/tls/`, optionally
//! requiring the fixture client certificate, parses each frame, and keeps
//! the messages it received.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(name)
}

/// One parsed RFC 5424 message.
#[derive(Debug, Clone)]
pub struct Message {
    pub pri: u8,
    pub header: String,
    /// The MSG part with the BOM stripped: the journal line.
    pub body: Vec<u8>,
}

impl Message {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("message body is the JSON record")
    }
}

pub struct Receiver {
    pub port: u16,
    messages: Arc<Mutex<Vec<Message>>>,
    down: Arc<AtomicBool>,
}

impl Receiver {
    /// Start listening on a loopback port. `require_client_cert` turns on
    /// mutual TLS against the fixture CA.
    pub async fn start(require_client_cert: bool) -> Self {
        let certs = CertificateDer::pem_file_iter(fixture("server.pem"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(fixture("server-key.pem")).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap();
        let config = if require_client_cert {
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_file_iter(fixture("ca.pem")).unwrap() {
                roots.add(cert.unwrap()).unwrap();
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap();
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .unwrap()
        } else {
            builder
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap()
        };
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let down = Arc::new(AtomicBool::new(false));
        let sink = Arc::clone(&messages);
        let gate = Arc::clone(&down);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                if gate.load(Ordering::Acquire) {
                    // Down: refuse the connection outright.
                    drop(tcp);
                    continue;
                }
                let acceptor = acceptor.clone();
                let sink = Arc::clone(&sink);
                let gate = Arc::clone(&gate);
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        if gate.load(Ordering::Acquire) {
                            // Went down mid-connection: close so the
                            // client's next write fails.
                            return;
                        }
                        let read = tokio::select! {
                            read = stream.read(&mut chunk) => read,
                            () = tokio::time::sleep(std::time::Duration::from_millis(20)) => continue,
                        };
                        match read {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                        }
                        while let Some((message, rest)) = parse_frame(&buffer) {
                            if !gate.load(Ordering::Acquire) {
                                sink.lock().unwrap().push(message);
                            }
                            buffer = rest;
                        }
                    }
                });
            }
        });
        Self {
            port,
            messages,
            down,
        }
    }

    pub fn url(&self) -> String {
        format!("syslog+tls://127.0.0.1:{}", self.port)
    }

    pub fn messages(&self) -> Vec<Message> {
        self.messages.lock().unwrap().clone()
    }

    /// Flip availability. Going down closes every open connection first
    /// (the connection tasks poll the flag every 20 ms), so the next
    /// delivery meets a closed peer, then a refused connect.
    pub async fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::Release);
        if down {
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        }
    }
}

/// Parse one `LEN SP MSG` frame off the front of `buffer`.
fn parse_frame(buffer: &[u8]) -> Option<(Message, Vec<u8>)> {
    let space = buffer.iter().position(|byte| *byte == b' ')?;
    let len: usize = std::str::from_utf8(&buffer[..space]).ok()?.parse().ok()?;
    let start = space + 1;
    if buffer.len() < start + len {
        return None;
    }
    let raw = &buffer[start..start + len];
    let rest = buffer[start + len..].to_vec();
    // <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
    let close = raw.iter().position(|byte| *byte == b'>')?;
    let pri: u8 = std::str::from_utf8(&raw[1..close]).ok()?.parse().ok()?;
    let after_pri = &raw[close + 1..];
    // Seven space-separated header fields (version through SD), then MSG.
    let mut fields = 0;
    let mut index = 0;
    while fields < 7 && index < after_pri.len() {
        if after_pri[index] == b' ' {
            fields += 1;
        }
        index += 1;
    }
    let header = String::from_utf8_lossy(&after_pri[..index.saturating_sub(1)]).into_owned();
    let body = after_pri[index..]
        .strip_prefix("\u{feff}".as_bytes())
        .unwrap_or(&after_pri[index..])
        .to_vec();
    Some((Message { pri, header, body }, rest))
}

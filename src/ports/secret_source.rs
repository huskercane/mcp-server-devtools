//! `SecretSource`: where the bytes behind a secret *reference* come from.
//!
//! Plan §3.8 (C.2a). A secret-bearing configuration value is either a
//! literal or a reference such as `file:///run/secrets/grafana#token`. The
//! reference names a **document** (the file, the Vault KV path, the Secrets
//! Manager entry) and, optionally, a key inside it. This port fetches the
//! document; extracting the key is domain logic in
//! [`crate::secrets::resolver`], so that two references into the same
//! document are always served from **one** fetch. That is what makes a
//! multi-part credential (Atlassian email + token, Zoom client id + secret)
//! rotate atomically for every adapter rather than only for the first one.
//!
//! ## Why this is its own port and not `KeychainBackend`
//!
//! [`crate::auth::keychain::KeychainBackend`] is synchronous, carries
//! `set`/`delete` for the `creds` CLI, and sits on the request path. A
//! provider is network I/O with its own authentication lifecycle. It gets an
//! async port that the request path never calls: the resolver fills a
//! snapshot in the background and `/mcp` reads the snapshot (§8, "no
//! provider call on the request path").
//!
//! ## What crosses the port
//!
//! Only the port's own types. A provider SDK error, an HTTP status, a
//! provider token — none of it reaches the domain. Every failure is one of
//! the three [`SecretSourceError`] shapes, whose text names the locator and
//! a category, never a value (constraint 8; plan §3.8 "Errors").
//!
//! Two implementations at day one: [`crate::secrets::FileSecretSource`] for
//! `file://` (always compiled in) and [`InMemorySecretSource`] for tests; the
//! conformance suite in `tests/secret_source_tests.rs` runs the same
//! assertions against both, which is how a later adapter is proven.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

/// The reference schemes the gateway recognises.
///
/// A configuration value starting with one of these followed by `://` is a
/// reference; anything else is a literal, so a secret that happens to
/// contain `://` under some other prefix is left untouched (constraint 1:
/// the community gateway's behaviour does not move). Adding a scheme is a
/// deliberate change here, not a parser heuristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// A file on a mounted volume: `file:///path[#json-key]`.
    File,
    /// `HashiCorp` Vault / `OpenBao` KV v2: `vault://mount/path#key` (C.2b).
    Vault,
    /// AWS Secrets Manager: `awssm://name-or-arn#json-key` (C.2c).
    AwsSecretsManager,
    /// Azure Key Vault: `azkv://vault-name/secret-name` (C.2d).
    AzureKeyVault,
}

impl Scheme {
    /// Every scheme, in the order the parser tries them.
    pub const ALL: [Self; 4] = [
        Self::File,
        Self::Vault,
        Self::AwsSecretsManager,
        Self::AzureKeyVault,
    ];

    /// The scheme text before `://`, and the `source` value audit records
    /// carry.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Vault => "vault",
            Self::AwsSecretsManager => "awssm",
            Self::AzureKeyVault => "azkv",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A document a source can fetch: the reference without its `#fragment`.
///
/// `target` is everything between `scheme://` and the fragment, uninterpreted
/// here; each adapter reads its own shape out of it (a path, a mount and
/// path, a name or ARN). Two references that differ only in their fragment
/// share a locator, and the resolver fetches a locator once.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretLocator {
    scheme: Scheme,
    target: String,
}

impl SecretLocator {
    #[must_use]
    pub fn new(scheme: Scheme, target: impl Into<String>) -> Self {
        Self {
            scheme,
            target: target.into(),
        }
    }

    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
}

impl fmt::Display for SecretLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}://{}", self.scheme, self.target)
    }
}

/// What a fetch returns: the document, the provider's version of it, and how
/// long the provider says it may be cached.
///
/// `document` is the whole secret as text — a plain value, or a JSON object
/// the resolver takes keys from. `version` is the rotation evidence: the
/// provider's own version id where it has one, a content hash otherwise.
/// It is copied into every audit record that names the credential, so it
/// must never be derived from anything secret in a reversible way.
#[derive(Clone, PartialEq, Eq)]
pub struct FetchedSecret {
    document: String,
    version: String,
    ttl: Option<Duration>,
}

impl FetchedSecret {
    #[must_use]
    pub fn new(document: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            document: document.into(),
            version: version.into(),
            ttl: None,
        }
    }

    /// Attach the provider's lease or cache hint.
    #[must_use]
    pub const fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    #[must_use]
    pub fn document(&self) -> &str {
        &self.document
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub const fn ttl(&self) -> Option<Duration> {
        self.ttl
    }
}

impl fmt::Debug for FetchedSecret {
    /// Redacted: the document is the secret.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FetchedSecret")
            .field("document", &"<redacted>")
            .field("version", &self.version)
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// The one error shape a source may return. Its text names the locator and
/// a category — never the document, never a provider credential, never a
/// provider's own error text (which may quote a request header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSourceError {
    /// The document does not exist at the locator.
    NotFound { locator: String },
    /// The provider could not be reached, refused the request, or the
    /// document could not be read. `detail` is a short category chosen by
    /// the adapter (an `io::ErrorKind` name, an HTTP status class), not
    /// pass-through text.
    Unavailable { locator: String, detail: String },
    /// The document was read but is not usable as text.
    Malformed { locator: String, detail: String },
}

impl SecretSourceError {
    #[must_use]
    pub fn locator(&self) -> &str {
        match self {
            Self::NotFound { locator }
            | Self::Unavailable { locator, .. }
            | Self::Malformed { locator, .. } => locator,
        }
    }

    /// The fixed category name (plan §3.8): what an operator greps for.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "secret_source_not_found",
            Self::Unavailable { .. } => "secret_source_unavailable",
            Self::Malformed { .. } => "secret_source_malformed",
        }
    }
}

impl fmt::Display for SecretSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { locator } => {
                write!(formatter, "{}: {locator} does not exist", self.category())
            }
            Self::Unavailable { locator, detail } | Self::Malformed { locator, detail } => {
                write!(formatter, "{}: {locator} ({detail})", self.category())
            }
        }
    }
}

impl std::error::Error for SecretSourceError {}

/// Boxed because sources are held as `Arc<dyn SecretSource>` keyed by
/// scheme: the set is decided by configuration at startup, so static
/// dispatch has nothing to specialise on. Never on the request path.
pub type SecretFetchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<FetchedSecret, SecretSourceError>> + Send + 'a>>;

/// Fetch a secret document by locator.
pub trait SecretSource: Send + Sync {
    /// The scheme this source serves. The resolver routes by it.
    fn scheme(&self) -> Scheme;

    /// Fetch the current document. Called from the background refresher and
    /// at startup — never from a tool call.
    fn fetch<'a>(&'a self, locator: &'a SecretLocator) -> SecretFetchFuture<'a>;
}

/// The test source: documents put in by the test, versions counted per put,
/// an outage switch. Serves any scheme so a test can stand it in for one.
pub struct InMemorySecretSource {
    scheme: Scheme,
    state: Mutex<InMemoryState>,
}

#[derive(Default)]
struct InMemoryState {
    documents: HashMap<String, (String, u64)>,
    outage: Option<String>,
    fetches: u64,
}

impl InMemorySecretSource {
    #[must_use]
    pub fn new(scheme: Scheme) -> Self {
        Self {
            scheme,
            state: Mutex::new(InMemoryState::default()),
        }
    }

    /// Store a document, bumping its version.
    pub fn put(&self, target: &str, document: &str) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = state
            .documents
            .entry(target.to_owned())
            .or_insert_with(|| (String::new(), 0));
        document.clone_into(&mut entry.0);
        entry.1 += 1;
    }

    pub fn remove(&self, target: &str) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .documents
            .remove(target);
    }

    /// Make every fetch fail with `Unavailable` until [`Self::restore`].
    pub fn fail_with(&self, detail: &str) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outage = Some(detail.to_owned());
    }

    pub fn restore(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outage = None;
    }

    /// How many fetches have been made — the "one fetch per locator" proof.
    #[must_use]
    pub fn fetches(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fetches
    }
}

impl SecretSource for InMemorySecretSource {
    fn scheme(&self) -> Scheme {
        self.scheme
    }

    fn fetch<'a>(&'a self, locator: &'a SecretLocator) -> SecretFetchFuture<'a> {
        let result = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.fetches += 1;
            if let Some(detail) = &state.outage {
                Err(SecretSourceError::Unavailable {
                    locator: locator.to_string(),
                    detail: detail.clone(),
                })
            } else {
                state.documents.get(locator.target()).map_or_else(
                    || {
                        Err(SecretSourceError::NotFound {
                            locator: locator.to_string(),
                        })
                    },
                    |(document, version)| {
                        Ok(FetchedSecret::new(document.clone(), format!("v{version}")))
                    },
                )
            }
        };
        Box::pin(std::future::ready(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetched_secret_debug_is_redacted() {
        let fetched = FetchedSecret::new("hunter2", "v1");
        let text = format!("{fetched:?}");
        assert!(!text.contains("hunter2"));
        assert!(text.contains("v1"));
    }

    #[test]
    fn error_text_names_the_locator_and_a_category_only() {
        let error = SecretSourceError::Unavailable {
            locator: "file:///run/secrets/x".to_owned(),
            detail: "PermissionDenied".to_owned(),
        };
        assert_eq!(
            error.to_string(),
            "secret_source_unavailable: file:///run/secrets/x (PermissionDenied)"
        );
        assert_eq!(error.category(), "secret_source_unavailable");
    }
}

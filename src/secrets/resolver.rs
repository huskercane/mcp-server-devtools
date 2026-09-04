//! Turning the references in a configuration into a [`SecretSnapshot`].

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;

use crate::ports::{Scheme, SecretLocator, SecretSource, SecretSourceError};

use super::reference::{ReferenceError, SecretReference};
use super::snapshot::{ResolvedSecret, SecretSnapshot};

/// The sources compiled into this build, by scheme.
///
/// A reference whose scheme has no source here is a typed startup error
/// (`no adapter compiled in for …`), never a missing implementation found
/// at the first tool call (plan §3.8, "Errors").
pub struct SecretResolver {
    sources: Vec<Arc<dyn SecretSource>>,
}

impl SecretResolver {
    #[must_use]
    pub fn new(sources: Vec<Arc<dyn SecretSource>>) -> Self {
        Self { sources }
    }

    /// The sources every build has: `file://`.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(vec![Arc::new(super::file::FileSecretSource)])
    }

    /// The default sources plus every compiled-in adapter the configuration
    /// enables: `vault://` when `MCP_VAULT_ADDR` is set (feature
    /// `secrets-vault`). Building an adapter does no network I/O; its
    /// settings are validated here, so a misconfigured provider is a
    /// startup refusal with a reason rather than a failed first fetch.
    ///
    /// # Errors
    ///
    /// The adapter's own configuration error, prefixed with its scheme.
    pub fn from_config(config: &crate::config::Config) -> Result<Self, String> {
        let mut sources: Vec<Arc<dyn SecretSource>> = vec![Arc::new(super::file::FileSecretSource)];
        #[cfg(feature = "secrets-vault")]
        if super::vault::VaultSettings::is_configured(config) {
            let vault = super::vault::VaultSecretSource::from_config(config)
                .map_err(|error| format!("vault://: {error}"))?;
            sources.push(Arc::new(vault));
        }
        #[cfg(not(feature = "secrets-vault"))]
        {
            let _ = (config, &mut sources);
        }
        Ok(Self::new(sources))
    }

    /// Whether this build carries an adapter for `scheme`, configured or
    /// not.
    #[must_use]
    pub const fn compiled_in(scheme: Scheme) -> bool {
        match scheme {
            Scheme::File => true,
            Scheme::Vault => cfg!(feature = "secrets-vault"),
            Scheme::AwsSecretsManager | Scheme::AzureKeyVault => false,
        }
    }

    #[must_use]
    pub fn source_for(&self, scheme: Scheme) -> Option<&Arc<dyn SecretSource>> {
        self.sources.iter().find(|source| source.scheme() == scheme)
    }

    /// Resolve every reference among `values`.
    ///
    /// Values that are not references are skipped, so the caller can hand
    /// over every configuration value without classifying them first. Each
    /// distinct document is fetched **once**, concurrently across documents,
    /// and every `#key` into it is taken from that single fetch: that is the
    /// atomic multi-part rule (plan §3.8), and it holds for every adapter.
    ///
    /// The first failure is the result — one unresolvable reference is a
    /// refusal, because a snapshot with a hole in it would turn into a
    /// credential-missing error at some later tool call with no pointer back
    /// to the cause.
    ///
    /// # Errors
    ///
    /// [`SecretResolveError`] naming the reference and the cause. Never the
    /// value.
    pub async fn resolve<'a>(
        &self,
        values: impl IntoIterator<Item = &'a str>,
    ) -> Result<SecretSnapshot, SecretResolveError> {
        // Deterministic order (BTreeMap) so the first error is stable.
        let mut by_locator: BTreeMap<String, (SecretLocator, Vec<SecretReference>)> =
            BTreeMap::new();
        for raw in values {
            let reference = match SecretReference::parse(raw) {
                Ok(Some(reference)) => reference,
                Ok(None) => continue,
                Err(cause) => {
                    return Err(SecretResolveError {
                        reference: raw.trim().to_owned(),
                        cause: ResolveCause::Invalid(cause),
                    });
                }
            };
            let key = reference.locator().to_string();
            by_locator
                .entry(key)
                .or_insert_with(|| (reference.locator().clone(), Vec::new()))
                .1
                .push(reference);
        }
        if by_locator.is_empty() {
            return Ok(SecretSnapshot::default());
        }

        let pending = by_locator.values().map(|(locator, references)| async move {
            let Some(source) = self.source_for(locator.scheme()) else {
                let scheme = locator.scheme();
                return Err(SecretResolveError {
                    reference: references[0].to_string(),
                    cause: if Self::compiled_in(scheme) {
                        ResolveCause::Unconfigured(scheme)
                    } else {
                        ResolveCause::NoSource(scheme)
                    },
                });
            };
            source
                .fetch(locator)
                .await
                .map_err(|cause| SecretResolveError {
                    reference: references[0].to_string(),
                    cause: ResolveCause::Source(cause),
                })
        });
        let documents = futures::future::join_all(pending).await;

        let mut entries = HashMap::with_capacity(by_locator.values().map(|(_, r)| r.len()).sum());
        for ((locator, references), document) in by_locator.values().zip(documents) {
            let fetched = document?;
            let source = locator.scheme().as_str();
            for reference in references {
                let value = extract(fetched.document(), reference.fragment()).map_err(|cause| {
                    SecretResolveError {
                        reference: reference.to_string(),
                        cause,
                    }
                })?;
                entries.insert(
                    reference.to_string(),
                    ResolvedSecret::new(value, source, fetched.version().to_owned()),
                );
            }
        }
        Ok(SecretSnapshot::new(entries))
    }
}

impl fmt::Debug for SecretResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_list()
            .entries(self.sources.iter().map(|source| source.scheme()))
            .finish()
    }
}

/// The value a reference names inside a fetched document.
///
/// Without a fragment the document *is* the value, less one trailing line
/// break — `echo -n` is the exception in practice, not the rule, and a
/// token with a newline glued on is never what anyone meant. With a
/// fragment the document is a JSON object and the value is the string under
/// that key; a non-string is an error rather than a stringification, so a
/// number that was meant as a string is caught at startup.
fn extract(document: &str, fragment: Option<&str>) -> Result<String, ResolveCause> {
    let value = match fragment {
        None => document
            .strip_suffix('\n')
            .map_or(document, |rest| rest.strip_suffix('\r').unwrap_or(rest))
            .to_owned(),
        Some(key) => {
            let parsed: serde_json::Value =
                serde_json::from_str(document).map_err(|_| ResolveCause::NotJsonObject)?;
            let object = parsed.as_object().ok_or(ResolveCause::NotJsonObject)?;
            match object.get(key) {
                None => return Err(ResolveCause::MissingKey(key.to_owned())),
                Some(serde_json::Value::String(value)) => value.clone(),
                Some(_) => return Err(ResolveCause::NotAString(key.to_owned())),
            }
        }
    };
    if value.trim().is_empty() {
        return Err(ResolveCause::Empty);
    }
    Ok(value)
}

/// Why a reference could not be resolved. Names keys and categories; never
/// document content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveCause {
    Invalid(ReferenceError),
    NoSource(Scheme),
    /// The adapter is compiled in but the configuration does not enable it
    /// (no `MCP_VAULT_ADDR`, say).
    Unconfigured(Scheme),
    Source(SecretSourceError),
    NotJsonObject,
    MissingKey(String),
    NotAString(String),
    Empty,
}

impl ResolveCause {
    /// The fixed category (what the health signal and the operator log
    /// carry).
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "secret_reference_invalid",
            Self::NoSource(_) => "secret_source_not_compiled",
            Self::Unconfigured(_) => "secret_source_unconfigured",
            Self::Source(error) => error.category(),
            Self::NotJsonObject | Self::MissingKey(_) | Self::NotAString(_) | Self::Empty => {
                "secret_document_malformed"
            }
        }
    }
}

impl fmt::Display for ResolveCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => write!(formatter, "{error}"),
            Self::NoSource(scheme) => write!(
                formatter,
                "no adapter for `{scheme}://` is compiled into this binary"
            ),
            Self::Unconfigured(scheme) => write!(
                formatter,
                "the `{scheme}://` adapter is compiled in but not configured (set {})",
                match scheme {
                    Scheme::Vault => "MCP_VAULT_ADDR and MCP_VAULT_AUTH",
                    Scheme::File | Scheme::AwsSecretsManager | Scheme::AzureKeyVault =>
                        "its address",
                }
            ),
            Self::Source(error) => write!(formatter, "{error}"),
            Self::NotJsonObject => formatter
                .write_str("the document is not a JSON object, so `#key` cannot select from it"),
            Self::MissingKey(key) => write!(formatter, "the document has no `{key}` key"),
            Self::NotAString(key) => write!(formatter, "`{key}` is not a JSON string"),
            Self::Empty => formatter.write_str("the value is empty"),
        }
    }
}

/// A reference that did not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretResolveError {
    /// The reference text (trimmed) — a locator and key, never a value.
    pub reference: String,
    pub cause: ResolveCause,
}

impl fmt::Display for SecretResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cannot resolve secret reference {}: {}",
            self.reference, self.cause
        )
    }
}

impl std::error::Error for SecretResolveError {}

impl From<SecretResolveError> for crate::error::McpError {
    fn from(error: SecretResolveError) -> Self {
        crate::error::unexpected(error.to_string(), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::InMemorySecretSource;

    fn resolver(source: Arc<InMemorySecretSource>) -> SecretResolver {
        SecretResolver::new(vec![source as Arc<dyn SecretSource>])
    }

    #[tokio::test]
    async fn one_fetch_serves_every_key_of_a_document() {
        let source = Arc::new(InMemorySecretSource::new(Scheme::File));
        source.put("/atlassian", r#"{"email":"a@x","token":"t1"}"#);
        let snapshot = resolver(Arc::clone(&source))
            .resolve([
                "file:///atlassian#email",
                "literal-value",
                " file:///atlassian#token ",
            ])
            .await
            .unwrap();
        assert_eq!(source.fetches(), 1);
        assert_eq!(snapshot.len(), 2);
        assert_eq!(
            snapshot.get("file:///atlassian#email").unwrap().value(),
            "a@x"
        );
        let token = snapshot.get("file:///atlassian#token").unwrap();
        assert_eq!(token.value(), "t1");
        assert_eq!(token.provenance().source, "file");
        assert_eq!(token.provenance().version, "v1");
    }

    #[tokio::test]
    async fn whole_document_loses_one_trailing_newline_only() {
        let source = Arc::new(InMemorySecretSource::new(Scheme::File));
        source.put("/a", "tok\n");
        source.put("/b", "tok\r\n");
        source.put("/c", "tok\n\n");
        let snapshot = resolver(source)
            .resolve(["file:///a", "file:///b", "file:///c"])
            .await
            .unwrap();
        assert_eq!(snapshot.get("file:///a").unwrap().value(), "tok");
        assert_eq!(snapshot.get("file:///b").unwrap().value(), "tok");
        assert_eq!(snapshot.get("file:///c").unwrap().value(), "tok\n");
    }

    #[tokio::test]
    async fn every_failure_names_the_reference_and_never_the_document() {
        let source = Arc::new(InMemorySecretSource::new(Scheme::File));
        source.put("/json", r#"{"n": 5, "s": "", "secret-value-xyz": "x"}"#);
        source.put("/text", "not json");
        let resolver = resolver(source);
        for (reference, expected) in [
            ("file:///missing", "secret_source_not_found"),
            ("file:///json#absent", "secret_document_malformed"),
            ("file:///json#n", "secret_document_malformed"),
            ("file:///json#s", "secret_document_malformed"),
            ("file:///text#k", "secret_document_malformed"),
            ("file:///json#", "secret_reference_invalid"),
            (
                "vault://secret/x#k",
                if SecretResolver::compiled_in(Scheme::Vault) {
                    "secret_source_unconfigured"
                } else {
                    "secret_source_not_compiled"
                },
            ),
            ("awssm://prod/x#k", "secret_source_not_compiled"),
        ] {
            let error = resolver.resolve([reference]).await.unwrap_err();
            assert_eq!(error.cause.category(), expected, "{reference}");
            assert_eq!(error.reference, reference);
            let text = error.to_string();
            assert!(text.contains(reference), "{text}");
            assert!(!text.contains("secret-value-xyz"), "{text}");
            assert!(!text.contains("not json"), "{text}");
        }
    }

    #[tokio::test]
    async fn no_references_is_an_empty_snapshot_with_no_fetch() {
        let source = Arc::new(InMemorySecretSource::new(Scheme::File));
        let snapshot = resolver(Arc::clone(&source))
            .resolve(["plain", "keychain", "https://x/#y"])
            .await
            .unwrap();
        assert!(snapshot.is_empty());
        assert_eq!(source.fetches(), 0);
    }
}

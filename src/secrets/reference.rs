//! Parsing a configuration value into a [`SecretReference`].

use std::fmt;

use crate::ports::{Scheme, SecretLocator};

/// The `"keychain"` sentinel and its URI spelling. Both mean "look this slot
/// up in the OS keychain", and the cascade in [`crate::auth`] treats them
/// identically. Not a [`SecretReference`]: the keychain is addressed by the
/// registry row (kind, vendor, principal), not by anything in the value, and
/// it is read synchronously on the request path as it always was.
#[must_use]
pub fn is_keychain_sentinel(value: &str) -> bool {
    matches!(value, "keychain" | "keychain://")
}

/// Whether a value is a reference, by prefix. Cheap enough for every
/// [`crate::config::Config::get_for`]: one byte dispatch and at most one
/// short prefix comparison, no allocation.
#[must_use]
pub fn is_reference(value: &str) -> bool {
    scheme_of(value).is_some()
}

fn scheme_of(value: &str) -> Option<Scheme> {
    let bytes = value.as_bytes();
    let candidate = match bytes.first()? {
        b'f' => Scheme::File,
        b'v' => Scheme::Vault,
        b'a' => match bytes.get(1)? {
            b'w' => Scheme::AwsSecretsManager,
            b'z' => Scheme::AzureKeyVault,
            _ => return None,
        },
        _ => return None,
    };
    let name = candidate.as_str();
    (bytes.len() > name.len() + 2
        && bytes.starts_with(name.as_bytes())
        && &bytes[name.len()..name.len() + 3] == b"://")
        .then_some(candidate)
}

/// A parsed reference: the document to fetch and, optionally, the key to
/// take from it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretReference {
    locator: SecretLocator,
    fragment: Option<String>,
}

impl SecretReference {
    /// Parse a configuration value.
    ///
    /// `Ok(None)` is a literal — not a reference at all. `Err` is a value
    /// that names a known scheme but is not well-formed, which is a
    /// configuration error rather than a secret: `file://` with nothing
    /// after it, or a trailing `#` with no key.
    ///
    /// The value is trimmed first, as every secret is before use.
    pub fn parse(raw: &str) -> Result<Option<Self>, ReferenceError> {
        let value = raw.trim();
        let Some(scheme) = scheme_of(value) else {
            return Ok(None);
        };
        let rest = &value[scheme.as_str().len() + 3..];
        let (target, fragment) = match rest.split_once('#') {
            Some((target, fragment)) => (target, Some(fragment)),
            None => (rest, None),
        };
        if target.is_empty() {
            return Err(ReferenceError::EmptyTarget { scheme });
        }
        if fragment == Some("") {
            return Err(ReferenceError::EmptyFragment { scheme });
        }
        // A KV v2 secret is a document of keys; without a `#key` there is
        // no value to send anywhere, so the reference is refused here
        // rather than turned into a JSON blob pretending to be a token.
        if scheme == Scheme::Vault && fragment.is_none() {
            return Err(ReferenceError::FragmentRequired { scheme });
        }
        Ok(Some(Self {
            locator: SecretLocator::new(scheme, target),
            fragment: fragment.map(str::to_owned),
        }))
    }

    #[must_use]
    pub const fn locator(&self) -> &SecretLocator {
        &self.locator
    }

    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }

    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.locator.scheme()
    }
}

impl fmt::Display for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.locator)?;
        if let Some(fragment) = &self.fragment {
            write!(formatter, "#{fragment}")?;
        }
        Ok(())
    }
}

/// A value that names a scheme but cannot be a reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceError {
    EmptyTarget {
        scheme: Scheme,
    },
    EmptyFragment {
        scheme: Scheme,
    },
    /// The scheme names documents of keys, so a `#key` is not optional.
    FragmentRequired {
        scheme: Scheme,
    },
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTarget { scheme } => {
                write!(formatter, "`{scheme}://` names nothing to fetch")
            }
            Self::EmptyFragment { scheme } => write!(
                formatter,
                "`{scheme}://…#` ends in `#` with no key after it"
            ),
            Self::FragmentRequired { scheme } => write!(
                formatter,
                "`{scheme}://` names a document of keys; add `#<key>` to say which one"
            ),
        }
    }
}

impl std::error::Error for ReferenceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_are_not_references() {
        for literal in [
            "",
            "hunter2",
            "keychain",
            "keychain://",
            "https://example.com/a#b",
            "files://x",
            "file:/x",
            "FILE:///x",
            "ftp://x",
            "aws://x",
            "az://x",
        ] {
            assert!(!is_reference(literal), "{literal:?} must be a literal");
            if !is_keychain_sentinel(literal) {
                assert_eq!(SecretReference::parse(literal), Ok(None), "{literal:?}");
            }
        }
    }

    #[test]
    fn keychain_alias_spellings() {
        assert!(is_keychain_sentinel("keychain"));
        assert!(is_keychain_sentinel("keychain://"));
        assert!(!is_keychain_sentinel("keychain://x"));
    }

    #[test]
    fn file_reference_with_and_without_fragment() {
        let plain = SecretReference::parse(" file:///run/secrets/token \n")
            .unwrap()
            .unwrap();
        assert_eq!(plain.scheme(), Scheme::File);
        assert_eq!(plain.locator().target(), "/run/secrets/token");
        assert_eq!(plain.fragment(), None);
        assert_eq!(plain.to_string(), "file:///run/secrets/token");

        let keyed = SecretReference::parse("file:///run/secrets/atlassian#api_token")
            .unwrap()
            .unwrap();
        assert_eq!(keyed.locator().target(), "/run/secrets/atlassian");
        assert_eq!(keyed.fragment(), Some("api_token"));
        assert_eq!(keyed.locator(), plain_locator("/run/secrets/atlassian"));
    }

    fn plain_locator(target: &str) -> &SecretLocator {
        Box::leak(Box::new(SecretLocator::new(Scheme::File, target)))
    }

    #[test]
    fn cloud_schemes_parse_even_when_no_adapter_is_compiled() {
        let vault = SecretReference::parse("vault://secret/mcp/grafana#token")
            .unwrap()
            .unwrap();
        assert_eq!(vault.scheme(), Scheme::Vault);
        assert_eq!(vault.locator().target(), "secret/mcp/grafana");
        let aws = SecretReference::parse("awssm://prod/mcp#token")
            .unwrap()
            .unwrap();
        assert_eq!(aws.scheme(), Scheme::AwsSecretsManager);
        let azure = SecretReference::parse("azkv://corp-kv/grafana-token")
            .unwrap()
            .unwrap();
        assert_eq!(azure.scheme(), Scheme::AzureKeyVault);
        assert_eq!(azure.fragment(), None);
        assert_eq!(
            SecretReference::parse("vault://secret/mcp/grafana"),
            Err(ReferenceError::FragmentRequired {
                scheme: Scheme::Vault
            })
        );
    }

    #[test]
    fn malformed_references_are_errors_not_literals() {
        assert_eq!(
            SecretReference::parse("file:///"),
            Ok(Some(SecretReference {
                locator: SecretLocator::new(Scheme::File, "/"),
                fragment: None
            }))
        );
        assert_eq!(
            SecretReference::parse("file:///x#"),
            Err(ReferenceError::EmptyFragment {
                scheme: Scheme::File
            })
        );
        assert_eq!(
            SecretReference::parse("vault://#k"),
            Err(ReferenceError::EmptyTarget {
                scheme: Scheme::Vault
            })
        );
        // A bare scheme is a broken reference, not a token: refusing it by
        // name beats sending `file://` upstream as a credential.
        assert!(is_reference("file://"));
        assert_eq!(
            SecretReference::parse("file://"),
            Err(ReferenceError::EmptyTarget {
                scheme: Scheme::File
            })
        );
    }

    #[test]
    fn fragment_splits_at_the_first_hash() {
        let reference = SecretReference::parse("file:///x#a#b").unwrap().unwrap();
        assert_eq!(reference.locator().target(), "/x");
        assert_eq!(reference.fragment(), Some("a#b"));
    }
}

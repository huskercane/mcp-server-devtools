//! `file://`: a secret on a mounted volume.
//!
//! The first adapter, and the one that is always compiled in. On Kubernetes
//! a `Secret` volume or a CSI Secrets Store volume (Vault, AWS, and Azure all
//! ship CSI providers) is refreshed by the kubelet with an atomic symlink
//! swap, so re-reading the path on every refresh sees each rotation whole.
//! Outside Kubernetes it is a Docker secret, a systemd credential, or any
//! file an operator can rotate in place.
//!
//! The version is a content hash: the volume has no version id of its own,
//! and the hash changes exactly when the bytes do. Only a prefix of it is
//! kept — enough to tell two rotations apart in an audit record, not enough
//! to be worth attacking as a commitment to the secret. It is a hash of a
//! high-entropy secret, so it does not leak the value; a low-entropy
//! secret (a short password) would be guessable from a full digest, which
//! is the other reason the record carries a prefix.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::ports::{
    FetchedSecret, Scheme, SecretFetchFuture, SecretLocator, SecretSource, SecretSourceError,
};

/// How many hex characters of the content hash become the version.
const VERSION_HEX_CHARS: usize = 16;

/// Largest file the adapter will read. A secret is small; a multi-megabyte
/// "secret" is a misconfiguration (or a device), and reading it into the
/// snapshot on every refresh would be a self-inflicted outage.
pub const MAX_SECRET_FILE_BYTES: u64 = 1024 * 1024;

/// Reads `file:///absolute/path` documents.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileSecretSource;

impl FileSecretSource {
    /// The filesystem path a locator names. `file:///etc/x` is `/etc/x`;
    /// `file://host/x` is refused, because a host part means something else
    /// on every platform and nothing here. On Windows `file:///C:/x` is
    /// `C:/x`.
    ///
    /// Percent-encoding is **not** decoded: a path with a space or a `#` in
    /// it cannot be referenced, and that is documented rather than
    /// half-supported.
    pub fn path_for(locator: &SecretLocator) -> Result<PathBuf, SecretSourceError> {
        let target = locator.target();
        if !target.starts_with('/') {
            return Err(SecretSourceError::Malformed {
                locator: locator.to_string(),
                detail: "path must be absolute: file:///path".to_owned(),
            });
        }
        let path = if cfg!(windows) && target.as_bytes().get(2) == Some(&b':') {
            &target[1..]
        } else {
            target
        };
        Ok(Path::new(path).to_path_buf())
    }
}

/// `sha256:<first 16 hex chars>` of the bytes.
#[must_use]
pub fn content_version(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut version = String::with_capacity(7 + VERSION_HEX_CHARS);
    version.push_str("sha256:");
    for byte in digest.iter().take(VERSION_HEX_CHARS / 2) {
        use std::fmt::Write as _;
        let _ = write!(version, "{byte:02x}");
    }
    version
}

impl SecretSource for FileSecretSource {
    fn scheme(&self) -> Scheme {
        Scheme::File
    }

    fn fetch<'a>(&'a self, locator: &'a SecretLocator) -> SecretFetchFuture<'a> {
        Box::pin(async move {
            let path = Self::path_for(locator)?;
            let unavailable = |detail: String| SecretSourceError::Unavailable {
                locator: locator.to_string(),
                detail,
            };
            // Size first: a refusal to read a huge file must not read it.
            let metadata = tokio::fs::metadata(&path).await.map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    SecretSourceError::NotFound {
                        locator: locator.to_string(),
                    }
                } else {
                    unavailable(format!("{:?}", error.kind()))
                }
            })?;
            if metadata.len() > MAX_SECRET_FILE_BYTES {
                return Err(SecretSourceError::Malformed {
                    locator: locator.to_string(),
                    detail: format!("larger than {MAX_SECRET_FILE_BYTES} bytes"),
                });
            }
            let bytes = tokio::fs::read(&path).await.map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    SecretSourceError::NotFound {
                        locator: locator.to_string(),
                    }
                } else {
                    unavailable(format!("{:?}", error.kind()))
                }
            })?;
            let version = content_version(&bytes);
            let document = String::from_utf8(bytes).map_err(|_| SecretSourceError::Malformed {
                locator: locator.to_string(),
                detail: "not UTF-8".to_owned(),
            })?;
            Ok(FetchedSecret::new(document, version))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_a_short_hash_prefix_that_tracks_content() {
        let one = content_version(b"token-1");
        let two = content_version(b"token-2");
        assert!(one.starts_with("sha256:"));
        assert_eq!(one.len(), 7 + VERSION_HEX_CHARS);
        assert_ne!(one, two);
        assert_eq!(one, content_version(b"token-1"));
    }

    #[test]
    fn host_form_is_refused() {
        let locator = SecretLocator::new(Scheme::File, "host/etc/x");
        let error = FileSecretSource::path_for(&locator).unwrap_err();
        assert!(matches!(error, SecretSourceError::Malformed { .. }));
        assert!(error.to_string().contains("file://host/etc/x"));
    }

    #[test]
    fn absolute_path_is_taken_verbatim() {
        let locator = SecretLocator::new(Scheme::File, "/run/secrets/x y");
        assert_eq!(
            FileSecretSource::path_for(&locator).unwrap(),
            PathBuf::from("/run/secrets/x y")
        );
    }
}

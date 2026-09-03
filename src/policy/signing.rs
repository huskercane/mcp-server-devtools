//! Ed25519 detached signatures (WPs B.3, B.4, B.6).
//!
//! One primitive, three uses: a policy document (`MCP_POLICY_FILE`) and the
//! revocation list (`MCP_REVOCATION_FILE`) are signed by whoever authors
//! them and verified by every gateway; audit checkpoints are signed by the
//! gateway and verified offline by `mcp-devtools audit verify`. The keys are
//! **not** shared between those two directions — policy authors hold the
//! policy signing key and the gateway holds only its public half, while the
//! gateway holds the audit signing key and an auditor holds only its public
//! half — so a compromised gateway cannot publish policy, and a policy
//! author cannot forge audit evidence.
//!
//! ## Format
//!
//! - **Private key**: a PKCS#8 v2 DER document on disk, created by
//!   [`write_key_file`] with owner-only permissions. Loaded with
//!   [`SigningKey::load`], which refuses a file readable by anyone else.
//! - **Public key**: the raw 32-byte Ed25519 key, base64 (standard alphabet,
//!   padded) — short enough for an environment variable or a `ConfigMap`.
//! - **Signature**: 64 bytes, base64, on one line in a sidecar file named
//!   `<file>.sig` next to the file it signs ([`detached_signature_path`]).
//!
//! ## Domain separation
//!
//! Every signature is over `<domain>\n<message>`, where the domain names
//! what is being signed ([`Domain`]). A signature over a policy document
//! therefore never verifies as a signature over a revocation list of the
//! same bytes, and neither verifies as an audit checkpoint — even if a
//! deployment reuses one key for two purposes against the advice above.
//!
//! Nothing here logs, formats, or otherwise emits key material. Errors are
//! categories plus the path of the file involved.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

/// Suffix of the detached signature sidecar: `policy.yaml` → `policy.yaml.sig`.
pub const SIGNATURE_SUFFIX: &str = ".sig";

/// Length of a raw Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Largest signature sidecar read. A base64 signature is 88 bytes; this
/// leaves room for a trailing newline and nothing else.
const MAX_SIGNATURE_FILE_BYTES: u64 = 256;

/// What a signature is over. The variant's label is prefixed to the
/// message before signing, so signatures cannot be replayed across uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// A policy document (`MCP_POLICY_FILE`).
    PolicyBundle,
    /// The revocation list (`MCP_REVOCATION_FILE`).
    RevocationList,
    /// An audit-journal checkpoint record.
    AuditCheckpoint,
}

impl Domain {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::PolicyBundle => b"mcp-devtools/policy-bundle/v1\n",
            Self::RevocationList => b"mcp-devtools/revocation-list/v1\n",
            Self::AuditCheckpoint => b"mcp-devtools/audit-checkpoint/v1\n",
        }
    }

    fn framed(self, message: &[u8]) -> Vec<u8> {
        let label = self.label();
        let mut framed = Vec::with_capacity(label.len() + message.len());
        framed.extend_from_slice(label);
        framed.extend_from_slice(message);
        framed
    }
}

/// Why a signing or verification step failed. Categories and file paths
/// only — never key bytes, never the signature, never the signed content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningError(String);

impl SigningError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for SigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for SigningError {}

/// A private Ed25519 key. Deliberately neither `Clone`, `Debug`, nor
/// `Serialize`: it is loaded once by the process that signs, used, and
/// dropped.
pub struct SigningKey {
    pair: Ed25519KeyPair,
}

impl SigningKey {
    /// Generate a fresh key. Returns the key and its PKCS#8 document, which
    /// is the only form the private half is ever written in.
    ///
    /// # Errors
    ///
    /// When the crypto provider cannot generate or serialize the key.
    pub fn generate() -> Result<(Self, Vec<u8>), SigningError> {
        let document = Ed25519KeyPair::generate_pkcs8(&aws_lc_rs::rand::SystemRandom::new())
            .map_err(|_| SigningError::new("cannot generate an Ed25519 key"))?;
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref())
            .map_err(|_| SigningError::new("generated key does not round-trip"))?;
        Ok((Self { pair }, document.as_ref().to_vec()))
    }

    /// Parse a PKCS#8 (v1 or v2) DER document.
    ///
    /// # Errors
    ///
    /// When the bytes are not a PKCS#8 Ed25519 private key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, SigningError> {
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
            .map_err(|_| SigningError::new("not a PKCS#8 Ed25519 private key"))?;
        Ok(Self { pair })
    }

    /// Load a key file written by [`write_key_file`].
    ///
    /// On Unix the file must not be readable by group or others: a signing
    /// key that another user on the host can read is not a signing key.
    /// This is checked before the bytes are read, so a misconfigured file
    /// is refused without ever being loaded.
    ///
    /// # Errors
    ///
    /// When the file cannot be read, is too permissive, or does not parse.
    pub fn load(path: &Path) -> Result<Self, SigningError> {
        let metadata = std::fs::metadata(path).map_err(|error| {
            SigningError::new(format!("cannot read key file {}: {error}", path.display()))
        })?;
        if !metadata.is_file() {
            return Err(SigningError::new(format!(
                "key file {} is not a regular file",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(SigningError::new(format!(
                    "key file {} is readable by other users (mode {mode:04o}); a signing \
                     key must be owner-only (0600)",
                    path.display()
                )));
            }
        }
        let der = std::fs::read(path).map_err(|error| {
            SigningError::new(format!("cannot read key file {}: {error}", path.display()))
        })?;
        Self::from_pkcs8(&der)
            .map_err(|error| SigningError::new(format!("key file {}: {error}", path.display())))
    }

    /// The public half.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        bytes.copy_from_slice(self.pair.public_key().as_ref());
        VerifyingKey { bytes }
    }

    /// Sign `message` under `domain`.
    #[must_use]
    pub fn sign(&self, domain: Domain, message: &[u8]) -> Signature {
        let signature = self.pair.sign(&domain.framed(message));
        let mut bytes = [0u8; SIGNATURE_LEN];
        bytes.copy_from_slice(signature.as_ref());
        Signature { bytes }
    }
}

/// A public Ed25519 key.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    bytes: [u8; PUBLIC_KEY_LEN],
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifyingKey")
            .field("key_id", &self.key_id())
            .finish()
    }
}

impl VerifyingKey {
    /// Parse the base64 form.
    ///
    /// # Errors
    ///
    /// When the text is not base64 or does not decode to 32 bytes.
    pub fn from_base64(text: &str) -> Result<Self, SigningError> {
        let decoded = BASE64
            .decode(text.trim())
            .map_err(|_| SigningError::new("public key is not base64"))?;
        let bytes: [u8; PUBLIC_KEY_LEN] = decoded.try_into().map_err(|_| {
            SigningError::new(format!(
                "public key must be {PUBLIC_KEY_LEN} bytes of raw Ed25519 key material"
            ))
        })?;
        Ok(Self { bytes })
    }

    /// The base64 form, for configuration and for printing after keygen.
    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.bytes)
    }

    /// The raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// A short, stable identifier for the key: `ed25519:` plus the first
    /// eight bytes of the SHA-256 of the public key, in hex. Recorded on
    /// signed records so a verifier knows which key to check with.
    #[must_use]
    pub fn key_id(&self) -> String {
        use std::fmt::Write as _;

        use sha2::{Digest as _, Sha256};

        let digest = Sha256::digest(self.bytes);
        let mut id = String::with_capacity(24);
        id.push_str("ed25519:");
        for byte in &digest[..8] {
            let _ = write!(id, "{byte:02x}");
        }
        id
    }

    /// Verify `signature` over `message` under `domain`.
    ///
    /// # Errors
    ///
    /// When the signature does not verify.
    pub fn verify(
        &self,
        domain: Domain,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SigningError> {
        UnparsedPublicKey::new(&ED25519, self.bytes)
            .verify(&domain.framed(message), &signature.bytes)
            .map_err(|_| SigningError::new("signature does not verify"))
    }
}

/// A detached signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    bytes: [u8; SIGNATURE_LEN],
}

impl fmt::Debug for Signature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Signature(..)")
    }
}

impl Signature {
    /// Parse the base64 form.
    ///
    /// # Errors
    ///
    /// When the text is not base64 or does not decode to 64 bytes.
    pub fn from_base64(text: &str) -> Result<Self, SigningError> {
        let decoded = BASE64
            .decode(text.trim())
            .map_err(|_| SigningError::new("signature is not base64"))?;
        let bytes: [u8; SIGNATURE_LEN] = decoded
            .try_into()
            .map_err(|_| SigningError::new(format!("signature must be {SIGNATURE_LEN} bytes")))?;
        Ok(Self { bytes })
    }

    /// The base64 form.
    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.bytes)
    }
}

/// `<file>.sig`, next to `file`.
#[must_use]
pub fn detached_signature_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(SIGNATURE_SUFFIX);
    PathBuf::from(name)
}

/// Read the detached signature for `file` (from `<file>.sig`).
///
/// # Errors
///
/// When the sidecar is missing, unreadable, oversized, or not a signature.
pub fn read_detached(file: &Path) -> Result<Signature, SigningError> {
    let path = detached_signature_path(file);
    let metadata = std::fs::metadata(&path).map_err(|error| {
        SigningError::new(format!("cannot read signature {}: {error}", path.display()))
    })?;
    if metadata.len() > MAX_SIGNATURE_FILE_BYTES {
        return Err(SigningError::new(format!(
            "signature file {} is too large to be a signature",
            path.display()
        )));
    }
    let text = std::fs::read_to_string(&path).map_err(|error| {
        SigningError::new(format!("cannot read signature {}: {error}", path.display()))
    })?;
    Signature::from_base64(&text)
        .map_err(|error| SigningError::new(format!("signature file {}: {error}", path.display())))
}

/// Write the detached signature for `file` (to `<file>.sig`), replacing
/// any existing one atomically.
///
/// # Errors
///
/// When the sidecar cannot be written.
pub fn write_detached(file: &Path, signature: &Signature) -> io::Result<PathBuf> {
    let path = detached_signature_path(file);
    let mut text = signature.to_base64();
    text.push('\n');
    write_atomically(&path, text.as_bytes(), false)?;
    Ok(path)
}

/// Write a private key document to `path`, owner-only, refusing to
/// overwrite an existing file (a key that already exists is either in use
/// or a mistake, and neither should be silently replaced).
///
/// # Errors
///
/// When the file exists or cannot be created.
pub fn write_key_file(path: &Path, pkcs8: &[u8]) -> io::Result<()> {
    write_atomically(path, pkcs8, true)
}

/// Write `contents` to `path` via a temporary file and rename, so a reader
/// never sees a partial file. `owner_only` also sets mode `0600` and
/// refuses to replace an existing file.
fn write_atomically(path: &Path, contents: &[u8], owner_only: bool) -> io::Result<()> {
    use std::io::Write as _;

    if owner_only && path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; refusing to overwrite a key",
                path.display()
            ),
        ));
    }
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let temp = {
        let mut name = path.file_name().unwrap_or_default().to_owned();
        name.push(".tmp");
        directory.map_or_else(|| PathBuf::from(&name), |dir| dir.join(&name))
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if owner_only {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    let written = (|| {
        file.write_all(contents)?;
        file.sync_all()
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    drop(file);
    if owner_only && path.exists() {
        let _ = std::fs::remove_file(&temp);
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; refusing to overwrite a key",
                path.display()
            ),
        ));
    }
    std::fs::rename(&temp, path)?;
    if let Some(dir) = directory
        && let Ok(handle) = std::fs::File::open(dir)
    {
        // Best effort: the rename is durable once the directory is synced;
        // a platform that cannot sync a directory still has the file.
        let _ = handle.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip_and_domains_are_separated() {
        let (key, _pkcs8) = SigningKey::generate().unwrap();
        let public = key.verifying_key();
        let signature = key.sign(Domain::PolicyBundle, b"version: 1\nrules: []\n");
        assert!(
            public
                .verify(Domain::PolicyBundle, b"version: 1\nrules: []\n", &signature)
                .is_ok()
        );
        assert!(
            public
                .verify(
                    Domain::RevocationList,
                    b"version: 1\nrules: []\n",
                    &signature
                )
                .is_err(),
            "a policy signature must not verify as a revocation-list signature"
        );
        assert!(
            public
                .verify(Domain::PolicyBundle, b"version: 2\nrules: []\n", &signature)
                .is_err()
        );
        let other = SigningKey::generate().unwrap().0.verifying_key();
        assert!(
            other
                .verify(Domain::PolicyBundle, b"version: 1\nrules: []\n", &signature)
                .is_err()
        );
    }

    #[test]
    fn keys_and_signatures_round_trip_through_base64_and_pkcs8() {
        let (key, pkcs8) = SigningKey::generate().unwrap();
        let reloaded = SigningKey::from_pkcs8(&pkcs8).unwrap();
        assert_eq!(reloaded.verifying_key(), key.verifying_key());
        let public = VerifyingKey::from_base64(&key.verifying_key().to_base64()).unwrap();
        assert_eq!(public, key.verifying_key());
        assert!(public.key_id().starts_with("ed25519:"));
        assert_eq!(public.key_id().len(), "ed25519:".len() + 16);
        let signature = key.sign(Domain::AuditCheckpoint, b"x");
        let parsed = Signature::from_base64(&signature.to_base64()).unwrap();
        assert_eq!(parsed, signature);
        assert!(VerifyingKey::from_base64("not base64!").is_err());
        assert!(VerifyingKey::from_base64(&BASE64.encode([0u8; 31])).is_err());
        assert!(Signature::from_base64(&BASE64.encode([0u8; 63])).is_err());
    }

    #[test]
    fn detached_signature_lives_next_to_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("policy.yaml");
        std::fs::write(&file, b"version: 1\nrules: []\n").unwrap();
        assert!(read_detached(&file).is_err(), "no sidecar yet");
        let (key, _) = SigningKey::generate().unwrap();
        let signature = key.sign(Domain::PolicyBundle, b"version: 1\nrules: []\n");
        let sidecar = write_detached(&file, &signature).unwrap();
        assert_eq!(sidecar, dir.path().join("policy.yaml.sig"));
        assert_eq!(read_detached(&file).unwrap(), signature);
        std::fs::write(&sidecar, "garbage").unwrap();
        assert!(read_detached(&file).is_err());
    }

    #[test]
    fn key_files_are_owner_only_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing.key");
        let (key, pkcs8) = SigningKey::generate().unwrap();
        write_key_file(&path, &pkcs8).unwrap();
        assert_eq!(
            write_key_file(&path, &pkcs8).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let loaded = SigningKey::load(&path).unwrap();
        assert_eq!(loaded.verifying_key(), key.verifying_key());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let error = SigningKey::load(&path).err().unwrap().to_string();
            assert!(error.contains("readable by other users"), "{error}");
        }
    }
}

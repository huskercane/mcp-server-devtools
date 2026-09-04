//! The revocation list: emergency deny by subject, by token id, or by
//! issue time (plan §3.6, WP B.4).
//!
//! Token expiry and group changes at the identity provider take effect
//! when a token expires and a new one is minted — bounded by the token TTL
//! plus the validated-token cache. That is fine for offboarding on a
//! schedule and useless in an incident. The revocation list is the control
//! that acts *now*:
//!
//! - **by subject**: every token of that `sub` is refused, cached or not;
//! - **by token id**: one `jti`, for a leaked token whose owner keeps working;
//! - **`not_before`** (`revoke all`): every token issued before that instant
//!   is refused, which invalidates the whole population at once — the
//!   answer to a signing-key compromise at the identity provider or a
//!   suspected gateway breach, after the key is rotated.
//!
//! The list is a signed, hot-reloaded [`SignedBundle`] like the policy —
//! same watcher, same journaling, same "last good list stays in force"
//! posture — and travels with it as the *policy bundle*. It is enforced in
//! the bearer middleware **after** validation and **regardless of the
//! validated-token cache**, so a revocation takes effect at the next
//! request once the watcher has picked the file up (≤ the poll interval),
//! not at the next cache miss. The cache is cleared and the revoked
//! subjects' sessions closed on every change as well, so no cached
//! validation or bound session outlives the list that revoked it.
//!
//! Fail closed on the facts: a token with no `iat` cannot be dated, so a
//! `not_before` cut-off revokes it; a token with no `jti` cannot be named,
//! so per-token revocation cannot help its owner — revoke the subject.
//!
//! ## Document
//!
//! ```yaml
//! version: 1
//! subjects:
//!   - subject: alice@acme.example
//!     revoked_at: 2026-09-03T10:00:00Z
//!     reason: offboarded
//! token_ids:
//!   - token_id: AT.5f3…
//!     revoked_at: 2026-09-03T10:05:00Z
//!     reason: pasted into a ticket
//! not_before:
//!   at: 2026-09-03T09:00:00Z
//!   reason: IdP signing key rotated after suspected compromise
//! ```
//!
//! Written by `mcp-devtools revoke …`, which rewrites the whole file and
//! re-signs it; hand-edited lists work too, as long as they are re-signed.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::policy::bundle::{BundleDocument, BundleError, SignedBundle, version_label};
use crate::policy::signing::Domain;
use crate::ports::audit_sink::{ControlEvent, ControlEventKind};
use crate::ports::token_validator::{Authenticated, TokenFacts};

/// Config key naming the revocation list. Required in enterprise mode.
pub const REVOCATION_FILE_KEY: &str = "MCP_REVOCATION_FILE";

/// Largest number of entries of either kind. A list past this is not a
/// revocation list, it is a mistake — and each entry costs a hash-set slot
/// on every gateway.
const MAX_ENTRIES: usize = 100_000;

/// A revoked subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedSubject {
    pub subject: String,
    /// RFC 3339, informational.
    pub revoked_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A revoked token, by `jti`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedToken {
    pub token_id: String,
    /// RFC 3339, informational.
    pub revoked_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The `revoke all` cut-off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotBefore {
    /// RFC 3339. Tokens issued before this instant are refused.
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The document as written. Public so the CLI can read, edit, and write
/// it; the gateway consumes the compiled [`RevocationDocument`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationFile {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<RevokedSubject>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub token_ids: Vec<RevokedToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<NotBefore>,
}

impl RevocationFile {
    /// An empty list at version 1 — what `revoke init` writes.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            version: 1,
            ..Self::default()
        }
    }

    /// Parse the YAML form.
    ///
    /// # Errors
    ///
    /// When the bytes do not parse or violate the schema.
    pub fn parse(bytes: &[u8]) -> Result<Self, BundleError> {
        let file: Self = serde_norway::from_slice(bytes)
            .map_err(|error| BundleError::new(format!("does not parse: {error}")))?;
        if file.subjects.len() > MAX_ENTRIES || file.token_ids.len() > MAX_ENTRIES {
            return Err(BundleError::new(format!(
                "more than {MAX_ENTRIES} entries; this is not a revocation list"
            )));
        }
        for entry in &file.subjects {
            if entry.subject.trim().is_empty() {
                return Err(BundleError::new("a subject entry is empty"));
            }
        }
        for entry in &file.token_ids {
            if entry.token_id.trim().is_empty() {
                return Err(BundleError::new("a token_id entry is empty"));
            }
        }
        if let Some(not_before) = &file.not_before {
            parse_rfc3339(&not_before.at).ok_or_else(|| {
                BundleError::new(format!(
                    "not_before.at {:?} is not an RFC 3339 timestamp",
                    not_before.at
                ))
            })?;
        }
        Ok(file)
    }

    /// The YAML form, deterministic: entries sorted by key so two lists
    /// with the same content have the same bytes and the same bundle hash.
    ///
    /// # Errors
    ///
    /// When serialization fails (it does not, for this shape).
    pub fn to_yaml(&self) -> Result<String, BundleError> {
        let mut sorted = self.clone();
        sorted.subjects.sort_by(|a, b| a.subject.cmp(&b.subject));
        sorted.token_ids.sort_by(|a, b| a.token_id.cmp(&b.token_id));
        serde_norway::to_string(&sorted)
            .map_err(|error| BundleError::new(format!("cannot serialize: {error}")))
    }
}

/// Why a validated token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// The list names the token's subject.
    Subject,
    /// The list names the token's `jti`.
    TokenId,
    /// The token was issued before the `not_before` cut-off — or carries
    /// no issue time at all, which a cut-off treats as before it.
    NotBefore,
}

impl RevocationReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::TokenId => "token_id",
            Self::NotBefore => "not_before",
        }
    }
}

/// The compiled list the middleware consults: set lookups and one
/// comparison, allocation-free per request.
#[derive(Debug)]
pub struct RevocationDocument {
    version: String,
    subjects: HashSet<String>,
    token_ids: HashSet<String>,
    /// Seconds since the Unix epoch.
    not_before: Option<u64>,
    not_before_label: Option<String>,
}

impl RevocationDocument {
    /// Whether `authenticated` is refused, and why.
    #[must_use]
    pub fn check(&self, authenticated: &Authenticated) -> Option<RevocationReason> {
        if self.subjects.contains(&authenticated.principal.subject) {
            return Some(RevocationReason::Subject);
        }
        if let Some(token_id) = &authenticated.token.token_id
            && self.token_ids.contains(token_id)
        {
            return Some(RevocationReason::TokenId);
        }
        if let Some(cutoff) = self.not_before {
            let before_cutoff = self.issued_before(&authenticated.token, cutoff);
            if before_cutoff {
                return Some(RevocationReason::NotBefore);
            }
        }
        None
    }

    /// A token without an issue time cannot be shown to postdate the
    /// cut-off, so it is treated as predating it (fail closed).
    #[allow(clippy::unused_self)]
    fn issued_before(&self, token: &TokenFacts, cutoff: u64) -> bool {
        token.issued_at.is_none_or(|issued_at| issued_at < cutoff)
    }

    /// Whether the list names `subject`.
    #[must_use]
    pub fn revokes_subject(&self, subject: &str) -> bool {
        self.subjects.contains(subject)
    }

    #[must_use]
    pub fn subject_count(&self) -> usize {
        self.subjects.len()
    }

    #[must_use]
    pub fn token_count(&self) -> usize {
        self.token_ids.len()
    }

    /// The `not_before` cut-off as written, if any.
    #[must_use]
    pub fn not_before(&self) -> Option<&str> {
        self.not_before_label.as_deref()
    }

    /// Seconds since the epoch of the cut-off, if any.
    #[must_use]
    pub const fn not_before_epoch(&self) -> Option<u64> {
        self.not_before
    }
}

impl BundleDocument for RevocationDocument {
    const DOMAIN: Domain = Domain::RevocationList;
    const NOUN: &'static str = "revocation list";
    const KINDS: [ControlEventKind; 3] = [
        ControlEventKind::RevocationLoaded,
        ControlEventKind::RevocationChanged,
        ControlEventKind::RevocationRejected,
    ];

    fn compile(bytes: &[u8]) -> Result<Self, BundleError> {
        let file = RevocationFile::parse(bytes)?;
        let not_before = file
            .not_before
            .as_ref()
            .and_then(|cutoff| parse_rfc3339(&cutoff.at));
        Ok(Self {
            version: version_label(file.version, bytes),
            subjects: file
                .subjects
                .into_iter()
                .map(|entry| entry.subject)
                .collect(),
            token_ids: file
                .token_ids
                .into_iter()
                .map(|entry| entry.token_id)
                .collect(),
            not_before,
            not_before_label: file.not_before.map(|cutoff| cutoff.at),
        })
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn describe(&self, event: &mut ControlEvent) {
        event.revoked_subjects = Some(self.subjects.len());
        event.revoked_tokens = Some(self.token_ids.len());
        event.not_before.clone_from(&self.not_before_label);
    }
}

/// The revocation list on disk: a [`SignedBundle`] over
/// [`RevocationDocument`].
pub type RevocationList = SignedBundle<RevocationDocument>;

/// RFC 3339 → seconds since the Unix epoch. `None` when it does not parse
/// or predates the epoch.
#[must_use]
pub fn parse_rfc3339(value: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .and_then(|parsed| u64::try_from(parsed.timestamp()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Principal, PrincipalAuthority};

    fn authenticated(subject: &str, iat: Option<u64>, jti: Option<&str>) -> Authenticated {
        Authenticated {
            principal: Principal {
                tenant: "acme".to_owned(),
                subject: subject.to_owned(),
                groups: Vec::new(),
                scopes: Vec::new(),
                authority: PrincipalAuthority::oidc("https://acme.okta.com/oauth2/default"),
            },
            token: TokenFacts {
                issued_at: iat,
                token_id: jti.map(str::to_owned),
            },
        }
    }

    const LIST: &str = "version: 1
subjects:
  - subject: alice@acme.example
    revoked_at: 2026-09-03T10:00:00Z
    reason: offboarded
token_ids:
  - token_id: AT.leaked
    revoked_at: 2026-09-03T10:05:00Z
not_before:
  at: 2026-09-03T09:00:00Z
";

    #[test]
    fn matches_by_subject_token_id_and_cutoff_and_fails_closed_without_iat() {
        let list = RevocationDocument::compile(LIST.as_bytes()).unwrap();
        // 2026-09-03T09:00:00Z
        let cutoff = list.not_before_epoch().unwrap();
        assert_eq!(cutoff, 1_788_426_000);
        assert_eq!(
            list.check(&authenticated("alice@acme.example", Some(cutoff + 1), None)),
            Some(RevocationReason::Subject)
        );
        assert_eq!(
            list.check(&authenticated(
                "bob@acme.example",
                Some(cutoff + 1),
                Some("AT.leaked")
            )),
            Some(RevocationReason::TokenId)
        );
        assert_eq!(
            list.check(&authenticated(
                "bob@acme.example",
                Some(cutoff - 1),
                Some("AT.fine")
            )),
            Some(RevocationReason::NotBefore)
        );
        assert_eq!(
            list.check(&authenticated("bob@acme.example", None, None)),
            Some(RevocationReason::NotBefore),
            "an undatable token cannot be shown to postdate the cut-off"
        );
        assert_eq!(
            list.check(&authenticated(
                "bob@acme.example",
                Some(cutoff),
                Some("AT.fine")
            )),
            None,
            "issued at the cut-off is not before it"
        );
        assert!(list.version().starts_with("v1+sha256:"));
        assert_eq!(list.subject_count(), 1);
        assert_eq!(list.token_count(), 1);
    }

    #[test]
    fn an_empty_list_revokes_nobody_and_an_undated_token_passes_without_a_cutoff() {
        let list = RevocationDocument::compile(b"version: 1\n").unwrap();
        assert_eq!(list.check(&authenticated("anyone", None, None)), None);
    }

    #[test]
    fn schema_errors_are_load_errors() {
        assert!(RevocationDocument::compile(b"version: 1\nsubjcts: []\n").is_err());
        assert!(
            RevocationDocument::compile(b"version: 1\nnot_before: { at: yesterday }\n").is_err()
        );
        assert!(
            RevocationDocument::compile(
                b"version: 1\nsubjects: [{ subject: '  ', revoked_at: x }]\n"
            )
            .is_err()
        );
    }

    #[test]
    fn yaml_round_trip_is_deterministic() {
        let mut file = RevocationFile::parse(LIST.as_bytes()).unwrap();
        file.subjects.push(RevokedSubject {
            subject: "aaron@acme.example".to_owned(),
            revoked_at: "2026-09-03T11:00:00Z".to_owned(),
            reason: None,
        });
        let yaml = file.to_yaml().unwrap();
        let reparsed = RevocationFile::parse(yaml.as_bytes()).unwrap();
        assert_eq!(reparsed.subjects[0].subject, "aaron@acme.example");
        assert_eq!(reparsed.to_yaml().unwrap(), yaml);
        assert_eq!(RevocationFile::empty().to_yaml().unwrap(), "version: 1\n");
    }
}

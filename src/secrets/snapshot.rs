//! The resolved view of every reference in a configuration.

use std::collections::HashMap;
use std::fmt;

use serde::Serialize;

/// Where a credential's bytes came from, and which version: the two
/// non-secret facts an audit record carries about a referenced secret
/// (plan §3.8, "Attribution"). A `version` that changes between two records
/// is the rotation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretProvenance {
    /// The reference scheme (`file`, `vault`, …).
    pub source: &'static str,
    /// The provider's version id, or a content hash for sources without one.
    pub version: String,
}

/// One resolved reference.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedSecret {
    value: String,
    provenance: SecretProvenance,
}

impl ResolvedSecret {
    #[must_use]
    pub fn new(value: String, source: &'static str, version: String) -> Self {
        Self {
            value,
            provenance: SecretProvenance { source, version },
        }
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    #[must_use]
    pub const fn provenance(&self) -> &SecretProvenance {
        &self.provenance
    }
}

impl fmt::Debug for ResolvedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSecret")
            .field("value", &"<redacted>")
            .field("provenance", &self.provenance)
            .finish()
    }
}

/// Every reference the configuration held when it was resolved, keyed by
/// the reference text (trimmed). Immutable once built; a refresh builds a
/// new one and swaps it in whole, so a request never sees half a rotation.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretSnapshot {
    entries: HashMap<String, ResolvedSecret>,
}

impl SecretSnapshot {
    #[must_use]
    pub fn new(entries: HashMap<String, ResolvedSecret>) -> Self {
        Self { entries }
    }

    /// The resolved secret for a reference, by its exact (trimmed) text.
    #[must_use]
    pub fn get(&self, reference: &str) -> Option<&ResolvedSecret> {
        self.entries.get(reference)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// This snapshot with `newer`'s entries on top. Anything only this
    /// snapshot knows is kept: a refresh computed against one configuration
    /// must not drop what a concurrent reload resolved for another, and an
    /// entry no configuration references any more is never read.
    #[must_use]
    pub fn merged_with(&self, newer: &Self) -> Self {
        let mut entries = HashMap::with_capacity(self.entries.len() + newer.entries.len());
        entries.extend(
            self.entries
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        entries.extend(
            newer
                .entries
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        Self { entries }
    }

    /// Whether `newer` would change anything this snapshot serves.
    #[must_use]
    pub fn differs_from(&self, newer: &Self) -> bool {
        newer
            .entries
            .iter()
            .any(|(key, value)| self.entries.get(key) != Some(value))
    }
}

impl fmt::Debug for SecretSnapshot {
    /// References and versions only — never values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = formatter.debug_map();
        for (reference, secret) in &self.entries {
            map.entry(reference, &secret.provenance.version);
        }
        map.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(pairs: &[(&str, &str, &str)]) -> SecretSnapshot {
        SecretSnapshot::new(
            pairs
                .iter()
                .map(|(reference, value, version)| {
                    (
                        (*reference).to_owned(),
                        ResolvedSecret::new((*value).to_owned(), "file", (*version).to_owned()),
                    )
                })
                .collect(),
        )
    }

    #[test]
    fn debug_shows_versions_never_values() {
        let text = format!("{:?}", snapshot(&[("file:///a", "hunter2", "sha256:1")]));
        assert!(text.contains("file:///a"));
        assert!(text.contains("sha256:1"));
        assert!(!text.contains("hunter2"));
    }

    #[test]
    fn merge_keeps_what_the_newer_snapshot_does_not_know() {
        let old = snapshot(&[("file:///a", "1", "v1"), ("file:///b", "1", "v1")]);
        let new = snapshot(&[("file:///a", "2", "v2")]);
        let merged = old.merged_with(&new);
        assert_eq!(merged.get("file:///a").unwrap().value(), "2");
        assert_eq!(merged.get("file:///b").unwrap().value(), "1");
        assert!(old.differs_from(&new));
        assert!(!merged.differs_from(&new));
    }
}

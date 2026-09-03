//! Hash chain and signed checkpoints over the audit journal (plan §3.3,
//! WP B.6; closes CF-8).
//!
//! The journal was tamper-*evident* by sequence alone: a gap or a duplicate
//! showed that something happened, but an edit *inside* a record — a
//! `deny` turned into an `allow`, a subject swapped — left the sequence
//! intact. The chain closes that: every line the writer appends extends a
//! running SHA-256 (`chain = H(chain ‖ line)`), and every N records or T
//! seconds — and at shutdown — the writer appends a **checkpoint** record
//! carrying the chain value over everything before it, signed with the
//! gateway's Ed25519 key. An offline verifier recomputes the chain from the
//! bytes on disk and compares it to each checkpoint; a single flipped bit
//! anywhere before a checkpoint changes the value the checkpoint carries.
//!
//! The signature is what makes tampering *detectable* rather than merely
//! evident: without it, whoever rewrote a record could recompute the chain
//! and rewrite the checkpoints too. With it, they would need the gateway's
//! private key. Exporting checkpoints to a second place ([`crate::ports::CheckpointSink`])
//! also catches the one edit a chain cannot: deleting the tail of the file —
//! a checkpoint in the export that the journal no longer holds is a
//! truncation.
//!
//! What is **not** protected: the records after the last checkpoint, until
//! the next one is written (bounded by N records / T seconds, and sealed at
//! every clean shutdown). That is the cost of not signing every record, and
//! §8 budgets it explicitly ("fsync batched per checkpoint, not per record").
//!
//! ## Record shape
//!
//! ```json
//! {"seq":42,"kind":"checkpoint","timestamp":"…","covers_from":30,"covers_to":41,
//!  "chain":"sha256:<64 hex>","previous_checkpoint":29,
//!  "key_id":"ed25519:…","signature":"<base64>"}
//! ```
//!
//! `chain` is the chain value **after line 41 and before this line**; the
//! checkpoint line itself is then folded into the chain like any other, so
//! the next checkpoint covers it. `covers_from` is the first sequence after
//! the previous checkpoint. The signature is over
//! [`Checkpoint::signing_payload`] — a fixed, newline-separated rendering of
//! the fields, never the JSON, so key order and whitespace cannot matter.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::policy::signing::{Domain, Signature, SigningKey, VerifyingKey};

/// The `kind` every checkpoint record carries.
pub const CHECKPOINT_KIND: &str = "checkpoint";

/// Domain-separation seed for the first chain value, so an empty journal's
/// chain is not the hash of nothing.
const CHAIN_SEED: &[u8] = b"mcp-devtools/audit-journal/chain/v1";

/// The running hash over every line written so far.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Chain([u8; 32]);

impl std::fmt::Debug for Chain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.label())
    }
}

impl Chain {
    /// The value before any line: `H(seed)`.
    #[must_use]
    pub fn genesis() -> Self {
        Self(Sha256::digest(CHAIN_SEED).into())
    }

    /// Fold one complete line (including its trailing newline) in.
    pub fn extend(&mut self, line: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        hasher.update(line);
        self.0 = hasher.finalize().into();
    }

    /// `sha256:<64 hex>`.
    #[must_use]
    pub fn label(&self) -> String {
        use std::fmt::Write as _;
        let mut label = String::with_capacity(71);
        label.push_str("sha256:");
        for byte in &self.0 {
            let _ = write!(label, "{byte:02x}");
        }
        label
    }

    /// Parse a [`Self::label`].
    #[must_use]
    pub fn parse(label: &str) -> Option<Self> {
        let hex = label.strip_prefix("sha256:")?;
        if hex.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let text = std::str::from_utf8(chunk).ok()?;
            bytes[index] = u8::from_str_radix(text, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

/// Serde helper: the fixed `kind` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointKind {
    Checkpoint,
}

/// A checkpoint record, without its `seq` (the writer splices that in, as
/// for every other record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub kind: CheckpointKind,
    pub timestamp: String,
    /// First sequence this checkpoint covers (the one after the previous
    /// checkpoint, or 1).
    pub covers_from: u64,
    /// Last sequence this checkpoint covers: its own sequence minus one.
    pub covers_to: u64,
    /// Chain value after `covers_to`, before this record.
    pub chain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint: Option<u64>,
    /// Which key signed it; absent on an unsigned checkpoint (a journal
    /// with no `MCP_AUDIT_SIGNING_KEY`, which okta mode refuses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Checkpoint {
    /// Build the record the writer is about to append as sequence `seq`.
    #[must_use]
    pub fn new(
        seq: u64,
        covers_from: u64,
        chain: &Chain,
        previous_checkpoint: Option<u64>,
        timestamp: String,
    ) -> Self {
        Self {
            kind: CheckpointKind::Checkpoint,
            timestamp,
            covers_from,
            covers_to: seq.saturating_sub(1),
            chain: chain.label(),
            previous_checkpoint,
            key_id: None,
            signature: None,
        }
    }

    /// The bytes a signature covers. Fixed rendering: the sequence this
    /// record has, then each field, newline-separated. Independent of the
    /// JSON encoding.
    #[must_use]
    pub fn signing_payload(&self, seq: u64) -> Vec<u8> {
        let mut payload = String::with_capacity(160);
        payload.push_str("checkpoint\n");
        push_line(&mut payload, &seq.to_string());
        push_line(&mut payload, &self.covers_from.to_string());
        push_line(&mut payload, &self.covers_to.to_string());
        push_line(&mut payload, &self.chain);
        push_line(
            &mut payload,
            &self
                .previous_checkpoint
                .map(|seq| seq.to_string())
                .unwrap_or_default(),
        );
        push_line(&mut payload, &self.timestamp);
        payload.into_bytes()
    }

    /// Sign as sequence `seq`.
    pub fn sign(&mut self, seq: u64, key: &SigningKey) {
        let signature = key.sign(Domain::AuditCheckpoint, &self.signing_payload(seq));
        self.key_id = Some(key.verifying_key().key_id());
        self.signature = Some(signature.to_base64());
    }

    /// Verify the signature with whichever of `keys` has the matching
    /// `key_id`. `Ok(None)` when the checkpoint is unsigned.
    ///
    /// # Errors
    ///
    /// When the checkpoint names a key not in `keys`, the signature does
    /// not parse, or it does not verify.
    pub fn verify(&self, seq: u64, keys: &[VerifyingKey]) -> Result<Option<String>, String> {
        let (Some(key_id), Some(signature)) = (&self.key_id, &self.signature) else {
            if self.key_id.is_some() || self.signature.is_some() {
                return Err("checkpoint carries a key id or a signature, not both".to_owned());
            }
            return Ok(None);
        };
        let key = keys
            .iter()
            .find(|key| key.key_id() == *key_id)
            .ok_or_else(|| format!("signed with unknown key {key_id}"))?;
        let signature =
            Signature::from_base64(signature).map_err(|error| format!("signature: {error}"))?;
        key.verify(
            Domain::AuditCheckpoint,
            &self.signing_payload(seq),
            &signature,
        )
        .map_err(|error| error.to_string())?;
        Ok(Some(key_id.clone()))
    }

    /// The chain value this checkpoint asserts.
    #[must_use]
    pub fn chain(&self) -> Option<Chain> {
        Chain::parse(&self.chain)
    }
}

fn push_line(payload: &mut String, value: &str) {
    payload.push_str(value);
    payload.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_is_order_sensitive_and_labels_round_trip() {
        let mut a = Chain::genesis();
        a.extend(b"{\"seq\":1}\n");
        a.extend(b"{\"seq\":2}\n");
        let mut b = Chain::genesis();
        b.extend(b"{\"seq\":2}\n");
        b.extend(b"{\"seq\":1}\n");
        assert_ne!(a, b);
        assert_eq!(Chain::parse(&a.label()), Some(a));
        assert_eq!(Chain::parse("sha256:zz"), None);
        assert_eq!(Chain::parse("md5:00"), None);
    }

    #[test]
    fn a_signed_checkpoint_verifies_only_as_written() {
        let (key, _) = SigningKey::generate().unwrap();
        let mut checkpoint = Checkpoint::new(10, 1, &Chain::genesis(), None, "t".to_owned());
        assert_eq!(checkpoint.verify(10, &[key.verifying_key()]), Ok(None));
        checkpoint.sign(10, &key);
        assert_eq!(
            checkpoint.verify(10, &[key.verifying_key()]),
            Ok(Some(key.verifying_key().key_id()))
        );
        assert!(checkpoint.verify(11, &[key.verifying_key()]).is_err());
        let other = SigningKey::generate().unwrap().0.verifying_key();
        assert!(
            checkpoint
                .verify(10, &[other])
                .unwrap_err()
                .contains("unknown key")
        );
        let mut edited = checkpoint.clone();
        edited.covers_to = 8;
        assert!(edited.verify(10, &[key.verifying_key()]).is_err());
        let json = serde_json::to_string(&checkpoint).unwrap();
        assert!(json.starts_with("{\"kind\":\"checkpoint\""));
        let parsed: Checkpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, checkpoint);
    }
}

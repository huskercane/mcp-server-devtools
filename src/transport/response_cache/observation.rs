//! Metadata-only cache observations. Serialize and enqueue only after releasing
//! the cache mutex. Rewards describe one entry's observed residency, not a
//! counterfactual upstream request or end-to-end tool success.

use std::sync::Arc;
use std::time::{Duration, Instant};

use http::HeaderMap;
use http::header::{ETAG, LAST_MODIFIED};
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::{Cache, CacheConfig, CacheKey, Entry, StoredBytes};

#[derive(Clone, Copy)]
pub(super) struct Choice {
    pub action: &'static str,
    pub probability: f64,
    pub ttl: Duration,
    pub base_ttl: Duration,
    pub exploration: bool,
}

pub(super) fn choose(exploration: bool, ttl: Duration, random: u8) -> Choice {
    let (action, probability, selected_ttl) = if !exploration {
        ("admit", 1.0, ttl)
    } else if random < 32 {
        ("reject", 0.125, Duration::ZERO)
    } else if random < 64 {
        ("admit_half_ttl", 0.125, ttl / 2)
    } else {
        ("admit", 0.75, ttl)
    };
    Choice {
        action,
        probability,
        ttl: selected_ttl,
        base_ttl: ttl,
        exploration,
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Decision {
    #[serde(skip)]
    vendor: String,
    #[serde(skip)]
    cache_key: String,
    #[serde(rename = "decisionId")]
    id: String,
    resource_fingerprint: String,
    policy_version: &'static str,
    action: &'static str,
    action_probability: f64,
    candidate_actions: &'static [&'static str],
    candidate_probabilities: &'static [f64],
    base_ttl_ms: u128,
    ttl_source: &'static str,
    has_etag: bool,
    has_last_modified: bool,
    pub compression_duration_us: u128,
    pub entries_before: usize,
    pub cache_bytes_before: usize,
    max_entries: usize,
    max_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin_tool: Option<String>,
}

impl Decision {
    pub(super) fn new(
        key: &CacheKey,
        headers: &HeaderMap,
        config: &CacheConfig,
        choice: Choice,
        ttl_source: &'static str,
    ) -> Self {
        let correlation = crate::audit::cache_call();
        let (call_id, tool) =
            correlation.map_or((None, None), |(call, tool)| (Some(call), Some(tool)));
        // Domain-separated, full-length hash; includes vendor but no identity.
        let mut digest = Sha256::new();
        digest.update(b"cache-resource-v2\0");
        digest.update(key.vendor.as_bytes());
        digest.update([0]);
        digest.update(key.url.as_bytes());
        Self {
            vendor: key.vendor.clone(),
            cache_key: key.audit_fingerprint(),
            id: uuid::Uuid::new_v4().to_string(),
            resource_fingerprint: hex::encode(digest.finalize()),
            policy_version: if choice.exploration {
                "collect-v2"
            } else {
                "fixed-v2"
            },
            action: choice.action,
            action_probability: choice.probability,
            candidate_actions: if choice.exploration {
                &["reject", "admit_half_ttl", "admit"]
            } else {
                &["admit"]
            },
            candidate_probabilities: if choice.exploration {
                &[0.125, 0.125, 0.75]
            } else {
                &[1.0]
            },
            base_ttl_ms: choice.base_ttl.as_millis(),
            ttl_source,
            has_etag: headers.contains_key(ETAG),
            has_last_modified: headers.contains_key(LAST_MODIFIED),
            compression_duration_us: 0,
            entries_before: 0,
            cache_bytes_before: 0,
            max_entries: config.max_entries,
            max_bytes: config.max_bytes,
            origin_call_id: call_id,
            origin_tool: tool,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Snapshot {
    #[serde(flatten, serialize_with = "serialize_decision")]
    decision: Arc<Decision>,
    ttl_ms: u128,
    age_ms: u128,
    remaining_ttl_ms: u128,
    upstream_latency_ms: u128,
    response_bytes: usize,
    entry_bytes: usize,
    compressed: bool,
    hit_count: u64,
    decode_duration_us: u128,
    estimated_saved_latency_ms: u128,
    residency_byte_ms: u128,
}

fn serialize_decision<S: Serializer>(
    decision: &Arc<Decision>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    decision.as_ref().serialize(serializer)
}

impl Snapshot {
    pub(super) fn new(entry: &Entry, now: Instant) -> Self {
        let age_ms = now.saturating_duration_since(entry.stored_at).as_millis();
        Self {
            decision: Arc::clone(&entry.decision),
            ttl_ms: entry.ttl.as_millis(),
            age_ms,
            remaining_ttl_ms: entry.expires_at.saturating_duration_since(now).as_millis(),
            upstream_latency_ms: entry.upstream_latency_ms,
            response_bytes: entry.response_bytes,
            entry_bytes: entry.stored_bytes,
            compressed: matches!(&entry.bytes, StoredBytes::Zstd(_)),
            hit_count: entry.hit_count,
            decode_duration_us: entry.decode_duration_us,
            estimated_saved_latency_ms: entry
                .upstream_latency_ms
                .saturating_mul(u128::from(entry.hit_count)),
            residency_byte_ms: if entry.decision.action == "reject" {
                0
            } else {
                age_ms.saturating_mul(entry.stored_bytes as u128)
            },
        }
    }
}

#[derive(Clone, Copy, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Totals {
    cumulative_hits: u64,
    cumulative_misses: u64,
    entries: usize,
    cache_bytes: usize,
}

impl Totals {
    pub(super) fn new(cache: &Cache) -> Self {
        Self {
            cumulative_hits: cache.hits,
            cumulative_misses: cache.misses,
            entries: cache.entries.len(),
            cache_bytes: cache.stored_bytes,
        }
    }
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Correlation {
    #[serde(skip_serializing_if = "Option::is_none")]
    call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool: Option<String>,
}

impl Correlation {
    fn current() -> Self {
        crate::audit::cache_call().map_or_else(Self::default, |(call_id, tool)| Self {
            call_id: Some(call_id),
            tool: Some(tool),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Record<'a> {
    event: &'static str,
    vendor: &'a str,
    cache_key: &'a str,
    outcome: &'static str,
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    observation_complete: Option<bool>,
    #[serde(flatten)]
    snapshot: Option<&'a Snapshot>,
    #[serde(flatten)]
    totals: Totals,
    #[serde(flatten)]
    correlation: Correlation,
}

pub(super) fn lookup(
    key: &CacheKey,
    snapshot: Option<&Snapshot>,
    hit: bool,
    reason: &'static str,
    totals: Totals,
) {
    crate::audit::cache_event(&Record {
        event: "http_cache_lookup",
        vendor: &key.vendor,
        cache_key: &key.audit_fingerprint(),
        outcome: if hit { "hit" } else { "miss" },
        reason,
        observation_complete: None,
        snapshot,
        totals,
        correlation: Correlation::current(),
    });
}

pub(super) fn decision(snapshot: &Snapshot, totals: Totals) {
    emit(
        snapshot,
        "http_cache_decision",
        if snapshot.decision.action == "reject" {
            "rejected"
        } else {
            "stored"
        },
        None,
        totals,
    );
}

pub(super) fn outcome(entry: &Entry, now: Instant, reason: &'static str, totals: Totals) {
    terminal(&Snapshot::new(entry, now), reason, totals);
}

pub(super) fn terminal(snapshot: &Snapshot, reason: &'static str, totals: Totals) {
    emit(
        snapshot,
        "http_cache_outcome",
        reason,
        Some(!matches!(reason, "session_end" | "decode_failed")),
        totals,
    );
}

fn emit(
    snapshot: &Snapshot,
    event: &'static str,
    outcome: &'static str,
    complete: Option<bool>,
    totals: Totals,
) {
    crate::audit::cache_event(&Record {
        event,
        vendor: &snapshot.decision.vendor,
        cache_key: &snapshot.decision.cache_key,
        outcome,
        reason: outcome,
        observation_complete: complete,
        snapshot: Some(snapshot),
        totals,
        correlation: Correlation::current(),
    });
}

pub(super) fn ineligible(key: &CacheKey, reason: &'static str) {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Ineligible<'a> {
        event: &'static str,
        vendor: &'a str,
        cache_key: String,
        outcome: &'static str,
        reason: &'static str,
        #[serde(flatten)]
        correlation: Correlation,
    }
    crate::audit::cache_event(&Ineligible {
        event: "http_cache_ineligible",
        vendor: &key.vendor,
        cache_key: key.audit_fingerprint(),
        outcome: "bypassed",
        reason,
        correlation: Correlation::current(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_random_buckets_match_logged_probabilities_and_ttl_bounds() {
        let mut counts = [0_u32; 3];
        for random in 0..=u8::MAX {
            let ttl = Duration::from_mins(1);
            let choice = choose(true, ttl, random);
            let index = match choice.action {
                "reject" => {
                    assert_eq!(choice.ttl, Duration::ZERO);
                    0
                }
                "admit_half_ttl" => {
                    assert_eq!(choice.ttl, ttl / 2);
                    1
                }
                "admit" => {
                    assert_eq!(choice.ttl, ttl);
                    2
                }
                _ => panic!("unexpected action"),
            };
            counts[index] += 1;
            assert!((choice.probability - [0.125, 0.125, 0.75][index]).abs() < f64::EPSILON);
            let fixed = choose(false, ttl, random);
            assert_eq!(fixed.action, "admit");
            assert!((fixed.probability - 1.0).abs() < f64::EPSILON);
            assert_eq!(fixed.ttl, ttl);
        }
        assert_eq!(counts, [32, 32, 192]);
    }
}

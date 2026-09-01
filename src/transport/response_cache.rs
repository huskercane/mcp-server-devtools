//! Bounded, process-local cache for successful upstream HTTP reads.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use reqwest::header::{
    CACHE_CONTROL, ETAG, EXPIRES, HeaderMap, HeaderName, HeaderValue, LAST_MODIFIED, SET_COOKIE,
    VARY,
};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use super::{RequestOptions, ResponseBody};
use crate::config::Config;

const DEFAULT_TTL_SECONDS: u64 = 60;
const DEFAULT_MAX_ENTRIES: usize = 512;
const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_COMPRESSION_THRESHOLD: usize = 16 * 1024;
const CACHE_POLICY_VERSION: &str = "fixed-v1";
const FIXED_POLICY_ACTIONS: &[&str] = &["admit"];

#[derive(Debug, Clone)]
pub(super) struct CacheConfig {
    pub enabled: bool,
    default_ttl: Duration,
    max_ttl: Duration,
    max_entries: usize,
    max_bytes: usize,
    compression_threshold: usize,
}

impl CacheConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            enabled: config.get_bool("HTTP_CACHE_ENABLED", false),
            default_ttl: seconds(
                config,
                "HTTP_CACHE_DEFAULT_TTL_SECONDS",
                DEFAULT_TTL_SECONDS,
            ),
            max_ttl: seconds(config, "HTTP_CACHE_MAX_TTL_SECONDS", 3600),
            max_entries: positive(config, "HTTP_CACHE_MAX_ENTRIES", DEFAULT_MAX_ENTRIES),
            max_bytes: positive(config, "HTTP_CACHE_MAX_BYTES", DEFAULT_MAX_BYTES),
            compression_threshold: positive(
                config,
                "HTTP_CACHE_COMPRESSION_THRESHOLD_BYTES",
                DEFAULT_COMPRESSION_THRESHOLD,
            ),
        }
    }
}

fn seconds(config: &Config, key: &str, default: u64) -> Duration {
    let configured_default = i64::try_from(default).unwrap_or(i64::MAX);
    let seconds = u64::try_from(config.get_int(key, configured_default))
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or(default);
    Duration::from_secs(seconds)
}

fn positive(config: &Config, key: &str, default: usize) -> usize {
    let configured_default = i64::try_from(default).unwrap_or(i64::MAX);
    usize::try_from(config.get_int(key, configured_default))
        .ok()
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct CacheKey {
    vendor: String,
    url: String,
    identity: [u8; 32],
    representation: [u8; 32],
}

impl CacheKey {
    pub fn new(
        vendor: &str,
        url: &str,
        auth_name: &HeaderName,
        auth_value: &HeaderValue,
        headers: &[(String, String)],
    ) -> Self {
        let mut identity = Sha256::new();
        identity.update(auth_name.as_str().as_bytes());
        identity.update([0]);
        identity.update(auth_value.as_bytes());

        let mut representation = Sha256::new();
        let mut headers = headers.to_vec();
        headers.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        for (name, value) in headers {
            representation.update(name.to_ascii_lowercase().as_bytes());
            representation.update([0]);
            representation.update(value.as_bytes());
            representation.update([0xff]);
        }

        Self {
            vendor: vendor.to_owned(),
            url: url.to_owned(),
            identity: identity.finalize().into(),
            representation: representation.finalize().into(),
        }
    }

    fn audit_fingerprint(&self) -> String {
        use std::fmt::Write as _;

        let mut digest = Sha256::new();
        digest.update(self.vendor.as_bytes());
        digest.update([0]);
        digest.update(self.url.as_bytes());
        digest.update([0]);
        digest.update(self.identity);
        digest.update(self.representation);
        let digest = digest.finalize();
        let mut fingerprint = String::with_capacity(16);
        for byte in &digest[..8] {
            let _ = write!(fingerprint, "{byte:02x}");
        }
        fingerprint
    }

    fn resource_fingerprint(&self) -> String {
        let resource = self
            .url
            .split(['?', '#'])
            .next()
            .unwrap_or(self.url.as_str());
        short_fingerprint([self.vendor.as_bytes(), resource.as_bytes()])
    }
}

fn short_fingerprint<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> String {
    use std::fmt::Write as _;

    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
        digest.update([0]);
    }
    let digest = digest.finalize();
    let mut fingerprint = String::with_capacity(16);
    for byte in &digest[..8] {
        let _ = write!(fingerprint, "{byte:02x}");
    }
    fingerprint
}

#[derive(Debug, Clone, Copy)]
enum BodyKind {
    Json,
    Text,
    Empty,
}

#[derive(Debug)]
enum StoredBytes {
    Plain(Vec<u8>),
    Zstd(Vec<u8>),
}

#[derive(Debug)]
struct Entry {
    kind: BodyKind,
    bytes: StoredBytes,
    stored_bytes: usize,
    expires_at: Instant,
    stored_at: Instant,
    ttl: Duration,
    response_bytes: usize,
    upstream_latency_ms: u128,
    last_used: u64,
    decision_id: String,
    cache_key_fingerprint: String,
    resource_fingerprint: String,
    vendor: String,
    ttl_source: &'static str,
    compression_duration_us: u128,
    has_etag: bool,
    has_last_modified: bool,
    hit_count: u64,
}

impl Entry {
    fn decode(&self) -> Option<(ResponseBody, u128)> {
        let started = Instant::now();
        let bytes = match &self.bytes {
            StoredBytes::Plain(bytes) => bytes.clone(),
            StoredBytes::Zstd(bytes) => zstd::stream::decode_all(Cursor::new(bytes)).ok()?,
        };
        let body = match self.kind {
            BodyKind::Json => serde_json::from_slice(&bytes).ok().map(ResponseBody::Json),
            BodyKind::Text => String::from_utf8(bytes).ok().map(ResponseBody::Text),
            BodyKind::Empty => Some(ResponseBody::Empty),
        }?;
        Some((body, started.elapsed().as_micros()))
    }
}

#[derive(Debug, Default)]
struct Cache {
    entries: HashMap<CacheKey, Entry>,
    stored_bytes: usize,
    clock: u64,
    hits: u64,
    misses: u64,
}

fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Cache::default()))
}

pub(super) fn request_is_cacheable(
    url: &str,
    auth_name: &HeaderName,
    options: &RequestOptions,
) -> bool {
    if options.body.is_some() || options.form.is_some() {
        return false;
    }
    let path = url.to_ascii_lowercase();
    let session_properties = path.contains("/webapp/sessionproperties");
    if ["/login", "/authentication-state", "/oauth", "/token"]
        .iter()
        .any(|sensitive| path.contains(sensitive))
    {
        return false;
    }
    session_properties
        || !matches!(
            auth_name.as_str().to_ascii_lowercase().as_str(),
            "cookie" | "sessionkey"
        )
}

#[allow(clippy::too_many_lines)] // Lookup and telemetry must observe one locked cache transaction.
pub(super) fn get(key: &CacheKey) -> Option<ResponseBody> {
    let fingerprint = key.audit_fingerprint();
    let resource_fingerprint = key.resource_fingerprint();
    let mut cache = cache().lock().ok()?;
    let now = Instant::now();
    let expired = cache
        .entries
        .get(key)
        .is_some_and(|entry| entry.expires_at <= now);
    let mut reason = "not_found";
    let mut ttl_ms = None;
    let mut age_ms = None;
    let mut remaining_ttl_ms = None;
    let mut upstream_latency_ms = None;
    let mut response_bytes = None;
    let mut entry_bytes = None;
    let mut compressed = None;
    let mut decision_id = None;
    let mut ttl_source = None;
    let mut compression_duration_us = None;
    let mut decode_duration_us = None;
    let mut has_etag = None;
    let mut has_last_modified = None;
    let mut hit_count = None;
    let mut expired_entry = None;
    if expired {
        if let Some(entry) = cache.entries.get(key) {
            reason = "expired";
            ttl_ms = Some(entry.ttl.as_millis());
            age_ms = Some(now.saturating_duration_since(entry.stored_at).as_millis());
            remaining_ttl_ms = Some(0);
            upstream_latency_ms = Some(entry.upstream_latency_ms);
            response_bytes = Some(entry.response_bytes);
            entry_bytes = Some(entry.stored_bytes);
            compressed = Some(matches!(&entry.bytes, StoredBytes::Zstd(_)));
            decision_id = Some(entry.decision_id.clone());
            ttl_source = Some(entry.ttl_source);
            compression_duration_us = Some(entry.compression_duration_us);
            has_etag = Some(entry.has_etag);
            has_last_modified = Some(entry.has_last_modified);
            hit_count = Some(entry.hit_count);
        }
        expired_entry = remove(&mut cache, key);
    }
    cache.clock = cache.clock.wrapping_add(1);
    let tick = cache.clock;
    let result = cache.entries.get_mut(key).and_then(|entry| {
        entry.last_used = tick;
        reason = "reused";
        ttl_ms = Some(entry.ttl.as_millis());
        age_ms = Some(now.saturating_duration_since(entry.stored_at).as_millis());
        remaining_ttl_ms = Some(entry.expires_at.saturating_duration_since(now).as_millis());
        upstream_latency_ms = Some(entry.upstream_latency_ms);
        response_bytes = Some(entry.response_bytes);
        entry_bytes = Some(entry.stored_bytes);
        compressed = Some(matches!(&entry.bytes, StoredBytes::Zstd(_)));
        decision_id = Some(entry.decision_id.clone());
        ttl_source = Some(entry.ttl_source);
        compression_duration_us = Some(entry.compression_duration_us);
        has_etag = Some(entry.has_etag);
        has_last_modified = Some(entry.has_last_modified);
        let (body, duration_us) = entry.decode()?;
        entry.hit_count = entry.hit_count.saturating_add(1);
        hit_count = Some(entry.hit_count);
        decode_duration_us = Some(duration_us);
        Some(body)
    });
    let outcome = if result.is_some() {
        cache.hits = cache.hits.saturating_add(1);
        "hit"
    } else {
        if reason == "reused" {
            reason = "decode_failed";
        }
        cache.misses = cache.misses.saturating_add(1);
        "miss"
    };
    let (hits, misses, entries, stored_bytes) = (
        cache.hits,
        cache.misses,
        cache.entries.len(),
        cache.stored_bytes,
    );
    drop(cache);
    if let Some(entry) = expired_entry {
        emit_terminal(&entry, "expired", hits, misses, entries, stored_bytes);
    }
    crate::audit::cache_event(crate::audit::CacheEvent {
        timestamp: String::new(),
        event: "http_cache_lookup",
        session_id: "",
        process_id: 0,
        vendor: &key.vendor,
        cache_key: &fingerprint,
        resource_fingerprint: Some(&resource_fingerprint),
        outcome,
        reason: Some(reason),
        action: None,
        decision_id: decision_id.as_deref(),
        ttl_source,
        ttl_ms,
        age_ms,
        remaining_ttl_ms,
        upstream_latency_ms,
        response_bytes,
        entry_bytes,
        compressed,
        compression_duration_us,
        decode_duration_us,
        has_etag,
        has_last_modified,
        hit_count,
        cumulative_hits: hits,
        cumulative_misses: misses,
        entries,
        cache_bytes: stored_bytes,
        ..Default::default()
    });
    result
}

#[allow(clippy::too_many_lines)] // Admission, eviction, and telemetry share one cache snapshot.
pub(super) fn store(
    key: CacheKey,
    body: &ResponseBody,
    headers: &HeaderMap,
    config: &CacheConfig,
    upstream_latency: Duration,
) {
    if headers.contains_key(SET_COOKIE)
        && !key
            .url
            .to_ascii_lowercase()
            .contains("/webapp/sessionproperties")
    {
        return;
    }
    let Some(ttl_decision) = response_ttl(headers, config) else {
        return;
    };
    let ttl = ttl_decision.ttl;
    let (kind, plain) = match body {
        ResponseBody::Json(value) => match serde_json::to_vec(value) {
            Ok(bytes) => (BodyKind::Json, bytes),
            Err(_) => return,
        },
        ResponseBody::Text(text) => (BodyKind::Text, text.as_bytes().to_vec()),
        ResponseBody::Empty => (BodyKind::Empty, Vec::new()),
    };
    if plain.len() > config.max_bytes / 2 {
        return;
    }
    let compression_started = Instant::now();
    let bytes = if plain.len() >= config.compression_threshold {
        match zstd::stream::encode_all(Cursor::new(&plain), 1) {
            Ok(compressed) if compressed.len() < plain.len() => StoredBytes::Zstd(compressed),
            _ => StoredBytes::Plain(plain),
        }
    } else {
        StoredBytes::Plain(plain)
    };
    let compression_duration_us = compression_started.elapsed().as_micros();
    let stored_bytes = match &bytes {
        StoredBytes::Plain(bytes) | StoredBytes::Zstd(bytes) => bytes.len(),
    };
    let compressed = matches!(&bytes, StoredBytes::Zstd(_));
    let response_bytes = plain_len(body);
    let fingerprint = key.audit_fingerprint();
    let resource_fingerprint = key.resource_fingerprint();
    let vendor = key.vendor.clone();
    let decision_id = uuid::Uuid::new_v4().to_string();
    let has_etag = headers.contains_key(ETAG);
    let has_last_modified = headers.contains_key(LAST_MODIFIED);
    let mut cache = match cache().lock() {
        Ok(cache) => cache,
        Err(error) => {
            warn!(%error, "HTTP response cache lock poisoned");
            return;
        }
    };
    let entries_before = cache.entries.len();
    let cache_bytes_before = cache.stored_bytes;
    let replaced = remove(&mut cache, &key);
    cache.clock = cache.clock.wrapping_add(1);
    let tick = cache.clock;
    let now = Instant::now();
    cache.stored_bytes += stored_bytes;
    cache.entries.insert(
        key,
        Entry {
            kind,
            bytes,
            stored_bytes,
            expires_at: now + ttl,
            stored_at: now,
            ttl,
            response_bytes,
            upstream_latency_ms: upstream_latency.as_millis(),
            last_used: tick,
            decision_id: decision_id.clone(),
            cache_key_fingerprint: fingerprint.clone(),
            resource_fingerprint: resource_fingerprint.clone(),
            vendor: vendor.clone(),
            ttl_source: ttl_decision.source,
            compression_duration_us,
            has_etag,
            has_last_modified,
            hit_count: 0,
        },
    );
    let evicted = evict(&mut cache, config);
    let (hits, misses, entries, cache_bytes) = (
        cache.hits,
        cache.misses,
        cache.entries.len(),
        cache.stored_bytes,
    );
    drop(cache);
    crate::audit::cache_event(crate::audit::CacheEvent {
        timestamp: String::new(),
        event: "http_cache_decision",
        session_id: "",
        process_id: 0,
        vendor: &vendor,
        cache_key: &fingerprint,
        resource_fingerprint: Some(&resource_fingerprint),
        outcome: "stored",
        reason: Some("cacheable_success"),
        action: Some("admit"),
        decision_id: Some(&decision_id),
        policy_version: Some(CACHE_POLICY_VERSION),
        action_probability: Some(1.0),
        candidate_actions: Some(FIXED_POLICY_ACTIONS),
        ttl_source: Some(ttl_decision.source),
        ttl_ms: Some(ttl.as_millis()),
        age_ms: Some(0),
        remaining_ttl_ms: Some(ttl.as_millis()),
        upstream_latency_ms: Some(upstream_latency.as_millis()),
        response_bytes: Some(response_bytes),
        entry_bytes: Some(stored_bytes),
        compressed: Some(compressed),
        compression_duration_us: Some(compression_duration_us),
        has_etag: Some(has_etag),
        has_last_modified: Some(has_last_modified),
        hit_count: Some(0),
        cumulative_hits: hits,
        cumulative_misses: misses,
        entries_before: Some(entries_before),
        cache_bytes_before: Some(cache_bytes_before),
        entries,
        cache_bytes,
        ..Default::default()
    });
    if let Some(entry) = replaced {
        emit_terminal(&entry, "replaced", hits, misses, entries, cache_bytes);
    }
    for entry in evicted {
        emit_terminal(&entry, "evicted", hits, misses, entries, cache_bytes);
    }
}

fn plain_len(body: &ResponseBody) -> usize {
    match body {
        ResponseBody::Json(value) => serde_json::to_vec(value).map_or(0, |bytes| bytes.len()),
        ResponseBody::Text(text) => text.len(),
        ResponseBody::Empty => 0,
    }
}

pub(super) fn invalidate_namespace(vendor: &str, base_url: &str) {
    let Ok(mut cache) = cache().lock() else {
        return;
    };
    let keys: Vec<_> = cache
        .entries
        .keys()
        .filter(|key| key.vendor == vendor && key.url.starts_with(base_url))
        .cloned()
        .collect();
    let mut invalidated = Vec::with_capacity(keys.len());
    for key in keys {
        if let Some(entry) = remove(&mut cache, &key) {
            invalidated.push(entry);
        }
    }
    let snapshot = cache_snapshot(&cache);
    drop(cache);
    for entry in invalidated {
        emit_terminal(
            &entry,
            "invalidated",
            snapshot.0,
            snapshot.1,
            snapshot.2,
            snapshot.3,
        );
    }
}

struct TtlDecision {
    ttl: Duration,
    source: &'static str,
}

fn response_ttl(headers: &HeaderMap, config: &CacheConfig) -> Option<TtlDecision> {
    if headers
        .get(VARY)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|part| part.trim() == "*"))
    {
        return None;
    }
    if let Some(value) = headers.get(CACHE_CONTROL).and_then(|v| v.to_str().ok()) {
        for directive in value.split(',').map(str::trim) {
            if directive.eq_ignore_ascii_case("no-store")
                || directive.eq_ignore_ascii_case("no-cache")
            {
                return None;
            }
            if let Some(seconds) = directive
                .strip_prefix("max-age=")
                .and_then(|value| value.trim_matches('"').parse::<u64>().ok())
            {
                return (seconds > 0).then(|| TtlDecision {
                    ttl: Duration::from_secs(seconds).min(config.max_ttl),
                    source: "cache_control",
                });
            }
        }
    }
    if let Some(expires) = headers.get(EXPIRES).and_then(|v| v.to_str().ok())
        && let Ok(at) = httpdate::parse_http_date(expires)
        && let Ok(ttl) = at.duration_since(SystemTime::now())
    {
        return (!ttl.is_zero()).then(|| TtlDecision {
            ttl: ttl.min(config.max_ttl),
            source: "expires",
        });
    }
    Some(TtlDecision {
        ttl: config.default_ttl.min(config.max_ttl),
        source: "default",
    })
}

fn remove(cache: &mut Cache, key: &CacheKey) -> Option<Entry> {
    let entry = cache.entries.remove(key);
    if let Some(entry) = &entry {
        cache.stored_bytes = cache.stored_bytes.saturating_sub(entry.stored_bytes);
    }
    entry
}

fn evict(cache: &mut Cache, config: &CacheConfig) -> Vec<Entry> {
    let mut evicted = Vec::new();
    while cache.entries.len() > config.max_entries || cache.stored_bytes > config.max_bytes {
        let Some(key) = cache
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        if let Some(entry) = remove(cache, &key) {
            evicted.push(entry);
        }
        debug!(
            entries = cache.entries.len(),
            bytes = cache.stored_bytes,
            "evicted HTTP cache entry"
        );
    }
    evicted
}

fn cache_snapshot(cache: &Cache) -> (u64, u64, usize, usize) {
    (
        cache.hits,
        cache.misses,
        cache.entries.len(),
        cache.stored_bytes,
    )
}

fn emit_terminal(
    entry: &Entry,
    outcome: &'static str,
    cumulative_hits: u64,
    cumulative_misses: u64,
    entries: usize,
    cache_bytes: usize,
) {
    let age_ms = entry.stored_at.elapsed().as_millis();
    let ttl_ms = entry.ttl.as_millis();
    let remaining_ttl_ms = entry
        .expires_at
        .saturating_duration_since(Instant::now())
        .as_millis();
    let estimated_saved_latency_ms = entry
        .upstream_latency_ms
        .saturating_mul(u128::from(entry.hit_count));
    let residency_byte_ms = age_ms.saturating_mul(entry.stored_bytes as u128);
    crate::audit::cache_event(crate::audit::CacheEvent {
        timestamp: String::new(),
        event: "http_cache_outcome",
        session_id: "",
        process_id: 0,
        vendor: &entry.vendor,
        cache_key: &entry.cache_key_fingerprint,
        resource_fingerprint: Some(&entry.resource_fingerprint),
        outcome,
        decision_id: Some(&entry.decision_id),
        policy_version: Some(CACHE_POLICY_VERSION),
        ttl_source: Some(entry.ttl_source),
        ttl_ms: Some(ttl_ms),
        age_ms: Some(age_ms),
        remaining_ttl_ms: Some(remaining_ttl_ms),
        upstream_latency_ms: Some(entry.upstream_latency_ms),
        response_bytes: Some(entry.response_bytes),
        entry_bytes: Some(entry.stored_bytes),
        compressed: Some(matches!(&entry.bytes, StoredBytes::Zstd(_))),
        compression_duration_us: Some(entry.compression_duration_us),
        has_etag: Some(entry.has_etag),
        has_last_modified: Some(entry.has_last_modified),
        hit_count: Some(entry.hit_count),
        estimated_saved_latency_ms: Some(estimated_saved_latency_ms),
        residency_byte_ms: Some(residency_byte_ms),
        cumulative_hits,
        cumulative_misses,
        entries,
        cache_bytes,
        ..Default::default()
    });
}

pub(super) fn shutdown() {
    let Ok(mut cache) = cache().lock() else {
        return;
    };
    let entries_to_close: Vec<_> = cache.entries.drain().map(|(_, entry)| entry).collect();
    cache.stored_bytes = 0;
    let snapshot = cache_snapshot(&cache);
    drop(cache);
    for entry in entries_to_close {
        emit_terminal(
            &entry,
            "session_end",
            snapshot.0,
            snapshot.1,
            snapshot.2,
            snapshot.3,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CacheConfig {
        CacheConfig {
            enabled: true,
            default_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(600),
            max_entries: 10,
            max_bytes: 1_000_000,
            compression_threshold: 1024,
        }
    }

    #[test]
    fn resource_fingerprint_omits_query_and_identity() {
        let authorization = HeaderName::from_static("authorization");
        let first = CacheKey::new(
            "jira",
            "https://example.test/rest/api/issue/DEV-1?fields=summary",
            &authorization,
            &HeaderValue::from_static("Bearer first"),
            &[],
        );
        let second = CacheKey::new(
            "jira",
            "https://example.test/rest/api/issue/DEV-1?fields=status",
            &authorization,
            &HeaderValue::from_static("Bearer second"),
            &[],
        );

        assert_eq!(first.resource_fingerprint(), second.resource_fingerprint());
        assert_ne!(first.audit_fingerprint(), second.audit_fingerprint());
        assert_eq!(first.resource_fingerprint().len(), 16);
    }

    #[test]
    fn ttl_decision_records_source_and_caps_upstream_lifetime() {
        let config = test_config();
        let mut headers = HeaderMap::new();
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=3600"));
        let upstream = response_ttl(&headers, &config).expect("cacheable");
        assert_eq!(upstream.source, "cache_control");
        assert_eq!(upstream.ttl, Duration::from_secs(600));

        let defaulted = response_ttl(&HeaderMap::new(), &config).expect("cacheable");
        assert_eq!(defaulted.source, "default");
        assert_eq!(defaulted.ttl, Duration::from_secs(60));
    }

    #[test]
    fn no_store_has_no_ttl_decision() {
        let mut headers = HeaderMap::new();
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
        assert!(response_ttl(&headers, &test_config()).is_none());
    }
}

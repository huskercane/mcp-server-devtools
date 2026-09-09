//! Bounded, process-local cache for successful upstream HTTP reads.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use http::header::{CACHE_CONTROL, EXPIRES, HeaderMap, HeaderName, HeaderValue, SET_COOKIE, VARY};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use super::{CacheMetadata, RequestOptions, ResponseBody};
use crate::config::Config;

const DEFAULT_TTL_SECONDS: u64 = 60;
const DEFAULT_MAX_ENTRIES: usize = 512;
const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_COMPRESSION_THRESHOLD: usize = 16 * 1024;

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
    /// `owner` partitions the cache by principal (WP A.5): the identity
    /// digest already covers the upstream credential, and folding the owner
    /// into the same fixed-width digest means one principal's cached
    /// response is never a hit for another — with no per-request
    /// allocation, and no change to the key for local mode, which hashes a
    /// constant.
    pub fn new(
        vendor: &str,
        url: &str,
        auth_name: &HeaderName,
        auth_value: &HeaderValue,
        headers: &[(String, String)],
        owner: &crate::policy::OwnerKey,
    ) -> Self {
        let mut identity = Sha256::new();
        owner.hash_into(&mut identity);
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
    fetched_at: String,
    ttl: Duration,
    response_bytes: usize,
    upstream_latency_ms: u128,
    last_used: u64,
}

impl Entry {
    fn decode(&self) -> Option<ResponseBody> {
        let bytes = match &self.bytes {
            StoredBytes::Plain(bytes) => bytes.clone(),
            StoredBytes::Zstd(bytes) => zstd::stream::decode_all(Cursor::new(bytes)).ok()?,
        };
        match self.kind {
            BodyKind::Json => serde_json::from_slice(&bytes).ok().map(ResponseBody::Json),
            BodyKind::Text => String::from_utf8(bytes).ok().map(ResponseBody::Text),
            BodyKind::Empty => Some(ResponseBody::Empty),
        }
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

pub(super) fn get(key: &CacheKey) -> Option<(ResponseBody, CacheMetadata)> {
    let fingerprint = key.audit_fingerprint();
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
        }
        remove(&mut cache, key);
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
        let body = entry.decode()?;
        Some((
            body,
            CacheMetadata {
                hit: true,
                age_ms: now.saturating_duration_since(entry.stored_at).as_millis(),
                fetched_at: entry.fetched_at.clone(),
            },
        ))
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
    crate::audit::cache_event(crate::audit::CacheEvent {
        timestamp: String::new(),
        event: "http_cache_lookup",
        session_id: "",
        process_id: 0,
        vendor: &key.vendor,
        cache_key: &fingerprint,
        outcome,
        reason: Some(reason),
        action: None,
        ttl_ms,
        age_ms,
        remaining_ttl_ms,
        upstream_latency_ms,
        response_bytes,
        entry_bytes,
        compressed,
        cumulative_hits: hits,
        cumulative_misses: misses,
        entries,
        cache_bytes: stored_bytes,
    });
    result
}

pub(super) fn store(
    key: CacheKey,
    body: &ResponseBody,
    headers: &HeaderMap,
    config: &CacheConfig,
    upstream_latency: Duration,
    metadata: &CacheMetadata,
) {
    if headers.contains_key(SET_COOKIE)
        && !key
            .url
            .to_ascii_lowercase()
            .contains("/webapp/sessionproperties")
    {
        return;
    }
    let Some(ttl) = response_ttl(headers, config) else {
        return;
    };
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
    let bytes = if plain.len() >= config.compression_threshold {
        match zstd::stream::encode_all(Cursor::new(&plain), 1) {
            Ok(compressed) if compressed.len() < plain.len() => StoredBytes::Zstd(compressed),
            _ => StoredBytes::Plain(plain),
        }
    } else {
        StoredBytes::Plain(plain)
    };
    let stored_bytes = match &bytes {
        StoredBytes::Plain(bytes) | StoredBytes::Zstd(bytes) => bytes.len(),
    };
    let compressed = matches!(&bytes, StoredBytes::Zstd(_));
    let response_bytes = plain_len(body);
    let fingerprint = key.audit_fingerprint();
    let vendor = key.vendor.clone();
    let mut cache = match cache().lock() {
        Ok(cache) => cache,
        Err(error) => {
            warn!(%error, "HTTP response cache lock poisoned");
            return;
        }
    };
    remove(&mut cache, &key);
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
            fetched_at: metadata.fetched_at.clone(),
            ttl,
            response_bytes,
            upstream_latency_ms: upstream_latency.as_millis(),
            last_used: tick,
        },
    );
    evict(&mut cache, config);
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
        outcome: "stored",
        reason: Some("cacheable_success"),
        action: Some("admit"),
        ttl_ms: Some(ttl.as_millis()),
        age_ms: Some(0),
        remaining_ttl_ms: Some(ttl.as_millis()),
        upstream_latency_ms: Some(upstream_latency.as_millis()),
        response_bytes: Some(response_bytes),
        entry_bytes: Some(stored_bytes),
        compressed: Some(compressed),
        cumulative_hits: hits,
        cumulative_misses: misses,
        entries,
        cache_bytes,
    });
}

fn plain_len(body: &ResponseBody) -> usize {
    match body {
        ResponseBody::Json(value) => serde_json::to_vec(value).map_or(0, |bytes| bytes.len()),
        ResponseBody::Text(text) => text.len(),
        ResponseBody::Empty => 0,
    }
}

/// Discard a previous representation before an explicit fresh read, so a
/// later ordinary read cannot fall back to the older cached snapshot.
pub(super) fn invalidate(key: &CacheKey) {
    let Ok(mut cache) = cache().lock() else {
        return;
    };
    remove(&mut cache, key);
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
    for key in keys {
        remove(&mut cache, &key);
    }
}

fn response_ttl(headers: &HeaderMap, config: &CacheConfig) -> Option<Duration> {
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
                return (seconds > 0).then(|| Duration::from_secs(seconds).min(config.max_ttl));
            }
        }
    }
    if let Some(expires) = headers.get(EXPIRES).and_then(|v| v.to_str().ok())
        && let Ok(at) = httpdate::parse_http_date(expires)
        && let Ok(ttl) = at.duration_since(SystemTime::now())
    {
        return (!ttl.is_zero()).then(|| ttl.min(config.max_ttl));
    }
    Some(config.default_ttl.min(config.max_ttl))
}

fn remove(cache: &mut Cache, key: &CacheKey) {
    if let Some(entry) = cache.entries.remove(key) {
        cache.stored_bytes = cache.stored_bytes.saturating_sub(entry.stored_bytes);
    }
}

fn evict(cache: &mut Cache, config: &CacheConfig) {
    while cache.entries.len() > config.max_entries || cache.stored_bytes > config.max_bytes {
        let Some(key) = cache
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        remove(cache, &key);
        debug!(
            entries = cache.entries.len(),
            bytes = cache.stored_bytes,
            "evicted HTTP cache entry"
        );
    }
}

//! Bounded, process-local cache for successful upstream HTTP reads.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use http::header::{CACHE_CONTROL, EXPIRES, HeaderMap, HeaderName, HeaderValue, SET_COOKIE, VARY};
use sha2::{Digest, Sha256};
use tracing::warn;

mod observation;
use observation::{Decision, Snapshot};

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
    exploration: bool,
}

impl CacheConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            enabled: config.get_bool("HTTP_CACHE_ENABLED", false),
            exploration: config.get_bool("HTTP_CACHE_EXPLORATION_ENABLED", false),
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
    decision: Arc<Decision>,
    hit_count: u64,
    decode_duration_us: u128,
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
    let mut cache = cache().lock().ok()?;
    let now = Instant::now();
    let expired = cache
        .entries
        .get(key)
        .is_some_and(|entry| entry.expires_at <= now);
    let ended = if expired {
        remove(&mut cache, key)
    } else {
        None
    };
    cache.clock = cache.clock.wrapping_add(1);
    let tick = cache.clock;
    let mut snapshot = None;
    let result = cache.entries.get_mut(key).and_then(|entry| {
        entry.last_used = tick;
        let started = Instant::now();
        let body = entry.decode();
        entry.decode_duration_us = entry
            .decode_duration_us
            .saturating_add(started.elapsed().as_micros());
        if body.is_some() {
            entry.hit_count = entry.hit_count.saturating_add(1);
        }
        snapshot = Some(Snapshot::new(entry, now));
        body.map(|body| {
            (
                body,
                CacheMetadata {
                    hit: true,
                    age_ms: now.saturating_duration_since(entry.stored_at).as_millis(),
                    fetched_at: entry.fetched_at.clone(),
                },
            )
        })
    });
    let reason = if result.is_some() {
        "reused"
    } else if expired {
        "expired"
    } else if snapshot.is_some() {
        "decode_failed"
    } else {
        "not_found"
    };
    if result.is_some() {
        cache.hits = cache.hits.saturating_add(1);
    } else {
        cache.misses = cache.misses.saturating_add(1);
    }
    let failed = if reason == "decode_failed" {
        remove(&mut cache, key)
    } else {
        None
    };
    let totals = observation::Totals::new(&cache);
    drop(cache);
    if let Some(entry) = ended {
        observation::outcome(&entry, now, "expired", totals);
    }
    if let Some(entry) = failed {
        observation::outcome(&entry, now, "decode_failed", totals);
    }
    observation::lookup(key, snapshot.as_ref(), result.is_some(), reason, totals);
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
    let blocked = headers.contains_key(SET_COOKIE)
        && !key
            .url
            .to_ascii_lowercase()
            .contains("/webapp/sessionproperties");
    let lifetime = response_ttl(headers, config);
    if blocked || lifetime.is_none() {
        observation::ineligible(
            &key,
            if blocked {
                "set_cookie"
            } else {
                "response_cache_policy"
            },
        );
        return;
    }
    let Some((base_ttl, ttl_source)) = lifetime else {
        return;
    };
    let Some((kind, plain)) = encode_body(body) else {
        return;
    };
    let response_bytes = plain.len();
    if response_bytes > config.max_bytes / 2 {
        observation::ineligible(&key, "response_too_large");
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
    let choice = observation::choose(
        config.exploration,
        base_ttl,
        uuid::Uuid::new_v4().as_bytes()[0],
    );
    let mut decision = Decision::new(&key, headers, config, choice, ttl_source);
    decision.compression_duration_us = compression_duration_us;
    let mut cache = match cache().lock() {
        Ok(cache) => cache,
        Err(error) => {
            warn!(%error, "HTTP response cache lock poisoned");
            return;
        }
    };
    decision.entries_before = cache.entries.len();
    decision.cache_bytes_before = cache.stored_bytes;
    let now = Instant::now();
    let mut entry = Entry {
        kind,
        bytes,
        stored_bytes,
        expires_at: now + choice.ttl,
        stored_at: now,
        fetched_at: metadata.fetched_at.clone(),
        ttl: choice.ttl,
        response_bytes,
        upstream_latency_ms: upstream_latency.as_millis(),
        last_used: 0,
        decision: Arc::new(decision),
        hit_count: 0,
        decode_duration_us: 0,
    };
    let snapshot = Snapshot::new(&entry, now);
    // A rejected admission has no residency or saved-latency reward. Its
    // compression work is still charged, because it was actually performed.
    if choice.action == "reject" {
        let totals = observation::Totals::new(&cache);
        drop(cache);
        observation::decision(&snapshot, totals);
        observation::outcome(&entry, now, "rejected", totals);
        return;
    }
    let replaced = remove(&mut cache, &key);
    cache.clock = cache.clock.wrapping_add(1);
    entry.last_used = cache.clock;
    cache.stored_bytes += stored_bytes;
    cache.entries.insert(key, entry);
    let evicted = evict(&mut cache, config);
    let totals = observation::Totals::new(&cache);
    drop(cache);
    observation::decision(&snapshot, totals);
    if let Some(entry) = replaced {
        observation::outcome(&entry, now, "replaced", totals);
    }
    for entry in evicted {
        observation::outcome(&entry, now, "evicted", totals);
    }
}

fn encode_body(body: &ResponseBody) -> Option<(BodyKind, Vec<u8>)> {
    match body {
        ResponseBody::Json(value) => serde_json::to_vec(value)
            .ok()
            .map(|bytes| (BodyKind::Json, bytes)),
        ResponseBody::Text(text) => Some((BodyKind::Text, text.as_bytes().to_vec())),
        ResponseBody::Empty => Some((BodyKind::Empty, Vec::new())),
    }
}

/// Discard a previous representation before an explicit fresh read.
pub(super) fn invalidate(key: &CacheKey) {
    let Ok(mut cache) = cache().lock() else {
        return;
    };
    let removed = remove(&mut cache, key);
    let totals = observation::Totals::new(&cache);
    drop(cache);
    if let Some(entry) = removed {
        observation::outcome(&entry, Instant::now(), "invalidated", totals);
    }
}

pub(super) fn invalidate_namespace(vendor: &str, base_url: &str) {
    drain_matching(
        |key, _| key.vendor == vendor && key.url.starts_with(base_url),
        "invalidated",
    );
}

pub(super) fn maintain(shutdown: bool) {
    let now = Instant::now();
    drain_matching(|_, entry| entry.expires_at <= now, "expired");
    if shutdown {
        drain_matching(|_, _| true, "session_end");
    }
}

fn drain_matching(predicate: impl Fn(&CacheKey, &Entry) -> bool, outcome: &'static str) {
    let Ok(mut cache) = cache().lock() else {
        return;
    };
    let mut removed = Vec::new();
    // Snapshot metadata without cloning URL-bearing keys or response buffers.
    cache.entries.retain(|key, entry| {
        if predicate(key, entry) {
            removed.push(Snapshot::new(entry, Instant::now()));
            false
        } else {
            true
        }
    });
    cache.stored_bytes = cache.entries.values().map(|entry| entry.stored_bytes).sum();
    let totals = observation::Totals::new(&cache);
    drop(cache);
    for snapshot in removed {
        observation::terminal(&snapshot, outcome, totals);
    }
}

fn response_ttl(headers: &HeaderMap, config: &CacheConfig) -> Option<(Duration, &'static str)> {
    if headers
        .get(VARY)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|part| part.trim() == "*"))
    {
        return None;
    }
    if let Some(value) = headers.get(CACHE_CONTROL).and_then(|v| v.to_str().ok()) {
        if value.split(',').map(str::trim).any(|directive| {
            directive.eq_ignore_ascii_case("no-store") || directive.eq_ignore_ascii_case("no-cache")
        }) {
            return None;
        }
        for directive in value.split(',').map(str::trim) {
            if let Some(seconds) = directive
                .strip_prefix("max-age=")
                .and_then(|value| value.trim_matches('"').parse::<u64>().ok())
            {
                return (seconds > 0).then(|| {
                    (
                        Duration::from_secs(seconds).min(config.max_ttl),
                        "cache_control",
                    )
                });
            }
        }
    }
    if let Some(expires) = headers.get(EXPIRES).and_then(|v| v.to_str().ok())
        && let Ok(at) = httpdate::parse_http_date(expires)
        && let Ok(ttl) = at.duration_since(SystemTime::now())
    {
        return (!ttl.is_zero()).then(|| (ttl.min(config.max_ttl), "expires"));
    }
    Some((config.default_ttl.min(config.max_ttl), "default"))
}

fn remove(cache: &mut Cache, key: &CacheKey) -> Option<Entry> {
    let entry = cache.entries.remove(key)?;
    cache.stored_bytes = cache.stored_bytes.saturating_sub(entry.stored_bytes);
    Some(entry)
}

fn evict(cache: &mut Cache, config: &CacheConfig) -> Vec<Entry> {
    let mut removed = Vec::new();
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
            removed.push(entry);
        }
    }
    removed
}

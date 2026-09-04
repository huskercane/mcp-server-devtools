//! Configuration loader with a three-source cascade that matches the TypeScript
//! reference (`src/utils/config.util.ts`).
//!
//! Priority (highest wins):
//! 1. Process environment variables
//! 2. `.env` file in the current working directory
//! 3. Global config file at `$HOME/.mcp/configs.json`
//!
//! Unlike the TS implementation, we never mutate `std::env` (Rust 2024
//! marks `std::env::set_var` as `unsafe` under multi-threaded contexts).
//! Instead we collect all three sources into an immutable snapshot. The
//! observable behavior (which value wins for a given key) is identical.
//!
//! ## Vendor scoping (added when Jira tools were introduced)
//!
//! Process env and `.env` are vendor-neutral and form the **shared** overlay
//! that both [`Config::get`] and [`Config::get_for`] read first.
//!
//! Global config sections are **vendor-scoped**. A user may define a
//! `bitbucket` section, a `jira` section, or both, and a vendor-specific key
//! in one section never leaks into another vendor's lookup.
//!
//! Lookup rules:
//!
//! - [`Config::get_for(vendor, key)`](Config::get_for): `shared` →
//!   `by_vendor[vendor]`. Reads the named vendor's section only; never
//!   crosses into a sibling vendor's section.
//! - [`Config::get(key)`](Config::get): `shared` → unambiguous vendor value.
//!   A key is "unambiguous" if exactly one vendor section defines it, OR all
//!   defining vendor sections agree on the same value (the copy-paste case).
//!   When vendor sections disagree, [`Config::get`] returns `None` and forces
//!   the caller to disambiguate via [`Config::get_for`].
//!
//! Shared keys (auth credentials, network timeout) read via [`Config::get`].
//! Vendor-specific keys (`BITBUCKET_DEFAULT_WORKSPACE`, `ATLASSIAN_SITE_NAME`)
//! read via [`Config::get_for`].

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use tracing::{debug, warn};

use crate::secrets::{ResolvedSecret, SecretProvenance, SecretSnapshot};

pub mod global;

/// Canonical vendor name for Bitbucket. Use these constants at call sites
/// instead of hard-coded strings so a typo becomes a compile error.
pub const VENDOR_BITBUCKET: &str = "bitbucket";

/// Canonical vendor name for Jira.
pub const VENDOR_JIRA: &str = "jira";

/// Canonical vendor name for Confluence.
pub const VENDOR_CONFLUENCE: &str = "confluence";

/// Canonical vendor name for Zoom. Unlike the Atlassian vendors, Zoom does
/// not share the `ATLASSIAN_*` credential model: it authenticates via
/// Server-to-Server OAuth (`ZOOM_ACCOUNT_ID` + `ZOOM_CLIENT_ID` +
/// `ZOOM_CLIENT_SECRET`) and the server auto-renews the short-lived bearer.
pub const VENDOR_ZOOM: &str = "zoom";

/// Canonical vendor name for `CircleCI`. Like Zoom, `CircleCI` does not share
/// the `ATLASSIAN_*` credential model: it authenticates with a single personal
/// API token (`CIRCLECI_TOKEN`) sent as `Authorization: Bearer <token>` — the
/// scheme `CircleCI`'s v2 API documents as recommended.
pub const VENDOR_CIRCLECI: &str = "circleci";

/// Canonical vendor name for Slack. Authenticates with a single bot/user OAuth
/// token (`SLACK_TOKEN`, typically `xoxb-…`) sent as `Authorization: Bearer
/// <token>` — the same carrier as Zoom/CircleCI. Slack's Web API is unusual in
/// that logical failures arrive as `200 OK` with `{"ok": false, "error": …}`;
/// that is handled in the vendor's success-body classifier, not here.
pub const VENDOR_SLACK: &str = "slack";

/// Canonical vendor name for Postman. Authenticates with an API key
/// (`POSTMAN_API_KEY`) sent in the custom `X-API-Key` header rather than
/// `Authorization` — see [`crate::auth::Credentials::ApiKeyHeader`].
pub const VENDOR_POSTMAN: &str = "postman";

/// Canonical vendor name for edX / Open edX discussion APIs. Authenticates
/// with a bearer token (`EDX_ACCESS_TOKEN`) and defaults to the edx.org LMS
/// base (`https://courses.edx.org`), with `EDX_API_BASE` available for Open
/// edX instances or tests.
pub const VENDOR_EDX: &str = "edx";

/// Canonical vendor name for New Relic. Like the other non-Atlassian vendors it
/// does not share the `ATLASSIAN_*` credential model: it authenticates with a
/// User API key (`NEW_RELIC_API_KEY`) sent in the custom `API-Key` header — see
/// [`crate::auth::Credentials::ApiKeyHeader`]. Its sole API is `NerdGraph` (a
/// single `GraphQL` endpoint), and EU-region accounts select a different host via
/// `NEW_RELIC_REGION=eu`.
pub const VENDOR_NEWRELIC: &str = "newrelic";

/// Canonical vendor name for Grafana. Like the other non-Atlassian vendors it
/// does not share the `ATLASSIAN_*` credential model: it authenticates with a
/// service-account token (`GRAFANA_TOKEN`) sent as `Authorization: Bearer` — see
/// [`crate::auth::Credentials::Bearer`]. Its base URL is required config
/// (`GRAFANA_URL`) since the same binary serves self-hosted and Grafana Cloud.
/// Logs are read by proxying `LogQL` to a Loki datasource through Grafana.
pub const VENDOR_GRAFANA: &str = "grafana";

/// Canonical vendor name for `SonarQube` / `SonarCloud`. Like the other
/// non-Atlassian vendors it does not share the `ATLASSIAN_*` credential model:
/// it authenticates with a user token (`SONARQUBE_TOKEN`) sent as
/// `Authorization: Bearer` — see [`crate::auth::Credentials::Bearer`]. Its base
/// URL is required config (`SONARQUBE_URL`) since the same binary serves
/// self-hosted `SonarQube` and `SonarCloud` (`https://sonarcloud.io`). The
/// headline use is reading back *why* a CI quality gate failed.
pub const VENDOR_SONARQUBE: &str = "sonarqube";

/// Canonical vendor name for Splunk. Splunk uses its management REST API,
/// configured by `SPLUNK_URL`, and authenticates with a token from
/// `SPLUNK_TOKEN`.
pub const VENDOR_SPLUNK: &str = "splunk";

/// Canonical vendor name for `NinjaOne`. Supports the public v2 API with a
/// bearer token or API session key, and (when explicitly configured) the
/// web-console session cookie used by legacy `/ws/...` endpoints.
pub const VENDOR_NINJAONE: &str = "ninjaone";

/// Canonical vendor name for WRDS (Wharton Research Data Services). WRDS is the
/// one vendor with no REST API: access is a direct **`PostgreSQL`** connection
/// (`wrds-pgdata.wharton.upenn.edu:9737`, SSL required), so it does not use the
/// `ATLASSIAN_*` credential model or the shared HTTP transport. Authentication
/// is a WRDS username + password (`WRDS_USERNAME` / `WRDS_PASSWORD`); the host,
/// port, and database default to the WRDS cloud values and are overridable
/// (`WRDS_HOST` / `WRDS_PORT` / `WRDS_DBNAME`) for tests or mirrors.
pub const VENDOR_WRDS: &str = "wrds";

/// Immutable configuration snapshot assembled from all three sources.
///
/// Internally split into a vendor-neutral `shared` overlay (process env +
/// `.env`) and a per-vendor map populated from the global config file. See
/// the module docs for lookup rules.
#[derive(Debug, Clone, Default)]
pub struct Config {
    shared: HashMap<String, String>,
    by_vendor: BTreeMap<String, HashMap<String, String>>,
    /// Every secret *reference* among the values above, resolved (plan
    /// §3.8). Lives on the config rather than beside it so that a tool
    /// call's config snapshot and its secret snapshot are one `Arc` and
    /// cannot tear against each other; the accessors expand a resolved
    /// reference in place, which is how a principal such as
    /// `ATLASSIAN_USER_EMAIL` can come from the same document as its token.
    /// Empty until [`Config::with_secrets`] — a configuration with no
    /// references never allocates one.
    secrets: Arc<SecretSnapshot>,
}

/// Outcome of [`Config::resolve`]. Distinguishes "key absent everywhere"
/// from "vendor sections disagree" — both of which appear as `None` from
/// [`Config::get`]. `creds migrate` needs the distinction to refuse
/// migrating an already-broken config silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved<'a> {
    /// Neither `shared` nor any vendor section defines the key.
    Missing,
    /// `shared` defines it, or all vendor sections that define it agree.
    Resolved(&'a str),
    /// Two or more vendor sections define the key with different values.
    /// Each `(vendor, value)` pair is reported in `by_vendor` order.
    Ambiguous { values: Vec<(&'a str, &'a str)> },
}

/// Builds the snapshot using the standard cascade. Calls to this function
/// read the filesystem (global config + `.env`) and `std::env`. It is
/// intentionally side-effect free.
pub fn load() -> Config {
    load_from_global_path(global::default_path().as_deref())
}

/// Build the standard cascade with an explicitly selected global config.
/// Kept crate-private for the live-config watcher, which must continue to
/// track the exact path selected at server startup.
pub(crate) fn load_from_global_path(global_path: Option<&Path>) -> Config {
    Config::load_from_sources(
        global_path,
        Some(Path::new(".env")),
        &env_map_from_process(),
    )
}

impl Config {
    /// Internal streaming acquisition ceiling. This is deliberately absent
    /// from public tool schemas and is clamped to the planner's hard ceiling.
    pub(crate) fn streaming_partition_concurrency(&self) -> usize {
        self.get("STREAMING_PARTITION_CONCURRENCY")
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| {
                (1..=crate::constants::data_limits::MAX_TIME_PARTITIONS).contains(value)
            })
            .unwrap_or(crate::constants::data_limits::DEFAULT_PARALLEL_TIME_PARTITIONS)
    }

    pub(crate) fn streaming_artifact_retention(&self) -> std::time::Duration {
        bounded_duration_seconds(
            self.get("STREAMING_ARTIFACT_RETENTION_SECONDS"),
            crate::constants::data_limits::DEFAULT_STREAMING_ARTIFACT_RETENTION,
            crate::constants::data_limits::MIN_STREAMING_ARTIFACT_RETENTION,
            crate::constants::data_limits::MAX_STREAMING_ARTIFACT_RETENTION,
        )
    }

    pub(crate) fn streaming_artifact_sweep_interval(&self) -> std::time::Duration {
        bounded_duration_seconds(
            self.get("STREAMING_ARTIFACT_SWEEP_INTERVAL_SECONDS"),
            crate::constants::data_limits::DEFAULT_STREAMING_ARTIFACT_SWEEP_INTERVAL,
            crate::constants::data_limits::MIN_STREAMING_ARTIFACT_SWEEP_INTERVAL,
            crate::constants::data_limits::MAX_STREAMING_ARTIFACT_SWEEP_INTERVAL,
        )
    }

    /// Pure builder used by tests and by [`load`]. Priority is applied as
    /// follows:
    ///
    /// - Global config sections are read into `by_vendor`, keyed by the
    ///   canonical vendor name (e.g. `"bitbucket"`, `"jira"`). Multiple
    ///   aliases for the same vendor are merged with the higher-priority
    ///   alias winning per-key.
    /// - `.env` and process env are merged into the vendor-neutral `shared`
    ///   overlay. Process env wins over `.env`.
    ///
    /// - `global_path`: optional path to a `configs.json` file.
    /// - `dotenv_path`: optional path to a `.env` file.
    /// - `process_env`: caller-supplied view of `std::env::vars()`.
    pub fn load_from_sources(
        global_path: Option<&Path>,
        dotenv_path: Option<&Path>,
        process_env: &HashMap<String, String>,
    ) -> Self {
        let mut shared: HashMap<String, String> = HashMap::new();
        let mut by_vendor: BTreeMap<String, HashMap<String, String>> = BTreeMap::new();

        // Global config: vendor-scoped sections.
        if let Some(path) = global_path
            && path.exists()
        {
            match global::read_all_vendors(path, crate::constants::PACKAGE_NAME) {
                Ok(map) => {
                    debug!(vendors = map.len(), "loaded global config sections");
                    by_vendor = map;
                }
                Err(err) => warn!(error = %err, "failed to read global config"),
            }
        }

        // .env: vendor-neutral, applied to shared.
        if let Some(path) = dotenv_path
            && path.exists()
        {
            match load_dotenv(path) {
                Ok(entries) => {
                    debug!(count = entries.len(), "loaded .env entries");
                    shared.extend(entries);
                }
                Err(err) => warn!(error = %err, "failed to read .env"),
            }
        }

        // Process env: vendor-neutral, highest-priority overlay on shared.
        for (k, v) in process_env {
            shared.insert(k.clone(), v.clone());
        }

        Self {
            shared,
            by_vendor,
            secrets: Arc::default(),
        }
    }

    /// Construct directly from a flat map. The map populates the
    /// vendor-neutral `shared` overlay, so all entries are visible from both
    /// [`get`](Self::get) and [`get_for`](Self::get_for). Useful for tests
    /// and library embedders that pass credentials in directly without a
    /// global config file.
    pub fn from_map(values: HashMap<String, String>) -> Self {
        Self {
            shared: values,
            by_vendor: BTreeMap::new(),
            secrets: Arc::default(),
        }
    }

    /// This configuration with a resolved secret snapshot attached. The
    /// maps are shared with `self` only by clone; the snapshot is shared
    /// by `Arc`, so attaching the same snapshot to a reloaded configuration
    /// costs nothing beyond the maps.
    #[must_use]
    pub fn with_secrets(mut self, secrets: Arc<SecretSnapshot>) -> Self {
        self.secrets = secrets;
        self
    }

    /// The attached snapshot (empty when nothing was resolved).
    #[must_use]
    pub const fn secrets(&self) -> &Arc<SecretSnapshot> {
        &self.secrets
    }

    /// Every value that is a secret reference, across `shared` and every
    /// vendor section, trimmed. What the resolver is handed at startup and
    /// on every refresh; duplicates are the resolver's problem.
    pub fn secret_references(&self) -> impl Iterator<Item = &str> {
        self.shared
            .values()
            .chain(self.by_vendor.values().flat_map(HashMap::values))
            .map(|value| value.trim())
            .filter(|value| crate::secrets::is_reference(value))
    }

    /// Where the value behind `key` came from, when it is a resolved
    /// reference: the scheme and the provider's version, for the audit
    /// record (plan §3.8, "Attribution"). `None` for a literal, a keychain
    /// sentinel, an absent key, or a reference that has not resolved.
    #[must_use]
    pub fn secret_provenance(&self, vendor: &str, key: &str) -> Option<&SecretProvenance> {
        let raw = self.raw_for(vendor, key)?.trim();
        if !crate::secrets::is_reference(raw) {
            return None;
        }
        self.secrets.get(raw).map(ResolvedSecret::provenance)
    }

    /// The configured text, before reference expansion.
    fn raw_for(&self, vendor: &str, key: &str) -> Option<&str> {
        if let Some(v) = self.shared.get(key) {
            return Some(v.as_str());
        }
        self.by_vendor
            .get(vendor)
            .and_then(|m| m.get(key))
            .map(String::as_str)
    }

    /// A resolved reference becomes its value; anything else is returned
    /// as it is — a literal, a keychain sentinel, or a reference the
    /// snapshot does not hold (which the credential cascade then refuses
    /// by name rather than sending upstream as a token).
    ///
    /// On the request path for every lookup, so: one byte dispatch to
    /// decide "not a reference" for the overwhelmingly common case, and a
    /// hash lookup only for an actual reference. No allocation either way.
    fn expand<'a>(&'a self, raw: &'a str) -> &'a str {
        let trimmed = raw.trim();
        if !crate::secrets::is_reference(trimmed) {
            return raw;
        }
        self.secrets.get(trimmed).map_or(raw, ResolvedSecret::value)
    }

    /// Vendor-neutral lookup. Returns the value when:
    /// - `shared` (process env / `.env`) defines it, OR
    /// - exactly one vendor section defines it, OR
    /// - all vendor sections that define it agree on the value.
    ///
    /// Returns `None` when two or more vendor sections define the key with
    /// different values; the caller must then disambiguate via
    /// [`get_for`](Self::get_for). Callers that need to distinguish "key
    /// absent everywhere" from "vendor sections disagree" should use
    /// [`Self::resolve`] instead.
    pub fn get(&self, key: &str) -> Option<&str> {
        match self.resolve(key) {
            Resolved::Resolved(v) => Some(v),
            Resolved::Missing | Resolved::Ambiguous { .. } => None,
        }
    }

    /// Vendor-neutral lookup with explicit disambiguation. Same priority
    /// order as [`Self::get`] but tells callers which case they hit.
    /// Used by `creds migrate` to refuse silently writing into a config
    /// whose vendor sections disagree about a credential.
    pub fn resolve(&self, key: &str) -> Resolved<'_> {
        if let Some(v) = self.shared.get(key) {
            return Resolved::Resolved(self.expand(v));
        }
        let mut hits: Vec<(&str, &str)> = Vec::new();
        for (vendor, vendor_map) in &self.by_vendor {
            if let Some(v) = vendor_map.get(key) {
                hits.push((vendor.as_str(), self.expand(v)));
            }
        }
        match hits.as_slice() {
            [] => Resolved::Missing,
            [(_, single)] => Resolved::Resolved(single),
            _ if hits.iter().all(|(_, v)| *v == hits[0].1) => Resolved::Resolved(hits[0].1),
            _ => Resolved::Ambiguous { values: hits },
        }
    }

    /// Vendor-scoped lookup. Reads `shared` first, then the named vendor's
    /// section only. Never reads another vendor's section.
    ///
    /// Use this for keys that are vendor-specific by definition
    /// (`BITBUCKET_DEFAULT_WORKSPACE`).
    pub fn get_for(&self, vendor: &str, key: &str) -> Option<&str> {
        self.raw_for(vendor, key).map(|raw| self.expand(raw))
    }

    /// Vendor-scoped lookup with a fallback chain through a caller-supplied
    /// list of sibling vendors. Reads `shared`, then `by_vendor[primary]`,
    /// then each fallback in order, returning the first defined value.
    ///
    /// Use this for keys that are nominally vendor-specific but realistically
    /// shared across products on the same Atlassian site. The canonical case
    /// is `ATLASSIAN_SITE_NAME`: the `jira` and `confluence` sections both
    /// rely on the same site shortname, so a user with one section populated
    /// shouldn't be forced to duplicate it under the other.
    ///
    /// Disagreement between sections is **not** detected here — callers that
    /// need disambiguation should use [`get_for`](Self::get_for) instead.
    /// The fallback list is intentionally explicit so unrelated vendors
    /// (e.g. Bitbucket) do not silently leak into the lookup.
    pub fn get_for_with_fallback(
        &self,
        primary: &str,
        fallbacks: &[&str],
        key: &str,
    ) -> Option<&str> {
        if let Some(v) = self.shared.get(key) {
            return Some(self.expand(v));
        }
        if let Some(v) = self.by_vendor.get(primary).and_then(|m| m.get(key)) {
            return Some(self.expand(v));
        }
        for vendor in fallbacks {
            if let Some(v) = self.by_vendor.get(*vendor).and_then(|m| m.get(key)) {
                return Some(self.expand(v));
            }
        }
        None
    }

    pub fn get_or(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or(default).to_owned()
    }

    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        self.get(key)
            .map_or(default, |v| v.eq_ignore_ascii_case("true"))
    }

    pub fn get_int(&self, key: &str, default: i64) -> i64 {
        self.get(key)
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(default)
    }

    /// Test/inspection helper. Counts entries across `shared` and every
    /// vendor section; a key present in both is counted once per map.
    pub fn len(&self) -> usize {
        self.shared.len() + self.by_vendor.values().map(HashMap::len).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.shared.is_empty() && self.by_vendor.values().all(HashMap::is_empty)
    }
}

fn bounded_duration_seconds(
    configured: Option<&str>,
    default: std::time::Duration,
    minimum: std::time::Duration,
    maximum: std::time::Duration,
) -> std::time::Duration {
    configured
        .and_then(|value| value.parse::<u64>().ok())
        .map(std::time::Duration::from_secs)
        .filter(|value| (*value >= minimum) && (*value <= maximum))
        .unwrap_or(default)
}

fn env_map_from_process() -> HashMap<String, String> {
    std::env::vars().collect()
}

fn load_dotenv(path: &Path) -> std::io::Result<HashMap<String, String>> {
    let iter = dotenvy::from_path_iter(path).map_err(std::io::Error::other)?;
    let mut map = HashMap::new();
    for entry in iter {
        let (k, v) = entry.map_err(std::io::Error::other)?;
        map.insert(k, v);
    }
    Ok(map)
}

/// Parse a `configs.json` value (typically deserialised from disk) for a given
/// package, returning a flat env map for the first matching alias.
///
/// Preserved for back-compat with the original single-vendor TS port; the
/// internal loader uses [`extract_all_vendor_sections`] instead. Exposed for
/// tests; production code should prefer [`global::read_all_vendors`] via
/// [`Config::load_from_sources`].
pub fn extract_environments_for(root: &Value, package_name: &str) -> HashMap<String, String> {
    let keys = candidate_keys(package_name);
    for key in &keys {
        if let Some(env) = read_environments_at(root, key) {
            return env;
        }
    }
    HashMap::new()
}

/// Read every recognised vendor section out of the global config root and
/// return a `canonical-vendor → env-map` table. Per-vendor alias merging
/// uses the same priority order as [`extract_environments_for`] (higher
/// priority overrides per-key).
///
/// `package_name` is used to extend the Bitbucket vendor's alias list with
/// the crate's published package name and its unscoped form, so a user with
/// a section keyed by the full package name still resolves.
pub fn extract_all_vendor_sections(
    root: &Value,
    package_name: &str,
) -> BTreeMap<String, HashMap<String, String>> {
    let mut out: BTreeMap<String, HashMap<String, String>> = BTreeMap::new();

    for (canonical, aliases) in vendor_aliases(package_name) {
        // Apply aliases in REVERSE priority so that higher-priority alias
        // values overwrite lower-priority ones in the merged map.
        let mut merged: HashMap<String, String> = HashMap::new();
        for alias in aliases.iter().rev() {
            if let Some(env) = read_environments_at(root, alias) {
                merged.extend(env);
            }
        }
        if !merged.is_empty() {
            out.insert(canonical.to_string(), merged);
        }
    }

    out
}

/// Look up `root[key].environments` and coerce the values into strings.
/// Returns `None` when the section or its `environments` map is missing.
fn read_environments_at(root: &Value, key: &str) -> Option<HashMap<String, String>> {
    let section = root.get(key).and_then(Value::as_object)?;
    let env = section.get("environments").and_then(Value::as_object)?;
    Some(
        env.iter()
            .filter_map(|(k, v)| match v {
                Value::String(s) => Some((k.clone(), s.clone())),
                Value::Bool(b) => Some((k.clone(), b.to_string())),
                Value::Number(n) => Some((k.clone(), n.to_string())),
                _ => None,
            })
            .collect(),
    )
}

/// Aliases we try inside `configs.json`, in priority order. Matches TS
/// `loadFromGlobalConfig` key probing logic. Used by the back-compat
/// [`extract_environments_for`] entry point.
pub fn candidate_keys(package_name: &str) -> Vec<String> {
    let short = "bitbucket".to_string();
    let product = "atlassian-bitbucket".to_string();
    let full = package_name.to_string();
    let unscoped = package_name
        .split_once('/')
        .map_or_else(|| package_name.to_string(), |(_, rest)| rest.to_string());
    let mut keys = vec![short, product, full, unscoped];
    for legacy in [
        crate::constants::LEGACY_PACKAGE_NAME,
        crate::constants::LEGACY_UNSCOPED_PACKAGE_NAME,
    ] {
        if !keys.iter().any(|key| key == legacy) {
            keys.push(legacy.to_string());
        }
    }
    keys
}

/// Per-vendor alias lists in priority order (highest priority first).
///
/// Both vendors include the upstream TS package names so existing
/// `~/.mcp/configs.json` files migrating from the TS reference servers
/// (`@aashari/mcp-server-atlassian-bitbucket`, `@aashari/mcp-server-atlassian-jira`)
/// keep resolving without edits. The Bitbucket vendor additionally
/// includes this crate's own `package_name`-derived aliases.
///
/// Exposed publicly so `creds migrate` can walk the raw JSON using the
/// same canonical-vendor → aliases mapping the loader uses.
pub fn vendor_aliases(package_name: &str) -> Vec<(&'static str, Vec<String>)> {
    let bitbucket_aliases = {
        let mut v = vec![
            "bitbucket".to_string(),
            "atlassian-bitbucket".to_string(),
            package_name.to_string(),
        ];
        let unscoped = package_name
            .split_once('/')
            .map_or_else(|| package_name.to_string(), |(_, rest)| rest.to_string());
        if !v.iter().any(|a| a == &unscoped) {
            v.push(unscoped);
        }
        // This project's pre-rename package names.
        v.push(crate::constants::LEGACY_PACKAGE_NAME.to_string());
        v.push(crate::constants::LEGACY_UNSCOPED_PACKAGE_NAME.to_string());
        // TS Bitbucket package names — kept so users migrating from the
        // upstream Node servers don't need to rekey their global config.
        v.push("@aashari/mcp-server-atlassian-bitbucket".to_string());
        v.push("mcp-server-atlassian-bitbucket".to_string());
        v
    };
    let jira_aliases = vec![
        "jira".to_string(),
        "atlassian-jira".to_string(),
        // TS Jira package names — same migration guarantee.
        "@aashari/mcp-server-atlassian-jira".to_string(),
        "mcp-server-atlassian-jira".to_string(),
    ];
    let confluence_aliases = vec![
        "confluence".to_string(),
        "atlassian-confluence".to_string(),
        // TS Confluence package names — same migration guarantee.
        "@aashari/mcp-server-atlassian-confluence".to_string(),
        "mcp-server-atlassian-confluence".to_string(),
    ];
    let zoom_aliases = vec!["zoom".to_string(), "mcp-server-zoom".to_string()];
    let circleci_aliases = vec![
        "circleci".to_string(),
        "circle-ci".to_string(),
        "mcp-server-circleci".to_string(),
    ];
    let slack_aliases = vec!["slack".to_string(), "mcp-server-slack".to_string()];
    let postman_aliases = vec!["postman".to_string(), "mcp-server-postman".to_string()];
    let edx_aliases = vec![
        "edx".to_string(),
        "openedx".to_string(),
        "open-edx".to_string(),
        "mcp-server-edx".to_string(),
    ];
    let newrelic_aliases = vec![
        "newrelic".to_string(),
        "new-relic".to_string(),
        "mcp-server-newrelic".to_string(),
    ];
    let grafana_aliases = vec!["grafana".to_string(), "mcp-server-grafana".to_string()];
    let sonarqube_aliases = vec![
        "sonarqube".to_string(),
        "sonar".to_string(),
        "sonarcloud".to_string(),
        "mcp-server-sonarqube".to_string(),
    ];
    let splunk_aliases = vec!["splunk".to_string(), "mcp-server-splunk".to_string()];
    let ninjaone_aliases = vec![
        "ninjaone".to_string(),
        "ninja-one".to_string(),
        "ninjarmm".to_string(),
        "mcp-server-ninjaone".to_string(),
    ];
    let wrds_aliases = vec!["wrds".to_string(), "mcp-server-wrds".to_string()];

    vec![
        (VENDOR_BITBUCKET, bitbucket_aliases),
        (VENDOR_JIRA, jira_aliases),
        (VENDOR_CONFLUENCE, confluence_aliases),
        (VENDOR_ZOOM, zoom_aliases),
        (VENDOR_CIRCLECI, circleci_aliases),
        (VENDOR_SLACK, slack_aliases),
        (VENDOR_POSTMAN, postman_aliases),
        (VENDOR_EDX, edx_aliases),
        (VENDOR_NEWRELIC, newrelic_aliases),
        (VENDOR_GRAFANA, grafana_aliases),
        (VENDOR_SONARQUBE, sonarqube_aliases),
        (VENDOR_SPLUNK, splunk_aliases),
        (VENDOR_NINJAONE, ninjaone_aliases),
        (VENDOR_WRDS, wrds_aliases),
    ]
}

/// Inbound authentication mode (`MCP_AUTH_MODE`).
///
/// `Off` is the community default: no inbound authentication, with the
/// stdio pipe or loopback bind as the trust boundary. `Okta` opts into the
/// enterprise inbound-auth path (Phase A). Parsing is fail-closed: an
/// unrecognised value is an error, never silently mapped to `Off`, because
/// "typo disables authentication" is exactly the failure mode
/// `docs/enterprise-product-plan.md` §1.2 forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMode {
    /// No inbound authentication (community default).
    #[default]
    Off,
    /// Okta-validated inbound bearer tokens (enterprise, Phase A).
    Okta,
}

impl AuthMode {
    /// Parse the raw `MCP_AUTH_MODE` value. Absent or empty means [`Off`]
    /// (the documented default); anything not exactly `off`/`okta`
    /// (ASCII-case-insensitive) is an error the server must refuse to start
    /// on.
    ///
    /// [`Off`]: AuthMode::Off
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason when the value is unrecognised.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw.map(str::trim) {
            None | Some("") => Ok(Self::Off),
            Some(value) if value.eq_ignore_ascii_case("off") => Ok(Self::Off),
            Some(value) if value.eq_ignore_ascii_case("okta") => Ok(Self::Okta),
            Some(other) => Err(format!(
                "unrecognised MCP_AUTH_MODE {other:?} (expected \"off\" or \"okta\"); \
                 refusing to guess an authentication mode"
            )),
        }
    }
}

/// Cross-platform `~/.mcp/configs.json` resolver.
pub fn default_global_path() -> Option<PathBuf> {
    global::default_path()
}

#[cfg(test)]
mod streaming_config_tests {
    use super::Config;
    use std::collections::HashMap;

    #[test]
    fn partition_concurrency_defaults_and_stays_within_planner_ceiling() {
        assert_eq!(Config::default().streaming_partition_concurrency(), 4);
        for (configured, expected) in [("1", 1), ("8", 8), ("16", 16)] {
            let config = Config::from_map(HashMap::from([(
                "STREAMING_PARTITION_CONCURRENCY".to_owned(),
                configured.to_owned(),
            )]));
            assert_eq!(config.streaming_partition_concurrency(), expected);
        }
        for invalid in ["0", "17", "invalid"] {
            let config = Config::from_map(HashMap::from([(
                "STREAMING_PARTITION_CONCURRENCY".to_owned(),
                invalid.to_owned(),
            )]));
            assert_eq!(config.streaming_partition_concurrency(), 4);
        }
    }

    #[test]
    fn artifact_retention_and_sweep_settings_are_bounded() {
        assert_eq!(
            Config::default().streaming_artifact_retention(),
            std::time::Duration::from_hours(1)
        );
        assert_eq!(
            Config::default().streaming_artifact_sweep_interval(),
            std::time::Duration::from_mins(1)
        );
        for (key, valid, invalid, expected) in [
            (
                "STREAMING_ARTIFACT_RETENTION_SECONDS",
                "600",
                "299",
                std::time::Duration::from_mins(10),
            ),
            (
                "STREAMING_ARTIFACT_SWEEP_INTERVAL_SECONDS",
                "30",
                "3601",
                std::time::Duration::from_secs(30),
            ),
        ] {
            let configured = Config::from_map(HashMap::from([(key.to_owned(), valid.to_owned())]));
            let actual = if key.contains("RETENTION") {
                configured.streaming_artifact_retention()
            } else {
                configured.streaming_artifact_sweep_interval()
            };
            assert_eq!(actual, expected);

            let invalid = Config::from_map(HashMap::from([(key.to_owned(), invalid.to_owned())]));
            let actual = if key.contains("RETENTION") {
                invalid.streaming_artifact_retention()
            } else {
                invalid.streaming_artifact_sweep_interval()
            };
            assert_eq!(
                actual,
                if key.contains("RETENTION") {
                    std::time::Duration::from_hours(1)
                } else {
                    std::time::Duration::from_mins(1)
                }
            );
        }
    }
}

#[cfg(test)]
mod auth_mode_tests {
    use super::AuthMode;

    #[test]
    fn absent_or_off_is_off_and_okta_is_okta() {
        assert_eq!(AuthMode::parse(None), Ok(AuthMode::Off));
        assert_eq!(AuthMode::parse(Some("")), Ok(AuthMode::Off));
        assert_eq!(AuthMode::parse(Some("off")), Ok(AuthMode::Off));
        assert_eq!(AuthMode::parse(Some(" OFF ")), Ok(AuthMode::Off));
        assert_eq!(AuthMode::parse(Some("okta")), Ok(AuthMode::Okta));
        assert_eq!(AuthMode::parse(Some("Okta")), Ok(AuthMode::Okta));
    }

    #[test]
    fn unknown_values_error_instead_of_silently_disabling_auth() {
        for bad in ["on", "true", "oauth", "octa", "0"] {
            let err = AuthMode::parse(Some(bad)).unwrap_err();
            assert!(err.contains("MCP_AUTH_MODE"), "{err}");
            assert!(err.contains(bad), "{err}");
        }
    }
}

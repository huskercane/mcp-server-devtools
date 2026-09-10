//! Resource extractors (WP 0.8): pure functions that turn a request into
//! the action-shaped half of an [`ActionContext`](super::ActionContext).
//!
//! The specification each function implements lives in
//! `docs/read-endpoint-inventory.md`; this module is the executable proof of
//! the §3.2 schema against one purpose-built tool (Grafana datasource reads)
//! and one passthrough endpoint (Jira `POST /rest/api/3/search/jql`).
//!
//! Ground rules (plan §3.2, budgets §8):
//!
//! - **Pure and total**: no I/O, no config, no identity — extractors see
//!   request data only, so they test as table lookups.
//! - **Sound over complete**: an extractor only claims a resource scope it
//!   can guarantee. Anything it cannot classify is
//!   [`ResourceType::Unknown`] + [`NormalizedAction::Passthrough`], which
//!   default-deny policy denies; anything it cannot *scope* is
//!   [`ResourceScope::unscoped`], which no id-scoped rule matches.
//! - **No regex on the hot path**: hand-rolled scanning only, and no
//!   allocation beyond the ids and the canonical path that actually leave
//!   the function.
//! - **Canonical input only.** Extractors take a [`CanonicalPath`], which
//!   only [`super::canonical`] can construct, so the §3.5 normalization
//!   (single unreserved decode, dot-segment removal, slash collapse,
//!   re-encoding) has always happened before a route is classified. A
//!   segment that still carries a percent-escape after canonicalization is
//!   never claimed as a resource id: it is an escape of a reserved or
//!   non-path character, and no id vocabulary here contains one.
//!
//! ## What "sound" cost us, and why it is the right trade
//!
//! Every scanner here fails to *no claim* rather than to a guess. A claim
//! that is too narrow authorizes a call that reaches further than the policy
//! believed — the failure that matters. A missing claim only costs
//! completeness: the call falls back to needing an explicit unscoped-read
//! rule. `NOT (project = PUBLIC)` is the canonical example (see
//! [`jira::project_keys_from_jql`]).

use crate::transport::HttpMethod;

use super::canonical::{CanonicalPath, CanonicalTarget};
use super::{
    ActionDetails, ApprovedReadDowngrade, NormalizedAction, RequestRisk, ResourceConstraint,
    ResourceScope, ResourceType,
};

/// How an allowlisted query value is retained in `query_attributes`.
///
/// There is deliberately **no verbatim option**. Every value here is written
/// by the caller, and bounding a caller-controlled string is not redacting
/// it: a token supplied as Jira's `fields` or Grafana's `direction` used to
/// land in the serialized `ActionContext` intact, just shorter. A value is
/// retained only if it *parses* as the shape the endpoint documents; anything
/// else is a digest, so an attribute can never carry text nobody validated.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Retention {
    /// One of a fixed set of literals (`direction`). Retained only on an
    /// exact, case-insensitive match against the set.
    ///
    /// This is the one shape exempt from the "no verbatim option" rule
    /// below, because it is not really a shape check on caller text at
    /// all: the value only survives by exact match against a small,
    /// server-owned vocabulary the caller does not control the membership
    /// of. A credential cannot coincidentally equal `"backward"`.
    Enumerated(&'static [&'static str]),
    /// A **caller-authored value with no closed shape** — a comma-separated
    /// field list (`fields`), a numeric bound (`limit`, `maxResults`), a
    /// time bound (`start`, `end`, `step`), or a search expression (`jql`,
    /// `LogQL`). Kept as a digest and a length, never as text.
    ///
    /// There is deliberately no per-shape verbatim option for any of these.
    /// Two earlier revisions each tried one: field lists were retained
    /// verbatim when every element matched `[A-Za-z0-9_.*-]+`, and numeric
    /// bounds when the value parsed as `u64`. Both alphabets are also real
    /// credential formats — `sk-live-…`/`xoxb-…` for the first, and this
    /// repository's own six-digit `NinjaOne` TOTP/MFA codes
    /// (`tests/ninjaone_session_tests.rs`) for the second — so
    /// `fields=xoxb-secret-token` and `limit=381164` each parsed as their
    /// declared shape and passed through unchanged. There is no caller-
    /// supplied shape here narrow enough to exclude every real credential
    /// format, unlike [`Retention::Enumerated`]'s closed vocabulary — so
    /// nothing in this variant is retained by shape at all.
    ///
    /// `docs/read-endpoint-inventory.md` decision 5 says raw query text does
    /// not enter audit, and it says so for a concrete reason: an expression
    /// can carry a token someone pasted into a query, a customer identifier,
    /// or the contents of whatever they were hunting for. An earlier
    /// revision documented that decision and then cloned the value verbatim
    /// and unbounded anyway, so the text reached every serialized
    /// `ActionContext`. A digest still lets two calls be correlated, or a
    /// query matched against one quoted in a later report, without the
    /// journal holding the material itself.
    Digest,
}

/// Longest value of any shape retained, parsed or not.
const MAX_ATTRIBUTE_VALUE: usize = 256;

/// Retain only allowlisted query keys, sorted by key (§3.2
/// `query_attributes`), each according to its declared [`Retention`].
fn allowlisted_attributes(
    params: &[(&str, &str)],
    allowlist: &[(&str, Retention)],
) -> Vec<(String, String)> {
    let mut kept: Vec<(String, String)> = params
        .iter()
        .filter_map(|(key, value)| {
            let retention = allowlist
                .iter()
                .find_map(|(allowed, retention)| (allowed == key).then_some(*retention))?;
            Some(((*key).to_owned(), retain(value, retention)))
        })
        .collect();
    kept.sort();
    kept
}

/// Retain `value` as its declared shape, or as a digest if it is not that
/// shape. Failing to a digest rather than dropping the key keeps the *fact*
/// that the caller sent something odd visible in the evidence.
fn retain(value: &str, retention: Retention) -> String {
    if value.len() > MAX_ATTRIBUTE_VALUE {
        return expression_digest(value);
    }
    let parsed = match retention {
        Retention::Enumerated(allowed) => parse_enumerated(value, allowed),
        Retention::Digest => None,
    };
    parsed.unwrap_or_else(|| expression_digest(value))
}

fn parse_enumerated(value: &str, allowed: &[&'static str]) -> Option<String> {
    let trimmed = value.trim();
    allowed
        .iter()
        .find(|candidate| candidate.eq_ignore_ascii_case(trimmed))
        .map(|candidate| (*candidate).to_owned())
}

/// `sha256:<16 hex chars>/<byte length>` — enough to correlate two identical
/// values and to see how big one was, and nothing else. Truncated to 64 bits
/// because this is a correlation handle, not a commitment.
///
/// Shared with [`super::ClientIdentity`], which needs the same "keep a
/// handle, not the text" treatment for client-reported names and request
/// ids. One implementation so the format cannot drift between them.
#[must_use]
pub(crate) fn opaque_handle(value: &str) -> String {
    expression_digest(value)
}

fn expression_digest(value: &str) -> String {
    use std::fmt::Write as _;

    use sha2::{Digest as _, Sha256};

    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::with_capacity(40);
    out.push_str("sha256:");
    for byte in &digest[..8] {
        let _ = write!(out, "{byte:02x}");
    }
    let _ = write!(out, "/{}", value.len());
    out
}

/// Grafana purpose-built read tools. `readOnlyHint` is true by construction
/// for both, so `request_risk` is [`RequestRisk::Read`] from tool identity,
/// not derived from the HTTP method.
pub mod grafana {
    use super::{
        ActionDetails, CanonicalPath, HttpMethod, NormalizedAction, ResourceScope, ResourceType,
        Retention, allowlisted_attributes,
    };

    /// Query params of `grafana_query_logs` that are policy-relevant.
    ///
    /// `query` is the `LogQL` the caller wrote, so it is retained as a digest
    /// rather than as text (see [`super::Retention::Digest`]). The label
    /// selectors inside it never restricted *which* datasource is read, so
    /// nothing about policy depends on having the expression.
    const QUERY_LOGS_ALLOWLIST: &[(&str, Retention)] = &[
        ("direction", Retention::Enumerated(&["backward", "forward"])),
        ("end", Retention::Digest),
        ("limit", Retention::Digest),
        ("query", Retention::Digest),
        ("start", Retention::Digest),
        ("step", Retention::Digest),
    ];

    /// Path segments of the datasource proxy prefix, without the UID.
    const PROXY_PREFIX: [&str; 4] = ["api", "datasources", "proxy", "uid"];
    /// Path segments of Loki's range query, after the UID.
    const LOKI_QUERY_RANGE: [&str; 4] = ["loki", "api", "v1", "query_range"];

    /// Grafana UIDs are at most 40 characters; 64 leaves headroom without
    /// letting an unbounded string into a path.
    const MAX_UID_LEN: usize = 64;

    /// Whether `uid` is a well-formed Grafana datasource UID.
    ///
    /// Grafana generates UIDs from `[A-Za-z0-9_-]`, and **the whole design
    /// of the datasource extractor rests on that**: the UID is interpolated
    /// into a proxy path, so a value carrying `/`, `..`, `%2f`, `?`, or `#`
    /// would address a different endpoint than the one policy classified.
    /// This is the single definition of that rule — the extractor uses it to
    /// decide whether it may classify the call at all, and
    /// `controllers::grafana` uses it to refuse the call before dispatch, so
    /// the two cannot drift into disagreeing about what is safe.
    #[must_use]
    pub fn is_valid_datasource_uid(uid: &str) -> bool {
        !uid.is_empty()
            && uid.len() <= MAX_UID_LEN
            && uid
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    }

    /// `grafana_query_logs`: a read of one Loki datasource through the
    /// Grafana datasource proxy. The datasource UID is the resource.
    ///
    /// A UID that is not [`is_valid_datasource_uid`] is **not** classified as
    /// a datasource read: it comes back `Passthrough`/`Unknown`/`Unscoped`,
    /// which default-deny denies. The hostile value is also kept out of
    /// `canonical_path`, so it never reaches an audit record or a log line
    /// dressed up as a legitimate path.
    #[must_use]
    pub fn query_logs(datasource_uid: &str, params: &[(&str, &str)]) -> ActionDetails {
        // A valid UID is unreserved-only and never `.`/`..`, so the plain
        // path always builds; the fallback arm exists so this stays total
        // rather than panicking if the alphabet and the builder ever drift.
        let proxy_path = is_valid_datasource_uid(datasource_uid)
            .then(|| {
                let [prefix0, prefix1, prefix2, prefix3] = PROXY_PREFIX;
                let [loki0, loki1, loki2, loki3] = LOKI_QUERY_RANGE;
                CanonicalPath::from_plain_segments(&[
                    prefix0,
                    prefix1,
                    prefix2,
                    prefix3,
                    datasource_uid,
                    loki0,
                    loki1,
                    loki2,
                    loki3,
                ])
            })
            .flatten();
        match proxy_path {
            Some(path) => ActionDetails::read(
                NormalizedAction::QueryLogs,
                path,
                allowlisted_attributes(params, QUERY_LOGS_ALLOWLIST),
                ResourceType::Datasource,
                ResourceScope::id(datasource_uid),
            ),
            None => ActionDetails::unclassified_with_attributes(
                HttpMethod::Get,
                proxy_prefix_path(),
                allowlisted_attributes(params, QUERY_LOGS_ALLOWLIST),
            ),
        }
    }

    /// The proxy prefix as a canonical path — where a hostile UID is
    /// reported *without* echoing the UID itself. The segments are plain
    /// literals, so the fallback to `/` is unreachable; it keeps the
    /// function total without an `expect`.
    fn proxy_prefix_path() -> CanonicalPath {
        CanonicalPath::from_plain_segments(&PROXY_PREFIX).unwrap_or_else(CanonicalPath::root)
    }

    /// `grafana_list_datasources`: enumerates datasources. Addresses the
    /// datasource collection, not one datasource — hence
    /// [`ResourceScope::collection`], which is distinct from both "one
    /// datasource" and "we could not tell", and needs its own allow rule.
    #[must_use]
    pub fn list_datasources() -> ActionDetails {
        ActionDetails::read(
            NormalizedAction::ListDatasources,
            CanonicalPath::from_plain_segments(&["api", "datasources"])
                .unwrap_or_else(CanonicalPath::root),
            Vec::new(),
            ResourceType::Datasource,
            ResourceScope::collection(),
        )
    }

    /// Classify a Grafana HTTP call by its canonical path, for the egress
    /// chokepoint: the request the vendor client is about to send, mapped
    /// back onto the same vocabulary the purpose-built tools declare.
    ///
    /// Only the two purpose-built read endpoints are mapped. Everything else
    /// is `Passthrough`/`Unknown`, which default-deny denies — including a
    /// proxy path whose UID segment is not a valid UID.
    #[must_use]
    pub fn extract(
        method: HttpMethod,
        path: CanonicalPath,
        query: &[(&str, &str)],
    ) -> ActionDetails {
        // Segment buffer sized for the longest mapped route (nine segments)
        // plus one so a longer path is detectably longer, not truncated.
        const MAX_SEGMENTS: usize = 10;
        if method != HttpMethod::Get {
            return ActionDetails::unclassified(method, path);
        }
        let mut buffer: [&str; MAX_SEGMENTS] = [""; MAX_SEGMENTS];
        let mut count = 0usize;
        for segment in path.as_str().split('/').filter(|part| !part.is_empty()) {
            if count == MAX_SEGMENTS {
                return ActionDetails::unclassified(method, path);
            }
            buffer[count] = segment;
            count += 1;
        }
        match &buffer[..count] {
            ["api", "datasources"] => list_datasources(),
            [
                "api",
                "datasources",
                "proxy",
                "uid",
                uid,
                "loki",
                "api",
                "v1",
                "query_range",
            ] if is_valid_datasource_uid(uid) => query_logs(uid, query),
            _ => ActionDetails::unclassified(method, path),
        }
    }
}

/// Slack purpose-built read tools (WP B.1) and the passthrough classifier
/// for the same endpoints.
///
/// Slack's Web API is method-shaped: one path segment per method
/// (`/conversations.history`), the arguments in the query string. The
/// resource is the **channel**, named by the `channel` parameter — so the
/// channel id is validated here the way Grafana's datasource UID is
/// (`[A-Z0-9]{1,64}`), and a call whose channel id does not pass is not
/// classified. `search.messages` reaches every channel the token can see
/// and cannot be scoped by anything in the request (an `in:` modifier is a
/// hint to Slack's ranking, not a bound), so it is an *unscoped* channel
/// read that needs its own rule.
pub mod slack {
    use super::{
        ActionDetails, CanonicalPath, HttpMethod, NormalizedAction, ResourceScope, ResourceType,
        Retention, allowlisted_attributes,
    };

    const FLAG: Retention = Retention::Enumerated(&["true", "false"]);

    const LIST_ALLOWLIST: &[(&str, Retention)] = &[
        ("cursor", Retention::Digest),
        ("exclude_archived", FLAG),
        ("limit", Retention::Digest),
        ("types", Retention::Digest),
    ];
    const HISTORY_ALLOWLIST: &[(&str, Retention)] = &[
        ("cursor", Retention::Digest),
        ("inclusive", FLAG),
        ("latest", Retention::Digest),
        ("limit", Retention::Digest),
        ("oldest", Retention::Digest),
        ("ts", Retention::Digest),
    ];
    const SEARCH_ALLOWLIST: &[(&str, Retention)] = &[
        ("count", Retention::Digest),
        ("page", Retention::Digest),
        ("query", Retention::Digest),
        ("sort", Retention::Enumerated(&["score", "timestamp"])),
        ("sort_dir", Retention::Enumerated(&["asc", "desc"])),
    ];

    /// Slack ids are short and uppercase alphanumeric (`C0123ABCDEF`,
    /// `G…`, `D…`); 64 leaves headroom without letting an unbounded string
    /// into a query the policy has classified.
    const MAX_ID_LEN: usize = 64;

    /// Whether `id` is a well-formed Slack channel id. The single
    /// definition shared with `controllers::slack`, so the controller
    /// refuses exactly what the extractor declines to classify.
    #[must_use]
    pub fn is_valid_channel_id(id: &str) -> bool {
        !id.is_empty()
            && id.len() <= MAX_ID_LEN
            && id
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    }

    /// Whether `ts` is a Slack message timestamp: digits, one `.`, digits.
    #[must_use]
    pub fn is_valid_message_ts(ts: &str) -> bool {
        let Some((seconds, fraction)) = ts.split_once('.') else {
            return false;
        };
        !seconds.is_empty()
            && !fraction.is_empty()
            && ts.len() <= 32
            && seconds.bytes().all(|byte| byte.is_ascii_digit())
            && fraction.bytes().all(|byte| byte.is_ascii_digit())
    }

    fn method_path(method: &'static str) -> CanonicalPath {
        CanonicalPath::from_plain_segments(&[method]).unwrap_or_else(CanonicalPath::root)
    }

    /// `slack_list_channels`: the channel collection.
    #[must_use]
    pub fn list_channels(params: &[(&str, &str)]) -> ActionDetails {
        ActionDetails::read(
            NormalizedAction::ListChannels,
            method_path("conversations.list"),
            allowlisted_attributes(params, LIST_ALLOWLIST),
            ResourceType::Channel,
            ResourceScope::collection(),
        )
    }

    /// A read of one channel (`conversations.info`, `.history`, `.replies`).
    /// An invalid channel id is not classified: `Passthrough`/`Unknown`/
    /// `Unscoped`, which default-deny denies, and the hostile value never
    /// enters the record.
    fn channel_read(
        action: NormalizedAction,
        method: &'static str,
        channel: &str,
        params: &[(&str, &str)],
    ) -> ActionDetails {
        if is_valid_channel_id(channel) {
            ActionDetails::read(
                action,
                method_path(method),
                allowlisted_attributes(params, HISTORY_ALLOWLIST),
                ResourceType::Channel,
                ResourceScope::id(channel),
            )
        } else {
            ActionDetails::unclassified_with_attributes(
                HttpMethod::Get,
                method_path(method),
                allowlisted_attributes(params, HISTORY_ALLOWLIST),
            )
        }
    }

    /// `slack_channel_info`.
    #[must_use]
    pub fn channel_info(channel: &str) -> ActionDetails {
        channel_read(
            NormalizedAction::ReadChannel,
            "conversations.info",
            channel,
            &[],
        )
    }

    /// `slack_channel_history`.
    #[must_use]
    pub fn channel_history(channel: &str, params: &[(&str, &str)]) -> ActionDetails {
        channel_read(
            NormalizedAction::ReadChannelHistory,
            "conversations.history",
            channel,
            params,
        )
    }

    /// `slack_thread_replies`.
    #[must_use]
    pub fn thread_replies(channel: &str, params: &[(&str, &str)]) -> ActionDetails {
        channel_read(
            NormalizedAction::ReadThread,
            "conversations.replies",
            channel,
            params,
        )
    }

    /// `slack_search_messages`: reaches every channel the token can see.
    #[must_use]
    pub fn search_messages(params: &[(&str, &str)]) -> ActionDetails {
        ActionDetails::read(
            NormalizedAction::SearchMessages,
            method_path("search.messages"),
            allowlisted_attributes(params, SEARCH_ALLOWLIST),
            ResourceType::Channel,
            ResourceScope::unscoped(),
        )
    }

    /// Classify a Slack HTTP call by its canonical path and query, for the
    /// egress chokepoint and the `slack_get` passthrough. Only the five
    /// read methods are mapped; everything else — every `POST`, every other
    /// method name — is `Passthrough`/`Unknown`, which default-deny denies.
    #[must_use]
    pub fn extract(
        method: HttpMethod,
        path: CanonicalPath,
        query: &[(&str, &str)],
    ) -> ActionDetails {
        if method != HttpMethod::Get {
            return ActionDetails::unclassified(method, path);
        }
        // `channel` names the resource, so it must name exactly one. A
        // repeated key is two answers to "which channel?": the gateway
        // would classify one while Slack could read the other (a last-value
        // parser), and the tool-level and egress decisions would agree with
        // each other but not with the request. Not classified, so denied.
        let mut channels = query
            .iter()
            .filter_map(|(key, value)| (*key == "channel").then_some(*value));
        let channel = channels.next().unwrap_or_default();
        if channels.next().is_some() {
            return ActionDetails::unclassified(method, path);
        }
        match path.as_str() {
            "/conversations.list" => list_channels(query),
            "/conversations.info" => channel_info(channel),
            "/conversations.history" => channel_history(channel, query),
            "/conversations.replies" => thread_replies(channel, query),
            "/search.messages" => search_messages(query),
            _ => ActionDetails::unclassified(method, path),
        }
    }
}

/// Jira passthrough extractor: maps `(method, path, query, body)` from the
/// generic `jira_*` verb tools onto normalized actions.
pub mod jira {
    use super::{
        ActionDetails, ApprovedReadDowngrade, CanonicalPath, HttpMethod, NormalizedAction,
        ResourceConstraint, ResourceScope, ResourceType, Retention, allowlisted_attributes,
    };

    /// Query keys retained for the GET search endpoint. The scope claim is
    /// extracted from `jql` before this runs; both `jql` and `fields` are
    /// retained only as a digest.
    const SEARCH_QUERY_ALLOWLIST: &[(&str, Retention)] = &[
        ("fields", Retention::Digest),
        ("jql", Retention::Digest),
        ("maxResults", Retention::Digest),
    ];

    /// The **only** body field the POST search extractor reads.
    ///
    /// Atlassian's request schema for `POST /rest/api/3/search/jql` has no
    /// `project` field — `jql` is the sole thing that selects issues. An
    /// earlier revision also read a body `project` and let it win, so
    /// `{"project":"PUBLIC","jql":"project = SECRET"}` classified as
    /// `PUBLIC` while Jira executed `SECRET`. Scope now comes only from the
    /// text Jira actually executes.
    const SEARCH_BODY_JQL_FIELD: &str = "jql";

    /// Longest path we bother classifying; the mapped routes are five
    /// segments. Deeper paths are `Unmapped` without allocating.
    const MAX_PATH_SEGMENTS: usize = 8;

    /// A classified route, holding any id it extracted as owned data so the
    /// borrow of the canonical path ends before the path is moved into the
    /// returned details. This is what keeps the extractor to one allocation
    /// for the path plus one per id, with no segment vectors.
    enum Route {
        ReadIssue(String),
        ListProjects,
        ReadProject(String),
        Search,
        Unmapped,
    }

    fn classify(method: HttpMethod, canonical_path: &str) -> Route {
        let mut buffer: [&str; MAX_PATH_SEGMENTS] = [""; MAX_PATH_SEGMENTS];
        let mut count = 0usize;
        for segment in canonical_path.split('/').filter(|part| !part.is_empty()) {
            if count == MAX_PATH_SEGMENTS {
                return Route::Unmapped;
            }
            buffer[count] = segment;
            count += 1;
        }

        match (method, &buffer[..count]) {
            (HttpMethod::Get, ["rest", "api", "3", "issue", key]) if is_plain_id(key) => {
                Route::ReadIssue((*key).to_owned())
            }
            (HttpMethod::Get, ["rest", "api", "3", "project"]) => Route::ListProjects,
            (HttpMethod::Get, ["rest", "api", "3", "project", key]) if is_plain_id(key) => {
                Route::ReadProject((*key).to_owned())
            }
            (HttpMethod::Get | HttpMethod::Post, ["rest", "api", "3", "search", "jql"]) => {
                Route::Search
            }
            _ => Route::Unmapped,
        }
    }

    /// A segment that can be claimed as an issue or project key. After
    /// canonicalization the only `%` left in a segment escapes a reserved
    /// or non-path byte, and no Jira key contains one — so a segment still
    /// carrying an escape is not something this extractor can vouch for.
    fn is_plain_id(segment: &str) -> bool {
        !segment.is_empty() && !segment.contains('%')
    }

    /// Classify a Jira REST call. Everything this function cannot prove is
    /// `Passthrough` + `Unknown` with the method-derived risk — which
    /// default-deny policy denies. In particular `POST /rest/api/3/issue`
    /// (issue creation) shares its verb with the search endpoint and must
    /// come out `Write`/`Unknown`, never `Read` — the exact confusion the
    /// brief's "policy granularity" section exists for.
    #[must_use]
    pub fn extract(
        method: HttpMethod,
        canonical_path: CanonicalPath,
        query: &[(&str, &str)],
        body: Option<&serde_json::Value>,
    ) -> ActionDetails {
        match classify(method, canonical_path.as_str()) {
            Route::ReadIssue(key) => ActionDetails::read(
                NormalizedAction::ReadIssue,
                canonical_path,
                allowlisted_attributes(query, &[("fields", Retention::Digest)]),
                ResourceType::Issue,
                ResourceScope::id(key),
            ),
            Route::ListProjects => ActionDetails::read(
                NormalizedAction::ReadProject,
                canonical_path,
                Vec::new(),
                ResourceType::Project,
                ResourceScope::collection(),
            ),
            Route::ReadProject(key) => ActionDetails::read(
                NormalizedAction::ReadProject,
                canonical_path,
                Vec::new(),
                ResourceType::Project,
                ResourceScope::id(key),
            ),
            Route::Search => {
                let (jql, attributes) = match method {
                    HttpMethod::Post => (
                        body.and_then(|value| value.get(SEARCH_BODY_JQL_FIELD))
                            .and_then(serde_json::Value::as_str),
                        Vec::new(),
                    ),
                    _ => (
                        query
                            .iter()
                            .find(|(key, _)| *key == "jql")
                            .map(|(_, value)| *value),
                        allowlisted_attributes(query, SEARCH_QUERY_ALLOWLIST),
                    ),
                };
                search_details(method, canonical_path, attributes, jql)
            }
            Route::Unmapped => ActionDetails::unclassified(method, canonical_path),
        }
    }

    /// Both search shapes are semantically issue searches and read-only by
    /// endpoint contract, so the extractor downgrades POST's method-derived
    /// `Write` to `Read` **for this endpoint only**.
    fn search_details(
        method: HttpMethod,
        canonical_path: CanonicalPath,
        query_attributes: Vec<(String, String)>,
        jql: Option<&str>,
    ) -> ActionDetails {
        // CF-2: a search returns *issues* — which ones is not provable, so
        // the issue scope is unscoped — and is bounded by *projects*, which
        // is a constraint in the project namespace, never an issue id.
        let constraint = jql
            .and_then(project_keys_from_jql)
            .and_then(|keys| ResourceConstraint::ids(ResourceType::Project, keys));
        // GET is an ordinary read; POST is the module's one downgrade, and
        // it can only be spelled by naming the approved endpoint — which
        // binds its own action, path, and resource type, so only the
        // genuinely call-site-variable scope and attributes are passed here.
        if method == HttpMethod::Get {
            return ActionDetails::read(
                NormalizedAction::SearchIssues,
                canonical_path,
                query_attributes,
                ResourceType::Issue,
                ResourceScope::unscoped(),
            )
            .constrained_by(constraint);
        }
        ActionDetails::read_downgrade(
            ApprovedReadDowngrade::JIRA_SEARCH_JQL,
            query_attributes,
            ResourceScope::unscoped(),
        )
        .constrained_by(constraint)
    }

    /// Longest JQL this scanner will look at. Beyond it the answer is "no
    /// claim" rather than an unbounded scan on the request path.
    const MAX_JQL_BYTES: usize = 8 * 1024;
    /// Token ceiling, for the same reason.
    const MAX_JQL_TOKENS: usize = 512;

    /// The project keys a JQL query is provably restricted to.
    ///
    /// **Sound, not complete.** A claim is made only when the whole query is
    /// a flat conjunction of positive clauses containing at least one
    /// `project = X` or `project in (A, B)`. The scanner returns `None` —
    /// "not provably restricted", which policy treats as unscoped — for
    /// *anything* else, and it rejects structurally before it reads
    /// anything:
    ///
    /// - any unquoted `OR`, `NOT`, or `!` **anywhere** in the query;
    /// - any `(` that is not the one opening an `in` list (so grouping and
    ///   JQL functions such as `membersOf(...)` yield no claim);
    /// - an unterminated quote, or any backslash (JQL string escapes are
    ///   not lexed here, and a crafted `\"` is precisely how a fake clause
    ///   would be smuggled past a naive scanner);
    /// - a malformed list, a dangling operator, or an over-long query.
    ///
    /// The `NOT` rule is the one that matters. An earlier revision only
    /// looked at the token immediately before `project`, so
    /// `NOT (project = PUBLIC)` — whose previous token is `(` — was claimed
    /// as "restricted to PUBLIC" while the query actually addresses *every
    /// project except* PUBLIC. A policy allowing PUBLIC would have
    /// authorized reads of everything else. Until a real expression parser
    /// exists, negation of any shape means no claim at all.
    #[must_use]
    pub fn project_keys_from_jql(jql: &str) -> Option<Vec<String>> {
        if jql.len() > MAX_JQL_BYTES || jql.contains('\\') {
            return None;
        }
        let tokens = lex_jql(jql)?;
        if !is_flat_conjunction(&tokens) {
            return None;
        }

        let mut keys: Vec<&str> = Vec::new();
        let mut index = 0;
        while index < tokens.len() {
            if tokens[index].quoted || !tokens[index].text.eq_ignore_ascii_case("project") {
                index += 1;
                continue;
            }
            // A trailing bare `project` means the query does not parse.
            let operator = tokens.get(index + 1)?;
            if operator.quoted {
                index += 1;
                continue;
            }
            if operator.text == "=" {
                let value = tokens.get(index + 2)?;
                if !is_value(value) {
                    return None;
                }
                keys.push(value.text);
                index += 3;
            } else if operator.text.eq_ignore_ascii_case("in") {
                index = read_in_list(&tokens, index, &mut keys)?;
            } else {
                // `~`, `is`, `was`, `>` … prove nothing positive, but they
                // do not make the query unsound either: skip the clause.
                index += 1;
            }
        }

        if keys.is_empty() {
            return None;
        }
        Some(keys.into_iter().map(str::to_owned).collect())
    }

    /// Reject every construct that would let a positive-looking `project`
    /// clause mean something other than a restriction.
    fn is_flat_conjunction(tokens: &[Token<'_>]) -> bool {
        for (index, token) in tokens.iter().enumerate() {
            if token.quoted {
                continue;
            }
            if token.text == "!"
                || token.text.eq_ignore_ascii_case("or")
                || token.text.eq_ignore_ascii_case("not")
            {
                return false;
            }
            if token.text == "(" {
                let opens_an_in_list = index
                    .checked_sub(1)
                    .and_then(|previous| tokens.get(previous))
                    .is_some_and(|previous| {
                        !previous.quoted && previous.text.eq_ignore_ascii_case("in")
                    });
                if !opens_an_in_list {
                    return false;
                }
            }
        }
        true
    }

    /// Consume `project in ( a, b, c )` starting at the `project` token,
    /// pushing the keys. Returns the index just past the closing paren, or
    /// `None` if the list is malformed.
    fn read_in_list<'a>(
        tokens: &[Token<'a>],
        project_index: usize,
        keys: &mut Vec<&'a str>,
    ) -> Option<usize> {
        let open = tokens.get(project_index + 2)?;
        if open.quoted || open.text != "(" {
            return None;
        }
        let mut cursor = project_index + 3;
        let mut expecting_value = true;
        loop {
            let token = tokens.get(cursor)?;
            if !token.quoted && token.text == ")" {
                break;
            }
            if !token.quoted && token.text == "," {
                if expecting_value {
                    return None; // `(, A)` or `(A,, B)`
                }
                expecting_value = true;
            } else {
                if !expecting_value {
                    return None; // two values with no comma between them
                }
                if !is_value(token) {
                    return None;
                }
                keys.push(token.text);
                expecting_value = false;
            }
            cursor += 1;
        }
        if expecting_value {
            return None; // empty list, or a trailing comma
        }
        Some(cursor + 1)
    }

    /// A token usable as a project key: any quoted string, or a bare word
    /// that is not a structural character.
    fn is_value(token: &Token<'_>) -> bool {
        if token.quoted {
            return !token.text.is_empty();
        }
        !token.text.is_empty() && !matches!(token.text, "(" | ")" | "," | "=" | "!")
    }

    /// A JQL token borrowed from the query. Borrowed, not owned: the scanner
    /// allocates only for the keys it actually claims.
    struct Token<'a> {
        text: &'a str,
        quoted: bool,
    }

    /// Split JQL into tokens: quoted strings (either quote style) stay one
    /// token with quotes stripped; `=`, `!`, `(`, `)`, `,` are always their
    /// own tokens; everything else splits on ASCII whitespace.
    ///
    /// `None` when the input does not lex — an unterminated quote, or more
    /// tokens than [`MAX_JQL_TOKENS`]. Guessing where an unterminated string
    /// ends is how a crafted quote smuggles a clause past the scanner, so it
    /// is a hard stop rather than a best effort.
    ///
    /// Byte scanning is safe here because every delimiter is ASCII: a UTF-8
    /// continuation byte is never equal to one, so every slice boundary this
    /// takes is a character boundary.
    fn lex_jql(jql: &str) -> Option<Vec<Token<'_>>> {
        let bytes = jql.as_bytes();
        let mut tokens: Vec<Token<'_>> = Vec::new();
        let mut word_start: Option<usize> = None;
        let mut index = 0usize;

        while index < bytes.len() {
            let byte = bytes[index];
            let is_quote = byte == b'"' || byte == b'\'';
            let is_structural = matches!(byte, b'=' | b'(' | b')' | b',' | b'!');
            let is_space = byte.is_ascii_whitespace();

            if (is_quote || is_structural || is_space)
                && let Some(start) = word_start.take()
            {
                push(&mut tokens, &jql[start..index], false)?;
            }

            if is_quote {
                let start = index + 1;
                let mut end = start;
                while end < bytes.len() && bytes[end] != byte {
                    end += 1;
                }
                if end >= bytes.len() {
                    return None; // unterminated quote
                }
                push(&mut tokens, &jql[start..end], true)?;
                index = end + 1;
                continue;
            }

            if is_structural {
                push(&mut tokens, &jql[index..=index], false)?;
            } else if !is_space && word_start.is_none() {
                word_start = Some(index);
            }
            index += 1;
        }

        if let Some(start) = word_start {
            push(&mut tokens, &jql[start..], false)?;
        }
        Some(tokens)
    }

    fn push<'a>(tokens: &mut Vec<Token<'a>>, text: &'a str, quoted: bool) -> Option<()> {
        if tokens.len() == MAX_JQL_TOKENS {
            return None;
        }
        tokens.push(Token { text, quoted });
        Some(())
    }
}

/// The wire request a vendor client is about to send, classified for the
/// egress chokepoint (plan §1.3). Vendors without an extractor are
/// `Passthrough`/`Unknown`, which default-deny denies: in enterprise mode a
/// vendor is reachable only once it has a read-endpoint inventory.
#[must_use]
pub fn for_vendor(
    vendor: &str,
    method: HttpMethod,
    target: &CanonicalTarget,
    body: Option<&serde_json::Value>,
) -> ActionDetails {
    if method == HttpMethod::Get && super::native::endpoint(vendor, target.path().as_str()) {
        return super::native::read(target.path().clone());
    }
    let query = target.query_pairs();
    match vendor {
        "mend" | "artifactory" if method == HttpMethod::Post => {
            ActionDetails::native_post_read(vendor, target.path().clone())
        }
        crate::config::VENDOR_GRAFANA => grafana::extract(method, target.path().clone(), &query),
        crate::config::VENDOR_JIRA => jira::extract(method, target.path().clone(), &query, body),
        crate::config::VENDOR_SLACK => slack::extract(method, target.path().clone(), &query),
        _ => ActionDetails::unclassified(method, target.path().clone()),
    }
}

/// What a tool call *asks for*, from its JSON arguments, for the tool-level
/// decision that runs before dispatch (plan §1.3: layered on top of egress,
/// never the only guard). Purpose-built tools map from their typed
/// arguments; passthrough tools canonicalize their `path` and `queryParams`
/// exactly as the transport will; anything else is
/// [`ActionDetails::unmapped_tool`] with the risk the server's own tool
/// annotations declare.
#[must_use]
pub fn for_tool(
    tool: &str,
    arguments: Option<&serde_json::Map<String, serde_json::Value>>,
    declared_risk: RequestRisk,
) -> ActionDetails {
    if super::native::tool(tool) {
        return super::native::read(CanonicalPath::parse("/").expect("static path"));
    }
    let text = |key: &str| {
        arguments
            .and_then(|args| args.get(key))
            .and_then(serde_json::Value::as_str)
    };
    match tool {
        "grafana_list_datasources" => grafana::list_datasources(),
        "grafana_query_logs" => {
            let uid = text("datasourceUid").unwrap_or_default();
            let limit = arguments
                .and_then(|args| args.get("limit"))
                .map(serde_json::Value::to_string);
            let mut params: Vec<(&str, &str)> = Vec::with_capacity(6);
            for key in ["query", "start", "end", "direction", "step"] {
                if let Some(value) = text(key) {
                    params.push((key, value));
                }
            }
            if let Some(limit) = limit.as_deref() {
                params.push(("limit", limit));
            }
            grafana::query_logs(uid, &params)
        }
        "slack_list_channels"
        | "slack_channel_info"
        | "slack_channel_history"
        | "slack_thread_replies"
        | "slack_search_messages" => slack_tool(tool, arguments),
        "slack_get" | "slack_post" | "slack_put" | "slack_patch" | "slack_delete" => {
            let method = match tool {
                "slack_get" => HttpMethod::Get,
                "slack_post" => HttpMethod::Post,
                "slack_put" => HttpMethod::Put,
                "slack_patch" => HttpMethod::Patch,
                _ => HttpMethod::Delete,
            };
            passthrough_details(method, arguments, |target, query, _body| {
                slack::extract(method, target.path().clone(), query)
            })
        }
        "jira_get" | "jira_post" | "jira_put" | "jira_patch" | "jira_delete" => {
            let method = match tool {
                "jira_get" => HttpMethod::Get,
                "jira_post" => HttpMethod::Post,
                "jira_put" => HttpMethod::Put,
                "jira_patch" => HttpMethod::Patch,
                _ => HttpMethod::Delete,
            };
            passthrough_details(method, arguments, |target, query, body| {
                jira::extract(method, target.path().clone(), query, body)
            })
        }
        _ => ActionDetails::unmapped_tool(declared_risk),
    }
}

/// The Slack purpose-built tools' half of [`for_tool`], from their typed
/// arguments (WP B.1).
fn slack_tool(
    tool: &str,
    arguments: Option<&serde_json::Map<String, serde_json::Value>>,
) -> ActionDetails {
    let text = |key: &str| {
        arguments
            .and_then(|args| args.get(key))
            .and_then(serde_json::Value::as_str)
    };
    match tool {
        "slack_list_channels" => {
            let limit = arguments
                .and_then(|args| args.get("limit"))
                .map(serde_json::Value::to_string);
            let archived = arguments
                .and_then(|args| args.get("excludeArchived"))
                .and_then(serde_json::Value::as_bool)
                .map(|flag| flag.to_string());
            let mut params: Vec<(&str, &str)> = Vec::with_capacity(4);
            for key in ["types", "cursor"] {
                if let Some(value) = text(key) {
                    params.push((key, value));
                }
            }
            if let Some(limit) = limit.as_deref() {
                params.push(("limit", limit));
            }
            if let Some(archived) = archived.as_deref() {
                params.push(("exclude_archived", archived));
            }
            slack::list_channels(&params)
        }
        "slack_channel_info" => slack::channel_info(text("channelId").unwrap_or_default()),
        "slack_channel_history" | "slack_thread_replies" => {
            let channel = text("channelId").unwrap_or_default();
            let limit = arguments
                .and_then(|args| args.get("limit"))
                .map(serde_json::Value::to_string);
            let inclusive = arguments
                .and_then(|args| args.get("inclusive"))
                .and_then(serde_json::Value::as_bool)
                .map(|flag| flag.to_string());
            let mut params: Vec<(&str, &str)> = Vec::with_capacity(6);
            for key in ["oldest", "latest", "cursor"] {
                if let Some(value) = text(key) {
                    params.push((key, value));
                }
            }
            if let Some(limit) = limit.as_deref() {
                params.push(("limit", limit));
            }
            if let Some(inclusive) = inclusive.as_deref() {
                params.push(("inclusive", inclusive));
            }
            if tool == "slack_thread_replies" {
                if let Some(ts) = text("threadTs") {
                    params.push(("ts", ts));
                }
                slack::thread_replies(channel, &params)
            } else {
                slack::channel_history(channel, &params)
            }
        }
        "slack_search_messages" => {
            let count = arguments
                .and_then(|args| args.get("count"))
                .map(serde_json::Value::to_string);
            let page = arguments
                .and_then(|args| args.get("page"))
                .map(serde_json::Value::to_string);
            let mut params: Vec<(&str, &str)> = Vec::with_capacity(5);
            for (key, argument) in [
                ("query", "query"),
                ("sort", "sort"),
                ("sort_dir", "sortDir"),
            ] {
                if let Some(value) = text(argument) {
                    params.push((key, value));
                }
            }
            if let Some(count) = count.as_deref() {
                params.push(("count", count));
            }
            if let Some(page) = page.as_deref() {
                params.push(("page", page));
            }
            slack::search_messages(&params)
        }
        _ => ActionDetails::unmapped_tool(RequestRisk::Read),
    }
}

/// Canonicalize a passthrough tool's `path` + `queryParams` the way the
/// controller and transport will, then hand the result to the vendor's
/// extractor. A path with no canonical form is `Unknown` (the transport
/// will refuse it too).
fn passthrough_details(
    method: HttpMethod,
    arguments: Option<&serde_json::Map<String, serde_json::Value>>,
    extract: impl FnOnce(&CanonicalTarget, &[(&str, &str)], Option<&serde_json::Value>) -> ActionDetails,
) -> ActionDetails {
    let path = arguments
        .and_then(|args| args.get("path"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let mut path_and_query = path.to_owned();
    if let Some(query) = arguments
        .and_then(|args| args.get("queryParams"))
        .and_then(serde_json::Value::as_object)
    {
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(
                query
                    .iter()
                    .filter_map(|(key, value)| Some((key.as_str(), value.as_str()?))),
            )
            .finish();
        if !encoded.is_empty() {
            path_and_query.push(if path_and_query.contains('?') {
                '&'
            } else {
                '?'
            });
            path_and_query.push_str(&encoded);
        }
    }
    let Ok(target) = CanonicalTarget::parse(&path_and_query) else {
        return ActionDetails::unclassified(method, CanonicalPath::root());
    };
    let query = target.query_pairs();
    let body = arguments.and_then(|args| args.get("body"));
    extract(&target, &query, body)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::policy::RequestRisk;

    /// Tests supply raw paths; production supplies a [`CanonicalPath`]
    /// minted by the transport. Canonicalizing here is the same step the
    /// transport performs before an extractor ever runs.
    fn extract_jira(
        method: HttpMethod,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&serde_json::Value>,
    ) -> ActionDetails {
        jira::extract(method, CanonicalPath::parse(path).unwrap(), query, body)
    }

    // ---- Grafana (purpose-built) ----

    /// The egress classifier maps the wire request back onto the same
    /// vocabulary the typed tool declares, so a tool-level decision and an
    /// egress decision about the same call are about the same facts.
    #[test]
    fn grafana_egress_extractor_agrees_with_the_typed_tool() {
        let query: &[(&str, &str)] = &[("query", "{app=\"api\"}"), ("limit", "10")];
        let via_wire = grafana::extract(
            HttpMethod::Get,
            CanonicalPath::parse("/api/datasources/proxy/uid/loki-prod/loki/api/v1/query_range")
                .unwrap(),
            query,
        );
        assert_eq!(via_wire, grafana::query_logs("loki-prod", query));

        assert_eq!(
            grafana::extract(
                HttpMethod::Get,
                CanonicalPath::parse("/api/datasources").unwrap(),
                &[]
            ),
            grafana::list_datasources()
        );

        // Anything else on the Grafana API is unmapped: a POST to the same
        // proxy, a write endpoint, a proxy path whose UID segment is not a
        // UID, or a longer path that merely starts like the mapped one.
        for (method, path) in [
            (
                HttpMethod::Post,
                "/api/datasources/proxy/uid/loki-prod/loki/api/v1/query_range",
            ),
            (
                HttpMethod::Get,
                "/api/datasources/proxy/uid/loki-prod/loki/api/v1/push",
            ),
            (
                HttpMethod::Get,
                "/api/datasources/proxy/uid/a%2Fb/loki/api/v1/query_range",
            ),
            (
                HttpMethod::Get,
                "/api/datasources/proxy/uid/loki-prod/loki/api/v1/query_range/extra",
            ),
            (HttpMethod::Delete, "/api/datasources"),
            (HttpMethod::Get, "/api/admin/settings"),
        ] {
            let details = grafana::extract(method, CanonicalPath::parse(path).unwrap(), &[]);
            assert_eq!(
                details.resource_type,
                ResourceType::Unknown,
                "{method:?} {path} must not classify"
            );
            assert_eq!(details.normalized_action, NormalizedAction::Passthrough);
        }
    }

    /// An id segment that still carries an escape after canonicalization
    /// is not a Jira key and must not be claimed as one.
    #[test]
    fn jira_never_claims_an_escaped_segment_as_an_id() {
        for path in [
            "/rest/api/3/issue/PLAT-1%2Fcomment",
            "/rest/api/3/issue/PLAT%201",
            "/rest/api/3/project/W%2FEB",
        ] {
            let details = extract_jira(HttpMethod::Get, path, &[], None);
            assert_eq!(details.resource_type, ResourceType::Unknown, "{path}");
            assert_eq!(details.resource_scope, ResourceScope::unscoped(), "{path}");
        }
        // Whereas an encoded *unreserved* character decodes into a plain
        // key and is fine.
        let details = extract_jira(HttpMethod::Get, "/rest/api/3/issue/PLAT%2D1", &[], None);
        assert_eq!(details.resource_scope, ResourceScope::id("PLAT-1"));
    }

    #[test]
    fn grafana_query_logs_is_a_datasource_read_with_allowlisted_sorted_attributes() {
        let details = grafana::query_logs(
            "loki-prod",
            &[
                ("query", "{app=\"api\"}"),
                ("limit", "100"),
                ("internal_knob", "1"), // not allowlisted: dropped
            ],
        );
        assert_eq!(details.normalized_action, NormalizedAction::QueryLogs);
        assert_eq!(details.resource_type, ResourceType::Datasource);
        assert_eq!(details.resource_scope, ResourceScope::id("loki-prod"));
        assert_eq!(details.request_risk, RequestRisk::Read);
        assert_eq!(
            details.canonical_path,
            "/api/datasources/proxy/uid/loki-prod/loki/api/v1/query_range"
        );
        let (limit_key, limit_value) = &details.query_attributes()[0];
        assert_eq!(limit_key, "limit");
        assert!(
            limit_value.starts_with("sha256:"),
            "limit has no numeric shape any more — a real credential can be \
             all digits too: {limit_value}"
        );
        let (key, value) = &details.query_attributes()[1];
        assert_eq!(key, "query");
        assert!(
            value.starts_with("sha256:") && value.ends_with("/11"),
            "LogQL must be retained as a digest + length, not text: {value}"
        );
        assert!(
            !value.contains("app="),
            "the expression itself must not reach query_attributes"
        );
    }

    #[test]
    fn grafana_list_datasources_is_a_collection_read_not_an_unscoped_one() {
        let details = grafana::list_datasources();
        assert_eq!(details.normalized_action, NormalizedAction::ListDatasources);
        assert_eq!(details.resource_type, ResourceType::Datasource);
        assert_eq!(
            details.resource_scope,
            ResourceScope::collection(),
            "a list endpoint is a collection read, distinguishable from \
             'we could not tell what this addresses'"
        );
        assert_eq!(details.request_risk, RequestRisk::Read);
    }

    /// A UID is interpolated into a proxy path. Anything that could
    /// re-point that path must not come back classified as an approved
    /// datasource read, and must not appear in the canonical path either.
    #[test]
    fn grafana_rejects_uids_that_could_escape_the_proxy_path_segment() {
        for hostile in [
            "loki-prod/../../admin/settings",
            "loki%2fprod",
            "loki-prod?x=1",
            "loki-prod#frag",
            "loki prod",
            "..",
            "",
            &"u".repeat(65),
        ] {
            let details = grafana::query_logs(hostile, &[]);
            assert_eq!(
                details.resource_type,
                ResourceType::Unknown,
                "uid {hostile:?} must not classify as a datasource"
            );
            assert_eq!(details.normalized_action, NormalizedAction::Passthrough);
            assert_eq!(details.resource_scope, ResourceScope::unscoped());
            assert_eq!(
                details.canonical_path, "/api/datasources/proxy/uid",
                "the hostile uid must not be echoed into the canonical path"
            );
        }
    }

    #[test]
    fn grafana_accepts_the_uid_alphabet_grafana_actually_generates() {
        for valid in ["loki-prod", "A1_b2", "0", &"u".repeat(64)] {
            assert!(
                grafana::is_valid_datasource_uid(valid),
                "{valid:?} should be accepted"
            );
        }
    }

    // ---- Jira passthrough: the POST search endpoint ----

    fn post_search(body: &serde_json::Value) -> ActionDetails {
        extract_jira(HttpMethod::Post, "/rest/api/3/search/jql", &[], Some(body))
    }

    #[test]
    fn post_search_is_downgraded_to_a_read_scoped_by_the_jql_project() {
        let details = post_search(&serde_json::json!({
            "jql": "project = PLAT AND text ~ \"timeout\"",
            "maxResults": 10,
        }));
        assert_eq!(details.normalized_action, NormalizedAction::SearchIssues);
        assert_eq!(details.method, HttpMethod::Post);
        assert_eq!(
            details.request_risk,
            RequestRisk::Read,
            "explicit downgrade"
        );
        assert_eq!(details.resource_type, ResourceType::Issue);
        // CF-2: the issues are unscoped; the *projects* are the constraint.
        assert!(details.resource_scope.is_unscoped());
        assert_eq!(details.constraint(), project_constraint(["PLAT"]).as_ref());
    }

    fn project_constraint<const N: usize>(keys: [&str; N]) -> Option<ResourceConstraint> {
        ResourceConstraint::ids(ResourceType::Project, keys)
    }

    #[test]
    fn post_search_keeps_every_project_of_an_in_list_as_a_structured_constraint() {
        let details = post_search(&serde_json::json!({
            "jql": "project in (WEB, PLAT, WEB) AND status = Open",
        }));
        assert_eq!(
            details.constraint(),
            project_constraint(["PLAT", "WEB"]).as_ref(),
            "both projects stay separately addressable — never comma-joined \
             into one opaque id"
        );
    }

    /// The body field Jira does not execute must not decide the scope.
    /// `POST /rest/api/3/search/jql` has no `project` in Atlassian's request
    /// schema; a deployment that ignores unknown properties would run the
    /// JQL while policy had classified the request by the decoy.
    #[test]
    fn post_search_ignores_a_body_project_field_and_trusts_only_the_jql() {
        let details = post_search(&serde_json::json!({
            "project": "PUBLIC",
            "jql": "project = SECRET",
        }));
        assert_eq!(
            details.constraint(),
            project_constraint(["SECRET"]).as_ref(),
            "the constraint must come from the JQL Jira actually executes"
        );

        // And with no JQL at all, a body `project` buys no claim either.
        let decoy_only = post_search(&serde_json::json!({ "project": "PUBLIC" }));
        assert_eq!(decoy_only.constraint(), None);
        assert!(decoy_only.resource_scope.is_unscoped());
    }

    #[test]
    fn post_search_makes_no_project_claim_it_cannot_prove() {
        for jql in [
            "project = PLAT OR assignee = bob", // OR defeats the guarantee
            "project != PLAT",                  // negation
            "project not in (PLAT, WEB)",       // negation
            "assignee = bob",                   // no project clause
            "project =",                        // unparseable
            "text ~ \"project = FAKE\"",        // inside quotes only
        ] {
            let details = post_search(&serde_json::json!({ "jql": jql }));
            assert_eq!(
                details.constraint(),
                None,
                "jql {jql:?} must not be claimed as project-constrained"
            );
            assert!(details.resource_scope.is_unscoped());
            // Still a classified read of issues — just unscoped.
            assert_eq!(details.resource_type, ResourceType::Issue);
            assert_eq!(details.request_risk, RequestRisk::Read);
        }
    }

    /// The regression this whole rewrite exists for, plus its neighbours.
    /// Each of these addresses more than the keys it names; claiming a scope
    /// would let a rule allowing that key authorize far more.
    #[test]
    fn negation_and_grouping_of_every_shape_yield_no_claim() {
        for jql in [
            "NOT (project = PUBLIC)",
            "not (project = PUBLIC)",
            "NoT   (   project   =   PUBLIC   )",
            "status = Open AND NOT (project = PUBLIC)",
            "NOT (NOT (project = PUBLIC))",
            "NOT (project in (PUBLIC, OTHER))",
            "(project = PUBLIC OR project = SECRET)",
            "project = PUBLIC OR (project = SECRET AND status = Open)",
            "(project = PUBLIC) AND status = Open",
            "project = PUBLIC AND (assignee = bob OR assignee = amy)",
            "project !=PUBLIC",
            "project! = PUBLIC",
        ] {
            assert_eq!(
                jira::project_keys_from_jql(jql),
                None,
                "jql {jql:?} must yield no project claim"
            );
        }
    }

    #[test]
    fn malformed_quoting_yields_no_claim_rather_than_a_guess() {
        for jql in [
            "project = \"PUBLIC",                              // unterminated
            "project = 'PUBLIC",                               // unterminated, other style
            "project = \"A\\\" AND project = SECRET\"",        // escaped quote
            "project = \"\"",                                  // empty key
            "project in (PLAT,)",                              // trailing comma
            "project in (,PLAT)",                              // leading comma
            "project in ()",                                   // empty list
            "project in (PLAT",                                // unterminated list
            "project in PLAT",                                 // missing parens
            "project in projectsLeadByUser()",                 // JQL function
            "assignee in membersOf(\"g\") AND project = PLAT", // function elsewhere
            "project",                                         // dangling
            "project in",                                      // dangling
        ] {
            assert_eq!(
                jira::project_keys_from_jql(jql),
                None,
                "jql {jql:?} must yield no project claim"
            );
        }
    }

    #[test]
    fn positive_conjunctions_still_produce_claims_in_any_case_and_spacing() {
        assert_eq!(
            jira::project_keys_from_jql("PROJECT=PLAT"),
            Some(vec!["PLAT".to_owned()])
        );
        assert_eq!(
            jira::project_keys_from_jql("status = Open and Project In (WEB,PLAT)"),
            Some(vec!["WEB".to_owned(), "PLAT".to_owned()])
        );
        // Two positive clauses union; `all_ids_allowed` then requires both.
        assert_eq!(
            jira::project_keys_from_jql("project = PLAT AND project in (WEB)"),
            Some(vec!["PLAT".to_owned(), "WEB".to_owned()])
        );
        // A neighbouring key that merely starts with `project` is a
        // different field and must not be read as one.
        assert_eq!(jira::project_keys_from_jql("projectType = software"), None);
        // `ORDER BY` is not an `OR`.
        assert_eq!(
            jira::project_keys_from_jql("project = PLAT ORDER BY created DESC"),
            Some(vec!["PLAT".to_owned()])
        );
    }

    #[test]
    fn over_long_queries_are_bounded_rather_than_scanned() {
        let long = format!("project = PLAT AND summary ~ \"{}\"", "x".repeat(9000));
        assert_eq!(jira::project_keys_from_jql(&long), None);
        let many_tokens = "a = b AND ".repeat(400) + "project = PLAT";
        assert_eq!(jira::project_keys_from_jql(&many_tokens), None);
    }

    #[test]
    fn quoted_project_keys_survive_with_quotes_stripped() {
        assert_eq!(
            jira::project_keys_from_jql("project = \"My Proj\" AND status = Open"),
            Some(vec!["My Proj".to_owned()])
        );
        assert_eq!(
            jira::project_keys_from_jql("project in ('A B', CDE)"),
            Some(vec!["A B".to_owned(), "CDE".to_owned()])
        );
        // A comma *inside* a quoted key is why ids are a list and never a
        // comma-joined string.
        assert_eq!(
            jira::project_keys_from_jql("project in (\"A,B\", C)"),
            Some(vec!["A,B".to_owned(), "C".to_owned()])
        );
        let details = post_search(&serde_json::json!({ "jql": "project in (\"A,B\", C)" }));
        assert_eq!(
            details.constraint(),
            project_constraint(["A,B", "C"]).as_ref()
        );
    }

    // ---- The confusion the brief warns about: same verb, different risk ----

    #[test]
    fn post_issue_creation_stays_write_and_unknown_never_a_read() {
        let details = extract_jira(
            HttpMethod::Post,
            "/rest/api/3/issue",
            &[],
            Some(&serde_json::json!({"fields": {"summary": "new issue"}})),
        );
        assert_eq!(details.normalized_action, NormalizedAction::Passthrough);
        assert_eq!(details.resource_type, ResourceType::Unknown);
        assert_eq!(details.request_risk, RequestRisk::Write);
    }

    #[test]
    fn unmapped_paths_are_passthrough_unknown_with_method_derived_risk() {
        let get = extract_jira(HttpMethod::Get, "/rest/api/3/somethingelse", &[], None);
        assert_eq!(get.resource_type, ResourceType::Unknown);
        assert_eq!(get.request_risk, RequestRisk::Read);

        let delete = extract_jira(HttpMethod::Delete, "/rest/api/3/issue/PLAT-1", &[], None);
        assert_eq!(delete.normalized_action, NormalizedAction::Passthrough);
        assert_eq!(delete.request_risk, RequestRisk::Destructive);

        // Deeper than the classifier looks: still unmapped, never a partial
        // match against a shorter route.
        let deep = extract_jira(
            HttpMethod::Get,
            "/rest/api/3/issue/PLAT-1/a/b/c/d/e/f/g",
            &[],
            None,
        );
        assert_eq!(deep.normalized_action, NormalizedAction::Passthrough);
        assert_eq!(deep.resource_type, ResourceType::Unknown);
    }

    // ---- Typed reads ----

    #[test]
    fn issue_and_project_reads_extract_their_resource_ids() {
        let issue = extract_jira(
            HttpMethod::Get,
            "//rest/api/3//issue/PLAT-123/",
            &[("fields", "summary"), ("expand", "changelog")],
            None,
        );
        assert_eq!(issue.normalized_action, NormalizedAction::ReadIssue);
        // Duplicate slashes collapse; the trailing slash is kept (Django-style
        // APIs distinguish it) and does not affect the classification.
        assert_eq!(issue.canonical_path, "/rest/api/3/issue/PLAT-123/");
        assert_eq!(issue.resource_scope, ResourceScope::id("PLAT-123"));
        assert_eq!(issue.query_attributes().len(), 1);
        assert_eq!(issue.query_attributes()[0].0, "fields");
        assert!(issue.query_attributes()[0].1.starts_with("sha256:"));

        let project = extract_jira(HttpMethod::Get, "/rest/api/3/project/WEB", &[], None);
        assert_eq!(project.normalized_action, NormalizedAction::ReadProject);
        assert_eq!(project.resource_type, ResourceType::Project);
        assert_eq!(project.resource_scope, ResourceScope::id("WEB"));

        let list = extract_jira(HttpMethod::Get, "/rest/api/3/project", &[], None);
        assert_eq!(list.resource_scope, ResourceScope::collection());
    }

    /// `docs/read-endpoint-inventory.md` decision 5, enforced. An earlier
    /// revision wrote that decision down and retained the text anyway.
    #[test]
    fn search_expressions_never_reach_query_attributes_as_text() {
        let secret_jql = "project = PLAT AND text ~ \"Bearer sk-live-abcdef0123456789\"";
        let details = extract_jira(
            HttpMethod::Get,
            "/rest/api/3/search/jql",
            &[("jql", secret_jql), ("fields", "summary")],
            None,
        );
        let serialized = serde_json::to_string(&details).unwrap();
        assert!(
            !serialized.contains("sk-live-abcdef0123456789"),
            "a token pasted into JQL must not reach the serialized context: {serialized}"
        );
        assert!(!serialized.contains("text ~"));

        let jql = details
            .query_attributes()
            .iter()
            .find(|(key, _)| key == "jql")
            .expect("jql attribute retained");
        assert!(jql.1.starts_with("sha256:"), "digest retained: {}", jql.1);
        // Same expression, same handle — correlation still works.
        let again = extract_jira(
            HttpMethod::Get,
            "/rest/api/3/search/jql",
            &[("jql", secret_jql)],
            None,
        );
        assert_eq!(
            again
                .query_attributes()
                .iter()
                .find(|(key, _)| key == "jql")
                .map(|(_, value)| value),
            Some(&jql.1)
        );
        // The constraint is still extracted from the real expression.
        assert_eq!(details.constraint(), project_constraint(["PLAT"]).as_ref());
    }

    /// Bounding a caller-controlled string is not redacting it. Every
    /// retained attribute must *parse* as its documented shape, or become a
    /// digest — a token supplied as `fields` or `direction` must not reach
    /// the serialized context intact, merely shorter.
    #[test]
    fn caller_supplied_attribute_values_must_parse_or_become_a_digest() {
        let token = "Bearer sk-live-abcdef0123456789";
        let details = extract_jira(
            HttpMethod::Get,
            "/rest/api/3/search/jql",
            &[
                ("fields", token),
                ("maxResults", token),
                ("jql", "project = PLAT"),
            ],
            None,
        );
        let serialized = serde_json::to_string(&details).unwrap();
        assert!(
            !serialized.contains("sk-live-abcdef0123456789"),
            "a token smuggled through a structural attribute must not \
             survive: {serialized}"
        );
        for (key, value) in details.query_attributes() {
            assert!(
                value.starts_with("sha256:"),
                "{key} did not parse and must be a digest, got {value}"
            );
        }

        let grafana = grafana::query_logs(
            "loki-prod",
            &[
                ("direction", token),
                ("limit", "12x"),
                ("start", "'; DROP TABLE --"),
                ("step", token),
            ],
        );
        let serialized = serde_json::to_string(&grafana).unwrap();
        assert!(!serialized.contains("sk-live"), "{serialized}");
        assert!(!serialized.contains("DROP TABLE"), "{serialized}");
    }

    /// A bare token — no `Bearer ` prefix, so no space — is the gap the
    /// "parses as `[A-Za-z0-9_.*-]+`" identifier-list shape used to miss:
    /// `xoxb-secret-token` is indistinguishable, by that alphabet, from a
    /// real Jira field name. `fields` no longer has a verbatim shape at all.
    #[test]
    fn bare_tokens_in_fields_are_digested_not_passed_through() {
        let details = extract_jira(
            HttpMethod::Get,
            "/rest/api/3/issue/PLAT-1",
            &[("fields", "xoxb-secret-token")],
            None,
        );
        let serialized = serde_json::to_string(&details).unwrap();
        assert!(
            !serialized.contains("xoxb-secret-token"),
            "a bare token in fields must not survive: {serialized}"
        );
        assert_eq!(details.query_attributes()[0].0, "fields");
        assert!(details.query_attributes()[0].1.starts_with("sha256:"));

        // A genuinely ordinary field list digests too — there is no
        // shape-based carve-out any more.
        let ordinary = extract_jira(
            HttpMethod::Get,
            "/rest/api/3/issue/PLAT-1",
            &[("fields", "summary,status,customfield_10001")],
            None,
        );
        assert!(ordinary.query_attributes()[0].1.starts_with("sha256:"));
        // Same list, same handle — correlation still works.
        assert_eq!(
            ordinary.query_attributes()[0].1,
            extract_jira(
                HttpMethod::Get,
                "/rest/api/3/issue/PLAT-1",
                &[("fields", "summary,status,customfield_10001")],
                None,
            )
            .query_attributes()[0]
                .1
        );
    }

    /// `direction` is the one attribute backed by a closed, server-owned
    /// vocabulary (`Retention::Enumerated`), so it is the one that survives
    /// verbatim — normalised to the known literal. Everything else here is
    /// caller-authored text with no shape narrow enough to exclude a
    /// credential, so even a well-formed value is retained only as a
    /// digest; see `numeric_values_including_mfa_shaped_codes_are_always_digested`
    /// for why `limit`/`start`/`step`/`end` no longer have a numeric or
    /// time-bound shape of their own.
    #[test]
    fn well_formed_attribute_values_survive_only_when_enumerated() {
        let details = grafana::query_logs(
            "loki-prod",
            &[
                ("direction", "BACKWARD"),
                ("limit", "500"),
                ("start", "1735689600"),
                ("step", "5m"),
                ("end", "2026-09-01T00:00:00Z"),
            ],
        );
        let attributes: std::collections::HashMap<&str, &str> = details
            .query_attributes()
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        assert_eq!(attributes["direction"], "backward");
        for key in ["end", "limit", "start", "step"] {
            assert!(
                attributes[key].starts_with("sha256:"),
                "{key} was well-formed but must still be a digest, got {}",
                attributes[key]
            );
        }
    }

    /// `limit`/`maxResults` once had their own numeric shape: parsed and
    /// re-rendered as a `u64`, which stopped `+007`-style tricks but not a
    /// genuine number — and a real credential can be exactly that shape.
    /// This repository's own `NinjaOne` TOTP/MFA codes
    /// (`tests/ninjaone_session_tests.rs`) are six ASCII digits, identical
    /// in shape to a page size. A caller setting `limit=381164` must not
    /// have that code end up in durable evidence merely because it also
    /// parses as a `u64`.
    #[test]
    fn numeric_values_including_mfa_shaped_codes_are_always_digested() {
        for value in [
            "500", "381164", "999999", "424242", "+007", "1_0", "0x10", " 12 ", "-1", "12.0",
        ] {
            let details = grafana::query_logs("loki-prod", &[("limit", value)]);
            let (_, retained) = &details.query_attributes()[0];
            assert!(
                retained.starts_with("sha256:"),
                "limit {value:?} retained as {retained}: must be a digest, \
                 not the caller's number"
            );
        }
    }

    #[test]
    fn over_long_attribute_values_are_digested_not_truncated() {
        let long = "x".repeat(5000);
        let details = extract_jira(
            HttpMethod::Get,
            "/rest/api/3/issue/PLAT-1",
            &[("fields", long.as_str())],
            None,
        );
        let (_, value) = &details.query_attributes()[0];
        assert!(
            value.starts_with("sha256:"),
            "an over-long value must be digested, not truncated: {value}"
        );
        assert!(value.len() < 64);
    }

    #[test]
    fn get_search_reads_jql_from_query_params() {
        let details = extract_jira(
            HttpMethod::Get,
            "/rest/api/3/search/jql",
            &[("jql", "project = PLAT"), ("maxResults", "5")],
            None,
        );
        assert_eq!(details.normalized_action, NormalizedAction::SearchIssues);
        assert_eq!(details.constraint(), project_constraint(["PLAT"]).as_ref());
        assert_eq!(details.request_risk, RequestRisk::Read);
    }

    // ---- The dispatch tables the enforcement points use ----

    #[test]
    fn for_tool_maps_typed_and_passthrough_arguments_and_denies_the_rest() {
        let grafana = for_tool(
            "grafana_query_logs",
            serde_json::json!({
                "datasourceUid": "loki-qa", "query": "{app=\"api\"}", "limit": 50
            })
            .as_object(),
            RequestRisk::Read,
        );
        assert_eq!(
            grafana,
            grafana::query_logs("loki-qa", &[("query", "{app=\"api\"}"), ("limit", "50")])
        );

        let list = for_tool("grafana_list_datasources", None, RequestRisk::Read);
        assert_eq!(list, grafana::list_datasources());

        let search = for_tool(
            "jira_get",
            serde_json::json!({
                "path": "/rest/api/3/search/jql",
                "queryParams": { "jql": "project = PLAT", "maxResults": "5" }
            })
            .as_object(),
            RequestRisk::Read,
        );
        assert_eq!(search.normalized_action(), NormalizedAction::SearchIssues);
        assert_eq!(search.constraint(), project_constraint(["PLAT"]).as_ref());

        let create = for_tool(
            "jira_post",
            serde_json::json!({ "path": "/rest/api/3/issue", "body": {"fields": {}} }).as_object(),
            RequestRisk::Write,
        );
        assert_eq!(create.resource_type(), ResourceType::Unknown);
        assert_eq!(create.request_risk(), RequestRisk::Write);

        // A path with no canonical form is unknown, like the transport will
        // refuse it.
        let hostile = for_tool(
            "jira_get",
            serde_json::json!({ "path": "https://evil.example/x" }).as_object(),
            RequestRisk::Read,
        );
        assert_eq!(hostile.resource_type(), ResourceType::Unknown);

        // No extractor: the server's own annotation decides the risk, and
        // the resource is unknown either way.
        let slack = for_tool("slack_post_message", None, RequestRisk::Write);
        assert_eq!(slack.resource_type(), ResourceType::Unknown);
        assert_eq!(slack.request_risk(), RequestRisk::Write);
        assert_eq!(slack.method(), HttpMethod::Post);
        let read_only = for_tool("some_read_tool", None, RequestRisk::Read);
        assert_eq!(read_only.request_risk(), RequestRisk::Read);
    }

    #[test]
    fn for_vendor_classifies_only_inventoried_vendors() {
        let target = CanonicalTarget::parse("/api/datasources").unwrap();
        assert_eq!(
            for_vendor("grafana", HttpMethod::Get, &target, None),
            grafana::list_datasources()
        );
        let target = CanonicalTarget::parse("/rest/api/3/issue/PLAT-1").unwrap();
        assert_eq!(
            for_vendor("jira", HttpMethod::Get, &target, None).normalized_action(),
            NormalizedAction::ReadIssue
        );
        let target = CanonicalTarget::parse("/api/chat.postMessage").unwrap();
        let slack = for_vendor("slack", HttpMethod::Post, &target, None);
        assert_eq!(slack.resource_type(), ResourceType::Unknown);
        assert_eq!(slack.request_risk(), RequestRisk::Write);
    }
}

#[cfg(test)]
mod slack_tests {
    use pretty_assertions::assert_eq;

    use super::slack;
    use super::*;

    fn target(path_and_query: &str) -> CanonicalTarget {
        CanonicalTarget::parse(path_and_query).expect("canonical")
    }

    #[test]
    fn channel_reads_are_scoped_to_the_channel_id_and_invalid_ids_are_unclassified() {
        let details = slack::channel_history("C0INCIDENTS", &[("limit", "50"), ("oldest", "1")]);
        assert_eq!(
            details.normalized_action(),
            NormalizedAction::ReadChannelHistory
        );
        assert_eq!(details.resource_type(), ResourceType::Channel);
        assert!(
            details
                .resource_scope()
                .all_ids_allowed(|id| id == "C0INCIDENTS")
        );
        assert_eq!(details.canonical_path(), "/conversations.history");
        assert_eq!(details.request_risk(), RequestRisk::Read);
        assert_eq!(
            details
                .query_attributes()
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            vec!["limit", "oldest"]
        );
        for hostile in ["c0incidents", "C0/../admin", "", "C0 INCIDENTS", "C0%2F"] {
            let details = slack::channel_history(hostile, &[]);
            assert_eq!(
                details.resource_type(),
                ResourceType::Unknown,
                "{hostile:?}"
            );
            assert_eq!(details.normalized_action(), NormalizedAction::Passthrough);
            assert!(!details.canonical_path().contains(hostile.trim()) || hostile.is_empty());
        }
    }

    #[test]
    fn list_is_the_collection_and_search_is_unscoped() {
        let list =
            slack::list_channels(&[("types", "public_channel"), ("exclude_archived", "true")]);
        assert_eq!(list.normalized_action(), NormalizedAction::ListChannels);
        assert!(list.resource_scope().is_collection());
        assert_eq!(
            list.query_attributes()[0],
            ("exclude_archived".to_owned(), "true".to_owned())
        );
        let search =
            slack::search_messages(&[("query", "outage in:#incidents"), ("sort", "TIMESTAMP")]);
        assert_eq!(search.normalized_action(), NormalizedAction::SearchMessages);
        assert!(search.resource_scope().is_unscoped());
        let attributes = search.query_attributes();
        assert!(
            attributes[0].1.starts_with("sha256:"),
            "query text is a digest: {attributes:?}"
        );
        assert_eq!(attributes[1], ("sort".to_owned(), "timestamp".to_owned()));
    }

    /// A `channel` given twice — once in the path's own query and once in
    /// `queryParams`, or twice in either — is not classified, whichever
    /// values it carries: the first value is what policy would judge and
    /// the second is what a last-value parser at Slack would read.
    #[test]
    fn a_repeated_channel_key_is_never_classified() {
        for (path, extra) in [
            ("/conversations.history?channel=C0ALLOWED", Some("C0SECRET")),
            (
                "/conversations.history?channel=C0ALLOWED",
                Some("C0ALLOWED"),
            ),
            (
                "/conversations.info?channel=C0ALLOWED&channel=C0SECRET",
                None,
            ),
            (
                "/conversations.replies?channel=C0A&channel=C0A&ts=1.2",
                None,
            ),
        ] {
            let mut arguments = serde_json::Map::new();
            arguments.insert(
                "path".to_owned(),
                serde_json::Value::String(path.to_owned()),
            );
            if let Some(extra) = extra {
                arguments.insert(
                    "queryParams".to_owned(),
                    serde_json::json!({ "channel": extra }),
                );
            }
            let via_tool = for_tool("slack_get", Some(&arguments), RequestRisk::Read);
            assert_eq!(
                via_tool.normalized_action(),
                NormalizedAction::Passthrough,
                "{path} + {extra:?}"
            );
            assert_eq!(via_tool.resource_type(), ResourceType::Unknown);
            // The egress chokepoint sees the same wire query and agrees.
            let wire = target(&match extra {
                Some(extra) => format!("{path}&channel={extra}"),
                None => path.to_owned(),
            });
            let via_egress = for_vendor(crate::config::VENDOR_SLACK, HttpMethod::Get, &wire, None);
            assert_eq!(
                via_egress.normalized_action(),
                NormalizedAction::Passthrough
            );
        }
        // One channel, however it arrives, still classifies.
        let single = for_vendor(
            crate::config::VENDOR_SLACK,
            HttpMethod::Get,
            &target("/conversations.history?limit=5&channel=C0ALLOWED"),
            None,
        );
        assert_eq!(
            single.normalized_action(),
            NormalizedAction::ReadChannelHistory
        );
    }

    #[test]
    fn passthrough_and_purpose_built_classify_alike() {
        let via_get = for_tool(
            "slack_get",
            Some(
                serde_json::json!({ "path": "/conversations.history", "queryParams": { "channel": "C0INCIDENTS", "limit": "5" } })
                    .as_object()
                    .unwrap(),
            ),
            RequestRisk::Read,
        );
        let purpose_built = for_tool(
            "slack_channel_history",
            Some(
                serde_json::json!({ "channelId": "C0INCIDENTS", "limit": 5 })
                    .as_object()
                    .unwrap(),
            ),
            RequestRisk::Read,
        );
        assert_eq!(via_get, purpose_built);
        let egress = for_vendor(
            crate::config::VENDOR_SLACK,
            HttpMethod::Get,
            &target("/conversations.history?channel=C0INCIDENTS&limit=5"),
            None,
        );
        assert_eq!(egress, purpose_built);
        // A write, an unknown method, and a POST to a read method are all unclassified.
        for (method, path) in [
            (HttpMethod::Post, "/chat.postMessage"),
            (HttpMethod::Get, "/users.list"),
            (
                HttpMethod::Post,
                "/conversations.history?channel=C0INCIDENTS",
            ),
        ] {
            let details = for_vendor(crate::config::VENDOR_SLACK, method, &target(path), None);
            assert_eq!(details.resource_type(), ResourceType::Unknown, "{path}");
        }
        assert!(slack::is_valid_message_ts("1700000000.123456"));
        assert!(!slack::is_valid_message_ts("1700000000"));
        assert!(!slack::is_valid_message_ts("17.00.00"));
    }
}

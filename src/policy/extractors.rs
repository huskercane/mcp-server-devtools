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
//! - Canonicalization here is the tool-level minimum (leading slash,
//!   trailing-slash trim, duplicate-slash collapse). The full §3.5
//!   canonicalizer (percent-decoding, dot-segments, fuzzing) is Phase A
//!   work (A.6) and slots in before these run in production.
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

use super::{ActionDetails, NormalizedAction, ResourceScope, ResourceType};

/// Minimal tool-level path normalization shared by extractors. See module
/// docs for what this deliberately does not do yet.
fn normalize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 1);
    out.push('/');
    let mut last_was_slash = true;
    for ch in path.chars() {
        if ch == '/' {
            if !last_was_slash {
                out.push('/');
            }
            last_was_slash = true;
        } else {
            out.push(ch);
            last_was_slash = false;
        }
    }
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

/// How an allowlisted query value is retained in `query_attributes`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Retention {
    /// A short structural knob (`limit`, `direction`, `fields`, `start`).
    /// Kept verbatim, bounded by [`MAX_ATTRIBUTE_VALUE`].
    Verbatim,
    /// A **search expression the caller wrote** — `LogQL`, JQL. Kept as a
    /// digest and a length, never as text.
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

/// Longest verbatim attribute value retained. Structural knobs are short;
/// anything longer is not a knob.
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

fn retain(value: &str, retention: Retention) -> String {
    match retention {
        Retention::Verbatim => {
            let mut bounded: String = value.chars().take(MAX_ATTRIBUTE_VALUE).collect();
            if bounded.len() < value.len() {
                bounded.push('…');
            }
            bounded
        }
        Retention::Digest => expression_digest(value),
    }
}

/// `sha256:<16 hex chars>/<byte length>` — enough to correlate two identical
/// expressions and to see how big one was, and nothing else. Truncated to 64
/// bits because this is a correlation handle, not a commitment.
fn expression_digest(value: &str) -> String {
    use sha2::{Digest as _, Sha256};

    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::with_capacity(40);
    out.push_str("sha256:");
    for byte in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    let _ = {
        use std::fmt::Write as _;
        write!(out, "/{}", value.len())
    };
    out
}

/// Grafana purpose-built read tools. `readOnlyHint` is true by construction
/// for both, so `request_risk` is [`RequestRisk::Read`] from tool identity,
/// not derived from the HTTP method.
pub mod grafana {
    use super::{
        ActionDetails, HttpMethod, NormalizedAction, ResourceScope, ResourceType, Retention,
        allowlisted_attributes,
    };

    /// Query params of `grafana_query_logs` that are policy-relevant.
    ///
    /// `query` is the `LogQL` the caller wrote, so it is retained as a digest
    /// rather than as text (see [`super::Retention::Digest`]). The label
    /// selectors inside it never restricted *which* datasource is read, so
    /// nothing about policy depends on having the expression.
    const QUERY_LOGS_ALLOWLIST: &[(&str, Retention)] = &[
        ("direction", Retention::Verbatim),
        ("end", Retention::Verbatim),
        ("limit", Retention::Verbatim),
        ("query", Retention::Digest),
        ("start", Retention::Verbatim),
        ("step", Retention::Verbatim),
    ];

    /// Path prefix of the datasource proxy, without the UID.
    const PROXY_PREFIX: &str = "/api/datasources/proxy/uid";

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
        if !is_valid_datasource_uid(datasource_uid) {
            return ActionDetails::unclassified_with_attributes(
                HttpMethod::Get,
                PROXY_PREFIX.to_owned(),
                allowlisted_attributes(params, QUERY_LOGS_ALLOWLIST),
            );
        }
        ActionDetails::read(
            NormalizedAction::QueryLogs,
            HttpMethod::Get,
            format!("{PROXY_PREFIX}/{datasource_uid}/loki/api/v1/query_range"),
            allowlisted_attributes(params, QUERY_LOGS_ALLOWLIST),
            ResourceType::Datasource,
            ResourceScope::id(datasource_uid),
        )
    }

    /// `grafana_list_datasources`: enumerates datasources. Addresses the
    /// datasource collection, not one datasource — hence
    /// [`ResourceScope::collection`], which is distinct from both "one
    /// datasource" and "we could not tell", and needs its own allow rule.
    #[must_use]
    pub fn list_datasources() -> ActionDetails {
        ActionDetails::read(
            NormalizedAction::ListDatasources,
            HttpMethod::Get,
            "/api/datasources".to_owned(),
            Vec::new(),
            ResourceType::Datasource,
            ResourceScope::collection(),
        )
    }
}

/// Jira passthrough extractor: maps `(method, path, query, body)` from the
/// generic `jira_*` verb tools onto normalized actions.
pub mod jira {
    use super::{
        ActionDetails, HttpMethod, NormalizedAction, ResourceScope, ResourceType, Retention,
        allowlisted_attributes, normalize_path,
    };

    /// Query keys retained for the GET search endpoint. The scope claim is
    /// extracted from `jql` before this runs; the expression itself is
    /// retained only as a digest.
    const SEARCH_QUERY_ALLOWLIST: &[(&str, Retention)] = &[
        ("fields", Retention::Verbatim),
        ("jql", Retention::Digest),
        ("maxResults", Retention::Verbatim),
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
            (HttpMethod::Get, ["rest", "api", "3", "issue", key]) => {
                Route::ReadIssue((*key).to_owned())
            }
            (HttpMethod::Get, ["rest", "api", "3", "project"]) => Route::ListProjects,
            (HttpMethod::Get, ["rest", "api", "3", "project", key]) => {
                Route::ReadProject((*key).to_owned())
            }
            (HttpMethod::Get | HttpMethod::Post, ["rest", "api", "3", "search", "jql"]) => {
                Route::Search
            }
            _ => Route::Unmapped,
        }
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
        path: &str,
        query: &[(&str, &str)],
        body: Option<&serde_json::Value>,
    ) -> ActionDetails {
        let canonical_path = normalize_path(path);

        match classify(method, &canonical_path) {
            Route::ReadIssue(key) => ActionDetails::read(
                NormalizedAction::ReadIssue,
                method,
                canonical_path,
                allowlisted_attributes(query, &[("fields", Retention::Verbatim)]),
                ResourceType::Issue,
                ResourceScope::id(key),
            ),
            Route::ListProjects => ActionDetails::read(
                NormalizedAction::ReadProject,
                method,
                canonical_path,
                Vec::new(),
                ResourceType::Project,
                ResourceScope::collection(),
            ),
            Route::ReadProject(key) => ActionDetails::read(
                NormalizedAction::ReadProject,
                method,
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
        canonical_path: String,
        query_attributes: Vec<(String, String)>,
        jql: Option<&str>,
    ) -> ActionDetails {
        let resource_scope = jql
            .and_then(project_keys_from_jql)
            .map_or(ResourceScope::unscoped(), ResourceScope::ids);
        // The one downgrade in this module, named as such: POST would derive
        // `Write`, and only this endpoint's read-only contract overrides it.
        ActionDetails::read_downgrade(
            NormalizedAction::SearchIssues,
            method,
            canonical_path,
            query_attributes,
            ResourceType::Issue,
            resource_scope,
        )
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

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::policy::RequestRisk;

    // ---- Grafana (purpose-built) ----

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
        assert_eq!(
            details.query_attributes[0],
            ("limit".to_owned(), "100".to_owned())
        );
        let (key, value) = &details.query_attributes[1];
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
        jira::extract(HttpMethod::Post, "/rest/api/3/search/jql", &[], Some(body))
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
        assert_eq!(details.resource_scope, ResourceScope::id("PLAT"));
    }

    #[test]
    fn post_search_keeps_every_project_of_an_in_list_as_a_structured_scope() {
        let details = post_search(&serde_json::json!({
            "jql": "project in (WEB, PLAT, WEB) AND status = Open",
        }));
        assert_eq!(
            details.resource_scope,
            ResourceScope::ids(["PLAT", "WEB"]),
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
            details.resource_scope,
            ResourceScope::id("SECRET"),
            "scope must come from the JQL Jira actually executes"
        );

        // And with no JQL at all, a body `project` buys no claim either.
        let decoy_only = post_search(&serde_json::json!({ "project": "PUBLIC" }));
        assert_eq!(decoy_only.resource_scope, ResourceScope::unscoped());
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
                details.resource_scope,
                ResourceScope::unscoped(),
                "jql {jql:?} must not be claimed as project-scoped"
            );
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
        assert_eq!(details.resource_scope, ResourceScope::ids(["A,B", "C"]));
    }

    // ---- The confusion the brief warns about: same verb, different risk ----

    #[test]
    fn post_issue_creation_stays_write_and_unknown_never_a_read() {
        let details = jira::extract(
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
        let get = jira::extract(HttpMethod::Get, "/rest/api/3/somethingelse", &[], None);
        assert_eq!(get.resource_type, ResourceType::Unknown);
        assert_eq!(get.request_risk, RequestRisk::Read);

        let delete = jira::extract(HttpMethod::Delete, "/rest/api/3/issue/PLAT-1", &[], None);
        assert_eq!(delete.normalized_action, NormalizedAction::Passthrough);
        assert_eq!(delete.request_risk, RequestRisk::Destructive);

        // Deeper than the classifier looks: still unmapped, never a partial
        // match against a shorter route.
        let deep = jira::extract(
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
        let issue = jira::extract(
            HttpMethod::Get,
            "//rest/api/3//issue/PLAT-123/",
            &[("fields", "summary"), ("expand", "changelog")],
            None,
        );
        assert_eq!(issue.normalized_action, NormalizedAction::ReadIssue);
        assert_eq!(issue.canonical_path, "/rest/api/3/issue/PLAT-123");
        assert_eq!(issue.resource_scope, ResourceScope::id("PLAT-123"));
        assert_eq!(
            issue.query_attributes,
            vec![("fields".to_owned(), "summary".to_owned())]
        );

        let project = jira::extract(HttpMethod::Get, "/rest/api/3/project/WEB", &[], None);
        assert_eq!(project.normalized_action, NormalizedAction::ReadProject);
        assert_eq!(project.resource_type, ResourceType::Project);
        assert_eq!(project.resource_scope, ResourceScope::id("WEB"));

        let list = jira::extract(HttpMethod::Get, "/rest/api/3/project", &[], None);
        assert_eq!(list.resource_scope, ResourceScope::collection());
    }

    /// `docs/read-endpoint-inventory.md` decision 5, enforced. An earlier
    /// revision wrote that decision down and retained the text anyway.
    #[test]
    fn search_expressions_never_reach_query_attributes_as_text() {
        let secret_jql = "project = PLAT AND text ~ \"Bearer sk-live-abcdef0123456789\"";
        let details = jira::extract(
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
            .query_attributes
            .iter()
            .find(|(key, _)| key == "jql")
            .expect("jql attribute retained");
        assert!(jql.1.starts_with("sha256:"), "digest retained: {}", jql.1);
        // Same expression, same handle — correlation still works.
        let again = jira::extract(
            HttpMethod::Get,
            "/rest/api/3/search/jql",
            &[("jql", secret_jql)],
            None,
        );
        assert_eq!(
            again
                .query_attributes
                .iter()
                .find(|(key, _)| key == "jql")
                .map(|(_, value)| value),
            Some(&jql.1)
        );
        // The scope claim is still extracted from the real expression.
        assert_eq!(details.resource_scope, ResourceScope::id("PLAT"));
    }

    #[test]
    fn verbatim_attribute_values_are_bounded() {
        let long = "x".repeat(5000);
        let details = jira::extract(
            HttpMethod::Get,
            "/rest/api/3/issue/PLAT-1",
            &[("fields", long.as_str())],
            None,
        );
        let (_, value) = &details.query_attributes[0];
        assert!(
            value.chars().count() <= MAX_ATTRIBUTE_VALUE + 1,
            "unbounded attribute value: {} chars",
            value.chars().count()
        );
        assert!(value.ends_with('…'), "truncation is visible");
    }

    #[test]
    fn get_search_reads_jql_from_query_params() {
        let details = jira::extract(
            HttpMethod::Get,
            "/rest/api/3/search/jql",
            &[("jql", "project = PLAT"), ("maxResults", "5")],
            None,
        );
        assert_eq!(details.normalized_action, NormalizedAction::SearchIssues);
        assert_eq!(details.resource_scope, ResourceScope::id("PLAT"));
        assert_eq!(details.request_risk, RequestRisk::Read);
    }
}

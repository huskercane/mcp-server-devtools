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
//!   default-deny policy denies.
//! - **No regex on the hot path**: hand-rolled scanning only.
//! - Canonicalization here is the tool-level minimum (leading slash,
//!   trailing-slash trim, duplicate-slash collapse). The full §3.5
//!   canonicalizer (percent-decoding, dot-segments, fuzzing) is Phase A
//!   work (A.6) and slots in before these run in production.

use crate::transport::HttpMethod;

use super::{ActionDetails, NormalizedAction, RequestRisk, ResourceType};

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

/// Retain only allowlisted query keys, decoded values as given, sorted by
/// key (§3.2 `query_attributes`).
fn allowlisted_attributes(params: &[(&str, &str)], allowlist: &[&str]) -> Vec<(String, String)> {
    let mut kept: Vec<(String, String)> = params
        .iter()
        .filter(|(key, _)| allowlist.contains(key))
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    kept.sort();
    kept
}

/// Grafana purpose-built read tools. `readOnlyHint` is true by construction
/// for both, so `request_risk` is [`RequestRisk::Read`] from tool identity,
/// not derived from the HTTP method.
pub mod grafana {
    use super::{
        ActionDetails, HttpMethod, NormalizedAction, RequestRisk, ResourceType,
        allowlisted_attributes,
    };

    /// Query params of `grafana_query_logs` that are policy-relevant.
    const QUERY_LOGS_ALLOWLIST: &[&str] = &["direction", "end", "limit", "query", "start", "step"];

    /// `grafana_query_logs`: a read of one Loki datasource through the
    /// Grafana datasource proxy. The datasource UID is the resource.
    #[must_use]
    pub fn query_logs(datasource_uid: &str, params: &[(&str, &str)]) -> ActionDetails {
        ActionDetails {
            normalized_action: NormalizedAction::QueryLogs,
            method: HttpMethod::Get,
            canonical_path: format!(
                "/api/datasources/proxy/uid/{datasource_uid}/loki/api/v1/query_range"
            ),
            query_attributes: allowlisted_attributes(params, QUERY_LOGS_ALLOWLIST),
            resource_type: ResourceType::Datasource,
            resource_id: Some(datasource_uid.to_owned()),
            request_risk: RequestRisk::Read,
        }
    }

    /// `grafana_list_datasources`: enumerates datasources. Addresses the
    /// datasource collection, not one datasource — `resource_id` is `None`,
    /// while the type stays classified (this is *not* the `Unknown` case).
    #[must_use]
    pub fn list_datasources() -> ActionDetails {
        ActionDetails {
            normalized_action: NormalizedAction::ListDatasources,
            method: HttpMethod::Get,
            canonical_path: "/api/datasources".to_owned(),
            query_attributes: Vec::new(),
            resource_type: ResourceType::Datasource,
            resource_id: None,
            request_risk: RequestRisk::Read,
        }
    }
}

/// Jira passthrough extractor: maps `(method, path, query, body)` from the
/// generic `jira_*` verb tools onto normalized actions.
pub mod jira {
    use super::{
        ActionDetails, HttpMethod, NormalizedAction, RequestRisk, ResourceType,
        allowlisted_attributes, normalize_path,
    };

    /// Query keys retained for the GET search endpoint.
    const SEARCH_QUERY_ALLOWLIST: &[&str] = &["fields", "jql", "maxResults"];

    /// Body fields the POST search extractor reads. Everything else in the
    /// body is pagination/shape control and is ignored for policy.
    const SEARCH_BODY_ALLOWLIST: &[&str] = &["jql", "project"];

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
        // Owned segments so the match arms may move `canonical_path` into
        // the details they build.
        let owned_segments: Vec<String> = canonical_path
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect();
        let segments: Vec<&str> = owned_segments.iter().map(String::as_str).collect();

        match (method, segments.as_slice()) {
            (HttpMethod::Get, ["rest", "api", "3", "issue", key]) => ActionDetails {
                normalized_action: NormalizedAction::ReadIssue,
                method,
                canonical_path,
                query_attributes: allowlisted_attributes(query, &["fields"]),
                resource_type: ResourceType::Issue,
                resource_id: Some((*key).to_owned()),
                request_risk: RequestRisk::Read,
            },
            (HttpMethod::Get, ["rest", "api", "3", "project"]) => ActionDetails {
                normalized_action: NormalizedAction::ReadProject,
                method,
                canonical_path,
                query_attributes: Vec::new(),
                resource_type: ResourceType::Project,
                resource_id: None,
                request_risk: RequestRisk::Read,
            },
            (HttpMethod::Get, ["rest", "api", "3", "project", key]) => ActionDetails {
                normalized_action: NormalizedAction::ReadProject,
                method,
                canonical_path,
                query_attributes: Vec::new(),
                resource_type: ResourceType::Project,
                resource_id: Some((*key).to_owned()),
                request_risk: RequestRisk::Read,
            },
            (HttpMethod::Get, ["rest", "api", "3", "search", "jql"]) => {
                let jql = query
                    .iter()
                    .find(|(key, _)| *key == "jql")
                    .map(|(_, value)| *value);
                search_details(
                    method,
                    canonical_path,
                    allowlisted_attributes(query, SEARCH_QUERY_ALLOWLIST),
                    jql,
                    None,
                )
            }
            (HttpMethod::Post, ["rest", "api", "3", "search", "jql"]) => {
                // Body-field allowlist: only `jql` and `project` are read.
                let jql = body
                    .and_then(|value| value.get(SEARCH_BODY_ALLOWLIST[0]))
                    .and_then(serde_json::Value::as_str);
                let project = body
                    .and_then(|value| value.get(SEARCH_BODY_ALLOWLIST[1]))
                    .and_then(serde_json::Value::as_str);
                search_details(method, canonical_path, Vec::new(), jql, project)
            }
            _ => ActionDetails {
                normalized_action: NormalizedAction::Passthrough,
                method,
                canonical_path,
                query_attributes: Vec::new(),
                resource_type: ResourceType::Unknown,
                resource_id: None,
                request_risk: RequestRisk::from_method(method),
            },
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
        explicit_project: Option<&str>,
    ) -> ActionDetails {
        let resource_id = match (explicit_project, jql) {
            (Some(project), _) if !project.trim().is_empty() => Some(project.trim().to_owned()),
            (_, Some(jql)) => project_keys_from_jql(jql).map(|keys| keys.join(",")),
            _ => None,
        };
        ActionDetails {
            normalized_action: NormalizedAction::SearchIssues,
            method,
            canonical_path,
            query_attributes,
            resource_type: ResourceType::Issue,
            resource_id,
            request_risk: RequestRisk::Read,
        }
    }

    /// The project keys a JQL query is provably restricted to.
    ///
    /// **Sound, not complete.** Returns `Some(keys)` only when the query is
    /// a conjunction (no top-level `OR`) containing at least one *positive*
    /// project constraint (`project = X` / `project in (A, B)`); the keys
    /// are the union of those constraints, sorted and deduplicated. Returns
    /// `None` — "not provably restricted" — for anything else, including
    /// `OR` queries, negations (`!=`, `not in`), and JQL it cannot lex.
    /// Policy then treats the search as unscoped, which can only *reduce*
    /// what an allow rule matches.
    ///
    /// Hand-rolled lexer (quotes respected, `=`/`(`/`)`/`,`/`!` split as
    /// their own tokens); no regex per the §8 budget.
    #[must_use]
    pub fn project_keys_from_jql(jql: &str) -> Option<Vec<String>> {
        let tokens = lex_jql(jql);
        let lowered: Vec<String> = tokens.iter().map(|t| t.text.to_ascii_lowercase()).collect();

        // A top-level OR (never inside quotes — the lexer keeps quoted
        // strings whole) means no single clause is guaranteed to constrain.
        if lowered
            .iter()
            .zip(&tokens)
            .any(|(lower, token)| !token.quoted && lower == "or")
        {
            return None;
        }

        let mut keys: Vec<String> = Vec::new();
        let mut index = 0;
        while index < tokens.len() {
            if !tokens[index].quoted && lowered[index] == "project" {
                let negated = index
                    .checked_sub(1)
                    .is_some_and(|previous| !tokens[previous].quoted && lowered[previous] == "not");
                match tokens.get(index + 1).map(|t| t.text.as_str()) {
                    Some("=") if !negated => {
                        if let Some(key) = tokens.get(index + 2) {
                            keys.push(key.text.clone());
                            index += 3;
                            continue;
                        }
                        return None; // dangling operator: unparseable
                    }
                    Some("!") => { /* `project != X`: negative, no claim */ }
                    Some(op)
                        if op.eq_ignore_ascii_case("in")
                            && !negated
                            && !prev_is_not(&tokens, &lowered, index) =>
                    {
                        let open = tokens.get(index + 2)?;
                        if open.text != "(" {
                            return None;
                        }
                        let mut cursor = index + 3;
                        loop {
                            match tokens.get(cursor) {
                                Some(token) if token.text == ")" => break,
                                Some(token) if token.text == "," => cursor += 1,
                                Some(token) => {
                                    keys.push(token.text.clone());
                                    cursor += 1;
                                }
                                None => return None, // unterminated list
                            }
                        }
                        index = cursor + 1;
                        continue;
                    }
                    _ => { /* `not in`, unknown operator: no positive claim */ }
                }
            }
            index += 1;
        }

        if keys.is_empty() {
            return None;
        }
        keys.sort();
        keys.dedup();
        Some(keys)
    }

    fn prev_is_not(tokens: &[Token], lowered: &[String], index: usize) -> bool {
        // `project not in (...)` lexes as [project, not, in, ...]; the caller
        // sees `in` at index+1 only for `project in`, so this guards the
        // variant where `not` sits between.
        tokens
            .get(index + 1)
            .is_some_and(|token| !token.quoted && lowered[index + 1] == "not")
    }

    struct Token {
        text: String,
        quoted: bool,
    }

    /// Split JQL into tokens: quoted strings (either quote style) stay one
    /// token with quotes stripped; `=`, `!`, `(`, `)`, `,` are always their
    /// own tokens; everything else splits on whitespace.
    fn lex_jql(jql: &str) -> Vec<Token> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut chars = jql.chars().peekable();
        while let Some(ch) = chars.next() {
            match ch {
                '"' | '\'' => {
                    flush(&mut tokens, &mut current);
                    let mut quoted = String::new();
                    for inner in chars.by_ref() {
                        if inner == ch {
                            break;
                        }
                        quoted.push(inner);
                    }
                    tokens.push(Token {
                        text: quoted,
                        quoted: true,
                    });
                }
                '=' | '(' | ')' | ',' | '!' => {
                    flush(&mut tokens, &mut current);
                    tokens.push(Token {
                        text: ch.to_string(),
                        quoted: false,
                    });
                }
                ch if ch.is_whitespace() => flush(&mut tokens, &mut current),
                ch => current.push(ch),
            }
        }
        flush(&mut tokens, &mut current);
        tokens
    }

    fn flush(tokens: &mut Vec<Token>, current: &mut String) {
        if !current.is_empty() {
            tokens.push(Token {
                text: std::mem::take(current),
                quoted: false,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

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
        assert_eq!(details.resource_id.as_deref(), Some("loki-prod"));
        assert_eq!(details.request_risk, RequestRisk::Read);
        assert_eq!(
            details.canonical_path,
            "/api/datasources/proxy/uid/loki-prod/loki/api/v1/query_range"
        );
        assert_eq!(
            details.query_attributes,
            vec![
                ("limit".to_owned(), "100".to_owned()),
                ("query".to_owned(), "{app=\"api\"}".to_owned()),
            ]
        );
    }

    #[test]
    fn grafana_list_datasources_is_a_classified_collection_read() {
        let details = grafana::list_datasources();
        assert_eq!(details.normalized_action, NormalizedAction::ListDatasources);
        assert_eq!(details.resource_type, ResourceType::Datasource);
        assert_eq!(details.resource_id, None);
        assert_eq!(details.request_risk, RequestRisk::Read);
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
        assert_eq!(details.resource_id.as_deref(), Some("PLAT"));
    }

    #[test]
    fn post_search_unions_project_in_lists_sorted_and_deduplicated() {
        let details = post_search(&serde_json::json!({
            "jql": "project in (WEB, PLAT, WEB) AND status = Open",
        }));
        assert_eq!(details.resource_id.as_deref(), Some("PLAT,WEB"));
    }

    #[test]
    fn post_search_respects_the_explicit_project_body_field() {
        let details = post_search(&serde_json::json!({
            "jql": "text ~ \"anything\"",
            "project": "PLAT",
        }));
        assert_eq!(details.resource_id.as_deref(), Some("PLAT"));
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
                details.resource_id, None,
                "jql {jql:?} must not be claimed as project-scoped"
            );
            // Still a classified read of issues — just unscoped.
            assert_eq!(details.resource_type, ResourceType::Issue);
            assert_eq!(details.request_risk, RequestRisk::Read);
        }
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
        assert_eq!(issue.resource_id.as_deref(), Some("PLAT-123"));
        assert_eq!(
            issue.query_attributes,
            vec![("fields".to_owned(), "summary".to_owned())]
        );

        let project = jira::extract(HttpMethod::Get, "/rest/api/3/project/WEB", &[], None);
        assert_eq!(project.normalized_action, NormalizedAction::ReadProject);
        assert_eq!(project.resource_type, ResourceType::Project);
        assert_eq!(project.resource_id.as_deref(), Some("WEB"));
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
        assert_eq!(details.resource_id.as_deref(), Some("PLAT"));
        assert_eq!(details.request_risk, RequestRisk::Read);
    }
}

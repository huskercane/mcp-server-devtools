//! File-backed policy: the v1 `PolicyDecisionPoint` (ADR-003, WP A.7).
//!
//! A static, versioned YAML document whose rules match a subset of the
//! canonical [`ActionContext`] fields. Data, not logic: no conditions, no
//! expressions, nothing a reviewer cannot read in a pull request. The schema
//! is shaped so that a later Cedar compile target is a translation, not a
//! redesign (plan §2.1).
//!
//! ```yaml
//! version: 3
//! rules:
//!   - id: sre-read-qa-grafana
//!     effect: allow
//!     subjects: { groups: [SRE] }
//!     match:
//!       vendor: grafana
//!       environment: qa
//!       request_risk: read
//!       resource_type: datasource
//!       resource_id: ["loki-qa", "prom-*"]
//!   - id: dev-jira-search-own-projects
//!     effect: allow
//!     subjects: { groups: [Developers] }
//!     match:
//!       vendor: jira
//!       normalized_action: [search_issues, read_issue]
//!       resource_type: [issue, project]
//!       constrained_by: { resource_type: project, resource_id: ["PLAT", "WEB-*"] }
//!       upstream_authority: shared
//! ```
//!
//! ## Semantics
//!
//! - **Default deny.** No matching rule is a denial, and the policy says so
//!   in its decision (`policy_version` is always set, so the denial can be
//!   attributed to the document that produced it).
//! - **Unclassified is denied before rules are consulted.** A call whose
//!   extractor produced `resource_type: unknown` cannot be allowed by any
//!   rule, however broad — a rule cannot even name `unknown` (it is a load
//!   error). This is the plan's "default-deny everywhere" for extractors.
//! - **Deny overrides allow.** Every rule is evaluated; a matching `deny`
//!   wins over any matching `allow`. Among allows, the first in document
//!   order is the one attributed.
//! - **Within a rule, every listed key must match** (AND). A key given a
//!   list matches when the call's value is any of them (OR), except the
//!   three resource keys, which are all-of over the call's ids:
//!   `resource_id` matches an id-scoped call only when *every* id the call
//!   addresses matches some pattern; it never matches an unscoped or
//!   collection call. `resource_scope: collection` / `unscoped` match that
//!   exact state and nothing else. `constrained_by` matches only a call that
//!   proved a constraint of that type, all of whose ids match. A rule that
//!   names none of the three is resource-agnostic.
//! - **Subjects** are required. `everyone: true`, or any of `groups`,
//!   `subjects`, `scopes` — each any-of, and every listed category must
//!   match. `*` is a wildcard in any of them.
//! - **Patterns** (`tool_name`, `canonical_path`, `resource_id`, and the
//!   constraint's ids) are globs with `*` only. No regex, on the request
//!   path or off it. **`*` matches any run of bytes, including `/`**: in a
//!   `canonical_path` pattern, `/api/*/query` matches `/api/a/b/query` as
//!   well as `/api/a/query`. There is no single-segment wildcard; write the
//!   segments you mean, and scope broad path patterns with a resource key.
//! - **Unknown keys are load errors.** A misspelt `resource_typ:` must not
//!   silently widen a rule, so every mapping is `deny_unknown_fields`.
//!
//! ## Load, compile, reload
//!
//! The document is parsed and compiled to typed matchers once, at load;
//! enum values are checked then (`request_risk: raed` is a load error, not
//! a rule that never matches). Evaluation reads an `Arc` snapshot. A
//! watcher polls the file and swaps in a new snapshot when the bytes change
//! and the new document compiles; a document that does not compile is
//! logged and the last good policy stays in force — a reload never fails
//! open. The policy version is `v<version>+sha256:<16 hex>` of the exact
//! bytes, so an audit record names the document that decided it.
//!
//! ## Signed bundles (WP B.3)
//!
//! When a verifying key is configured (`MCP_POLICY_PUBLIC_KEY`, required in
//! `MCP_AUTH_MODE=okta`), the document must be accompanied by a detached
//! Ed25519 signature in `<file>.sig` ([`super::signing`]), and a document
//! whose signature is missing or does not verify is refused exactly like
//! one that does not compile: at startup that is fatal, on reload the last
//! good policy stays in force. Signing is a separate step from writing the
//! file, so a policy change is two files landing on disk; the watcher only
//! ever sees a mismatch as a rejected reload, and picks the pair up on the
//! next tick once both are in place.
//!
//! A change is **journaled before it is applied**: the watcher stages the
//! new document, appends a `policy_changed` control record carrying the old
//! and new version labels and the signature status, and only then commits
//! the staged document. A change whose record cannot be made durable is
//! not applied — the same write-before-act rule a tool call follows — and
//! health reports the policy as degraded until the journal recovers.
//! Rejected reloads are journaled too, once per distinct failure, not once
//! per poll. The machinery is [`super::bundle::SignedBundle`], shared with
//! the revocation list; this module supplies the document.
//!
//! **A file that disappears or becomes unreadable is treated the same way:
//! the last good policy stays in force**, indefinitely. Deleting the file is
//! therefore *not* an emergency deny — a gateway keeps serving under the
//! document it last compiled, which is the same posture the plan gives a
//! gateway whose control plane is down (§3.4, "last signed policy bundle").
//! The state is not silent: `FilePolicy::degraded` reports the last
//! reload failure, and the HTTP health banner prints it. To stop traffic,
//! publish a document that denies (`version: N, rules: []` denies
//! everything) or take the gateway out of rotation; the deny-list and
//! `revoke-all` controls arrive in Phase B (CF-16).

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::ports::audit_sink::ControlEventKind;
use crate::ports::policy_decision_point::PolicyDecisionPoint;
use crate::transport::HttpMethod;

use super::bundle::{BundleDocument, BundleError, SignedBundle, version_label};
use super::signing::Domain;
use super::{
    ActionContext, EnvironmentClass, NormalizedAction, PolicyDecision, PolicyEffect, Principal,
    RequestRisk, ResourceType, UpstreamAuthority,
};

/// Config key naming the policy document. Required in enterprise mode.
pub const POLICY_FILE_KEY: &str = "MCP_POLICY_FILE";

/// Config key holding the base64 Ed25519 public key that policy documents
/// (and the revocation list) must be signed with. Required in enterprise
/// mode; optional for local dry runs.
pub const POLICY_PUBLIC_KEY_KEY: &str = "MCP_POLICY_PUBLIC_KEY";

/// How often the watcher looks at the file.
pub const POLICY_WATCH_INTERVAL: Duration = super::bundle::WATCH_INTERVAL;

/// Largest document accepted.
const MAX_POLICY_BYTES: usize = super::bundle::MAX_DOCUMENT_BYTES;

/// Why a document was refused. Carries the document's own text (rule ids,
/// key names), never anything from a request.
pub type PolicyError = BundleError;

// ---------------------------------------------------------------------------
// Document schema (what the operator writes)
// ---------------------------------------------------------------------------

/// A scalar or a list of them; both spellings mean "any of these".
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(one) => vec![one],
            Self::Many(many) => many,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    version: u32,
    /// Accepted for readability; only `deny` is a legal value.
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    rules: Vec<RuleDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDocument {
    id: String,
    effect: PolicyEffect,
    #[serde(default)]
    description: Option<String>,
    subjects: SubjectsDocument,
    #[serde(default, rename = "match")]
    matcher: MatchDocument,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectsDocument {
    #[serde(default)]
    everyone: Option<bool>,
    #[serde(default)]
    groups: Option<OneOrMany<String>>,
    #[serde(default)]
    subjects: Option<OneOrMany<String>>,
    #[serde(default)]
    scopes: Option<OneOrMany<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatchDocument {
    #[serde(default)]
    vendor: Option<OneOrMany<String>>,
    #[serde(default)]
    environment: Option<OneOrMany<String>>,
    #[serde(default)]
    tool_name: Option<OneOrMany<String>>,
    #[serde(default)]
    normalized_action: Option<OneOrMany<NormalizedAction>>,
    #[serde(default)]
    request_risk: Option<OneOrMany<RequestRisk>>,
    #[serde(default)]
    resource_type: Option<OneOrMany<ResourceType>>,
    #[serde(default)]
    resource_id: Option<OneOrMany<String>>,
    #[serde(default)]
    resource_scope: Option<String>,
    #[serde(default)]
    constrained_by: Option<ConstraintDocument>,
    #[serde(default)]
    upstream_authority: Option<OneOrMany<UpstreamAuthority>>,
    #[serde(default)]
    method: Option<OneOrMany<String>>,
    #[serde(default)]
    canonical_path: Option<OneOrMany<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConstraintDocument {
    resource_type: ResourceType,
    resource_id: OneOrMany<String>,
}

// ---------------------------------------------------------------------------
// Compiled form (what evaluation reads)
// ---------------------------------------------------------------------------

/// A `*`-only glob. Anything else in the pattern is literal.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Glob {
    pattern: String,
}

impl Glob {
    fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_owned(),
        }
    }

    /// Classic two-pointer wildcard match: linear in the input, no
    /// allocation, no backtracking blow-up.
    fn matches(&self, value: &str) -> bool {
        let pattern = self.pattern.as_bytes();
        let text = value.as_bytes();
        let (mut p, mut t) = (0usize, 0usize);
        let mut star: Option<(usize, usize)> = None;
        while t < text.len() {
            if p < pattern.len() && pattern[p] == b'*' {
                star = Some((p, t));
                p += 1;
            } else if p < pattern.len() && pattern[p] == text[t] {
                p += 1;
                t += 1;
            } else if let Some((star_p, star_t)) = star {
                p = star_p + 1;
                t = star_t + 1;
                star = Some((star_p, star_t + 1));
            } else {
                return false;
            }
        }
        while p < pattern.len() && pattern[p] == b'*' {
            p += 1;
        }
        p == pattern.len()
    }
}

fn globs(values: Option<OneOrMany<String>>) -> Option<Vec<Glob>> {
    values.map(|values| {
        values
            .into_vec()
            .iter()
            .map(|value| Glob::new(value))
            .collect()
    })
}

fn any_glob(globs: &[Glob], value: &str) -> bool {
    globs.iter().any(|glob| glob.matches(value))
}

#[derive(Debug)]
struct SubjectMatcher {
    everyone: bool,
    groups: Option<Vec<Glob>>,
    subjects: Option<Vec<Glob>>,
    scopes: Option<Vec<Glob>>,
}

impl SubjectMatcher {
    fn matches(&self, principal: &Principal) -> bool {
        if self.everyone {
            return true;
        }
        let groups_ok = self
            .groups
            .as_ref()
            .is_none_or(|globs| principal.groups.iter().any(|group| any_glob(globs, group)));
        let subject_ok = self
            .subjects
            .as_ref()
            .is_none_or(|globs| any_glob(globs, &principal.subject));
        let scopes_ok = self
            .scopes
            .as_ref()
            .is_none_or(|globs| principal.scopes.iter().any(|scope| any_glob(globs, scope)));
        groups_ok && subject_ok && scopes_ok
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    Collection,
    Unscoped,
}

#[derive(Debug)]
struct CompiledRule {
    id: String,
    effect: PolicyEffect,
    subjects: SubjectMatcher,
    vendor: Option<Vec<String>>,
    environment: Option<Vec<EnvironmentClass>>,
    tool_name: Option<Vec<Glob>>,
    normalized_action: Option<Vec<NormalizedAction>>,
    request_risk: Option<Vec<RequestRisk>>,
    resource_type: Option<Vec<ResourceType>>,
    resource_id: Option<Vec<Glob>>,
    resource_scope: Option<ScopeKind>,
    constrained_by: Option<(ResourceType, Vec<Glob>)>,
    upstream_authority: Option<Vec<UpstreamAuthority>>,
    method: Option<Vec<HttpMethod>>,
    canonical_path: Option<Vec<Glob>>,
}

impl CompiledRule {
    fn matches(&self, context: &ActionContext) -> bool {
        self.mismatch(context).is_none()
    }

    /// The first key of this rule that `context` fails, or `None` when the
    /// rule matches. The same early-return walk `matches` always did; the
    /// key name is what `policy explain` prints (WP B.2).
    fn mismatch(&self, context: &ActionContext) -> Option<&'static str> {
        if !self.subjects.matches(context.principal()) {
            return Some("subjects");
        }
        if !self
            .vendor
            .as_ref()
            .is_none_or(|list| list.iter().any(|item| item == context.vendor()))
        {
            return Some("vendor");
        }
        if !contains(self.environment.as_deref(), &context.environment()) {
            return Some("environment");
        }
        if !self
            .tool_name
            .as_ref()
            .is_none_or(|globs| any_glob(globs, context.tool_name()))
        {
            return Some("tool_name");
        }
        if !contains(
            self.normalized_action.as_deref(),
            &context.normalized_action(),
        ) {
            return Some("normalized_action");
        }
        if !contains(self.request_risk.as_deref(), &context.request_risk()) {
            return Some("request_risk");
        }
        if !contains(self.resource_type.as_deref(), &context.resource_type()) {
            return Some("resource_type");
        }
        if !contains(
            self.upstream_authority.as_deref(),
            &context.upstream_identity().authority,
        ) {
            return Some("upstream_authority");
        }
        if !contains(self.method.as_deref(), &context.method()) {
            return Some("method");
        }
        if !self
            .canonical_path
            .as_ref()
            .is_none_or(|globs| any_glob(globs, context.canonical_path()))
        {
            return Some("canonical_path");
        }
        // The three resource keys: all-of, and each only for its own state.
        if let Some(globs) = &self.resource_id
            && !context
                .resource_scope()
                .all_ids_allowed(|id| any_glob(globs, id))
        {
            return Some("resource_id");
        }
        if let Some(kind) = self.resource_scope {
            let scope = context.resource_scope();
            let ok = match kind {
                ScopeKind::Collection => scope.is_collection(),
                ScopeKind::Unscoped => scope.is_unscoped(),
            };
            if !ok {
                return Some("resource_scope");
            }
        }
        if let Some((resource_type, globs)) = &self.constrained_by
            && !context.constraint().is_some_and(|constraint| {
                constraint.resource_type() == *resource_type
                    && constraint.scope().all_ids_allowed(|id| any_glob(globs, id))
            })
        {
            return Some("constrained_by");
        }
        None
    }
}

/// `None` matches anything; `Some(list)` matches a member.
fn contains<T: PartialEq>(list: Option<&[T]>, value: &T) -> bool {
    list.is_none_or(|list| list.contains(value))
}

/// A compiled policy document: the rules as matchers plus the version
/// label. Public so the bundle type can name it; its fields are not.
#[derive(Debug)]
pub struct CompiledPolicy {
    version: String,
    rules: Vec<CompiledRule>,
}

impl BundleDocument for CompiledPolicy {
    const DOMAIN: Domain = Domain::PolicyBundle;
    const NOUN: &'static str = "policy";
    const KINDS: [ControlEventKind; 3] = [
        ControlEventKind::PolicyLoaded,
        ControlEventKind::PolicyChanged,
        ControlEventKind::PolicyRejected,
    ];

    fn compile(bytes: &[u8]) -> Result<Self, BundleError> {
        compile(bytes)
    }

    fn version(&self) -> &str {
        &self.version
    }
}

fn parse_method(value: &str) -> Result<HttpMethod, PolicyError> {
    match value.to_ascii_uppercase().as_str() {
        "GET" => Ok(HttpMethod::Get),
        "POST" => Ok(HttpMethod::Post),
        "PUT" => Ok(HttpMethod::Put),
        "PATCH" => Ok(HttpMethod::Patch),
        "DELETE" => Ok(HttpMethod::Delete),
        other => Err(PolicyError::new(format!("unknown HTTP method {other:?}"))),
    }
}

fn compile(bytes: &[u8]) -> Result<CompiledPolicy, PolicyError> {
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(PolicyError::new("policy document is too large"));
    }
    let document: PolicyDocument = serde_norway::from_slice(bytes)
        .map_err(|error| PolicyError::new(format!("policy does not parse: {error}")))?;
    if let Some(default) = &document.default
        && !default.eq_ignore_ascii_case("deny")
    {
        return Err(PolicyError::new(format!(
            "`default` may only be `deny`, got {default:?}; there is no permissive default"
        )));
    }

    let mut rules = Vec::with_capacity(document.rules.len());
    let mut seen_ids: Vec<&str> = Vec::with_capacity(document.rules.len());
    for rule in &document.rules {
        if rule.id.trim().is_empty() {
            return Err(PolicyError::new("a rule has an empty `id`"));
        }
        if seen_ids.contains(&rule.id.as_str()) {
            return Err(PolicyError::new(format!("duplicate rule id {:?}", rule.id)));
        }
        seen_ids.push(&rule.id);
    }
    for rule in document.rules {
        rules.push(compile_rule(rule)?);
    }

    Ok(CompiledPolicy {
        version: version_label(document.version, bytes),
        rules,
    })
}

fn parse_environments(
    rule_id: &str,
    values: Option<OneOrMany<String>>,
) -> Result<Option<Vec<EnvironmentClass>>, PolicyError> {
    values
        .map(|values| {
            values
                .into_vec()
                .iter()
                .map(|value| {
                    EnvironmentClass::parse(value).ok_or_else(|| {
                        PolicyError::new(format!(
                            "rule {rule_id:?}: unknown environment {value:?} (prod, staging, qa, dev)"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
}

fn parse_methods(
    rule_id: &str,
    values: Option<OneOrMany<String>>,
) -> Result<Option<Vec<HttpMethod>>, PolicyError> {
    values
        .map(|values| {
            values
                .into_vec()
                .iter()
                .map(|value| {
                    parse_method(value)
                        .map_err(|error| PolicyError::new(format!("rule {rule_id:?}: {error}")))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
}

/// Compile one rule, checking every enum and pattern now so a typo is a
/// load error rather than a rule that never matches.
fn compile_rule(rule: RuleDocument) -> Result<CompiledRule, PolicyError> {
    let id = rule.id;
    let _ = rule.description;
    let subjects = compile_subjects(&id, rule.subjects)?;
    let matcher = rule.matcher;
    let environment = parse_environments(&id, matcher.environment)?;
    let resource_type = matcher.resource_type.map(OneOrMany::into_vec);
    if resource_type
        .as_ref()
        .is_some_and(|types| types.contains(&ResourceType::Unknown))
    {
        return Err(PolicyError::new(format!(
            "rule {id:?}: `resource_type: unknown` cannot be matched — unclassified calls \
             are always denied"
        )));
    }
    let resource_scope = matcher
        .resource_scope
        .as_deref()
        .map(|value| match value {
            "collection" => Ok(ScopeKind::Collection),
            "unscoped" => Ok(ScopeKind::Unscoped),
            other => Err(PolicyError::new(format!(
                "rule {id:?}: `resource_scope` must be `collection` or `unscoped`, got {other:?}"
            ))),
        })
        .transpose()?;
    let constrained_by = match matcher.constrained_by {
        None => None,
        Some(constraint) => {
            if constraint.resource_type == ResourceType::Unknown {
                return Err(PolicyError::new(format!(
                    "rule {id:?}: `constrained_by.resource_type: unknown` is not a constraint"
                )));
            }
            let ids: Vec<Glob> = constraint
                .resource_id
                .into_vec()
                .iter()
                .map(|value| Glob::new(value))
                .collect();
            if ids.is_empty() {
                return Err(PolicyError::new(format!(
                    "rule {id:?}: `constrained_by.resource_id` is empty"
                )));
            }
            Some((constraint.resource_type, ids))
        }
    };
    let method = parse_methods(&id, matcher.method)?;
    let resource_id = globs(matcher.resource_id);
    if resource_id.as_ref().is_some_and(Vec::is_empty) {
        return Err(PolicyError::new(format!(
            "rule {id:?}: `resource_id` is empty"
        )));
    }
    Ok(CompiledRule {
        id,
        effect: rule.effect,
        subjects,
        vendor: matcher.vendor.map(|values| {
            values
                .into_vec()
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .collect()
        }),
        environment,
        tool_name: globs(matcher.tool_name),
        normalized_action: matcher.normalized_action.map(OneOrMany::into_vec),
        request_risk: matcher.request_risk.map(OneOrMany::into_vec),
        resource_type,
        resource_id,
        resource_scope,
        constrained_by,
        upstream_authority: matcher.upstream_authority.map(OneOrMany::into_vec),
        method,
        canonical_path: globs(matcher.canonical_path),
    })
}

fn compile_subjects(
    rule_id: &str,
    subjects: SubjectsDocument,
) -> Result<SubjectMatcher, PolicyError> {
    let everyone = subjects.everyone.unwrap_or(false);
    let compiled = SubjectMatcher {
        everyone,
        groups: globs(subjects.groups),
        subjects: globs(subjects.subjects),
        scopes: globs(subjects.scopes),
    };
    let named =
        compiled.groups.is_some() || compiled.subjects.is_some() || compiled.scopes.is_some();
    if !everyone && !named {
        return Err(PolicyError::new(format!(
            "rule {rule_id:?}: `subjects` must name `groups`, `subjects`, or `scopes`, or say \
             `everyone: true`; a rule that applies to nobody is a mistake, and one that \
             applies to everybody must say so"
        )));
    }
    if everyone && named {
        return Err(PolicyError::new(format!(
            "rule {rule_id:?}: `everyone: true` cannot be combined with named subjects"
        )));
    }
    for (label, list) in [
        ("groups", &compiled.groups),
        ("subjects", &compiled.subjects),
        ("scopes", &compiled.scopes),
    ] {
        if list.as_ref().is_some_and(Vec::is_empty) {
            return Err(PolicyError::new(format!(
                "rule {rule_id:?}: `subjects.{label}` is empty"
            )));
        }
    }
    Ok(compiled)
}

// ---------------------------------------------------------------------------
// The decision point
// ---------------------------------------------------------------------------

/// A policy document on disk, verified, compiled, hot-reloadable — a
/// [`SignedBundle`] over [`CompiledPolicy`]. `load`, `load_verified`,
/// `from_bytes`, `reload`, `stage`/`commit`, `spawn_watcher`, `degraded`,
/// and `signature` come from the bundle.
pub type FilePolicy = SignedBundle<CompiledPolicy>;

impl CompiledPolicy {
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl SignedBundle<CompiledPolicy> {
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.snapshot().document.rule_count()
    }

    /// Every rule, as data, in document order (WP B.5 access review, WP
    /// B.2 explain).
    #[must_use]
    pub fn describe_rules(&self) -> Vec<RuleDescription> {
        self.snapshot()
            .document
            .rules
            .iter()
            .map(CompiledRule::describe)
            .collect()
    }

    /// Evaluate `context` and say why: the decision, and for every rule
    /// whether it matched and, if not, the first key it failed on (WP B.2,
    /// `policy explain`). Same semantics as `evaluate`: an unclassified
    /// resource is denied before rules are consulted, a matching deny wins,
    /// the first matching allow is attributed.
    #[must_use]
    pub fn explain(&self, context: &ActionContext) -> Explanation {
        let snapshot = self.snapshot();
        let policy = &snapshot.document;
        let unclassified = context.resource_type() == ResourceType::Unknown;
        let mut rules: Vec<RuleTrace> = policy
            .rules
            .iter()
            .map(|rule| RuleTrace {
                id: rule.id.clone(),
                effect: rule.effect,
                mismatch: rule.mismatch(context),
                decisive: false,
            })
            .collect();
        let decision = <Self as PolicyDecisionPoint>::evaluate(self, context);
        if !unclassified
            && let Some(rule_id) = &decision.rule_id
            && let Some(trace) = rules.iter_mut().find(|trace| trace.id == *rule_id)
        {
            trace.decisive = true;
        }
        Explanation {
            decision,
            unclassified,
            rules,
        }
    }

    /// The rules whose `subjects` clause matches `principal` — what this
    /// principal *could* be allowed or denied, before any call is matched.
    /// The access review is this, per member of each group.
    #[must_use]
    pub fn rules_for(&self, principal: &Principal) -> Vec<RuleDescription> {
        self.snapshot()
            .document
            .rules
            .iter()
            .filter(|rule| rule.subjects.matches(principal))
            .map(CompiledRule::describe)
            .collect()
    }
}

/// One rule's part in a decision (`policy explain`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RuleTrace {
    pub id: String,
    pub effect: PolicyEffect,
    /// The first key the call failed, or `None` when the rule matched.
    pub mismatch: Option<&'static str>,
    /// Whether this is the rule the decision names.
    pub decisive: bool,
}

impl RuleTrace {
    #[must_use]
    pub const fn matched(&self) -> bool {
        self.mismatch.is_none()
    }
}

/// A decision with its reasons.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Explanation {
    pub decision: PolicyDecision,
    /// The resource could not be classified, so no rule was consulted.
    pub unclassified: bool,
    pub rules: Vec<RuleTrace>,
}

/// A rule as data: what the document said, after compilation, with every
/// list normalized to a list of strings. What the access review and
/// `policy explain` print.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RuleDescription {
    pub id: String,
    pub effect: PolicyEffect,
    pub subjects: SubjectsDescription,
    /// The match keys the rule names, in the document's vocabulary.
    /// Absent keys match anything.
    pub matches: std::collections::BTreeMap<&'static str, Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct SubjectsDescription {
    pub everyone: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

fn glob_patterns(globs: Option<&Vec<Glob>>) -> Vec<String> {
    globs
        .map(|globs| globs.iter().map(|glob| glob.pattern.clone()).collect())
        .unwrap_or_default()
}

fn enum_labels<T: serde::Serialize>(values: Option<&Vec<T>>) -> Vec<String> {
    values
        .map(|values| {
            values
                .iter()
                .map(|value| {
                    serde_json::to_value(value)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default()
}

impl CompiledRule {
    fn describe(&self) -> RuleDescription {
        let mut matches = std::collections::BTreeMap::new();
        let mut put = |key: &'static str, values: Vec<String>| {
            if !values.is_empty() {
                matches.insert(key, values);
            }
        };
        put("vendor", self.vendor.clone().unwrap_or_default());
        put("environment", enum_labels(self.environment.as_ref()));
        put("tool_name", glob_patterns(self.tool_name.as_ref()));
        put(
            "normalized_action",
            enum_labels(self.normalized_action.as_ref()),
        );
        put("request_risk", enum_labels(self.request_risk.as_ref()));
        put("resource_type", enum_labels(self.resource_type.as_ref()));
        put("resource_id", glob_patterns(self.resource_id.as_ref()));
        put(
            "resource_scope",
            self.resource_scope
                .map(|kind| match kind {
                    ScopeKind::Collection => vec!["collection".to_owned()],
                    ScopeKind::Unscoped => vec!["unscoped".to_owned()],
                })
                .unwrap_or_default(),
        );
        if let Some((resource_type, globs)) = &self.constrained_by {
            let label = serde_json::to_value(resource_type)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_default();
            put(
                "constrained_by",
                globs
                    .iter()
                    .map(|glob| format!("{label}:{}", glob.pattern))
                    .collect(),
            );
        }
        put(
            "upstream_authority",
            enum_labels(self.upstream_authority.as_ref()),
        );
        put(
            "method",
            self.method
                .as_ref()
                .map(|methods| {
                    methods
                        .iter()
                        .map(|method| method.as_str().to_owned())
                        .collect()
                })
                .unwrap_or_default(),
        );
        put(
            "canonical_path",
            glob_patterns(self.canonical_path.as_ref()),
        );
        RuleDescription {
            id: self.id.clone(),
            effect: self.effect,
            subjects: SubjectsDescription {
                everyone: self.subjects.everyone,
                groups: glob_patterns(self.subjects.groups.as_ref()),
                subjects: glob_patterns(self.subjects.subjects.as_ref()),
                scopes: glob_patterns(self.subjects.scopes.as_ref()),
            },
            matches,
        }
    }
}

impl PolicyDecisionPoint for FilePolicy {
    fn evaluate(&self, context: &ActionContext) -> PolicyDecision {
        let snapshot = self.snapshot();
        let policy = &snapshot.document;
        if context.resource_type() == ResourceType::Unknown {
            return PolicyDecision::default_deny_under(
                &policy.version,
                "the call's resource could not be classified; unclassified calls are always denied",
            );
        }
        let mut allowed_by: Option<&CompiledRule> = None;
        for rule in &policy.rules {
            if !rule.matches(context) {
                continue;
            }
            match rule.effect {
                PolicyEffect::Deny => {
                    return PolicyDecision::by_rule(PolicyEffect::Deny, &rule.id, &policy.version);
                }
                PolicyEffect::Allow => {
                    if allowed_by.is_none() {
                        allowed_by = Some(rule);
                    }
                }
            }
        }
        match allowed_by {
            Some(rule) => PolicyDecision::by_rule(PolicyEffect::Allow, &rule.id, &policy.version),
            None => PolicyDecision::default_deny_under(
                &policy.version,
                "no rule allows this call; default deny",
            ),
        }
    }

    fn version(&self) -> Option<String> {
        Some(SignedBundle::version(self))
    }

    fn degraded(&self) -> Option<String> {
        SignedBundle::degraded(self)
    }
}

impl PolicyDecisionPoint for Arc<FilePolicy> {
    fn evaluate(&self, context: &ActionContext) -> PolicyDecision {
        <FilePolicy as PolicyDecisionPoint>::evaluate(self, context)
    }

    fn version(&self) -> Option<String> {
        <FilePolicy as PolicyDecisionPoint>::version(self)
    }

    fn degraded(&self) -> Option<String> {
        <FilePolicy as PolicyDecisionPoint>::degraded(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_star_only() {
        let cases = [
            ("loki-*", "loki-prod", true),
            ("loki-*", "loki-", true),
            ("loki-*", "prom-prod", false),
            ("*", "", true),
            ("*", "anything", true),
            ("PLAT", "PLAT", true),
            ("PLAT", "PLAT-1", false),
            ("*/query_range", "/api/x/query_range", true),
            ("/api/*/proxy/*", "/api/datasources/proxy/uid/x", true),
            // `*` is not segment-bounded: it crosses `/` (module docs). A
            // pattern meant for one segment matches deeper paths too.
            ("/api/*/query", "/api/a/query", true),
            ("/api/*/query", "/api/a/b/c/query", true),
            ("a*b*c", "aXXbYYc", true),
            ("a*b*c", "aXXbYY", false),
            ("[a]", "a", false),
        ];
        for (pattern, value, expected) in cases {
            assert_eq!(
                Glob::new(pattern).matches(value),
                expected,
                "{pattern} vs {value}"
            );
        }
    }

    #[test]
    fn documents_with_typos_or_permissive_defaults_do_not_compile() {
        let bad = [
            (
                "unknown key",
                "version: 1\nrules:\n  - id: r\n    effect: allow\n    subjects: {everyone: true}\n    match: {resource_typ: issue}\n",
            ),
            (
                "bad effect",
                "version: 1\nrules:\n  - id: r\n    effect: permit\n    subjects: {everyone: true}\n",
            ),
            (
                "bad risk",
                "version: 1\nrules:\n  - id: r\n    effect: allow\n    subjects: {everyone: true}\n    match: {request_risk: raed}\n",
            ),
            (
                "bad env",
                "version: 1\nrules:\n  - id: r\n    effect: allow\n    subjects: {everyone: true}\n    match: {environment: pord}\n",
            ),
            (
                "unknown resource",
                "version: 1\nrules:\n  - id: r\n    effect: allow\n    subjects: {everyone: true}\n    match: {resource_type: unknown}\n",
            ),
            (
                "no subjects",
                "version: 1\nrules:\n  - id: r\n    effect: allow\n    subjects: {}\n",
            ),
            (
                "everyone plus groups",
                "version: 1\nrules:\n  - id: r\n    effect: allow\n    subjects: {everyone: true, groups: [x]}\n",
            ),
            (
                "permissive default",
                "version: 1\ndefault: allow\nrules: []\n",
            ),
            (
                "duplicate id",
                "version: 1\nrules:\n  - id: r\n    effect: allow\n    subjects: {everyone: true}\n  - id: r\n    effect: deny\n    subjects: {everyone: true}\n",
            ),
            (
                "bad scope",
                "version: 1\nrules:\n  - id: r\n    effect: allow\n    subjects: {everyone: true}\n    match: {resource_scope: ids}\n",
            ),
            (
                "empty resource_id",
                "version: 1\nrules:\n  - id: r\n    effect: allow\n    subjects: {everyone: true}\n    match: {resource_id: []}\n",
            ),
            (
                "bad method",
                "version: 1\nrules:\n  - id: r\n    effect: allow\n    subjects: {everyone: true}\n    match: {method: FETCH}\n",
            ),
        ];
        for (label, document) in bad {
            assert!(
                FilePolicy::from_bytes(document.as_bytes()).is_err(),
                "{label} must not compile"
            );
        }
        let ok = FilePolicy::from_bytes(b"version: 1\ndefault: deny\nrules: []\n").unwrap();
        assert_eq!(ok.rule_count(), 0);
        assert!(ok.version().unwrap().starts_with("v1+sha256:"));
    }
}

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
//! new document ([`FilePolicy::stage`]), appends a `policy_changed` control
//! record carrying the old and new version labels and the signature
//! status, and only then commits the staged document
//! ([`FilePolicy::commit`]). A change whose record cannot be made durable
//! is not applied — the same write-before-act rule a tool call follows —
//! and health reports the policy as degraded until the journal recovers.
//! Rejected reloads are journaled too, once per distinct failure, not once
//! per poll.
//!
//! **A file that disappears or becomes unreadable is treated the same way:
//! the last good policy stays in force**, indefinitely. Deleting the file is
//! therefore *not* an emergency deny — a gateway keeps serving under the
//! document it last compiled, which is the same posture the plan gives a
//! gateway whose control plane is down (§3.4, "last signed policy bundle").
//! The state is not silent: [`FilePolicy::degraded`] reports the last
//! reload failure, and the HTTP health banner prints it. To stop traffic,
//! publish a document that denies (`version: N, rules: []` denies
//! everything) or take the gateway out of rotation; the deny-list and
//! `revoke-all` controls arrive in Phase B (CF-16).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use serde::Deserialize;

use crate::ports::audit_sink::{AuditSink, ControlEvent, ControlEventKind, SignatureStatus};
use crate::ports::policy_decision_point::PolicyDecisionPoint;
use crate::transport::HttpMethod;

use super::signing::{Domain, VerifyingKey};
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
pub const POLICY_WATCH_INTERVAL: Duration = Duration::from_millis(500);

/// Largest document accepted.
const MAX_POLICY_BYTES: usize = 4 * 1024 * 1024;

/// Why a document was refused. Carries the document's own text (rule ids,
/// key names), never anything from a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(String);

impl PolicyError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

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
        if !self.subjects.matches(context.principal()) {
            return false;
        }
        if !self
            .vendor
            .as_ref()
            .is_none_or(|list| list.iter().any(|item| item == context.vendor()))
        {
            return false;
        }
        if !contains(self.environment.as_deref(), &context.environment()) {
            return false;
        }
        if !self
            .tool_name
            .as_ref()
            .is_none_or(|globs| any_glob(globs, context.tool_name()))
        {
            return false;
        }
        if !contains(
            self.normalized_action.as_deref(),
            &context.normalized_action(),
        ) {
            return false;
        }
        if !contains(self.request_risk.as_deref(), &context.request_risk()) {
            return false;
        }
        if !contains(self.resource_type.as_deref(), &context.resource_type()) {
            return false;
        }
        if !contains(
            self.upstream_authority.as_deref(),
            &context.upstream_identity().authority,
        ) {
            return false;
        }
        if !contains(self.method.as_deref(), &context.method()) {
            return false;
        }
        if !self
            .canonical_path
            .as_ref()
            .is_none_or(|globs| any_glob(globs, context.canonical_path()))
        {
            return false;
        }
        // The three resource keys: all-of, and each only for its own state.
        if let Some(globs) = &self.resource_id
            && !context
                .resource_scope()
                .all_ids_allowed(|id| any_glob(globs, id))
        {
            return false;
        }
        if let Some(kind) = self.resource_scope {
            let scope = context.resource_scope();
            let ok = match kind {
                ScopeKind::Collection => scope.is_collection(),
                ScopeKind::Unscoped => scope.is_unscoped(),
            };
            if !ok {
                return false;
            }
        }
        if let Some((resource_type, globs)) = &self.constrained_by
            && !context.constraint().is_some_and(|constraint| {
                constraint.resource_type() == *resource_type
                    && constraint.scope().all_ids_allowed(|id| any_glob(globs, id))
            })
        {
            return false;
        }
        true
    }
}

/// `None` matches anything; `Some(list)` matches a member.
fn contains<T: PartialEq>(list: Option<&[T]>, value: &T) -> bool {
    list.is_none_or(|list| list.contains(value))
}

#[derive(Debug)]
struct CompiledPolicy {
    version: String,
    rules: Vec<CompiledRule>,
    /// How the document was authenticated: `None` when no verifying key is
    /// configured, `Some` (always `verified: true`) when one is.
    signature: Option<SignatureStatus>,
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
        signature: None,
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

fn version_label(version: u32, bytes: &[u8]) -> String {
    let mut label = format!("v{version}+");
    push_digest_label(&mut label, bytes);
    label
}

/// `sha256:<16 hex>` of `bytes` — the bundle hash on its own, for a
/// document that was refused before its version number could be read.
fn digest_label(bytes: &[u8]) -> String {
    let mut label = String::with_capacity(23);
    push_digest_label(&mut label, bytes);
    label
}

fn push_digest_label(label: &mut String, bytes: &[u8]) {
    use std::fmt::Write as _;

    use sha2::{Digest as _, Sha256};

    let digest = Sha256::digest(bytes);
    label.push_str("sha256:");
    for byte in &digest[..8] {
        let _ = write!(label, "{byte:02x}");
    }
}

/// Read the document at `path` and, when a verifying key is configured,
/// its detached signature. Returns the bytes and the signature status.
fn read_document(
    path: &Path,
    verifier: Option<&VerifyingKey>,
) -> Result<(Vec<u8>, Option<SignatureStatus>), PolicyError> {
    let bytes = std::fs::read(path).map_err(|error| {
        PolicyError::new(format!("cannot read policy {}: {error}", path.display()))
    })?;
    let signature = verify_document(path, &bytes, verifier)?;
    Ok((bytes, signature))
}

/// Check the detached signature of `bytes` when a verifier is configured.
fn verify_document(
    path: &Path,
    bytes: &[u8],
    verifier: Option<&VerifyingKey>,
) -> Result<Option<SignatureStatus>, PolicyError> {
    let Some(verifier) = verifier else {
        return Ok(None);
    };
    let signature = super::signing::read_detached(path)
        .map_err(|error| PolicyError::new(format!("policy {}: {error}", path.display())))?;
    verifier
        .verify(Domain::PolicyBundle, bytes, &signature)
        .map_err(|error| {
            PolicyError::new(format!(
                "policy {}: {error} (key {})",
                path.display(),
                verifier.key_id()
            ))
        })?;
    Ok(Some(SignatureStatus {
        verified: true,
        key_id: Some(verifier.key_id()),
    }))
}

// ---------------------------------------------------------------------------
// The decision point
// ---------------------------------------------------------------------------

/// A policy document on disk, compiled, hot-reloadable.
pub struct FilePolicy {
    path: PathBuf,
    /// The key documents must be signed with; `None` for unsigned local
    /// dry runs.
    verifier: Option<VerifyingKey>,
    current: RwLock<Arc<CompiledPolicy>>,
    /// The bytes the current snapshot was compiled from, for the watcher.
    loaded_bytes: RwLock<Vec<u8>>,
    /// Why the last reload failed, while the last good document stays in
    /// force. Cleared by the next successful reload. Off the request path:
    /// written by the watcher, read by health.
    last_reload_error: Mutex<Option<String>>,
}

/// A document that has been read, verified, and compiled but not yet put
/// in force. Produced by [`FilePolicy::stage`], consumed by
/// [`FilePolicy::commit`]; the gap between them is where the change record
/// is made durable.
pub struct StagedPolicy {
    compiled: CompiledPolicy,
    bytes: Vec<u8>,
}

impl StagedPolicy {
    /// Version label of the staged document.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.compiled.version
    }

    /// Signature status of the staged document.
    #[must_use]
    pub fn signature(&self) -> Option<&SignatureStatus> {
        self.compiled.signature.as_ref()
    }
}

/// What [`FilePolicy::commit`] reports: the labels of the document that
/// was in force and the one that now is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyChange {
    pub previous_version: String,
    pub version: String,
    pub signature: Option<SignatureStatus>,
}

/// Where the watcher journals policy events (WP B.3).
pub struct PolicyAudit {
    pub sink: Arc<dyn AuditSink>,
    pub append_timeout: Duration,
}

impl FilePolicy {
    /// Read and compile the document at `path`, unsigned.
    ///
    /// # Errors
    ///
    /// When the file cannot be read or does not compile. A startup caller
    /// treats this as fatal: enterprise mode never runs with no policy.
    pub fn load(path: &Path) -> Result<Arc<Self>, PolicyError> {
        Self::load_with(path, None)
    }

    /// Read, verify against `verifier`, and compile the document at
    /// `path`. The detached signature must be in `<path>.sig`.
    ///
    /// # Errors
    ///
    /// When the file or its signature cannot be read, the signature does
    /// not verify, or the document does not compile.
    pub fn load_verified(path: &Path, verifier: VerifyingKey) -> Result<Arc<Self>, PolicyError> {
        Self::load_with(path, Some(verifier))
    }

    fn load_with(path: &Path, verifier: Option<VerifyingKey>) -> Result<Arc<Self>, PolicyError> {
        let (bytes, signature) = read_document(path, verifier.as_ref())?;
        let mut compiled = compile(&bytes)
            .map_err(|error| PolicyError::new(format!("policy {}: {error}", path.display())))?;
        compiled.signature = signature;
        Ok(Arc::new(Self {
            path: path.to_owned(),
            verifier,
            current: RwLock::new(Arc::new(compiled)),
            loaded_bytes: RwLock::new(bytes),
            last_reload_error: Mutex::new(None),
        }))
    }

    /// Compile a document from bytes, for `policy check` and tests. Not
    /// reloadable (there is no file to watch).
    ///
    /// # Errors
    ///
    /// When the document does not compile.
    pub fn from_bytes(bytes: &[u8]) -> Result<Arc<Self>, PolicyError> {
        let compiled = compile(bytes)?;
        Ok(Arc::new(Self {
            path: PathBuf::new(),
            verifier: None,
            current: RwLock::new(Arc::new(compiled)),
            loaded_bytes: RwLock::new(bytes.to_vec()),
            last_reload_error: Mutex::new(None),
        }))
    }

    /// How the document in force was authenticated (see
    /// [`CompiledPolicy::signature`]).
    #[must_use]
    pub fn signature(&self) -> Option<SignatureStatus> {
        self.snapshot().signature.clone()
    }

    /// Whether documents must carry a verified signature.
    #[must_use]
    pub const fn requires_signature(&self) -> bool {
        self.verifier.is_some()
    }

    /// Why the last reload failed — the file vanished, became unreadable,
    /// or does not compile — while the last good document stays in force.
    /// `None` when the document in force is the one on disk.
    #[must_use]
    pub fn degraded(&self) -> Option<String> {
        self.last_reload_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn note_reload<T>(&self, outcome: &Result<T, PolicyError>) {
        let mut last = self
            .last_reload_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *last = outcome.as_ref().err().map(ToString::to_string);
    }

    /// Record a failure that happened *after* staging — the change record
    /// could not be journaled — so health reports it like any other stale
    /// policy state.
    fn note_failure(&self, reason: &str) {
        let mut last = self
            .last_reload_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *last = Some(reason.to_owned());
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.snapshot().rules.len()
    }

    fn snapshot(&self) -> Arc<CompiledPolicy> {
        Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Re-read the file and put a changed document in force at once —
    /// [`Self::stage`] followed by [`Self::commit`], with nothing journaled
    /// in between. For tests and unaudited local dry runs; the watcher
    /// journals the change between the two steps. `Ok(false)` means the
    /// bytes on disk are the ones already in force.
    ///
    /// # Errors
    ///
    /// When the file cannot be read, its signature does not verify, or it
    /// does not compile. The current policy stays in force and the failure
    /// is reported by [`Self::degraded`].
    pub fn reload(&self) -> Result<bool, PolicyError> {
        match self.stage()? {
            Some(staged) => {
                self.commit(staged);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Read, verify, and compile the file without putting it in force.
    /// `Ok(None)` when the bytes on disk are the ones already in force.
    /// Records the outcome for [`Self::degraded`]: a failure sets it, a
    /// success (changed or not) clears it.
    ///
    /// # Errors
    ///
    /// When the file cannot be read, its signature does not verify, or it
    /// does not compile.
    pub fn stage(&self) -> Result<Option<StagedPolicy>, PolicyError> {
        let outcome = self.stage_inner();
        self.note_reload(&outcome);
        outcome
    }

    fn stage_inner(&self) -> Result<Option<StagedPolicy>, PolicyError> {
        let (bytes, signature) = read_document(&self.path, self.verifier.as_ref())?;
        let unchanged = *self
            .loaded_bytes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            == bytes;
        if unchanged {
            return Ok(None);
        }
        let mut compiled = compile(&bytes)?;
        compiled.signature = signature;
        Ok(Some(StagedPolicy { compiled, bytes }))
    }

    /// Put a staged document in force. In-flight decisions keep the
    /// snapshot they started with.
    pub fn commit(&self, staged: StagedPolicy) -> PolicyChange {
        let previous_version = {
            let mut current = self
                .current
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let previous = current.version.clone();
            *current = Arc::new(staged.compiled);
            previous
        };
        *self
            .loaded_bytes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = staged.bytes;
        let now = self.snapshot();
        PolicyChange {
            previous_version,
            version: now.version.clone(),
            signature: now.signature.clone(),
        }
    }

    /// The label a rejected document is journaled under: its own bundle
    /// hash when it could be read, so the refused bytes are identifiable.
    fn rejected_version(&self) -> Option<String> {
        std::fs::read(&self.path)
            .ok()
            .map(|bytes| digest_label(&bytes))
    }

    /// Poll the file and reload on change, on the current Tokio runtime.
    /// Holds only a `Weak`, so the task ends with the policy. A no-op with a
    /// warning outside a runtime, like the config watcher.
    ///
    /// With `audit`, the policy in force is journaled when the watcher
    /// starts (`policy_loaded`), every change is journaled **before** it is
    /// committed (`policy_changed`), and each distinct rejected reload is
    /// journaled once (`policy_rejected`). A change whose record cannot be
    /// made durable within the bound is not applied.
    pub fn spawn_watcher(self: &Arc<Self>, audit: Option<PolicyAudit>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(path = %self.path.display(), "policy watcher requires a Tokio runtime");
            return;
        };
        let weak: Weak<Self> = Arc::downgrade(self);
        runtime.spawn(async move {
            if let Some(audit) = &audit
                && let Some(policy) = weak.upgrade()
            {
                let snapshot = policy.snapshot();
                let mut event = ControlEvent::now(ControlEventKind::PolicyLoaded);
                event.source = Some(policy.path.display().to_string());
                event.version = Some(snapshot.version.clone());
                event.signature = snapshot.signature.clone();
                if let Err(error) = append_control(audit, &event).await {
                    tracing::error!(
                        failure = %crate::ports::audit_sink::AuditFailure::classify(&error),
                        "failed to journal the policy in force at startup"
                    );
                }
            }
            let mut interval = tokio::time::interval(POLICY_WATCH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let Some(policy) = weak.upgrade() else {
                    return;
                };
                let previous_error = policy.degraded();
                let path = policy.path.clone();
                // Reading, verifying, and compiling a policy is file I/O
                // plus parsing: off the worker threads.
                let staging = Arc::clone(&policy);
                let outcome = tokio::task::spawn_blocking(move || staging.stage()).await;
                match outcome {
                    Ok(Ok(None)) => {}
                    Ok(Ok(Some(staged))) => {
                        if let Some(audit) = &audit {
                            let mut event = ControlEvent::now(ControlEventKind::PolicyChanged);
                            event.source = Some(path.display().to_string());
                            event.previous_version = policy.version();
                            event.version = Some(staged.version().to_owned());
                            event.signature = staged.signature().cloned();
                            if let Err(error) = append_control(audit, &event).await {
                                // Not applied: the record is the evidence
                                // that the policy changed, and a change
                                // nobody can prove is a change that did
                                // not happen. The next tick tries again.
                                const REASON: &str = "policy change could not be journaled; \
                                    last good policy in force";
                                policy.note_failure(REASON);
                                tracing::error!(
                                    path = %path.display(),
                                    failure = %crate::ports::audit_sink::AuditFailure::classify(&error),
                                    REASON
                                );
                                continue;
                            }
                        }
                        let change = policy.commit(staged);
                        tracing::info!(
                            path = %path.display(),
                            from = %change.previous_version,
                            to = %change.version,
                            signed = change.signature.as_ref().is_some_and(|status| status.verified),
                            "reloaded policy"
                        );
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(
                            path = %path.display(),
                            %error,
                            "policy cannot be reloaded; keeping the previous policy in force"
                        );
                        let reason = error.to_string();
                        if let Some(audit) = &audit
                            && previous_error.as_deref() != Some(reason.as_str())
                        {
                            let mut event = ControlEvent::now(ControlEventKind::PolicyRejected)
                                .with_reason(&reason);
                            event.source = Some(path.display().to_string());
                            event.previous_version = policy.version();
                            event.version = policy.rejected_version();
                            if let Err(error) = append_control(audit, &event).await {
                                tracing::error!(
                                    failure = %crate::ports::audit_sink::AuditFailure::classify(&error),
                                    "failed to journal a rejected policy reload"
                                );
                            }
                        }
                    }
                    Err(error) => tracing::warn!(%error, "policy reload task failed"),
                }
            }
        });
    }
}

/// Bounded control-record append for the watcher (CF-14 semantics: the
/// bound limits the wait, and a timeout means "not proven durable").
async fn append_control(audit: &PolicyAudit, event: &ControlEvent) -> std::io::Result<u64> {
    super::egress::append_control_bounded(audit.sink.as_ref(), event, audit.append_timeout).await
}

impl PolicyDecisionPoint for FilePolicy {
    fn evaluate(&self, context: &ActionContext) -> PolicyDecision {
        let policy = self.snapshot();
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
        Some(self.snapshot().version.clone())
    }

    fn degraded(&self) -> Option<String> {
        FilePolicy::degraded(self)
    }
}

impl PolicyDecisionPoint for Arc<FilePolicy> {
    fn evaluate(&self, context: &ActionContext) -> PolicyDecision {
        FilePolicy::evaluate(self, context)
    }

    fn version(&self) -> Option<String> {
        FilePolicy::version(self)
    }

    fn degraded(&self) -> Option<String> {
        FilePolicy::degraded(self)
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

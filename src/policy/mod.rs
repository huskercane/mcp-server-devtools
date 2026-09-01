//! Enterprise core types: the canonical vocabulary every policy decision,
//! audit record, and golden test shares (§3.2 of
//! `docs/enterprise-product-plan.md`).
//!
//! These types are part of the crate's **public library surface** (ADR-001):
//! the private `mcp-devtools-enterprise` crate builds against them, so
//! changing them is a versioned-API change, not an internal refactor.
//!
//! Design rules carried over from the plan:
//!
//! - An [`ActionContext`] is constructed *before* policy evaluation and never
//!   mutated after.
//! - Client name/version ([`ClientIdentity`]) is **telemetry only** — it is
//!   never an authorization input unless bound to the token, which nothing
//!   here does.
//! - [`RequestRisk`] is **derived** (from the normalized action or HTTP
//!   method), never client-supplied.
//! - An unclassifiable resource is [`ResourceType::Unknown`] — a distinct
//!   variant, not a string — and default-deny policy treats it as denied.
//! - The inbound MCP token never appears here: [`Principal`] carries
//!   validated claims, not the raw token (guiding constraint 4).
//!
//! Serialization uses `snake_case` field and variant names throughout,
//! matching the plan's §3.2 field list and §3.2 policy-YAML examples. (The
//! legacy `AUDIT_LOG` JSONL keeps its camelCase shape untouched — that
//! surface is parity-locked; this one is new.)

pub mod extractors;

use serde::Serialize;

use crate::transport::HttpMethod;

/// The authenticated caller, as established by the inbound trust boundary.
///
/// Carries validated claims only — never the raw inbound token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Principal {
    /// Tenant identifier. Single-tenant deployments use a fixed label.
    pub tenant: String,
    /// Authenticated subject (the `IdP`'s `sub`, or a local-mode marker).
    pub subject: String,
    /// `IdP` group memberships, as validated from token claims.
    pub groups: Vec<String>,
    /// OAuth scopes granted to the token.
    pub scopes: Vec<String>,
    /// How this principal was authenticated.
    pub authority: PrincipalAuthority,
}

impl Principal {
    /// The implicit principal for local community mode (`MCP_AUTH_MODE=off`):
    /// stdio or loopback HTTP, where the bind address is the trust boundary.
    #[must_use]
    pub fn local() -> Self {
        Self {
            tenant: "local".to_owned(),
            subject: "local".to_owned(),
            groups: Vec::new(),
            scopes: Vec::new(),
            authority: PrincipalAuthority::Local,
        }
    }
}

/// How the inbound identity was established.
///
/// `#[non_exhaustive]`: Entra and EMA variants arrive in later phases;
/// downstream matches must carry a deny arm, which is the default-deny
/// posture anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PrincipalAuthority {
    /// Community trust boundary: stdio or loopback bind, no inbound token.
    Local,
    /// Okta-validated bearer token (Phase A).
    Okta,
}

/// MCP client self-identification (`clientInfo`).
///
/// **Telemetry only.** This is self-reported by the client and must never be
/// an authorization input unless bound to the token (e.g. a `client_id`
/// claim) — which this type deliberately cannot express.
///
/// Self-reported also means attacker-controlled: build it with
/// [`ClientIdentity::reported`], which bounds and sanitizes each field, so a
/// client cannot inject control characters, newlines, or megabytes of text
/// into every audit record it triggers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ClientIdentity {
    pub name: Option<String>,
    pub version: Option<String>,
}

/// Longest client-reported `name`/`version` retained. Real values are short
/// (`"claude-ai"`, `"1.2.3"`); anything longer is padding, not information.
const CLIENT_FIELD_MAX_CHARS: usize = 128;

impl ClientIdentity {
    /// Bound and sanitize a client's self-reported `clientInfo`.
    ///
    /// Control characters (newlines included — they would otherwise forge
    /// JSONL record boundaries in the journal) are dropped, the result is
    /// truncated to [`CLIENT_FIELD_MAX_CHARS`] characters, and a field left
    /// empty by that is recorded as absent rather than as `""`.
    #[must_use]
    pub fn reported(name: Option<&str>, version: Option<&str>) -> Self {
        Self {
            name: name.and_then(bounded_client_field),
            version: version.and_then(bounded_client_field),
        }
    }
}

fn bounded_client_field(value: &str) -> Option<String> {
    let cleaned: String = value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(CLIENT_FIELD_MAX_CHARS)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else if trimmed.len() == cleaned.len() {
        Some(cleaned)
    } else {
        Some(trimmed.to_owned())
    }
}

/// Deployment environment classification of a vendor account.
///
/// Always sourced from **configuration**, never from the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EnvironmentClass {
    Prod,
    Staging,
    Qa,
    Dev,
    /// No classification configured. Default-deny policy treats this
    /// conservatively — an unclassified environment matches no
    /// environment-scoped allow rule.
    Unclassified,
}

impl EnvironmentClass {
    /// Parse a configured classification. Unknown strings are `None` so the
    /// caller can fail loudly instead of silently mapping a typo (`"pord"`)
    /// to something permissive.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "prod" | "production" => Some(Self::Prod),
            "staging" => Some(Self::Staging),
            "qa" => Some(Self::Qa),
            "dev" | "development" => Some(Self::Dev),
            _ => None,
        }
    }
}

/// Whether an upstream call runs under shared or delegated authority
/// (ADR-006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamAuthority {
    /// A service credential configured on the gateway. May exceed the
    /// caller's own upstream rights; upstream audit shows the service
    /// identity, so gateway audit must carry the real subject.
    Shared,
    /// A per-user credential obtained by delegation (deferred; no delegated
    /// flow exists yet, the variant exists so audit and policy can already
    /// distinguish the two and no silent fallback between them can hide in a
    /// boolean).
    Delegated,
}

/// A credential slot's identity, as something only the secret registry can
/// mint.
///
/// This is what makes [`CredentialLabel`] safe. A constructor that took the
/// slot name as `&str` accepted *any* string, so
/// `CredentialLabel::slot("jira", token)` compiled and serialized the token
/// into every audit event — redacting `Debug` did nothing about `Serialize`.
/// A `&'static VendorSecret` can only come from the registry table in
/// [`crate::auth::secrets`], which is compile-time data; a credential
/// resolved at runtime is a `String` and cannot be one.
///
/// Sealed: only this crate implements it, so a downstream adapter cannot
/// hand-roll a "slot" out of a secret it happens to hold.
pub trait CredentialSlot: sealed::Sealed {
    /// The config key naming this slot. Static by construction.
    fn slot_key(&self) -> &'static str;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::auth::secrets::VendorSecret {}
    impl Sealed for super::TestSlot {}
}

impl CredentialSlot for crate::auth::secrets::VendorSecret {
    fn slot_key(&self) -> &'static str {
        self.secret_key
    }
}

/// A slot name for tests and for brokers that pin an identity without a
/// registry row. Still `&'static str`: a runtime-resolved secret is a
/// `String` and will not coerce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestSlot(pub &'static str);

impl CredentialSlot for TestSlot {
    fn slot_key(&self) -> &'static str {
        self.0
    }
}

/// Stable, non-secret name for the credential *slot* that acts upstream —
/// e.g. `jira/ATLASSIAN_API_TOKEN/alice@example.com`.
///
/// A newtype rather than a `String`, and one whose constructors take a
/// [`CredentialSlot`] rather than a string, so the slot half of a label can
/// only come from compile-time registry data. The principal half is
/// necessarily runtime data (an account read from config), so it is
/// sanitized and bounded rather than typed — but it is never where a secret
/// lives, and a label with a secret in the *principal* position would still
/// name the right slot.
///
/// `Debug` is redacted so a label never reaches a log line by accident.
/// `Display` and `Serialize` keep the real text: audit evidence must name
/// the slot.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CredentialLabel(String);

/// Longest label segment retained. Slot names are config key names and
/// principals are accounts; both are short by nature.
const LABEL_SEGMENT_MAX_CHARS: usize = 128;

impl CredentialLabel {
    /// `vendor/SECRET_KEY` — a slot with no account behind it.
    #[must_use]
    pub fn slot(vendor: &str, slot: &impl CredentialSlot) -> Self {
        Self(format!(
            "{}/{}",
            label_segment(vendor),
            label_segment(slot.slot_key())
        ))
    }

    /// `vendor/SECRET_KEY/principal` — a slot bound to a named account.
    #[must_use]
    pub fn principal_slot(vendor: &str, slot: &impl CredentialSlot, principal: &str) -> Self {
        Self(format!(
            "{}/{}/{}",
            label_segment(vendor),
            label_segment(slot.slot_key()),
            label_segment(principal)
        ))
    }

    /// `vendor/unconfigured` — no slot for this vendor resolves. The attempt
    /// is still evidence, so the identity stays nameable.
    #[must_use]
    pub fn unconfigured(vendor: &str) -> Self {
        Self(format!("{}/unconfigured", label_segment(vendor)))
    }

    /// `vendor/indeterminate` — a slot *will* act, but which one is decided
    /// by state this broker cannot observe before dispatch.
    ///
    /// Naming the wrong slot is worse than admitting the gap: an auditor who
    /// sees `indeterminate` knows to look further, while a confident wrong
    /// label silently misattributes the action. See
    /// [`crate::ports::credential_broker`].
    #[must_use]
    pub fn indeterminate(vendor: &str) -> Self {
        Self(format!("{}/indeterminate", label_segment(vendor)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn label_segment(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control() && *ch != '/')
        .take(LABEL_SEGMENT_MAX_CHARS)
        .collect()
}

impl std::fmt::Debug for CredentialLabel {
    /// Redacted: `Debug` is what ends up in `tracing` output and panic
    /// messages, and a label is only *contractually* non-secret. Read the
    /// text through [`CredentialLabel::as_str`] where it is meant to be seen.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CredentialLabel(<redacted>)")
    }
}

impl std::fmt::Display for CredentialLabel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The upstream identity selected by the `CredentialBroker` for a call.
///
/// Identifies *which* credential acts upstream — never the credential value
/// itself. Appears in every enterprise audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamIdentity {
    /// Stable, non-secret label for the credential slot. Rotating the secret
    /// keeps the label; changing the account moves it.
    pub label: CredentialLabel,
    /// Canonical vendor name (`VENDOR_*` constants in [`crate::config`]).
    pub vendor: String,
    /// Environment classification of the vendor account, from configuration.
    pub environment: EnvironmentClass,
    /// Shared or delegated authority.
    pub authority: UpstreamAuthority,
}

/// Classification of the resource a call addresses.
///
/// `#[non_exhaustive]`: the vocabulary grows per vendor as read-endpoint
/// inventories land (WP 0.8+). [`Self::Unknown`] is a **distinct variant**,
/// not a string: anything an extractor cannot classify lands there, and
/// default-deny policy denies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResourceType {
    Issue,
    Project,
    Channel,
    Datasource,
    Dashboard,
    /// The extractor could not classify the resource. Denied by default.
    Unknown,
}

/// Vendor-neutral name for what a call semantically does.
///
/// Purpose-built tools set this from their identity; passthrough tools map
/// `(method, path)` through a per-vendor extractor table, and anything
/// unmapped is [`Self::Passthrough`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NormalizedAction {
    ReadIssue,
    SearchIssues,
    ReadProject,
    QueryLogs,
    ListDatasources,
    ReadDatasource,
    /// No per-endpoint mapping exists. Paired with
    /// [`ResourceType::Unknown`] this is what default-deny denies.
    Passthrough,
}

/// Risk class of a call. Derived — never client-supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestRisk {
    Read,
    Write,
    Destructive,
}

impl RequestRisk {
    /// Conservative derivation from the HTTP method, for passthrough calls
    /// with no finer-grained mapping. `POST` is `Write` even when the
    /// endpoint is semantically a search — a per-endpoint extractor must
    /// downgrade it explicitly (the Jira `POST /rest/api/3/search/jql` case).
    #[must_use]
    pub const fn from_method(method: HttpMethod) -> Self {
        match method {
            HttpMethod::Get => Self::Read,
            HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch => Self::Write,
            HttpMethod::Delete => Self::Destructive,
        }
    }
}

/// What a call does, as established by a typed tool or a passthrough
/// extractor — the action-shaped half of an [`ActionContext`], before the
/// identity fields are attached.
///
/// Extractors return this; [`ActionContext::assemble`] joins it with the
/// principal, client, vendor, and upstream identity. The split keeps
/// extractors pure functions over request data, testable without any
/// identity plumbing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionDetails {
    normalized_action: NormalizedAction,
    #[serde(serialize_with = "serialize_method")]
    method: HttpMethod,
    /// Canonicalized request path (§3.5; full canonicalization lands in
    /// Phase A — until then this is the normalized tool-level path).
    canonical_path: String,
    /// Allowlisted query keys/values, sorted by key. Search expressions are
    /// retained as digests, not text — see `policy::extractors`.
    query_attributes: Vec<(String, String)>,
    resource_type: ResourceType,
    /// Which resources of that type the call addresses. See
    /// [`ResourceScope`] — the three cases are deliberately distinct.
    resource_scope: ResourceScope,
    request_risk: RequestRisk,
}

impl ActionDetails {
    /// A **read**, as claimed by an extractor that knows the endpoint.
    ///
    /// `request_risk` is not a parameter. Making `ActionContext`'s fields
    /// private only moved the problem: `ActionDetails` was still a public
    /// struct literal, so an extractor could hand `assemble` a
    /// `POST /rest/api/3/issue` carrying `RequestRisk::Read` and the
    /// "derived, never client-supplied" invariant would be gone before
    /// `ActionContext` ever saw it. Risk now comes from *which constructor
    /// was called*, and a read downgrade for a POST endpoint is a visible,
    /// greppable act ([`Self::read_downgrade`]).
    #[must_use]
    pub fn read(
        normalized_action: NormalizedAction,
        method: HttpMethod,
        canonical_path: String,
        query_attributes: Vec<(String, String)>,
        resource_type: ResourceType,
        resource_scope: ResourceScope,
    ) -> Self {
        Self {
            normalized_action,
            method,
            canonical_path,
            query_attributes,
            resource_type,
            resource_scope,
            request_risk: RequestRisk::Read,
        }
    }

    /// A read on an endpoint whose HTTP method says otherwise — the Jira
    /// `POST /rest/api/3/search/jql` case.
    ///
    /// Separate from [`Self::read`] so every downgrade is a named call site
    /// that a reviewer can enumerate, rather than a `RequestRisk::Read`
    /// literal indistinguishable from any other.
    #[must_use]
    pub fn read_downgrade(
        normalized_action: NormalizedAction,
        method: HttpMethod,
        canonical_path: String,
        query_attributes: Vec<(String, String)>,
        resource_type: ResourceType,
        resource_scope: ResourceScope,
    ) -> Self {
        Self::read(
            normalized_action,
            method,
            canonical_path,
            query_attributes,
            resource_type,
            resource_scope,
        )
    }

    /// Anything the extractor could not classify: `Passthrough`/`Unknown`/
    /// unscoped, with the risk derived conservatively from the method.
    #[must_use]
    pub fn unclassified(method: HttpMethod, canonical_path: String) -> Self {
        Self {
            normalized_action: NormalizedAction::Passthrough,
            method,
            canonical_path,
            query_attributes: Vec::new(),
            resource_type: ResourceType::Unknown,
            resource_scope: ResourceScope::unscoped(),
            request_risk: RequestRisk::from_method(method),
        }
    }

    /// Like [`Self::unclassified`], keeping attributes already extracted.
    #[must_use]
    pub fn unclassified_with_attributes(
        method: HttpMethod,
        canonical_path: String,
        query_attributes: Vec<(String, String)>,
    ) -> Self {
        Self {
            query_attributes,
            ..Self::unclassified(method, canonical_path)
        }
    }

    #[must_use]
    pub const fn normalized_action(&self) -> NormalizedAction {
        self.normalized_action
    }

    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    #[must_use]
    pub fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    #[must_use]
    pub fn query_attributes(&self) -> &[(String, String)] {
        &self.query_attributes
    }

    #[must_use]
    pub const fn resource_type(&self) -> ResourceType {
        self.resource_type
    }

    #[must_use]
    pub const fn resource_scope(&self) -> &ResourceScope {
        &self.resource_scope
    }

    #[must_use]
    pub const fn request_risk(&self) -> RequestRisk {
        self.request_risk
    }
}

/// Which resources of a [`ResourceType`] a call addresses.
///
/// Three cases that a nullable id cannot tell apart, and that authorize
/// differently:
///
/// - **unscoped** — the extractor could not *prove* what the call reaches.
///   It may reach anything the credential can see.
/// - **collection** — the endpoint addresses the type's collection (a list
///   endpoint), which is a distinct permission from reading a member.
/// - **ids** — the call is provably restricted to exactly these ids, and
///   the list is guaranteed non-empty, sorted, and deduplicated.
///
/// **Authorization over ids is all-of, never any-of.** A search constrained
/// to `(PUBLIC, SECRET)` is authorized only if *both* are allowed; matching
/// on "any id is allowed" would let one permitted project carry a response
/// full of denied ones.
///
/// This is an opaque struct, not a public enum, because both of those
/// sentences have to be *enforceable* rather than merely written down. A
/// public `Ids(Vec<String>)` variant let any caller build `Ids(vec![])`, for
/// which an "every id is allowed" check passes **vacuously** — an empty
/// scope from a buggy extractor would satisfy an id-scoped allow rule
/// without the rule's predicate ever running. It also handed a rule engine
/// the ids directly, so writing the any-of check took no effort at all.
/// Now the only way to read ids out is [`Self::all_ids_allowed`], and the
/// only way to build an id scope is [`Self::ids`], which collapses empty to
/// unscoped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ResourceScope(Scope);

/// Private representation. `Ids` is unreachable from outside this module, so
/// its non-empty invariant holds by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "ids")]
enum Scope {
    Unscoped,
    Collection,
    Ids(Vec<String>),
}

impl ResourceScope {
    /// The extractor could not prove what this call reaches.
    #[must_use]
    pub const fn unscoped() -> Self {
        Self(Scope::Unscoped)
    }

    /// The call addresses the type's collection, not any single member.
    #[must_use]
    pub const fn collection() -> Self {
        Self(Scope::Collection)
    }

    /// Exactly these ids, sorted and deduplicated.
    ///
    /// An empty or all-blank input is [`Self::unscoped`], never an empty id
    /// list: "restricted to nothing" is not a claim any caller can back, and
    /// an empty list would authorize vacuously.
    #[must_use]
    pub fn ids<I, S>(ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut ids: Vec<String> = ids
            .into_iter()
            .map(Into::into)
            .filter(|id| !id.trim().is_empty())
            .collect();
        if ids.is_empty() {
            return Self::unscoped();
        }
        ids.sort_unstable();
        ids.dedup();
        Self(Scope::Ids(ids))
    }

    /// Shorthand for a single-resource read (`GET /issue/PLAT-1`).
    #[must_use]
    pub fn id(id: impl Into<String>) -> Self {
        Self::ids([id])
    }

    #[must_use]
    pub const fn is_unscoped(&self) -> bool {
        matches!(self.0, Scope::Unscoped)
    }

    #[must_use]
    pub const fn is_collection(&self) -> bool {
        matches!(self.0, Scope::Collection)
    }

    /// How many ids this scope names; `0` for unscoped and collection.
    ///
    /// Deliberately a count and not the ids: enough for a rule engine to log
    /// or bound its work, not enough to reimplement matching. Authorization
    /// goes through [`Self::all_ids_allowed`].
    #[must_use]
    pub fn id_count(&self) -> usize {
        match &self.0 {
            Scope::Ids(ids) => ids.len(),
            _ => 0,
        }
    }

    /// Whether **every** id this call addresses satisfies `allowed`.
    ///
    /// `false` for unscoped and collection — neither is authorized by an
    /// id-scoped rule, and each needs its own explicit permission. This is
    /// the all-of check, and it is the only id-matching operation the type
    /// offers; there is deliberately no any-of counterpart and no way to
    /// build one from the outside.
    #[must_use]
    pub fn all_ids_allowed(&self, allowed: impl Fn(&str) -> bool) -> bool {
        match &self.0 {
            // Non-empty by construction, so this can never pass vacuously.
            Scope::Ids(ids) => ids.iter().all(|id| allowed(id)),
            _ => false,
        }
    }
}

/// The canonical object every policy decision and audit record is built
/// from. Constructed before evaluation; never mutated after.
///
/// **Every field is private and read-only.** "Constructed once, never
/// mutated" and "risk is derived, never client-supplied" are invariants, and
/// public fields made them documentation rather than facts: a caller could
/// downgrade `request_risk` to `Read` after assembly, or pair
/// `vendor: "jira"` with an upstream identity that says `grafana`. The
/// duplicated facts are now *derived* from the selected upstream identity
/// instead of passed alongside it, so the contradiction is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionContext {
    principal: Principal,
    /// Telemetry only — never an authorization input. See [`ClientIdentity`].
    client: ClientIdentity,
    /// Canonical vendor name. Derived from `upstream_identity.vendor`.
    vendor: String,
    /// Configured account / base-URL label for multi-account vendors.
    vendor_account: Option<String>,
    /// Environment classification, from configuration, not the request.
    /// Derived from `upstream_identity.environment`.
    environment: EnvironmentClass,
    tool_name: String,
    normalized_action: NormalizedAction,
    #[serde(serialize_with = "serialize_method")]
    method: HttpMethod,
    canonical_path: String,
    query_attributes: Vec<(String, String)>,
    resource_type: ResourceType,
    resource_scope: ResourceScope,
    /// Optional classification from configuration (e.g. `"restricted"`).
    resource_class: Option<String>,
    upstream_identity: UpstreamIdentity,
    request_risk: RequestRisk,
}

impl ActionContext {
    /// Join the identity-shaped fields with an extractor's [`ActionDetails`].
    ///
    /// `vendor` and `environment` are **not** parameters: they are read off
    /// `upstream_identity`, which is the authority for both. The action half
    /// can only arrive as an [`ActionDetails`] built by an extractor, so
    /// `request_risk` stays derived.
    #[must_use]
    pub fn assemble(
        principal: Principal,
        client: ClientIdentity,
        vendor_account: Option<String>,
        tool_name: impl Into<String>,
        details: ActionDetails,
        resource_class: Option<String>,
        upstream_identity: UpstreamIdentity,
    ) -> Self {
        Self {
            principal,
            client,
            vendor: upstream_identity.vendor.clone(),
            vendor_account,
            environment: upstream_identity.environment,
            tool_name: tool_name.into(),
            normalized_action: details.normalized_action,
            method: details.method,
            canonical_path: details.canonical_path,
            query_attributes: details.query_attributes,
            resource_type: details.resource_type,
            resource_scope: details.resource_scope,
            resource_class,
            upstream_identity,
            request_risk: details.request_risk,
        }
    }

    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    #[must_use]
    pub fn client(&self) -> &ClientIdentity {
        &self.client
    }

    #[must_use]
    pub fn vendor(&self) -> &str {
        &self.vendor
    }

    #[must_use]
    pub fn vendor_account(&self) -> Option<&str> {
        self.vendor_account.as_deref()
    }

    #[must_use]
    pub const fn environment(&self) -> EnvironmentClass {
        self.environment
    }

    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    #[must_use]
    pub const fn normalized_action(&self) -> NormalizedAction {
        self.normalized_action
    }

    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    #[must_use]
    pub fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    #[must_use]
    pub fn query_attributes(&self) -> &[(String, String)] {
        &self.query_attributes
    }

    #[must_use]
    pub const fn resource_type(&self) -> ResourceType {
        self.resource_type
    }

    #[must_use]
    pub const fn resource_scope(&self) -> &ResourceScope {
        &self.resource_scope
    }

    #[must_use]
    pub fn resource_class(&self) -> Option<&str> {
        self.resource_class.as_deref()
    }

    #[must_use]
    pub const fn upstream_identity(&self) -> &UpstreamIdentity {
        &self.upstream_identity
    }

    #[must_use]
    pub const fn request_risk(&self) -> RequestRisk {
        self.request_risk
    }
}

/// Outcome of a policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

/// A policy decision, as recorded in audit and returned to enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyDecision {
    pub effect: PolicyEffect,
    /// Id of the rule that fired; `None` for the implicit default.
    pub rule_id: Option<String>,
    /// Version/hash of the policy bundle evaluated; `None` before a policy
    /// engine exists (local mode).
    pub policy_version: Option<String>,
    /// Human-readable decision reason, carried into audit and tool errors.
    pub reason: String,
}

impl PolicyDecision {
    /// The decision local community mode operates under: everything the
    /// process can reach is allowed, exactly as before enterprise types
    /// existed — made explicit instead of implicit.
    #[must_use]
    pub fn local_allow() -> Self {
        Self {
            effect: PolicyEffect::Allow,
            rule_id: None,
            policy_version: None,
            reason: "local mode: no inbound authentication, loopback/stdio trust boundary"
                .to_owned(),
        }
    }

    /// The default-deny decision enterprise mode falls back to when no rule
    /// matches.
    #[must_use]
    pub fn default_deny(reason: impl Into<String>) -> Self {
        Self {
            effect: PolicyEffect::Deny,
            rule_id: None,
            policy_version: None,
            reason: reason.into(),
        }
    }
}

// serde's `serialize_with` contract passes the field by reference; the
// trivially-copy lint does not apply to a signature serde fixes.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn serialize_method<S: serde::Serializer>(
    method: &HttpMethod,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(method.as_str())
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    fn sample_context() -> ActionContext {
        ActionContext::assemble(
            Principal {
                tenant: "acme".to_owned(),
                subject: "user@acme.example".to_owned(),
                groups: vec!["SRE".to_owned()],
                scopes: vec!["mcp:tools".to_owned()],
                authority: PrincipalAuthority::Okta,
            },
            ClientIdentity {
                name: Some("claude".to_owned()),
                version: Some("1.0".to_owned()),
            },
            Some("grafana-main".to_owned()),
            "grafana_query_logs",
            ActionDetails {
                normalized_action: NormalizedAction::QueryLogs,
                method: HttpMethod::Get,
                canonical_path: "/api/datasources/proxy/uid/loki-prod/loki/api/v1/query_range"
                    .to_owned(),
                query_attributes: vec![("query".to_owned(), "{app=\"api\"}".to_owned())],
                resource_type: ResourceType::Datasource,
                resource_scope: ResourceScope::id("loki-prod"),
                request_risk: RequestRisk::Read,
            },
            None,
            UpstreamIdentity {
                label: CredentialLabel::slot(
                    crate::config::VENDOR_GRAFANA,
                    &TestSlot("GRAFANA_TOKEN"),
                ),
                vendor: crate::config::VENDOR_GRAFANA.to_owned(),
                environment: EnvironmentClass::Prod,
                authority: UpstreamAuthority::Shared,
            },
        )
    }

    /// Locks the serialized shape of the canonical object. Every audit
    /// record and golden decision table depends on these exact names; a
    /// rename here is a breaking API change and must fail a test, not slip
    /// through a refactor.
    #[test]
    fn action_context_serialized_shape_is_the_section_3_2_field_list() {
        let value = serde_json::to_value(sample_context()).unwrap();
        assert_eq!(
            value,
            json!({
                "principal": {
                    "tenant": "acme",
                    "subject": "user@acme.example",
                    "groups": ["SRE"],
                    "scopes": ["mcp:tools"],
                    "authority": "okta",
                },
                "client": { "name": "claude", "version": "1.0" },
                "vendor": "grafana",
                "vendor_account": "grafana-main",
                "environment": "prod",
                "tool_name": "grafana_query_logs",
                "normalized_action": "query_logs",
                "method": "GET",
                "canonical_path":
                    "/api/datasources/proxy/uid/loki-prod/loki/api/v1/query_range",
                "query_attributes": [["query", "{app=\"api\"}"]],
                "resource_type": "datasource",
                "resource_scope": { "kind": "ids", "ids": ["loki-prod"] },
                "resource_class": null,
                "upstream_identity": {
                    "label": "grafana/GRAFANA_TOKEN",
                    "vendor": "grafana",
                    "environment": "prod",
                    "authority": "shared",
                },
                "request_risk": "read",
            })
        );
    }

    #[test]
    fn request_risk_derivation_is_conservative_for_post() {
        assert_eq!(RequestRisk::from_method(HttpMethod::Get), RequestRisk::Read);
        // POST is Write even for search-shaped endpoints; only a
        // per-endpoint extractor may downgrade it.
        assert_eq!(
            RequestRisk::from_method(HttpMethod::Post),
            RequestRisk::Write
        );
        assert_eq!(
            RequestRisk::from_method(HttpMethod::Put),
            RequestRisk::Write
        );
        assert_eq!(
            RequestRisk::from_method(HttpMethod::Patch),
            RequestRisk::Write
        );
        assert_eq!(
            RequestRisk::from_method(HttpMethod::Delete),
            RequestRisk::Destructive
        );
    }

    #[test]
    fn environment_parse_rejects_unknown_values_instead_of_guessing() {
        assert_eq!(
            EnvironmentClass::parse("prod"),
            Some(EnvironmentClass::Prod)
        );
        assert_eq!(
            EnvironmentClass::parse(" Production "),
            Some(EnvironmentClass::Prod)
        );
        assert_eq!(EnvironmentClass::parse("qa"), Some(EnvironmentClass::Qa));
        assert_eq!(EnvironmentClass::parse("pord"), None);
        assert_eq!(EnvironmentClass::parse(""), None);
    }

    #[test]
    fn local_mode_decision_is_an_explicit_allow_with_a_reason() {
        let decision = PolicyDecision::local_allow();
        assert_eq!(decision.effect, PolicyEffect::Allow);
        assert!(decision.rule_id.is_none());
        assert!(decision.policy_version.is_none());
        assert!(decision.reason.contains("local mode"));
    }

    #[test]
    fn context_vendor_and_environment_cannot_contradict_the_upstream_identity() {
        // `assemble` no longer accepts them; they can only come from the
        // identity that was actually selected.
        let context = sample_context();
        assert_eq!(context.vendor(), context.upstream_identity().vendor);
        assert_eq!(
            context.environment(),
            context.upstream_identity().environment
        );
    }

    #[test]
    fn multi_resource_scope_authorizes_all_of_never_any_of() {
        let scope = ResourceScope::ids(["SECRET", "PUBLIC", "PUBLIC"]);
        assert_eq!(
            scope,
            ResourceScope::ids(["PUBLIC", "SECRET"]),
            "sorted and deduplicated"
        );
        assert_eq!(scope.id_count(), 2);

        // The whole point: one allowed member must not authorize the call.
        assert!(
            !scope.all_ids_allowed(|id| id == "PUBLIC"),
            "a search spanning PUBLIC and SECRET must not be authorized by \
             a rule that only allows PUBLIC"
        );
        assert!(scope.all_ids_allowed(|id| id == "PUBLIC" || id == "SECRET"));
    }

    #[test]
    fn unscoped_and_collection_are_distinct_and_neither_matches_an_id_rule() {
        assert_ne!(ResourceScope::unscoped(), ResourceScope::collection());
        assert_eq!(ResourceScope::unscoped().id_count(), 0);
        assert_eq!(ResourceScope::collection().id_count(), 0);
        assert!(ResourceScope::unscoped().is_unscoped());
        assert!(ResourceScope::collection().is_collection());
        // Both need their own explicit permission; an "allow everything by
        // id" predicate must not authorize either.
        assert!(!ResourceScope::unscoped().all_ids_allowed(|_| true));
        assert!(!ResourceScope::collection().all_ids_allowed(|_| true));
        // An empty id list is "no proof", not "restricted to nothing".
        assert_eq!(
            ResourceScope::ids(Vec::<String>::new()),
            ResourceScope::unscoped()
        );
        assert_eq!(ResourceScope::id("  "), ResourceScope::unscoped());

        // The invariant the opaque type exists for: an id scope can never be
        // empty, so `all_ids_allowed` can never pass vacuously. There is no
        // constructor that produces one, and the variant is unreachable.
        let from_blanks = ResourceScope::ids(["", "   "]);
        assert!(from_blanks.is_unscoped());
        assert!(
            !from_blanks.all_ids_allowed(|_| false),
            "an empty id list must not authorize by having nothing to check"
        );
    }

    #[test]
    fn credential_label_debug_is_redacted_while_audit_keeps_the_text() {
        let label = CredentialLabel::principal_slot(
            "jira",
            &TestSlot("ATLASSIAN_API_TOKEN"),
            "a@b.example",
        );
        assert_eq!(label.as_str(), "jira/ATLASSIAN_API_TOKEN/a@b.example");
        assert_eq!(
            serde_json::to_value(&label).unwrap(),
            json!("jira/ATLASSIAN_API_TOKEN/a@b.example"),
            "audit evidence must still name the slot"
        );
        assert_eq!(format!("{label:?}"), "CredentialLabel(<redacted>)");
        // A whole `UpstreamIdentity` inherits the redaction through derive.
        let identity = UpstreamIdentity {
            label,
            vendor: "jira".to_owned(),
            environment: EnvironmentClass::Unclassified,
            authority: UpstreamAuthority::Shared,
        };
        assert!(!format!("{identity:?}").contains("a@b.example"));
    }

    #[test]
    fn label_segments_cannot_smuggle_separators_or_control_characters() {
        let label = CredentialLabel::principal_slot("jira", &TestSlot("TOKEN"), "a\nb/c\td");
        assert_eq!(label.as_str(), "jira/TOKEN/abcd");
        assert_eq!(
            CredentialLabel::principal_slot("jira", &TestSlot("TOKEN"), &"x".repeat(500))
                .as_str()
                .len(),
            "jira/TOKEN/".len() + LABEL_SEGMENT_MAX_CHARS
        );
    }

    #[test]
    fn client_identity_is_bounded_and_stripped_of_control_characters() {
        let hostile = ClientIdentity::reported(
            Some("evil\n{\"seq\":99,\"kind\":\"forged\"}"),
            Some(&"9".repeat(4096)),
        );
        let name = hostile.name.unwrap();
        assert!(!name.contains('\n'), "no forged JSONL record boundaries");
        assert_eq!(hostile.version.unwrap().len(), CLIENT_FIELD_MAX_CHARS);
        assert_eq!(ClientIdentity::reported(Some("   "), None).name, None);
        assert_eq!(
            ClientIdentity::reported(None, None),
            ClientIdentity::default()
        );
    }
}

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
/// Self-reported also means attacker-controlled, and every field here is
/// copied into a durable audit record the operator cannot edit. Stripping
/// control characters and truncating was not enough — bounding a string is
/// not redacting it: a client reporting its name as `Bearer sk-live-…` had
/// that persisted, merely shorter. Fields are private and built by
/// [`ClientIdentity::reported`], which keeps a value only if it looks like
/// the identifier it claims to be and otherwise substitutes a digest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ClientIdentity {
    name: Option<String>,
    version: Option<String>,
}

/// Longest client-reported value retained. Real values are short
/// (`"claude-ai"`, `"1.2.3"`); anything longer is not a name.
const CLIENT_FIELD_MAX_CHARS: usize = 64;

impl ClientIdentity {
    /// Sanitize a client's self-reported `clientInfo`.
    #[must_use]
    pub fn reported(name: Option<&str>, version: Option<&str>) -> Self {
        Self {
            name: name.and_then(safe_identifier),
            version: version.and_then(safe_identifier),
        }
    }

    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

/// Sanitize the JSON-RPC request id that correlates an intent record with
/// its outcome.
///
/// The id is chosen by the caller and may be any JSON string, so it reached
/// durable evidence verbatim: a client sending `"id": "Bearer sk-live-…"`
/// had that persisted in every record for the call. A plain identifier is
/// kept so an operator can still line the record up against a client log;
/// anything else becomes a digest, which correlates exactly as well, because
/// the intent and the outcome digest the same input.
#[must_use]
pub fn correlation_id(raw: &str) -> String {
    safe_identifier(raw).unwrap_or_else(|| "unset".to_owned())
}

/// Keep `value` when it is a plain identifier; digest it otherwise.
///
/// The accepted shape is deliberately narrow — letters, digits, and
/// `._-:@/+`, no spaces — which covers every real client name, semantic
/// version, and JSON-RPC id while excluding the shapes a credential takes
/// (`Bearer <token>` and `Basic <blob>` both need the space). A rejected
/// value still leaves a stable handle, so the record shows that *something*
/// was reported and two calls reporting the same thing still match.
fn safe_identifier(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let plausible = trimmed.chars().count() <= CLIENT_FIELD_MAX_CHARS
        && trimmed.chars().all(|ch| {
            ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ':' | '@' | '/' | '+')
        });
    if plausible {
        Some(trimmed.to_owned())
    } else {
        Some(extractors::opaque_handle(trimmed))
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
    /// The vendor this slot belongs to. Taken from the slot rather than
    /// passed alongside it, so a label cannot name one vendor's slot under
    /// another vendor's heading.
    fn slot_vendor(&self) -> &str;
    /// The config key naming this slot. Static by construction.
    fn slot_key(&self) -> &'static str;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::auth::secrets::VendorSecret {}
    #[cfg(any(test, feature = "test-support"))]
    impl Sealed for super::TestSlot {}
}

impl CredentialSlot for crate::auth::secrets::VendorSecret {
    fn slot_vendor(&self) -> &str {
        self.vendor()
    }

    fn slot_key(&self) -> &'static str {
        self.secret_key()
    }
}

/// A slot for tests and for brokers that pin an identity without a registry
/// row.
///
/// Behind `cfg(test)` / the non-default `test-support` feature, because it is
/// the one way to build a `CredentialSlot` that the secret registry did not
/// issue. In a production build it does not exist, so
/// `CredentialLabel::slot(&TestSlot(Box::leak(token.into_boxed_str())))` —
/// which otherwise defeats the whole sealed-trait argument — will not
/// compile.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestSlot {
    pub vendor: &'static str,
    pub key: &'static str,
}

#[cfg(any(test, feature = "test-support"))]
impl TestSlot {
    #[must_use]
    pub const fn new(vendor: &'static str, key: &'static str) -> Self {
        Self { vendor, key }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl CredentialSlot for TestSlot {
    fn slot_vendor(&self) -> &str {
        self.vendor
    }

    fn slot_key(&self) -> &'static str {
        self.key
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
    ///
    /// The vendor comes from the slot, not from a separate argument: passing
    /// both allowed a label that named one vendor's slot under another
    /// vendor's heading.
    #[must_use]
    pub fn slot(slot: &impl CredentialSlot) -> Self {
        Self(format!(
            "{}/{}",
            label_segment(slot.slot_vendor()),
            label_segment(slot.slot_key())
        ))
    }

    /// `vendor/SECRET_KEY/principal` — a slot bound to a named account.
    #[must_use]
    pub fn principal_slot(slot: &impl CredentialSlot, principal: &str) -> Self {
        Self(format!(
            "{}/{}/{}",
            label_segment(slot.slot_vendor()),
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
    /// A **`GET`** read.
    ///
    /// Neither the method nor the risk is a parameter: this constructor can
    /// only produce a `GET` read. `ActionDetails` was a public struct literal
    /// once, so an extractor could hand `assemble` a `POST /rest/api/3/issue`
    /// carrying `RequestRisk::Read` and the "derived, never client-supplied"
    /// invariant was gone before `ActionContext` saw it. A non-`GET` read now
    /// has to name an approved endpoint ([`Self::read_downgrade`]).
    #[must_use]
    pub fn read(
        normalized_action: NormalizedAction,
        canonical_path: String,
        query_attributes: Vec<(String, String)>,
        resource_type: ResourceType,
        resource_scope: ResourceScope,
    ) -> Self {
        Self {
            normalized_action,
            method: HttpMethod::Get,
            canonical_path,
            query_attributes,
            resource_type,
            resource_scope,
            request_risk: RequestRisk::Read,
        }
    }

    /// A read on an endpoint whose HTTP method says otherwise.
    ///
    /// The method comes from the [`ApprovedReadDowngrade`] value, whose
    /// construction is private — so the constants on that type *are* the
    /// approved set, and adding to it is a diff a reviewer will see. Taking
    /// an arbitrary `HttpMethod` here (and in [`Self::read`]) left the
    /// downgrade wide open: `read(…, HttpMethod::Post, …)` compiled and
    /// produced exactly what this named site exists to make visible, so the
    /// "one greppable downgrade" property was a convention, not a rule.
    #[must_use]
    pub fn read_downgrade(
        downgrade: ApprovedReadDowngrade,
        normalized_action: NormalizedAction,
        canonical_path: String,
        query_attributes: Vec<(String, String)>,
        resource_type: ResourceType,
        resource_scope: ResourceScope,
    ) -> Self {
        Self {
            normalized_action,
            method: downgrade.method,
            canonical_path,
            query_attributes,
            resource_type,
            resource_scope,
            request_risk: RequestRisk::Read,
        }
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

/// An endpoint whose HTTP method is not `GET` but whose contract is
/// read-only, approved as such by review.
///
/// Construction is private, so this list *is* the approved set: there is no
/// way to mint a downgrade for an endpoint that is not named here. Each entry
/// is a security-relevant line item for the two-person review
/// (`docs/read-endpoint-inventory.md`, decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovedReadDowngrade {
    method: HttpMethod,
    endpoint: &'static str,
}

impl ApprovedReadDowngrade {
    /// Jira issue search. A `POST` because the JQL travels in the body; it
    /// creates nothing. Approved after the fictitious `project` body field
    /// was removed and the JQL gate was made sound.
    pub const JIRA_SEARCH_JQL: Self = Self {
        method: HttpMethod::Post,
        endpoint: "POST /rest/api/3/search/jql",
    };

    /// The endpoint this downgrade covers, for diagnostics and review.
    #[must_use]
    pub const fn endpoint(self) -> &'static str {
        self.endpoint
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
                label: CredentialLabel::slot(&TestSlot::new(
                    crate::config::VENDOR_GRAFANA,
                    "GRAFANA_TOKEN",
                )),
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
            &TestSlot::new("jira", "ATLASSIAN_API_TOKEN"),
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

    /// The sealed trait is only an argument if a slot cannot be minted. Two
    /// escape hatches used to remain: `TestSlot` accepted any `&'static str`
    /// in a production build (and `Box::leak` turns any token into one), and
    /// `VendorSecret`'s public fields let downstream code build a row that
    /// already implemented the trait.
    #[test]
    fn a_credential_slot_can_only_come_from_the_registry() {
        // Every registry row is a slot, and its vendor comes with it.
        let row = crate::auth::secrets::for_vendor(crate::config::VENDOR_SLACK)
            .next()
            .expect("slack has a registry row");
        assert_eq!(CredentialLabel::slot(row).as_str(), "slack/SLACK_TOKEN");
        assert_eq!(row.slot_vendor(), "slack");

        // `TestSlot` exists only under cfg(test)/`test-support`; a release
        // build of a downstream crate cannot name it at all. `VendorSecret`
        // fields are `pub(crate)`, so a downstream crate cannot build a row
        // either — both are compile-time properties, asserted by the fact
        // that this test is the only place either appears.
        let pinned = TestSlot::new("grafana", "GRAFANA_TOKEN");
        assert_eq!(
            CredentialLabel::slot(&pinned).as_str(),
            "grafana/GRAFANA_TOKEN"
        );
    }

    #[test]
    fn label_segments_cannot_smuggle_separators_or_control_characters() {
        let label = CredentialLabel::principal_slot(&TestSlot::new("jira", "TOKEN"), "a\nb/c\td");
        assert_eq!(label.as_str(), "jira/TOKEN/abcd");
        assert_eq!(
            CredentialLabel::principal_slot(&TestSlot::new("jira", "TOKEN"), &"x".repeat(500))
                .as_str()
                .len(),
            "jira/TOKEN/".len() + LABEL_SEGMENT_MAX_CHARS
        );
    }

    /// Bounding is not redaction. A client-reported value is kept only if it
    /// looks like the identifier it claims to be; anything else leaves a
    /// handle, not the text.
    #[test]
    fn client_reported_values_are_kept_only_when_they_look_like_identifiers() {
        let ordinary = ClientIdentity::reported(Some("claude-ai"), Some("1.2.3"));
        assert_eq!(ordinary.name(), Some("claude-ai"));
        assert_eq!(ordinary.version(), Some("1.2.3"));

        let hostile = ClientIdentity::reported(
            Some("Bearer sk-live-abcdef0123456789"),
            Some("evil\n{\"seq\":99,\"kind\":\"forged\"}"),
        );
        let serialized = serde_json::to_string(&hostile).unwrap();
        assert!(
            !serialized.contains("sk-live-abcdef0123456789"),
            "a token reported as a client name must not persist: {serialized}"
        );
        assert!(!serialized.contains("forged"), "{serialized}");
        assert!(hostile.name().unwrap().starts_with("sha256:"));
        assert!(hostile.version().unwrap().starts_with("sha256:"));

        // Over-long is a handle too, not a truncation.
        let long = ClientIdentity::reported(Some(&"9".repeat(4096)), None);
        assert!(long.name().unwrap().starts_with("sha256:"));

        assert_eq!(ClientIdentity::reported(Some("   "), None).name(), None);
        assert_eq!(
            ClientIdentity::reported(None, None),
            ClientIdentity::default()
        );
    }

    /// A JSON-RPC id is caller-chosen and lands in durable evidence.
    #[test]
    fn correlation_ids_are_sanitized_but_still_correlate() {
        assert_eq!(correlation_id("42"), "42");
        assert_eq!(correlation_id("req-2026-09-01-0001"), "req-2026-09-01-0001");
        assert_eq!(correlation_id(""), "unset");

        let hostile = correlation_id("Bearer sk-live-abcdef0123456789");
        assert!(hostile.starts_with("sha256:"), "{hostile}");
        assert!(!hostile.contains("sk-live"));
        // Intent and outcome digest the same input, so the pair still lines
        // up in the journal.
        assert_eq!(hostile, correlation_id("Bearer sk-live-abcdef0123456789"));
        assert_ne!(hostile, correlation_id("Bearer sk-live-somethingelse00"));
    }

    /// `read` cannot express a non-GET read at all, and a downgrade can only
    /// name an endpoint from the approved list.
    #[test]
    fn read_downgrades_are_limited_to_approved_endpoints() {
        let get = ActionDetails::read(
            NormalizedAction::ReadIssue,
            "/rest/api/3/issue/PLAT-1".to_owned(),
            Vec::new(),
            ResourceType::Issue,
            ResourceScope::id("PLAT-1"),
        );
        assert_eq!(get.method(), HttpMethod::Get);
        assert_eq!(get.request_risk(), RequestRisk::Read);

        let downgraded = ActionDetails::read_downgrade(
            ApprovedReadDowngrade::JIRA_SEARCH_JQL,
            NormalizedAction::SearchIssues,
            "/rest/api/3/search/jql".to_owned(),
            Vec::new(),
            ResourceType::Issue,
            ResourceScope::unscoped(),
        );
        assert_eq!(downgraded.method(), HttpMethod::Post);
        assert_eq!(downgraded.request_risk(), RequestRisk::Read);
        assert_eq!(
            ApprovedReadDowngrade::JIRA_SEARCH_JQL.endpoint(),
            "POST /rest/api/3/search/jql"
        );

        // An unclassified call keeps the conservative method-derived risk.
        assert_eq!(
            ActionDetails::unclassified(HttpMethod::Post, "/rest/api/3/issue".to_owned())
                .request_risk(),
            RequestRisk::Write
        );
    }
}

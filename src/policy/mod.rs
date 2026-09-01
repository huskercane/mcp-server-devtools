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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ClientIdentity {
    pub name: Option<String>,
    pub version: Option<String>,
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

/// The upstream identity selected by the `CredentialBroker` for a call.
///
/// Identifies *which* credential acts upstream — never the credential value
/// itself. Appears in every enterprise audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamIdentity {
    /// Stable, non-secret label for the credential slot, e.g.
    /// `jira/ATLASSIAN_API_TOKEN/alice@example.com`. Rotating the secret
    /// keeps the label; changing the account moves it.
    pub label: String,
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
    pub normalized_action: NormalizedAction,
    #[serde(serialize_with = "serialize_method")]
    pub method: HttpMethod,
    /// Canonicalized request path (§3.5; full canonicalization lands in
    /// Phase A — until then this is the normalized tool-level path).
    pub canonical_path: String,
    /// Allowlisted, decoded query keys/values, sorted by key.
    pub query_attributes: Vec<(String, String)>,
    pub resource_type: ResourceType,
    /// Exact id or pattern extracted from path/args/allowlisted body fields.
    /// `None` when the endpoint addresses no single resource (e.g. a list),
    /// while an *unclassifiable* resource is `resource_type: Unknown`, not
    /// `None` here.
    pub resource_id: Option<String>,
    pub request_risk: RequestRisk,
}

/// The canonical object every policy decision and audit record is built
/// from. Constructed before evaluation; never mutated after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionContext {
    pub principal: Principal,
    /// Telemetry only — never an authorization input. See [`ClientIdentity`].
    pub client: ClientIdentity,
    /// Canonical vendor name.
    pub vendor: String,
    /// Configured account / base-URL label for multi-account vendors.
    pub vendor_account: Option<String>,
    /// Environment classification, from configuration, not the request.
    pub environment: EnvironmentClass,
    pub tool_name: String,
    pub normalized_action: NormalizedAction,
    #[serde(serialize_with = "serialize_method")]
    pub method: HttpMethod,
    pub canonical_path: String,
    pub query_attributes: Vec<(String, String)>,
    pub resource_type: ResourceType,
    pub resource_id: Option<String>,
    /// Optional classification from configuration (e.g. `"restricted"`).
    pub resource_class: Option<String>,
    pub upstream_identity: UpstreamIdentity,
    pub request_risk: RequestRisk,
}

impl ActionContext {
    /// Join the identity-shaped fields with an extractor's [`ActionDetails`].
    #[must_use]
    #[allow(clippy::too_many_arguments)] // The §3.2 field list *is* this wide; a builder would restate it.
    pub fn assemble(
        principal: Principal,
        client: ClientIdentity,
        vendor: impl Into<String>,
        vendor_account: Option<String>,
        environment: EnvironmentClass,
        tool_name: impl Into<String>,
        details: ActionDetails,
        resource_class: Option<String>,
        upstream_identity: UpstreamIdentity,
    ) -> Self {
        Self {
            principal,
            client,
            vendor: vendor.into(),
            vendor_account,
            environment,
            tool_name: tool_name.into(),
            normalized_action: details.normalized_action,
            method: details.method,
            canonical_path: details.canonical_path,
            query_attributes: details.query_attributes,
            resource_type: details.resource_type,
            resource_id: details.resource_id,
            resource_class,
            upstream_identity,
            request_risk: details.request_risk,
        }
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
            crate::config::VENDOR_GRAFANA,
            Some("grafana-main".to_owned()),
            EnvironmentClass::Prod,
            "grafana_query_logs",
            ActionDetails {
                normalized_action: NormalizedAction::QueryLogs,
                method: HttpMethod::Get,
                canonical_path: "/api/datasources/proxy/uid/loki-prod/loki/api/v1/query_range"
                    .to_owned(),
                query_attributes: vec![("query".to_owned(), "{app=\"api\"}".to_owned())],
                resource_type: ResourceType::Datasource,
                resource_id: Some("loki-prod".to_owned()),
                request_risk: RequestRisk::Read,
            },
            None,
            UpstreamIdentity {
                label: "grafana/GRAFANA_TOKEN".to_owned(),
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
                "resource_id": "loki-prod",
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
}

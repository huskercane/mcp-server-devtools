//! `CredentialBroker` port: who acts upstream, as an identity — never a
//! secret (WP 0.6).
//!
//! ## The boundary
//!
//! Credential *values* are resolved where they always were
//! ([`crate::auth::Credentials`] over the [`crate::auth::secrets`] registry).
//! This port answers a different question the enterprise control plane and
//! every audit event need answered: **which** credential slot would act for a
//! vendor, as a stable, non-secret [`UpstreamIdentity`] label with vendor,
//! environment classification, and `Shared`/`Delegated` authority.
//!
//! Splitting identification from resolution keeps the secret material out of
//! the audit path entirely: nothing implementing this trait ever touches a
//! token, so no future refactor can accidentally log one from here.
//!
//! ## Why this is a port
//!
//! Two real implementations exist from day one (the bar `ports::mod`
//! documents): [`ConfigCredentialBroker`] wraps the existing registry-driven
//! resolution order, and [`StaticCredentialBroker`] lets tests pin an
//! identity without constructing vendor config. Later phases add secret
//! providers (Vault, AWS SM) and delegated OAuth behind the same trait.
//!
//! Dispatch is `dyn`-friendly on purpose, unlike [`super::command_runner`]:
//! the broker is consulted once per tool call on a path that already does
//! file I/O (the audit journal), so vtable dispatch is noise, and a generic
//! parameter would ripple through `DevtoolsServer` and every
//! `#[tool_router]` block. That tradeoff is documented here per the
//! architecture conventions.

use std::collections::HashMap;

use crate::auth::secrets;
use crate::config::Config;
use crate::policy::{EnvironmentClass, UpstreamAuthority, UpstreamIdentity};

/// Config key holding the environment classification of a vendor account
/// (`prod` / `staging` / `qa` / `dev`). Vendor-scoped: a `jira` section may
/// classify Jira as `prod` while `grafana` says `qa`; the shared overlay
/// classifies the whole deployment. Absent or unrecognised values are
/// [`EnvironmentClass::Unclassified`], which environment-scoped allow rules
/// never match — the conservative direction.
pub const ENVIRONMENT_KEY: &str = "MCP_VENDOR_ENVIRONMENT";

/// Identifies the upstream identity that acts for a vendor.
///
/// Implementations must be pure over their inputs and must never return or
/// log secret material — the returned label appears in every audit event.
pub trait CredentialBroker: Send + Sync {
    /// The identity that would act upstream for `vendor` under `config`.
    ///
    /// Total by design: even an unconfigured vendor gets a stable
    /// `"{vendor}/unconfigured"` label, so an audit record can always name
    /// the upstream identity (the subsequent dispatch fails with the usual
    /// auth-missing error; the audit trail still shows what was attempted).
    fn upstream_identity(&self, config: &Config, vendor: &str) -> UpstreamIdentity;
}

/// Production broker: wraps the existing resolution registry
/// ([`crate::auth::secrets::VENDOR_SECRETS`]).
///
/// The label is derived from the first registry row for the vendor whose
/// secret key is configured — the same declaration order resolution uses —
/// as `vendor/SECRET_KEY` or `vendor/SECRET_KEY/principal` when the row has
/// a configured account. Rotating the secret value keeps the label; moving
/// to a different account or slot changes it. Authority is always
/// [`UpstreamAuthority::Shared`] until delegated OAuth exists (ADR-006):
/// every credential the gateway holds today is a service credential acting
/// on behalf of whoever calls the tool.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConfigCredentialBroker;

impl CredentialBroker for ConfigCredentialBroker {
    fn upstream_identity(&self, config: &Config, vendor: &str) -> UpstreamIdentity {
        let environment = config
            .get_for(vendor, ENVIRONMENT_KEY)
            .and_then(EnvironmentClass::parse)
            .unwrap_or(EnvironmentClass::Unclassified);

        let label = secrets::for_vendor(vendor)
            .find(|row| {
                config
                    .get_for(vendor, row.secret_key)
                    .is_some_and(|value| !value.trim().is_empty())
            })
            .map_or_else(
                || format!("{vendor}/unconfigured"),
                |row| {
                    let principal = row
                        .principal_key
                        .and_then(|key| config.get_for(vendor, key))
                        .filter(|value| !value.trim().is_empty());
                    match principal {
                        Some(principal) => {
                            format!("{vendor}/{}/{principal}", row.secret_key)
                        }
                        None => format!("{vendor}/{}", row.secret_key),
                    }
                },
            );

        UpstreamIdentity {
            label,
            vendor: vendor.to_owned(),
            environment,
            authority: UpstreamAuthority::Shared,
        }
    }
}

/// In-memory broker for tests: pins the identity per vendor, no config
/// required. The second real implementation that justifies the port.
#[derive(Debug, Clone, Default)]
pub struct StaticCredentialBroker {
    identities: HashMap<String, UpstreamIdentity>,
}

impl StaticCredentialBroker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin the identity returned for `vendor`.
    #[must_use]
    pub fn with(mut self, vendor: &str, identity: UpstreamIdentity) -> Self {
        self.identities.insert(vendor.to_owned(), identity);
        self
    }
}

impl CredentialBroker for StaticCredentialBroker {
    fn upstream_identity(&self, _config: &Config, vendor: &str) -> UpstreamIdentity {
        self.identities
            .get(vendor)
            .cloned()
            .unwrap_or_else(|| UpstreamIdentity {
                label: format!("{vendor}/unconfigured"),
                vendor: vendor.to_owned(),
                environment: EnvironmentClass::Unclassified,
                authority: UpstreamAuthority::Shared,
            })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use pretty_assertions::assert_eq;

    use super::*;
    use crate::config::{VENDOR_GRAFANA, VENDOR_JIRA, VENDOR_SLACK};

    fn config(pairs: &[(&str, &str)]) -> Config {
        Config::from_map(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<HashMap<_, _>>(),
        )
    }

    #[test]
    fn label_names_the_configured_slot_and_principal() {
        let config = config(&[
            ("ATLASSIAN_API_TOKEN", "secret-token"),
            ("ATLASSIAN_USER_EMAIL", "alice@example.com"),
        ]);
        let identity = ConfigCredentialBroker.upstream_identity(&config, VENDOR_JIRA);
        assert_eq!(identity.label, "jira/ATLASSIAN_API_TOKEN/alice@example.com");
        assert_eq!(identity.vendor, "jira");
        assert_eq!(identity.authority, UpstreamAuthority::Shared);
    }

    #[test]
    fn label_is_stable_across_secret_rotation() {
        let before = config(&[
            ("SLACK_TOKEN", "xoxb-old"),
            ("MCP_VENDOR_ENVIRONMENT", "prod"),
        ]);
        let after = config(&[
            ("SLACK_TOKEN", "xoxb-new"),
            ("MCP_VENDOR_ENVIRONMENT", "prod"),
        ]);
        assert_eq!(
            ConfigCredentialBroker.upstream_identity(&before, VENDOR_SLACK),
            ConfigCredentialBroker.upstream_identity(&after, VENDOR_SLACK),
        );
    }

    #[test]
    fn label_never_contains_the_secret_value() {
        let secret = "xoxb-super-secret-value";
        let config = config(&[("SLACK_TOKEN", secret)]);
        let identity = ConfigCredentialBroker.upstream_identity(&config, VENDOR_SLACK);
        assert_eq!(identity.label, "slack/SLACK_TOKEN");
        assert!(!identity.label.contains(secret));
        assert!(!serde_json::to_string(&identity).unwrap().contains(secret));
    }

    #[test]
    fn environment_classification_comes_from_config_and_defaults_closed() {
        let classified = config(&[("GRAFANA_TOKEN", "tok"), ("MCP_VENDOR_ENVIRONMENT", "qa")]);
        assert_eq!(
            ConfigCredentialBroker
                .upstream_identity(&classified, VENDOR_GRAFANA)
                .environment,
            EnvironmentClass::Qa
        );

        let unset = config(&[("GRAFANA_TOKEN", "tok")]);
        assert_eq!(
            ConfigCredentialBroker
                .upstream_identity(&unset, VENDOR_GRAFANA)
                .environment,
            EnvironmentClass::Unclassified
        );

        // A typo classifies as Unclassified (matches no allow rule) rather
        // than guessing.
        let typo = config(&[("GRAFANA_TOKEN", "tok"), ("MCP_VENDOR_ENVIRONMENT", "pord")]);
        assert_eq!(
            ConfigCredentialBroker
                .upstream_identity(&typo, VENDOR_GRAFANA)
                .environment,
            EnvironmentClass::Unclassified
        );
    }

    #[test]
    fn unconfigured_vendor_still_gets_a_stable_label() {
        let empty = Config::from_map(HashMap::new());
        let identity = ConfigCredentialBroker.upstream_identity(&empty, VENDOR_JIRA);
        assert_eq!(identity.label, "jira/unconfigured");
    }

    #[test]
    fn static_broker_pins_identities_for_tests() {
        let pinned = UpstreamIdentity {
            label: "grafana/TEST_SLOT".to_owned(),
            vendor: "grafana".to_owned(),
            environment: EnvironmentClass::Prod,
            authority: UpstreamAuthority::Shared,
        };
        let broker = StaticCredentialBroker::new().with(VENDOR_GRAFANA, pinned.clone());
        let empty = Config::from_map(HashMap::new());
        assert_eq!(broker.upstream_identity(&empty, VENDOR_GRAFANA), pinned);
        assert_eq!(
            broker.upstream_identity(&empty, VENDOR_JIRA).label,
            "jira/unconfigured"
        );
    }
}

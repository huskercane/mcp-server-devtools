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
//! the audit path entirely: nothing implementing this trait ever receives a
//! token, so no future refactor can accidentally log one from here.
//!
//! ## Predicting the same slot the resolver will pick
//!
//! Write-before-dispatch means the identity is recorded *before* the
//! credential is resolved, so the broker predicts rather than observes. A
//! prediction that uses different rules than the resolver is worse than no
//! prediction: it signs the audit trail with the wrong account.
//!
//! [`ConfigCredentialBroker`] therefore walks the registry with the same
//! rules [`crate::auth::Credentials`] uses, **including the implicit
//! keychain fallback** — an earlier revision only looked for a value in
//! config, so a vendor whose token lived solely in the OS keychain
//! dispatched happily while every audit record said `vendor/unconfigured`.
//! Presence is probed through [`crate::auth::keychain::KeychainBackend::contains`],
//! which answers a yes/no question and never hands the secret to this
//! module. The probe only runs when config is silent about every slot, and
//! it runs on the blocking pool — the OS keychain backends are synchronous
//! and can block on a D-Bus round trip or an ACL prompt.
//!
//! What remains is a narrow time-of-check gap: config or the keychain could
//! change between the prediction and the resolution microseconds later. That
//! is a rotation-during-a-call race, not a rules mismatch, and it closes
//! properly when delegated credentials (ADR-006) let one resolution produce
//! both the value and the identity.
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
use std::future::Future;
use std::pin::Pin;

use crate::auth::keychain::KeychainBackend;
use crate::auth::{os_keychain, secrets};
use crate::config::Config;
use crate::policy::{CredentialLabel, EnvironmentClass, UpstreamAuthority, UpstreamIdentity};

/// Config key holding the environment classification of a vendor account
/// (`prod` / `staging` / `qa` / `dev`). Vendor-scoped: a `jira` section may
/// classify Jira as `prod` while `grafana` says `qa`; the shared overlay
/// classifies the whole deployment. Absent or unrecognised values are
/// [`EnvironmentClass::Unclassified`], which environment-scoped allow rules
/// never match — the conservative direction.
pub const ENVIRONMENT_KEY: &str = "MCP_VENDOR_ENVIRONMENT";

/// The future [`CredentialBroker::upstream_identity`] returns.
pub type UpstreamIdentityFuture<'a> = Pin<Box<dyn Future<Output = UpstreamIdentity> + Send + 'a>>;

/// Identifies the upstream identity that acts for a vendor.
///
/// Implementations must never return or log secret material — the returned
/// label appears in every audit event.
pub trait CredentialBroker: Send + Sync {
    /// The identity that would act upstream for `vendor` under `config`.
    ///
    /// Total by design: even an unconfigured vendor gets a stable
    /// `"{vendor}/unconfigured"` label, so an audit record can always name
    /// the upstream identity (the subsequent dispatch fails with the usual
    /// auth-missing error; the audit trail still shows what was attempted).
    ///
    /// Async because answering correctly can require asking the OS keychain
    /// whether a slot exists (see the module docs), which blocks. The
    /// question is only asked when config leaves it open.
    fn upstream_identity<'a>(
        &'a self,
        config: &'a Config,
        vendor: &'a str,
    ) -> UpstreamIdentityFuture<'a>;
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
    fn upstream_identity<'a>(
        &'a self,
        config: &'a Config,
        vendor: &'a str,
    ) -> UpstreamIdentityFuture<'a> {
        let environment = config
            .get_for(vendor, ENVIRONMENT_KEY)
            .and_then(EnvironmentClass::parse)
            .unwrap_or(EnvironmentClass::Unclassified);

        // Fast path: config already decides which slot acts, so nothing has
        // to be asked of the keychain and no thread is borrowed to ask it.
        // This is the path every containerized deployment takes.
        match slot_label(config, &NoKeychain, vendor) {
            Attribution::Slot(label) => {
                return Box::pin(std::future::ready(identity(
                    label,
                    vendor.to_owned(),
                    environment,
                )));
            }
            Attribution::Indeterminate => {
                return Box::pin(std::future::ready(identity(
                    CredentialLabel::indeterminate(vendor),
                    vendor.to_owned(),
                    environment,
                )));
            }
            Attribution::Nothing => {}
        }

        // Config is silent about every slot for this vendor, which is
        // exactly when the resolver falls back to the OS keychain — so the
        // broker has to look there too, off the async worker.
        let probe = config.clone();
        let owned_vendor = vendor.to_owned();
        let probe_vendor = owned_vendor.clone();
        Box::pin(async move {
            let attribution = tokio::task::spawn_blocking(move || {
                slot_label(&probe, os_keychain(), &probe_vendor)
            })
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "keychain slot probe failed; attributing as unconfigured");
                Attribution::Nothing
            });
            let label = match attribution {
                Attribution::Slot(label) => label,
                Attribution::Indeterminate => CredentialLabel::indeterminate(&owned_vendor),
                Attribution::Nothing => CredentialLabel::unconfigured(&owned_vendor),
            };
            identity(label, owned_vendor, environment)
        })
    }
}

/// Assemble the identity around a resolved label. Authority is always
/// [`UpstreamAuthority::Shared`] until delegated OAuth exists (ADR-006).
fn identity(
    label: CredentialLabel,
    vendor: String,
    environment: EnvironmentClass,
) -> UpstreamIdentity {
    UpstreamIdentity {
        label,
        vendor,
        environment,
        authority: UpstreamAuthority::Shared,
    }
}

/// What the broker can say about which slot will act for a vendor.
enum Attribution {
    /// This slot resolves and will be the one that acts.
    Slot(CredentialLabel),
    /// A credential will act, but which one is decided by state the broker
    /// cannot observe before dispatch (see
    /// [`secrets::resolution_is_observable`]).
    Indeterminate,
    /// Nothing resolves for this vendor.
    Nothing,
}

impl Attribution {
    /// The label text, for tests and diagnostics.
    #[cfg(test)]
    fn label(&self) -> Option<&str> {
        match self {
            Self::Slot(label) => Some(label.as_str()),
            _ => None,
        }
    }
}

/// The slot that would act for `vendor`.
///
/// This mirrors the vendors' own resolution: registry declaration order,
/// **request-path slots only** ([`secrets::SlotRole`]), "a declared principal
/// must be configured for the row to resolve at all", and the plaintext /
/// `"keychain"` sentinel / implicit-fallback cascade. Keeping one description
/// of that order in one function is what stops the prediction and the
/// resolution from drifting apart.
///
/// Where the order alone is not enough to know — a vendor whose resolver
/// consults runtime state — this answers [`Attribution::Indeterminate`]
/// rather than naming a slot it cannot vouch for. A wrong label is worse than
/// an honest gap: it misattributes the action silently, while
/// `vendor/indeterminate` tells an auditor to look further.
fn slot_label(config: &Config, backend: &dyn KeychainBackend, vendor: &str) -> Attribution {
    let observable = secrets::resolution_is_observable(vendor);

    for row in secrets::for_vendor(vendor) {
        // A login input mints a session; the session acts, not this row.
        if row.role == secrets::SlotRole::LoginInput {
            continue;
        }

        let configured_principal = row
            .principal_key
            .and_then(|key| config.get_for(vendor, key))
            .filter(|value| !value.trim().is_empty());
        // A row that names an account does not resolve without one — the
        // resolver returns early in that case, token or no token.
        if row.principal_key.is_some() && configured_principal.is_none() {
            continue;
        }

        let resolves = match config.get_for(vendor, row.secret_key).map(str::trim) {
            Some("") => false,
            // A plaintext value or the explicit `"keychain"` sentinel: this
            // row wins, and the label is the same either way — the slot has
            // not moved, only where its bytes live.
            Some(_) => true,
            // Absent: the implicit keychain fallback decides.
            None => backend.contains(row.kind, vendor, row.principal(configured_principal)),
        };

        if resolves {
            return Attribution::Slot(match configured_principal {
                Some(principal) => CredentialLabel::principal_slot(vendor, row, principal),
                None => CredentialLabel::slot(vendor, row),
            });
        }

        // For a vendor whose resolver consults invisible state, only the
        // *first* request-path slot can be claimed with confidence: it is
        // tried before that state is consulted. Once it has failed to
        // resolve, anything after it may be pre-empted by a runtime session
        // or a per-alias credential, so the honest answer is "cannot tell".
        if !observable {
            return Attribution::Indeterminate;
        }
    }

    if observable {
        Attribution::Nothing
    } else {
        // No request-path slot is configured at all, but a login session may
        // still be alive and serve the call.
        Attribution::Indeterminate
    }
}

/// A backend that answers "nothing is stored" without doing any I/O, so the
/// config-only pass can share [`slot_label`] with the keychain-aware one.
struct NoKeychain;

impl KeychainBackend for NoKeychain {
    fn get(
        &self,
        _kind: crate::auth::keychain::SecretKind,
        _vendor: &str,
        _principal: &str,
    ) -> crate::auth::keychain::KeychainResult<Option<String>> {
        Ok(None)
    }
    fn set(
        &self,
        _kind: crate::auth::keychain::SecretKind,
        _vendor: &str,
        _principal: &str,
        _secret: &str,
    ) -> crate::auth::keychain::KeychainResult<()> {
        Ok(())
    }
    fn delete(
        &self,
        _kind: crate::auth::keychain::SecretKind,
        _vendor: &str,
        _principal: &str,
    ) -> crate::auth::keychain::KeychainResult<()> {
        Ok(())
    }
    fn contains(
        &self,
        _kind: crate::auth::keychain::SecretKind,
        _vendor: &str,
        _principal: &str,
    ) -> bool {
        false
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
    fn upstream_identity<'a>(
        &'a self,
        _config: &'a Config,
        vendor: &'a str,
    ) -> UpstreamIdentityFuture<'a> {
        let identity = self
            .identities
            .get(vendor)
            .cloned()
            .unwrap_or_else(|| UpstreamIdentity {
                label: CredentialLabel::unconfigured(vendor),
                vendor: vendor.to_owned(),
                environment: EnvironmentClass::Unclassified,
                authority: UpstreamAuthority::Shared,
            });
        Box::pin(std::future::ready(identity))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use pretty_assertions::assert_eq;

    use super::*;
    use crate::auth::keychain::{InMemoryKeychain, SecretKind};
    use crate::config::{VENDOR_GRAFANA, VENDOR_JIRA, VENDOR_NINJAONE, VENDOR_SLACK};
    use crate::policy::TestSlot;

    fn config(pairs: &[(&str, &str)]) -> Config {
        Config::from_map(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<HashMap<_, _>>(),
        )
    }

    #[tokio::test]
    async fn label_names_the_configured_slot_and_principal() {
        let config = config(&[
            ("ATLASSIAN_API_TOKEN", "secret-token"),
            ("ATLASSIAN_USER_EMAIL", "alice@example.com"),
        ]);
        let identity = ConfigCredentialBroker
            .upstream_identity(&config, VENDOR_JIRA)
            .await;
        assert_eq!(
            identity.label.as_str(),
            "jira/ATLASSIAN_API_TOKEN/alice@example.com"
        );
        assert_eq!(identity.vendor, "jira");
        assert_eq!(identity.authority, UpstreamAuthority::Shared);
    }

    #[tokio::test]
    async fn label_is_stable_across_secret_rotation() {
        let before = config(&[
            ("SLACK_TOKEN", "xoxb-old"),
            ("MCP_VENDOR_ENVIRONMENT", "prod"),
        ]);
        let after = config(&[
            ("SLACK_TOKEN", "xoxb-new"),
            ("MCP_VENDOR_ENVIRONMENT", "prod"),
        ]);
        assert_eq!(
            ConfigCredentialBroker
                .upstream_identity(&before, VENDOR_SLACK)
                .await,
            ConfigCredentialBroker
                .upstream_identity(&after, VENDOR_SLACK)
                .await,
        );
    }

    #[tokio::test]
    async fn label_never_contains_the_secret_value() {
        let secret = "xoxb-super-secret-value";
        let config = config(&[("SLACK_TOKEN", secret)]);
        let identity = ConfigCredentialBroker
            .upstream_identity(&config, VENDOR_SLACK)
            .await;
        assert_eq!(identity.label.as_str(), "slack/SLACK_TOKEN");
        assert!(!identity.label.as_str().contains(secret));
        assert!(!serde_json::to_string(&identity).unwrap().contains(secret));
    }

    #[tokio::test]
    async fn environment_classification_comes_from_config_and_defaults_closed() {
        let classified = config(&[("GRAFANA_TOKEN", "tok"), ("MCP_VENDOR_ENVIRONMENT", "qa")]);
        assert_eq!(
            ConfigCredentialBroker
                .upstream_identity(&classified, VENDOR_GRAFANA)
                .await
                .environment,
            EnvironmentClass::Qa
        );

        let unset = config(&[("GRAFANA_TOKEN", "tok")]);
        assert_eq!(
            ConfigCredentialBroker
                .upstream_identity(&unset, VENDOR_GRAFANA)
                .await
                .environment,
            EnvironmentClass::Unclassified
        );

        // A typo classifies as Unclassified (matches no allow rule) rather
        // than guessing.
        let typo = config(&[("GRAFANA_TOKEN", "tok"), ("MCP_VENDOR_ENVIRONMENT", "pord")]);
        assert_eq!(
            ConfigCredentialBroker
                .upstream_identity(&typo, VENDOR_GRAFANA)
                .await
                .environment,
            EnvironmentClass::Unclassified
        );
    }

    #[tokio::test]
    async fn unconfigured_vendor_still_gets_a_stable_label() {
        let empty = Config::from_map(HashMap::new());
        let identity = ConfigCredentialBroker
            .upstream_identity(&empty, VENDOR_JIRA)
            .await;
        assert_eq!(identity.label.as_str(), "jira/unconfigured");
    }

    /// The attribution bug this rewrite exists for: a token that lives only
    /// in the OS keychain resolves and dispatches, so the audit record must
    /// name its slot rather than claim the vendor was unconfigured.
    #[test]
    fn a_slot_resolvable_only_through_the_keychain_is_named_not_called_unconfigured() {
        let config = config(&[]);
        let keychain = InMemoryKeychain::new();

        // Nothing anywhere: unconfigured, and that is the truth.
        assert_eq!(slot_label(&config, &keychain, VENDOR_SLACK).label(), None);

        // The implicit fallback will find this at dispatch time. The
        // principal for a bare vendor token is the config key name.
        keychain
            .set(SecretKind::Token, VENDOR_SLACK, "SLACK_TOKEN", "xoxb-x")
            .unwrap();
        assert_eq!(
            slot_label(&config, &keychain, VENDOR_SLACK).label(),
            Some("slack/SLACK_TOKEN"),
            "a keychain-resolved call must not be attributed to \
             `slack/unconfigured`"
        );
    }

    /// The same rule in the other direction: the resolver refuses a row
    /// whose declared principal is missing, so the broker must not name it.
    #[test]
    fn a_row_whose_account_is_unconfigured_does_not_resolve() {
        let token_only = config(&[("ATLASSIAN_API_TOKEN", "secret-token")]);
        assert_eq!(
            slot_label(&token_only, &NoKeychain, VENDOR_JIRA).label(),
            None
        );

        let with_account = config(&[
            ("ATLASSIAN_API_TOKEN", "secret-token"),
            ("ATLASSIAN_USER_EMAIL", "alice@example.com"),
        ]);
        assert!(
            slot_label(&with_account, &NoKeychain, VENDOR_JIRA)
                .label()
                .is_some()
        );
    }

    #[test]
    fn the_keychain_sentinel_and_a_plaintext_value_name_the_same_slot() {
        let plaintext = config(&[("SLACK_TOKEN", "xoxb-real")]);
        let sentinel = config(&[("SLACK_TOKEN", "keychain")]);
        assert_eq!(
            slot_label(&plaintext, &NoKeychain, VENDOR_SLACK).label(),
            slot_label(&sentinel, &NoKeychain, VENDOR_SLACK).label(),
            "where the bytes live does not move the slot"
        );
    }

    #[test]
    fn an_empty_configured_value_is_not_a_credential() {
        let blank = config(&[("SLACK_TOKEN", "   ")]);
        assert_eq!(slot_label(&blank, &NoKeychain, VENDOR_SLACK).label(), None);
    }

    /// `NinjaOne` declares its login inputs before its request credentials,
    /// and its resolver prefers an in-memory session it never writes to
    /// config. A registry-order scanner named the password slot for calls the
    /// access token served.
    #[test]
    fn ninjaone_login_inputs_are_never_named_as_the_acting_credential() {
        let login_only = config(&[
            ("NINJAONE_EMAIL", "op@example.com"),
            ("NINJAONE_PASSWORD", "hunter2"),
            ("NINJAONE_TOTP_SECRET", "seed"),
        ]);
        assert_eq!(
            slot_label(&login_only, &NoKeychain, VENDOR_NINJAONE).label(),
            None,
            "a password that only feeds `ninjaone_login` never acts upstream"
        );

        // With the access token configured too, the resolver takes the token
        // first and unconditionally — so that is the honest attribution.
        let with_token = config(&[
            ("NINJAONE_EMAIL", "op@example.com"),
            ("NINJAONE_PASSWORD", "hunter2"),
            ("NINJAONE_ACCESS_TOKEN", "tok"),
        ]);
        assert_eq!(
            slot_label(&with_token, &NoKeychain, VENDOR_NINJAONE).label(),
            Some("ninjaone/NINJAONE_ACCESS_TOKEN")
        );
    }

    /// Where the broker cannot see what decides — a live login session, a
    /// per-alias `NINJAONE_SERVERS` credential — it must say so rather than
    /// name the next slot in the table.
    #[tokio::test]
    async fn unobservable_resolution_is_labelled_indeterminate_not_guessed() {
        // A static session key is configured, but `resolve_auth` prefers an
        // in-memory key minted by `ninjaone_login`, which no amount of config
        // inspection can reveal.
        let session = config(&[("NINJAONE_SESSION_KEY", "sk")]);
        assert!(
            matches!(
                slot_label(&session, &NoKeychain, VENDOR_NINJAONE),
                Attribution::Indeterminate
            ),
            "the configured key may be pre-empted by a minted session"
        );

        let identity = ConfigCredentialBroker
            .upstream_identity(&session, VENDOR_NINJAONE)
            .await;
        assert_eq!(identity.label.as_str(), "ninjaone/indeterminate");

        // Nothing configured at all is still indeterminate, not
        // "unconfigured": a login session may be serving the call.
        let empty = Config::from_map(HashMap::new());
        assert_eq!(
            ConfigCredentialBroker
                .upstream_identity(&empty, VENDOR_NINJAONE)
                .await
                .label
                .as_str(),
            "ninjaone/indeterminate"
        );
    }

    /// The observable vendors keep exact attribution; only `NinjaOne` pays
    /// the indeterminate price.
    #[test]
    fn observable_vendors_are_still_named_exactly() {
        for (vendor, pairs, expected) in [
            (
                VENDOR_SLACK,
                &[("SLACK_TOKEN", "x")][..],
                "slack/SLACK_TOKEN",
            ),
            (
                VENDOR_GRAFANA,
                &[("GRAFANA_TOKEN", "x")][..],
                "grafana/GRAFANA_TOKEN",
            ),
        ] {
            assert_eq!(
                slot_label(&config(pairs), &NoKeychain, vendor).label(),
                Some(expected)
            );
        }
    }

    #[tokio::test]
    async fn static_broker_pins_identities_for_tests() {
        let pinned = UpstreamIdentity {
            label: CredentialLabel::slot(VENDOR_GRAFANA, &TestSlot("TEST_SLOT")),
            vendor: "grafana".to_owned(),
            environment: EnvironmentClass::Prod,
            authority: UpstreamAuthority::Shared,
        };
        let broker = StaticCredentialBroker::new().with(VENDOR_GRAFANA, pinned.clone());
        let empty = Config::from_map(HashMap::new());
        assert_eq!(
            broker.upstream_identity(&empty, VENDOR_GRAFANA).await,
            pinned
        );
        assert_eq!(
            broker
                .upstream_identity(&empty, VENDOR_JIRA)
                .await
                .label
                .as_str(),
            "jira/unconfigured"
        );
    }
}

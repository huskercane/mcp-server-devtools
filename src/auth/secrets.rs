//! Registry of every secret the config can hold, and how it maps to a
//! keychain slot.
//!
//! One table drives three things that used to drift apart: runtime resolution
//! (`"keychain"` sentinel expansion), `creds migrate`, and the `creds set`
//! kind/vendor validation. Adding a vendor secret means adding a row here —
//! not touching three call sites.
//!
//! ## Principals
//!
//! A keychain entry is addressed by `(kind, vendor, principal)`, but most
//! vendor tokens have no account attached: there is no "who" for
//! `SLACK_TOKEN`. Those rows carry `principal_key: None` and fall back to
//! **the config key name as the principal**, which is self-describing in the
//! OS keychain UI and stays unique for vendors holding several tokens (e.g.
//! `NinjaOne`'s access token, session key, and session cookie).
//!
//! Rows that do have a natural account — an Atlassian email, a Zoom client id,
//! a WRDS or `NinjaOne` login — name it, so rotating the account moves the slot.

use super::keychain::SecretKind;
use crate::config::{
    VENDOR_BITBUCKET, VENDOR_CIRCLECI, VENDOR_CONFLUENCE, VENDOR_EDX, VENDOR_GRAFANA, VENDOR_JIRA,
    VENDOR_NEWRELIC, VENDOR_NINJAONE, VENDOR_POSTMAN, VENDOR_SLACK, VENDOR_SONARQUBE,
    VENDOR_SPLUNK, VENDOR_WRDS, VENDOR_ZOOM,
};

/// What a registry row is used for on the **request path**.
///
/// The registry's declaration order doubles as the resolution order the
/// credential broker predicts, so a row that is not a request credential at
/// all must say so. `NinjaOne` is why: `NINJAONE_PASSWORD` and
/// `NINJAONE_TOTP_SECRET` are inputs to an interactive console login and are
/// never sent with a tool request, but they are declared before
/// `NINJAONE_ACCESS_TOKEN`. A broker that walked rows blindly labelled the
/// password slot for a call the access token actually served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotRole {
    /// Resolved and sent with an upstream request. Eligible to be named as
    /// the identity that acted.
    RequestCredential,
    /// An input to an interactive login exchange, which mints something else
    /// (a session) that does the acting. Never an attribution target.
    LoginInput,
}

/// One secret-bearing config key, and the keychain slot it maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fields are `pub(crate)`, not `pub`. A row is *evidence* that a slot
/// exists — `CredentialLabel` treats being one as proof that a string is a
/// config key name rather than a credential — so a downstream adapter must
/// not be able to mint one. Public getters expose everything readable; only
/// construction is closed, and only this file constructs.
pub struct VendorSecret {
    /// Canonical vendor name; also the keychain service suffix.
    pub(crate) vendor: &'static str,
    /// The config key holding the secret (or the `"keychain"` sentinel).
    pub(crate) secret_key: &'static str,
    /// Config key holding the account this secret belongs to, when the vendor
    /// has one. `None` means the principal is the secret key itself.
    pub(crate) principal_key: Option<&'static str>,
    pub(crate) kind: SecretKind,
    /// Whether this slot can act on the request path. See [`SlotRole`].
    pub(crate) role: SlotRole,
}

impl VendorSecret {
    #[must_use]
    pub const fn vendor(&self) -> &'static str {
        self.vendor
    }

    #[must_use]
    pub const fn secret_key(&self) -> &'static str {
        self.secret_key
    }

    #[must_use]
    pub const fn principal_key(&self) -> Option<&'static str> {
        self.principal_key
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    #[must_use]
    pub const fn role(&self) -> SlotRole {
        self.role
    }
}

impl VendorSecret {
    /// The keychain account for this secret: the configured principal where
    /// the vendor has one, otherwise the config key name.
    pub fn principal<'a>(&self, configured: Option<&'a str>) -> &'a str
    where
        'static: 'a,
    {
        match (self.principal_key, configured) {
            (Some(_), Some(principal)) if !principal.is_empty() => principal,
            _ => self.secret_key,
        }
    }
}

/// Shorthand for a row whose principal is the key name itself.
const fn token(vendor: &'static str, secret_key: &'static str) -> VendorSecret {
    VendorSecret {
        vendor,
        secret_key,
        principal_key: None,
        kind: SecretKind::Token,
        role: SlotRole::RequestCredential,
    }
}

/// Shorthand for a row with a real account behind it.
const fn owned(
    vendor: &'static str,
    secret_key: &'static str,
    principal_key: &'static str,
    kind: SecretKind,
) -> VendorSecret {
    VendorSecret {
        vendor,
        secret_key,
        principal_key: Some(principal_key),
        kind,
        role: SlotRole::RequestCredential,
    }
}

/// Like [`owned`], for a credential that only feeds an interactive login.
const fn login_input(
    vendor: &'static str,
    secret_key: &'static str,
    principal_key: &'static str,
    kind: SecretKind,
) -> VendorSecret {
    VendorSecret {
        vendor,
        secret_key,
        principal_key: Some(principal_key),
        kind,
        role: SlotRole::LoginInput,
    }
}

/// Every secret the server will expand from the keychain.
///
/// Deliberately absent: `NINJAONE_DB_ENVIRONMENTS`. It is a JSON document with
/// per-environment passwords inside, not a single secret, so it does not fit a
/// one-string slot — storing the whole blob would put hostnames and usernames
/// in the keychain too and make editing it a round-trip through `creds set`.
///
/// Absent for a different reason: the `password` and `totpSecret` fields of a
/// `NINJAONE_SERVERS` entry. Those *are* keychain-backed, each under its
/// entry's own `email`, but a row here names a config key and they are
/// addressed by a path into a nested document. The two places that need to
/// know handle them explicitly — [`crate::vendor::ninjaone`] resolves them at
/// login, and `cli::creds` migrates them.
pub const VENDOR_SECRETS: &[VendorSecret] = &[
    // Atlassian: one API token per product, plus Bitbucket's app password.
    owned(
        VENDOR_BITBUCKET,
        "ATLASSIAN_API_TOKEN",
        "ATLASSIAN_USER_EMAIL",
        SecretKind::ApiToken,
    ),
    owned(
        VENDOR_JIRA,
        "ATLASSIAN_API_TOKEN",
        "ATLASSIAN_USER_EMAIL",
        SecretKind::ApiToken,
    ),
    owned(
        VENDOR_CONFLUENCE,
        "ATLASSIAN_API_TOKEN",
        "ATLASSIAN_USER_EMAIL",
        SecretKind::ApiToken,
    ),
    owned(
        VENDOR_BITBUCKET,
        "ATLASSIAN_BITBUCKET_APP_PASSWORD",
        "ATLASSIAN_BITBUCKET_USERNAME",
        SecretKind::AppPassword,
    ),
    // Zoom's client secret belongs to the client id, not to a person.
    owned(
        VENDOR_ZOOM,
        "ZOOM_CLIENT_SECRET",
        "ZOOM_CLIENT_ID",
        SecretKind::Token,
    ),
    // Single-token vendors.
    token(VENDOR_SLACK, "SLACK_TOKEN"),
    token(VENDOR_CIRCLECI, "CIRCLECI_TOKEN"),
    token(VENDOR_POSTMAN, "POSTMAN_API_KEY"),
    token(VENDOR_NEWRELIC, "NEW_RELIC_API_KEY"),
    token(VENDOR_GRAFANA, "GRAFANA_TOKEN"),
    token(VENDOR_SONARQUBE, "SONARQUBE_TOKEN"),
    token(VENDOR_SPLUNK, "SPLUNK_TOKEN"),
    token(VENDOR_EDX, "EDX_ACCESS_TOKEN"),
    // WRDS logs in with a real account.
    owned(
        VENDOR_WRDS,
        "WRDS_PASSWORD",
        "WRDS_USERNAME",
        SecretKind::Password,
    ),
    // NinjaOne: console login (account-scoped) plus three carrier credentials
    // that have no account of their own.
    //
    // The password and TOTP seed are *login inputs*: `vendor::ninjaone::login`
    // exchanges them for a session, and the session — not these — travels with
    // a tool request. They are declared first for keychain-migration order, so
    // they must be marked, or the broker names them for calls the access token
    // serves. The three carriers below are in the order
    // `NinjaOneVendor::resolve_auth` actually tries them.
    login_input(
        VENDOR_NINJAONE,
        "NINJAONE_PASSWORD",
        "NINJAONE_EMAIL",
        SecretKind::Password,
    ),
    login_input(
        VENDOR_NINJAONE,
        "NINJAONE_TOTP_SECRET",
        "NINJAONE_EMAIL",
        SecretKind::TotpSecret,
    ),
    token(VENDOR_NINJAONE, "NINJAONE_ACCESS_TOKEN"),
    token(VENDOR_NINJAONE, "NINJAONE_SESSION_KEY"),
    token(VENDOR_NINJAONE, "NINJAONE_SESSION_COOKIE"),
];

/// Look up the row for a `(vendor, secret_key)` pair.
pub fn lookup(vendor: &str, secret_key: &str) -> Option<&'static VendorSecret> {
    VENDOR_SECRETS
        .iter()
        .find(|secret| secret.vendor == vendor && secret.secret_key == secret_key)
}

/// Look up a row by config key alone. Used by the CLI so `--kind SLACK_TOKEN`
/// resolves; ambiguous only for `ATLASSIAN_API_TOKEN`, where every row shares
/// the same kind, so the first match is correct.
pub fn lookup_by_key(secret_key: &str) -> Option<&'static VendorSecret> {
    VENDOR_SECRETS
        .iter()
        .find(|secret| secret.secret_key == secret_key)
}

/// Every secret registered for a vendor, in declaration order.
pub fn for_vendor(vendor: &str) -> impl Iterator<Item = &'static VendorSecret> {
    VENDOR_SECRETS
        .iter()
        .filter(move |secret| secret.vendor == vendor)
}

/// Whether the broker can tell, from configuration alone, which slot will act
/// for `vendor`.
///
/// `false` means the vendor's resolver consults state the broker cannot see
/// before dispatch, so a config-only prediction may name the wrong slot.
/// `NinjaOne` is the case: `resolve_auth` prefers an **in-memory session key**
/// minted by `ninjaone_login` over the configured `NINJAONE_SESSION_KEY`, and
/// a `NINJAONE_SERVERS` alias can carry its own credentials selected per
/// request. Neither is visible from `Config` plus this table.
///
/// The broker answers `indeterminate` rather than guessing in that case. The
/// real fix — resolving the credential selection once, before the intent
/// record, and labelling from that same selection — needs credential
/// resolution to move ahead of dispatch across every controller; it is
/// tracked as a Phase A work package in `docs/enterprise-carry-forward.md`.
#[must_use]
pub fn resolution_is_observable(vendor: &str) -> bool {
    vendor != VENDOR_NINJAONE
}

/// Whether a `(kind, vendor)` pair addresses any real slot. Drives the CLI
/// guard that keeps operators from filing an entry nothing will ever read.
pub fn kind_supported_by(kind: SecretKind, vendor: &str) -> bool {
    VENDOR_SECRETS
        .iter()
        .any(|secret| secret.kind == kind && secret.vendor == vendor)
}

/// Canonical vendors that hold at least one registered secret, in declaration
/// order and without duplicates. Used for CLI help and validation.
pub fn vendors_with_secrets() -> Vec<&'static str> {
    let mut vendors: Vec<&'static str> = Vec::with_capacity(VENDOR_SECRETS.len());
    for secret in VENDOR_SECRETS {
        if !vendors.contains(&secret.vendor) {
            vendors.push(secret.vendor);
        }
    }
    vendors
}

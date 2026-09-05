//! C.2b (`docs/enterprise-product-plan.md` §3.8): the `vault://` adapter
//! against a fake Vault that speaks just enough of the HTTP API. Locks the
//! request shapes and the failure categories on every OS; the real-server
//! proof, against `HashiCorp` Vault and `OpenBao` containers, is
//! `tests/vault_live_tests.rs`.
#![cfg(feature = "secrets-vault")]

mod support;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mcp_server_devtools::config::Config;
use mcp_server_devtools::ports::{Scheme, SecretLocator, SecretSource, SecretSourceError};
use mcp_server_devtools::secrets::{SecretResolver, VaultSecretSource, VaultSettings};
use serde_json::json;
use support::fake_vault::{FakeVault, Lease};
use support::secret_source_conformance::{Fixture, conformance};

const ROOT: &str = "hvs.root-token-for-tests";

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<HashMap<_, _>>(),
    )
}

fn token_source(vault: &FakeVault, extra: &[(&str, &str)]) -> VaultSecretSource {
    let addr = vault.addr();
    let mut pairs = vec![
        ("MCP_VAULT_ADDR", addr.as_str()),
        ("MCP_VAULT_AUTH", "token"),
        ("MCP_VAULT_TOKEN", ROOT),
    ];
    pairs.extend_from_slice(extra);
    VaultSecretSource::from_config(&config(&pairs)).unwrap()
}

fn locator(target: &str) -> SecretLocator {
    SecretLocator::new(Scheme::Vault, target)
}

struct VaultFixture {
    vault: FakeVault,
}

impl Fixture for VaultFixture {
    fn source(&self) -> Arc<dyn SecretSource> {
        Arc::new(token_source(&self.vault, &[]))
    }
    fn put(&self, target: &str, document: &str) {
        self.vault.write_kv(target, json!({ "value": document }));
    }
    fn remove(&self, target: &str) {
        self.vault.destroy_kv(target);
    }
    fn target(&self, name: &str) -> String {
        format!("secret/mcp/{name}")
    }
    fn scheme(&self) -> Scheme {
        Scheme::Vault
    }
    fn fetched_form(&self, document: &str) -> String {
        json!({ "value": document }).to_string()
    }
}

#[tokio::test]
async fn vault_adapter_conforms() {
    let vault = FakeVault::start().await;
    vault.accept_token(ROOT, Lease::default());
    conformance(&VaultFixture { vault }).await;
}

#[tokio::test]
async fn token_auth_sends_the_token_and_the_namespace_and_reports_the_kv_version() {
    let vault = FakeVault::start().await;
    vault.accept_token(ROOT, Lease::default());
    vault.write_kv("secret/mcp/grafana", json!({ "token": "glsa_v1" }));
    vault.write_kv("secret/mcp/grafana", json!({ "token": "glsa_v2" }));

    let plain = token_source(&vault, &[]);
    let fetched = plain.fetch(&locator("secret/mcp/grafana")).await.unwrap();
    assert_eq!(fetched.document(), r#"{"token":"glsa_v2"}"#);
    assert_eq!(fetched.version(), "2", "Vault's own KV version number");
    let reads = vault.kv_reads();
    assert_eq!(
        reads.last().unwrap().path,
        "/v1/secret/mcp/data/grafana".replace("mcp/data", "data/mcp")
    );
    assert_eq!(reads.last().unwrap().token.as_deref(), Some(ROOT));
    assert_eq!(reads.last().unwrap().namespace, None);

    let namespaced = token_source(&vault, &[("MCP_VAULT_NAMESPACE", "admin/platform")]);
    namespaced
        .fetch(&locator("secret/mcp/grafana"))
        .await
        .unwrap();
    let requests = vault.requests();
    let since = requests.len() - 2;
    assert!(
        requests[since..]
            .iter()
            .all(|request| request.namespace.as_deref() == Some("admin/platform")),
        "lookup-self and the read both carry X-Vault-Namespace: {requests:?}"
    );

    // The resolver takes `#key` from that one document — `source` and
    // `version` are what the audit record will carry.
    let resolver = SecretResolver::new(vec![Arc::new(plain)]);
    let snapshot = resolver
        .resolve(["vault://secret/mcp/grafana#token"])
        .await
        .unwrap();
    let entry = snapshot.get("vault://secret/mcp/grafana#token").unwrap();
    assert_eq!(entry.value(), "glsa_v2");
    assert_eq!(entry.provenance().source, "vault");
    assert_eq!(entry.provenance().version, "2");
}

#[tokio::test]
async fn approle_logs_in_once_and_again_after_the_token_is_refused() {
    let vault = FakeVault::start().await;
    vault.with(|state| state.approle = Some(("role-id-1".to_owned(), "secret-id-1".to_owned())));
    vault.write_kv("kv/app", json!({ "k": "v" }));
    let source = VaultSecretSource::from_config(&config(&[
        ("MCP_VAULT_ADDR", &vault.addr()),
        ("MCP_VAULT_AUTH", "approle"),
        ("MCP_VAULT_ROLE_ID", "role-id-1"),
        ("MCP_VAULT_SECRET_ID", "secret-id-1"),
    ]))
    .unwrap();

    source.fetch(&locator("kv/app")).await.unwrap();
    source.fetch(&locator("kv/app")).await.unwrap();
    assert_eq!(source.logins(), 1, "the session is reused across fetches");
    let login = &vault.logins()[0];
    assert_eq!(login.path, "/v1/auth/approle/login");
    assert_eq!(login.body["role_id"], "role-id-1");
    assert_eq!(login.body["secret_id"], "secret-id-1");
    assert_eq!(login.token, None, "a login carries no token");

    // Vault revokes the token (a policy change, an operator): one 403, one
    // fresh login, one retry.
    let issued = vault.kv_reads().last().unwrap().token.clone().unwrap();
    vault.revoke_token(&issued);
    let fetched = source.fetch(&locator("kv/app")).await.unwrap();
    assert_eq!(fetched.document(), r#"{"k":"v"}"#);
    assert_eq!(source.logins(), 2);

    // Wrong secret id: a login refusal is a category, and never the ids.
    let wrong = VaultSecretSource::from_config(&config(&[
        ("MCP_VAULT_ADDR", &vault.addr()),
        ("MCP_VAULT_AUTH", "approle"),
        ("MCP_VAULT_ROLE_ID", "role-id-1"),
        ("MCP_VAULT_SECRET_ID", "secret-id-WRONG"),
    ]))
    .unwrap();
    let error = wrong.fetch(&locator("kv/app")).await.unwrap_err();
    assert!(
        matches!(error, SecretSourceError::Unavailable { .. }),
        "{error:?}"
    );
    let text = format!("{error} {error:?}");
    assert!(text.contains("login refused"), "{text}");
    assert!(!text.contains("secret-id"), "{text}");
    assert!(!text.contains("role-id"), "{text}");
}

#[tokio::test]
async fn kubernetes_login_reads_the_projected_token_at_every_login() {
    let vault = FakeVault::start().await;
    vault.with(|state| state.kubernetes_role = Some("mcp-devtools".to_owned()));
    vault.write_kv("kv/app", json!({ "k": "v" }));
    let dir = tempfile::tempdir().unwrap();
    let jwt_path = dir.path().join("token");
    std::fs::write(&jwt_path, "eyJ.projected-1\n").unwrap();
    let source = VaultSecretSource::from_config(&config(&[
        ("MCP_VAULT_ADDR", &vault.addr()),
        ("MCP_VAULT_AUTH", "kubernetes"),
        ("MCP_VAULT_ROLE", "mcp-devtools"),
        ("MCP_VAULT_JWT_PATH", jwt_path.to_str().unwrap()),
        ("MCP_VAULT_AUTH_MOUNT", "/kubernetes/"),
    ]))
    .unwrap();

    source.fetch(&locator("kv/app")).await.unwrap();
    let login = &vault.logins()[0];
    assert_eq!(login.path, "/v1/auth/kubernetes/login");
    assert_eq!(login.body["role"], "mcp-devtools");
    assert_eq!(login.body["jwt"], "eyJ.projected-1", "trimmed");

    // The kubelet rotates the projection; the next login uses it.
    std::fs::write(&jwt_path, "eyJ.projected-2").unwrap();
    let issued = vault.kv_reads().last().unwrap().token.clone().unwrap();
    vault.revoke_token(&issued);
    source.fetch(&locator("kv/app")).await.unwrap();
    assert_eq!(vault.logins()[1].body["jwt"], "eyJ.projected-2");

    // No projection: a category, never a path traversal into the error.
    std::fs::remove_file(&jwt_path).unwrap();
    vault.revoke_token(&vault.kv_reads().last().unwrap().token.clone().unwrap());
    let error = source.fetch(&locator("kv/app")).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("service-account token unreadable"),
        "{error}"
    );
}

#[tokio::test]
async fn a_renewable_lease_is_renewed_past_two_thirds_and_an_expired_one_is_replaced() {
    let vault = FakeVault::start().await;
    vault.with(|state| {
        state.approle = Some(("r".to_owned(), "s".to_owned()));
        state.issued_lease = Lease {
            seconds: 3,
            renewable: true,
        };
    });
    vault.write_kv("kv/app", json!({ "k": "v" }));
    let source = VaultSecretSource::from_config(&config(&[
        ("MCP_VAULT_ADDR", &vault.addr()),
        ("MCP_VAULT_AUTH", "approle"),
        ("MCP_VAULT_ROLE_ID", "r"),
        ("MCP_VAULT_SECRET_ID", "s"),
    ]))
    .unwrap();

    source.fetch(&locator("kv/app")).await.unwrap();
    assert_eq!(source.renewals(), 0);
    tokio::time::sleep(Duration::from_millis(2200)).await;
    source.fetch(&locator("kv/app")).await.unwrap();
    assert_eq!(
        source.renewals(),
        1,
        "past two thirds of a 3 s lease: renewed"
    );
    assert_eq!(source.logins(), 1, "renewed, not re-obtained");
    assert_eq!(vault.with(|state| state.renewals), 1);
    let renew = vault
        .requests()
        .into_iter()
        .find(|request| request.path == "/v1/auth/token/renew-self")
        .expect("a renew-self request");
    assert!(renew.token.is_some());

    // A lease that cannot be renewed and has run out: a fresh login.
    vault.with(|state| {
        state.issued_lease = Lease {
            seconds: 1,
            renewable: false,
        };
    });
    let fresh = VaultSecretSource::from_config(&config(&[
        ("MCP_VAULT_ADDR", &vault.addr()),
        ("MCP_VAULT_AUTH", "approle"),
        ("MCP_VAULT_ROLE_ID", "r"),
        ("MCP_VAULT_SECRET_ID", "s"),
    ]))
    .unwrap();
    fresh.fetch(&locator("kv/app")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    fresh.fetch(&locator("kv/app")).await.unwrap();
    assert_eq!(
        fresh.logins(),
        2,
        "an expired, non-renewable lease is replaced"
    );
    assert_eq!(fresh.renewals(), 0);
}

#[tokio::test]
async fn a_secret_id_held_in_a_file_is_reread_at_each_login() {
    let vault = FakeVault::start().await;
    vault.with(|state| state.approle = Some(("r".to_owned(), "sid-1".to_owned())));
    vault.write_kv("kv/app", json!({ "k": "v" }));
    let dir = tempfile::tempdir().unwrap();
    let secret_id_path = dir.path().join("secret-id");
    std::fs::write(&secret_id_path, "sid-1\n").unwrap();
    let reference = format!("file://{}", secret_id_path.to_str().unwrap());
    let source = VaultSecretSource::from_config(&config(&[
        ("MCP_VAULT_ADDR", &vault.addr()),
        ("MCP_VAULT_AUTH", "approle"),
        ("MCP_VAULT_ROLE_ID", "r"),
        ("MCP_VAULT_SECRET_ID", &reference),
    ]))
    .unwrap();
    source.fetch(&locator("kv/app")).await.unwrap();

    // The secret id is rotated at Vault and in the file; the old token is
    // revoked; the next login reads the new id.
    vault.with(|state| state.approle = Some(("r".to_owned(), "sid-2".to_owned())));
    std::fs::write(&secret_id_path, "sid-2").unwrap();
    vault.revoke_token(&vault.kv_reads().last().unwrap().token.clone().unwrap());
    source.fetch(&locator("kv/app")).await.unwrap();
    assert_eq!(vault.logins()[1].body["secret_id"], "sid-2");
}

#[tokio::test]
async fn sealed_deleted_and_malformed_are_categories_that_never_carry_the_token() {
    let vault = FakeVault::start().await;
    vault.accept_token(ROOT, Lease::default());
    vault.write_kv("kv/app", json!({ "k": "v" }));
    vault.write_kv("kv/list", json!(["not", "an", "object"]));
    let source = token_source(&vault, &[]);

    vault.delete_kv("kv/app");
    assert!(
        matches!(
            source.fetch(&locator("kv/app")).await.unwrap_err(),
            SecretSourceError::NotFound { .. }
        ),
        "a soft-deleted version is not a value"
    );

    let malformed = source.fetch(&locator("kv/list")).await.unwrap_err();
    assert!(
        matches!(malformed, SecretSourceError::Malformed { .. }),
        "{malformed:?}"
    );

    let bad_shape = source.fetch(&locator("nomount")).await.unwrap_err();
    assert!(matches!(bad_shape, SecretSourceError::Malformed { .. }));
    assert!(
        bad_shape
            .to_string()
            .contains("vault://<mount>/<path>#<key>")
    );

    vault.with(|state| state.sealed = true);
    let sealed = source.fetch(&locator("kv/app")).await.unwrap_err();
    assert_eq!(sealed.category(), "secret_source_unavailable");
    assert!(sealed.to_string().contains("sealed"), "{sealed}");
    for error in [&sealed, &malformed, &bad_shape] {
        let text = format!("{error} {error:?}");
        assert!(!text.contains(ROOT), "leaks the token: {text}");
        assert!(!text.contains("hvs."), "leaks a token: {text}");
    }
    assert!(
        !format!("{source:?}").contains(ROOT),
        "Debug leaks the token"
    );
}

#[tokio::test]
async fn resolver_from_config_builds_the_adapter_only_when_an_address_is_set() {
    let vault = FakeVault::start().await;
    vault.accept_token(ROOT, Lease::default());
    vault.write_kv("secret/mcp/grafana", json!({ "token": "glsa" }));

    let unconfigured = SecretResolver::from_config(&config(&[])).unwrap();
    let error = unconfigured
        .resolve(["vault://secret/mcp/grafana#token"])
        .await
        .unwrap_err();
    assert_eq!(error.cause.category(), "secret_source_unconfigured");
    assert!(error.to_string().contains("MCP_VAULT_ADDR"), "{error}");

    let half = SecretResolver::from_config(&config(&[("MCP_VAULT_ADDR", &vault.addr())]));
    let reason = half.unwrap_err();
    assert!(reason.starts_with("vault://:"), "{reason}");
    assert!(reason.contains("MCP_VAULT_AUTH"), "{reason}");

    let configured = SecretResolver::from_config(&config(&[
        ("MCP_VAULT_ADDR", &vault.addr()),
        ("MCP_VAULT_AUTH", "token"),
        ("MCP_VAULT_TOKEN", ROOT),
    ]))
    .unwrap();
    let snapshot = configured
        .resolve(["vault://secret/mcp/grafana#token", "literal"])
        .await
        .unwrap();
    assert_eq!(
        snapshot
            .get("vault://secret/mcp/grafana#token")
            .unwrap()
            .value(),
        "glsa"
    );
    let settings = VaultSettings::from_config(&config(&[
        ("MCP_VAULT_ADDR", &vault.addr()),
        ("MCP_VAULT_AUTH", "token"),
        ("MCP_VAULT_TOKEN", ROOT),
    ]))
    .unwrap();
    assert_eq!(settings.auth.method(), "token");
}

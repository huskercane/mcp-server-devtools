//! C.2b: the `vault://` adapter against a **real** Vault or `OpenBao`
//! server in dev mode — the real-provider proof for KV v2 reads, `AppRole`
//! and token authentication, lease renewal, rotation, and the failure
//! categories (plan §3.8, "Real Vault container"). CI runs it against both
//! `hashicorp/vault` and `openbao/openbao`; the two speak the same API.
//!
//! Skipped unless `MCP_TEST_VAULT_ADDR` is set (`MCP_TEST_VAULT_TOKEN` is
//! the root token, default `root`). To run locally:
//!
//! ```bash
//! docker run -d --name vault -p 127.0.0.1:8200:8200 hashicorp/vault:1.21.4 \
//!   server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200
//! MCP_TEST_VAULT_ADDR=http://127.0.0.1:8200 cargo test --test vault_live_tests -- --nocapture
//! ```
#![cfg(feature = "secrets-vault")]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mcp_server_devtools::config::Config;
use mcp_server_devtools::ports::{Scheme, SecretLocator, SecretSource, SecretSourceError};
use mcp_server_devtools::secrets::VaultSecretSource;
use serde_json::{Value, json};

const POLICY: &str = "mcp-devtools-live-test";
const ROLE: &str = "mcp-devtools-live-test";
const SECRET_PATH: &str = "secret/mcp-live-test/grafana";

fn vault_addr() -> Option<String> {
    std::env::var("MCP_TEST_VAULT_ADDR")
        .ok()
        .map(|addr| addr.trim().trim_end_matches('/').to_owned())
        .filter(|addr| !addr.is_empty())
}

fn root_token() -> String {
    std::env::var("MCP_TEST_VAULT_TOKEN").unwrap_or_else(|_| "root".to_owned())
}

fn config(pairs: &[(&str, &str)]) -> Config {
    Config::from_map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<HashMap<_, _>>(),
    )
}

fn locator() -> SecretLocator {
    SecretLocator::new(Scheme::Vault, SECRET_PATH)
}

/// The root-token administrative client the test sets the server up with.
struct Admin {
    http: reqwest::Client,
    addr: String,
    token: String,
}

impl Admin {
    async fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_mins(2);
        loop {
            if let Ok(response) = self
                .http
                .get(format!("{}/v1/sys/health", self.addr))
                .send()
                .await
                && response.status().as_u16() == 200
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "Vault at {} never became ready",
                self.addr
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut request = self
            .http
            .request(method, format!("{}/v1/{path}", self.addr))
            .header("X-Vault-Token", &self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("Vault reachable");
        let status = response.status().as_u16();
        let body = response.json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
    }

    /// Idempotent setup: a read policy, the `AppRole` method with a
    /// short-lived role, and the first version of the secret.
    async fn prepare(&self) -> (String, String, u64) {
        let (status, body) = self
            .call(
                reqwest::Method::PUT,
                &format!("sys/policies/acl/{POLICY}"),
                Some(json!({
                    "policy": "path \"secret/data/mcp-live-test/*\" { capabilities = [\"read\"] }"
                })),
            )
            .await;
        assert!(status < 300, "policy: {status} {body}");
        let (status, body) = self
            .call(
                reqwest::Method::POST,
                "sys/auth/approle",
                Some(json!({ "type": "approle" })),
            )
            .await;
        assert!(
            status < 300 || body.to_string().contains("already in use"),
            "enable approle: {status} {body}"
        );
        let (status, body) = self
            .call(
                reqwest::Method::POST,
                &format!("auth/approle/role/{ROLE}"),
                Some(json!({
                    "token_policies": [POLICY],
                    "token_ttl": "10s",
                    "token_max_ttl": "2m",
                })),
            )
            .await;
        assert!(status < 300, "role: {status} {body}");
        let (_, role) = self
            .call(
                reqwest::Method::GET,
                &format!("auth/approle/role/{ROLE}/role-id"),
                None,
            )
            .await;
        let role_id = role["data"]["role_id"].as_str().unwrap().to_owned();
        let (_, secret) = self
            .call(
                reqwest::Method::POST,
                &format!("auth/approle/role/{ROLE}/secret-id"),
                Some(json!({})),
            )
            .await;
        let secret_id = secret["data"]["secret_id"].as_str().unwrap().to_owned();
        let version = self.write_secret("glsa_v1").await;
        (role_id, secret_id, version)
    }

    /// Write the secret and return the KV version Vault assigned.
    async fn write_secret(&self, token: &str) -> u64 {
        let (status, body) = self
            .call(
                reqwest::Method::POST,
                "secret/data/mcp-live-test/grafana",
                Some(json!({ "data": { "token": token, "url": "https://grafana.example" } })),
            )
            .await;
        assert!(status < 300, "write: {status} {body}");
        body["data"]["version"].as_u64().expect("version")
    }
}

#[tokio::test]
async fn kv_reads_approle_and_token_leases_and_rotation_against_a_real_server() {
    let Some(addr) = vault_addr() else {
        eprintln!("MCP_TEST_VAULT_ADDR is not set; skipping the Vault live test");
        return;
    };
    let admin = Admin {
        http: reqwest::Client::new(),
        addr: addr.clone(),
        token: root_token(),
    };
    admin.wait_ready().await;
    let (role_id, secret_id, version_v1) = admin.prepare().await;

    // 1. Token auth (root): the document is the KV data object and the
    //    version is Vault's.
    let by_token = VaultSecretSource::from_config(&config(&[
        ("MCP_VAULT_ADDR", &addr),
        ("MCP_VAULT_AUTH", "token"),
        ("MCP_VAULT_TOKEN", &root_token()),
    ]))
    .unwrap();
    let fetched = by_token
        .fetch(&locator())
        .await
        .expect("root reads the secret");
    let document: Value = serde_json::from_str(fetched.document()).unwrap();
    assert_eq!(document["token"], "glsa_v1");
    assert_eq!(fetched.version(), version_v1.to_string());

    // 2. AppRole with a 10 s token: the login happens once, and a fetch
    //    past two thirds of the lease renews rather than logs in again.
    let by_approle = VaultSecretSource::from_config(&config(&[
        ("MCP_VAULT_ADDR", &addr),
        ("MCP_VAULT_AUTH", "approle"),
        ("MCP_VAULT_ROLE_ID", &role_id),
        ("MCP_VAULT_SECRET_ID", &secret_id),
    ]))
    .unwrap();
    by_approle
        .fetch(&locator())
        .await
        .expect("approle reads the secret");
    assert_eq!(by_approle.logins(), 1);
    tokio::time::sleep(Duration::from_millis(7200)).await;
    by_approle
        .fetch(&locator())
        .await
        .expect("still readable after renewal");
    assert_eq!(
        by_approle.renewals(),
        1,
        "renewed at two thirds of a 10 s lease"
    );
    assert_eq!(by_approle.logins(), 1);

    // 3. Rotation: a new KV version is a new document and a new version.
    let version_v2 = admin.write_secret("glsa_v2").await;
    let rotated = by_approle.fetch(&locator()).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(rotated.document()).unwrap()["token"],
        "glsa_v2"
    );
    assert_eq!(rotated.version(), version_v2.to_string());
    assert!(version_v2 > version_v1);

    // 4. Failure categories from the real server: a path that does not
    //    exist, and one the policy does not grant (403 → one re-login →
    //    still refused → `forbidden`), with no token in the text.
    let missing = SecretLocator::new(Scheme::Vault, "secret/mcp-live-test/absent");
    assert!(matches!(
        by_approle.fetch(&missing).await.unwrap_err(),
        SecretSourceError::NotFound { .. }
    ));
    let denied = SecretLocator::new(Scheme::Vault, "secret/elsewhere/grafana");
    let error = by_approle.fetch(&denied).await.unwrap_err();
    assert!(
        matches!(error, SecretSourceError::Unavailable { .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("forbidden"), "{error}");
    assert_eq!(by_approle.logins(), 2, "one fresh login before giving up");
    assert!(!format!("{error:?}").contains("hvs."));

    // 5. A short-lived renewable token given directly is renewed too:
    //    `lookup-self` told the adapter its lease.
    let (status, created) = admin
        .call(
            reqwest::Method::POST,
            "auth/token/create",
            Some(json!({ "ttl": "6s", "renewable": true, "policies": [POLICY] })),
        )
        .await;
    assert!(status < 300, "token create: {status} {created}");
    let short = created["auth"]["client_token"].as_str().unwrap().to_owned();
    let by_short_token = VaultSecretSource::from_config(&config(&[
        ("MCP_VAULT_ADDR", &addr),
        ("MCP_VAULT_AUTH", "token"),
        ("MCP_VAULT_TOKEN", &short),
    ]))
    .unwrap();
    by_short_token.fetch(&locator()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(4500)).await;
    by_short_token
        .fetch(&locator())
        .await
        .expect("readable after renewal");
    assert_eq!(by_short_token.renewals(), 1);
}

//! WP C.1b: the real-identity-provider proof, against a Keycloak container.
//!
//! Every other validator test signs tokens with a checked-in key and serves
//! a JWKS from wiremock, which proves the validator against tokens *we*
//! shaped. This one obtains tokens from a real Keycloak realm
//! (`tests/fixtures/keycloak/mcp-realm.json`, imported at container
//! start), so what is exercised is the whole path against a provider's own
//! output: its discovery-free `certs` endpoint, its `scope` string, the
//! `aud` it does and does not emit, its `/`-prefixed group paths, and its
//! key rotation through the admin API — the last of which no mocked JWKS
//! can stand in for.
//!
//! Skipped unless `MCP_KEYCLOAK_URL` is set (CI's `keycloak` job sets it;
//! locally, run the container the same way — see
//! `docs/identity-provider-runbook.md`). Without the variable every test
//! here passes trivially, so `cargo test` stays hermetic.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mcp_server_devtools::auth::oidc::{OidcJwksValidator, OidcSettings};
use mcp_server_devtools::config::{Config, OidcKeys};
use mcp_server_devtools::policy::PrincipalAuthority;
use mcp_server_devtools::ports::{TokenRejection, TokenValidator};
use serde_json::{Value, json};
use std::sync::Arc;

const REALM: &str = "mcp";
const AUDIENCE: &str = "api://mcp-devtools";

/// The base URL of the Keycloak under test, or `None` to skip.
fn keycloak_url() -> Option<String> {
    std::env::var("MCP_KEYCLOAK_URL")
        .ok()
        .map(|url| url.trim().trim_end_matches('/').to_owned())
        .filter(|url| !url.is_empty())
}

fn admin_credentials() -> (String, String) {
    (
        std::env::var("MCP_KEYCLOAK_ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_owned()),
        std::env::var("MCP_KEYCLOAK_ADMIN_PASSWORD").unwrap_or_else(|_| "admin".to_owned()),
    )
}

/// Wait for the imported realm to answer discovery. Keycloak in `start-dev`
/// takes tens of seconds to boot on a CI runner.
async fn wait_for_realm(client: &reqwest::Client, base: &str) {
    let discovery = format!("{base}/realms/{REALM}/.well-known/openid-configuration");
    let deadline = Instant::now() + Duration::from_mins(3);
    loop {
        if let Ok(response) = client.get(&discovery).send().await
            && response.status().is_success()
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Keycloak realm {REALM} did not become ready at {discovery}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Resource Owner Password grant — the realm enables it for the two test
/// clients so the test needs no browser.
async fn password_grant(
    client: &reqwest::Client,
    base: &str,
    client_id: &str,
    client_secret: &str,
    username: &str,
    password: &str,
) -> String {
    let response = client
        .post(format!(
            "{base}/realms/{REALM}/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("username", username),
            ("password", password),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("token endpoint reachable");
    let status = response.status();
    let body: Value = response.json().await.expect("token response is JSON");
    assert!(status.is_success(), "token grant failed: {body}");
    body["access_token"]
        .as_str()
        .expect("access_token present")
        .to_owned()
}

async fn admin_token(client: &reqwest::Client, base: &str) -> String {
    let (username, password) = admin_credentials();
    let response = client
        .post(format!(
            "{base}/realms/master/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", username.as_str()),
            ("password", password.as_str()),
        ])
        .send()
        .await
        .expect("master realm token endpoint reachable");
    let status = response.status();
    let body: Value = response.json().await.expect("admin token response is JSON");
    assert!(status.is_success(), "admin token grant failed: {body}");
    body["access_token"].as_str().unwrap().to_owned()
}

fn settings(base: &str) -> OidcSettings {
    // Through configuration, not a struct literal: the point is that the
    // Keycloak profile's *defaults* (the `certs` URL, `sub`, `groups`)
    // resolve against a real realm from nothing but issuer and audience.
    let config = Config::from_map(HashMap::from([
        ("MCP_OIDC_PROFILE".to_owned(), "keycloak".to_owned()),
        (
            "MCP_OIDC_ISSUER".to_owned(),
            format!("{base}/realms/{REALM}"),
        ),
        ("MCP_OIDC_AUDIENCE".to_owned(), AUDIENCE.to_owned()),
        ("MCP_TENANT".to_owned(), "acme".to_owned()),
    ]));
    let mut settings =
        OidcSettings::from_config(&config, OidcKeys::Oidc).expect("keycloak settings");
    // Rotation below must be observed on the next unknown kid, not 30 s later.
    settings.jwks_min_refetch_interval = Duration::ZERO;
    settings
}

/// The whole proof in one sequence, because it shares one container and
/// its later steps (rotation) change the realm for the earlier ones.
#[tokio::test]
async fn keycloak_realm_tokens_validate_through_the_keycloak_profile_including_rotation() {
    let Some(base) = keycloak_url() else {
        eprintln!("MCP_KEYCLOAK_URL is not set; skipping the Keycloak live test");
        return;
    };
    let http = reqwest::Client::new();
    wait_for_realm(&http, &base).await;
    let issuer = format!("{base}/realms/{REALM}");
    let validator = Arc::new(OidcJwksValidator::new(
        settings(&base),
        reqwest::Client::new(),
    ));

    // 1. A token from the client with the audience mapper: the profile's
    //    defaults read Keycloak's actual claim shapes.
    let alice = password_grant(
        &http,
        &base,
        "mcp-devtools",
        "mcp-devtools-test-secret",
        "alice",
        "alice-password",
    )
    .await;
    let principal = validator
        .validate(&alice)
        .await
        .expect("alice's token validates");
    let claims = unverified_claims(&alice);
    assert_eq!(principal.subject, claims["sub"].as_str().unwrap());
    assert_eq!(principal.tenant, "acme");
    assert_eq!(principal.authority, PrincipalAuthority::oidc(&issuer));
    assert_eq!(
        principal.groups,
        vec!["engineering/platform", "finance"],
        "full-path group membership, the mapper's leading slash removed; \
         raw claim was {}",
        claims["groups"]
    );
    assert!(
        principal.scopes.contains(&"openid".to_owned()),
        "Keycloak's `scope` string is read: {:?}",
        principal.scopes
    );
    assert!(
        claims["aud"]
            .as_array()
            .is_some_and(|aud| aud.iter().any(|a| a == AUDIENCE))
            || claims["aud"] == AUDIENCE,
        "the audience mapper put our audience in `aud`: {}",
        claims["aud"]
    );

    // 2. A user in no groups is a principal with no groups — not an error.
    let bob = password_grant(
        &http,
        &base,
        "mcp-devtools",
        "mcp-devtools-test-secret",
        "bob",
        "bob-password",
    )
    .await;
    let bob_principal = validator
        .validate(&bob)
        .await
        .expect("bob's token validates");
    assert!(bob_principal.groups.is_empty());

    // 3. The default Keycloak token shape — no audience mapper — carries
    //    `aud: account` only (or nothing of ours), and is refused. This is
    //    the "Keycloak `aud`" row of plan §3.9: a runbook step, not a
    //    relaxation.
    let unmapped = password_grant(
        &http,
        &base,
        "mcp-unmapped",
        "mcp-unmapped-test-secret",
        "alice",
        "alice-password",
    )
    .await;
    let unmapped_claims = unverified_claims(&unmapped);
    assert_ne!(
        unmapped_claims["aud"], AUDIENCE,
        "precondition: the unmapped client must not emit our audience"
    );
    // Keycloak 26 emits no `aud` at all here; older realms whose `roles`
    // scope still adds the `account` client emit `aud: "account"`. Both
    // are refusals, and neither is ours to relax.
    let rejection = validator.validate(&unmapped).await.unwrap_err();
    assert!(
        matches!(
            rejection,
            TokenRejection::MissingClaim("aud") | TokenRejection::WrongAudience
        ),
        "a token without the audience mapper is refused, got {rejection:?}: {unmapped_claims}"
    );

    rotation_and_withdrawal(&http, &base, &validator, &alice, &principal.subject).await;
}

/// Steps 4 and 5: rotate the realm's signing key through the admin API,
/// then withdraw the old one.
async fn rotation_and_withdrawal(
    http: &reqwest::Client,
    base: &str,
    validator: &Arc<OidcJwksValidator>,
    alice: &str,
    subject: &str,
) {
    // 4. Rotation through the admin API: a new RSA key provider with a
    //    higher priority becomes the signing key for every new token. The
    //    validator sees an unknown kid, refetches the real `certs`
    //    endpoint, and validates — and the old token still verifies while
    //    its key is published.
    let admin = admin_token(http, base).await;
    add_signing_key(http, base, &admin).await;
    let old_kid = jsonwebtoken::decode_header(alice).unwrap().kid.unwrap();
    let rotated = password_grant(
        http,
        base,
        "mcp-devtools",
        "mcp-devtools-test-secret",
        "alice",
        "alice-password",
    )
    .await;
    let new_kid = jsonwebtoken::decode_header(&rotated).unwrap().kid.unwrap();
    assert_ne!(old_kid, new_kid, "the realm signs with the new key");
    let after_rotation = validator
        .validate(&rotated)
        .await
        .expect("a token under the rotated key validates after the refetch");
    assert_eq!(after_rotation.subject, subject);
    assert!(
        validator.validate(alice).await.is_ok(),
        "the previous key is still published, so tokens under it still verify"
    );

    // 5. Withdrawal: disable the old key provider. The next key fetch no
    //    longer lists it, which evicts every cached validation it vouched
    //    for; the old token is then unknown, not served from the cache.
    disable_key_provider(http, base, &admin, &old_kid).await;
    validator
        .refresh_keys()
        .await
        .expect("the certs endpoint is fetched after the withdrawal");
    assert_eq!(
        validator.validate(alice).await.unwrap_err(),
        TokenRejection::UnknownKey,
        "a token under a withdrawn key is not served from the validated cache"
    );
    assert!(
        validator.validate(&rotated).await.is_ok(),
        "the rotated key keeps serving"
    );
}

async fn admin_get(http: &reqwest::Client, admin: &str, url: String) -> Value {
    http.get(url)
        .bearer_auth(admin)
        .send()
        .await
        .expect("admin API reachable")
        .json()
        .await
        .expect("admin API answers JSON")
}

/// Add an RSA key provider with a higher priority than the realm's
/// generated default, so every new token is signed by it.
async fn add_signing_key(http: &reqwest::Client, base: &str, admin: &str) {
    let realm = admin_get(http, admin, format!("{base}/admin/realms/{REALM}")).await;
    let priority = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let created = http
        .post(format!("{base}/admin/realms/{REALM}/components"))
        .bearer_auth(admin)
        .json(&json!({
            "name": "rotated-by-keycloak-live-test",
            "providerId": "rsa-generated",
            "providerType": "org.keycloak.keys.KeyProvider",
            "parentId": realm["id"],
            "config": {
                // Above any key the realm already has, including one a
                // previous run of this test left behind.
                "priority": [priority],
                "enabled": ["true"],
                "active": ["true"],
                "algorithm": ["RS256"],
                "keySize": ["2048"],
            }
        }))
        .send()
        .await
        .unwrap();
    assert!(
        created.status().is_success(),
        "creating the rotated key failed: {} {}",
        created.status(),
        created.text().await.unwrap_or_default()
    );
}

/// Disable the provider behind `kid`, which removes the key from the
/// realm's `certs` document.
async fn disable_key_provider(http: &reqwest::Client, base: &str, admin: &str, kid: &str) {
    let keys = admin_get(http, admin, format!("{base}/admin/realms/{REALM}/keys")).await;
    let provider = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["kid"] == kid)
        .and_then(|key| key["providerId"].as_str())
        .expect("the kid's provider is listed")
        .to_owned();
    let url = format!("{base}/admin/realms/{REALM}/components/{provider}");
    let mut component = admin_get(http, admin, url.clone()).await;
    component["config"]["enabled"] = json!(["false"]);
    component["config"]["active"] = json!(["false"]);
    let disabled = http
        .put(url)
        .bearer_auth(admin)
        .json(&component)
        .send()
        .await
        .unwrap();
    assert!(
        disabled.status().is_success(),
        "disabling the old key failed: {}",
        disabled.status()
    );
}

/// The payload, decoded without verification — for assertions about what
/// Keycloak *emitted*, never as an input to the validator under test.
fn unverified_claims(token: &str) -> Value {
    use base64::Engine as _;
    let payload = token.split('.').nth(1).expect("three-part JWT");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    serde_json::from_slice(&bytes).expect("JSON claims")
}

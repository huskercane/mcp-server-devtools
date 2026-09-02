//! WP A.1 / A.10: the JWKS negative matrix against a wiremock identity provider.
//!
//! Every test signs real RS256 tokens with the checked-in test key
//! (`tests/fixtures/okta_test_rsa_pkcs1.der`, generated for this suite and
//! used nowhere else) and serves its public half as a JWKS from wiremock, so
//! what is exercised is the production validator end to end: header parsing,
//! key lookup, rotation, signature verification, claim validation, and the
//! two caches.

use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, get_current_timestamp};
use mcp_server_devtools::auth::okta::{OktaJwksValidator, OktaSettings};
use mcp_server_devtools::policy::PrincipalAuthority;
use mcp_server_devtools::ports::{TokenRejection, TokenValidator};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PRIVATE_KEY_DER: &[u8] = include_bytes!("fixtures/okta_test_rsa_pkcs1.der");
const PUBLIC_JWK: &str = include_str!("fixtures/okta_test_jwk.json");
const ISSUER: &str = "https://acme.okta.com/oauth2/default";
const AUDIENCE: &str = "api://mcp-devtools";

fn jwk_with_kid(kid: &str) -> Value {
    let mut jwk: Value = serde_json::from_str(PUBLIC_JWK).unwrap();
    jwk["kid"] = json!(kid);
    jwk
}

fn jwks(kids: &[&str]) -> Value {
    json!({ "keys": kids.iter().map(|kid| jwk_with_kid(kid)).collect::<Vec<_>>() })
}

async fn mount_jwks(server: &MockServer, kids: &[&str], expect: Option<u64>) {
    let mut mock = Mock::given(method("GET"))
        .and(path("/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks(kids)));
    if let Some(expected) = expect {
        mock = mock.expect(expected);
    }
    mock.mount(server).await;
}

fn settings(server: &MockServer) -> OktaSettings {
    OktaSettings {
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
        jwks_url: format!("{}/keys", server.uri()),
        groups_claim: "groups".to_owned(),
        clock_skew: Duration::from_mins(1),
        tenant: "acme".to_owned(),
        jwks_refresh: Duration::from_mins(10),
        jwks_min_refetch_interval: Duration::from_secs(30),
    }
}

fn validator(settings: OktaSettings) -> Arc<OktaJwksValidator> {
    Arc::new(OktaJwksValidator::new(settings, reqwest::Client::new()))
}

fn base_claims() -> Value {
    let now = get_current_timestamp();
    json!({
        "sub": "alice@acme.example",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 300,
        "scp": ["mcp:tools", "openid"],
        "groups": ["SRE", "Developers"],
    })
}

fn sign_with_kid(claims: &Value, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    encode(&header, claims, &EncodingKey::from_rsa_der(PRIVATE_KEY_DER)).unwrap()
}

fn sign(claims: &Value) -> String {
    sign_with_kid(claims, "test-key-1")
}

#[tokio::test]
async fn a_valid_token_yields_a_principal_with_claims_mapped() {
    let server = MockServer::start().await;
    mount_jwks(&server, &["test-key-1"], Some(1)).await;
    let validator = validator(settings(&server));

    let principal = validator.validate(&sign(&base_claims())).await.unwrap();
    assert_eq!(principal.tenant, "acme");
    assert_eq!(principal.subject, "alice@acme.example");
    assert_eq!(principal.groups, vec!["Developers", "SRE"]);
    assert_eq!(principal.scopes, vec!["mcp:tools", "openid"]);
    assert_eq!(principal.authority, PrincipalAuthority::Okta);

    // Second validation of the same token: served from the validated-token
    // cache, so the JWKS is still fetched exactly once (`expect(1)`).
    let again = validator.validate(&sign(&base_claims())).await.unwrap();
    assert_eq!(again.subject, principal.subject);
}

#[tokio::test]
async fn space_separated_scope_claim_and_custom_groups_claim_are_read() {
    let server = MockServer::start().await;
    mount_jwks(&server, &["test-key-1"], None).await;
    let mut settings = settings(&server);
    settings.groups_claim = "roles".to_owned();
    let validator = validator(settings);

    let mut claims = base_claims();
    claims.as_object_mut().unwrap().remove("scp");
    claims.as_object_mut().unwrap().remove("groups");
    claims["scope"] = json!("mcp:tools mcp:admin");
    claims["roles"] = json!(["Auditors", 42, "Auditors"]);
    let principal = validator.validate(&sign(&claims)).await.unwrap();
    assert_eq!(principal.scopes, vec!["mcp:admin", "mcp:tools"]);
    assert_eq!(
        principal.groups,
        vec!["Auditors"],
        "non-strings dropped, deduplicated"
    );
}

/// The negative matrix. Each row is one way a token can be wrong, and the
/// category the validator must report — never anything more.
// One table, one function: splitting the rows across helpers would hide the
// matrix this test exists to show.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn the_negative_matrix() {
    let server = MockServer::start().await;
    mount_jwks(&server, &["test-key-1"], None).await;
    let validator = validator(settings(&server));
    let now = get_current_timestamp();

    let mut expired = base_claims();
    expired["exp"] = json!(now - 600);
    let mut not_yet = base_claims();
    not_yet["nbf"] = json!(now + 600);
    let mut wrong_iss = base_claims();
    wrong_iss["iss"] = json!("https://evil.okta.com/oauth2/default");
    let mut wrong_aud = base_claims();
    wrong_aud["aud"] = json!("api://someone-else");
    let mut aud_list_without_us = base_claims();
    aud_list_without_us["aud"] = json!(["api://a", "api://b"]);
    let mut no_sub = base_claims();
    no_sub.as_object_mut().unwrap().remove("sub");
    let mut no_exp = base_claims();
    no_exp.as_object_mut().unwrap().remove("exp");
    let mut no_aud = base_claims();
    no_aud.as_object_mut().unwrap().remove("aud");

    let valid = sign(&base_claims());
    let tampered = {
        let mut parts: Vec<&str> = valid.split('.').collect();
        let payload = base64_url(
            &serde_json::to_vec(&{
                let mut claims = base_claims();
                claims["groups"] = json!(["Admins"]);
                claims
            })
            .unwrap(),
        );
        parts[1] = &payload;
        parts.join(".")
    };
    let alg_none = format!(
        "{}.{}.",
        base64_url(br#"{"alg":"none","typ":"JWT","kid":"test-key-1"}"#),
        base64_url(&serde_json::to_vec(&base_claims()).unwrap())
    );
    // Key confusion: HMAC-sign with the public key material as the secret.
    let hs256 = {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key-1".to_owned());
        encode(
            &header,
            &base_claims(),
            &EncodingKey::from_secret(PUBLIC_JWK.as_bytes()),
        )
        .unwrap()
    };

    let rows: Vec<(&str, String, TokenRejection)> = vec![
        ("expired", sign(&expired), TokenRejection::Expired),
        ("not yet valid", sign(&not_yet), TokenRejection::NotYetValid),
        (
            "wrong issuer",
            sign(&wrong_iss),
            TokenRejection::WrongIssuer,
        ),
        (
            "wrong audience",
            sign(&wrong_aud),
            TokenRejection::WrongAudience,
        ),
        (
            "audience list without us",
            sign(&aud_list_without_us),
            TokenRejection::WrongAudience,
        ),
        (
            "missing sub",
            sign(&no_sub),
            TokenRejection::MissingClaim("sub"),
        ),
        (
            "missing exp",
            sign(&no_exp),
            TokenRejection::MissingClaim("exp"),
        ),
        (
            "missing aud",
            sign(&no_aud),
            TokenRejection::MissingClaim("aud"),
        ),
        (
            "tampered payload",
            tampered,
            TokenRejection::InvalidSignature,
        ),
        ("alg none", alg_none, TokenRejection::Malformed),
        (
            "HS256 key confusion",
            hs256,
            TokenRejection::UnsupportedAlgorithm,
        ),
        (
            "unknown kid",
            sign_with_kid(&base_claims(), "rotated-away"),
            TokenRejection::UnknownKey,
        ),
        (
            "no kid",
            {
                let header = Header::new(Algorithm::RS256);
                encode(
                    &header,
                    &base_claims(),
                    &EncodingKey::from_rsa_der(PRIVATE_KEY_DER),
                )
                .unwrap()
            },
            TokenRejection::UnknownKey,
        ),
        ("garbage", "not.a.jwt".to_owned(), TokenRejection::Malformed),
        ("empty", String::new(), TokenRejection::Malformed),
    ];
    for (label, token, expected) in rows {
        let rejection = validator
            .validate(&token)
            .await
            .expect_err(&format!("{label}: must be rejected"));
        assert_eq!(rejection, expected, "{label}");
        // Nothing about the token in the rejection.
        let text = format!("{rejection} {rejection:?}");
        assert!(
            token.is_empty() || !text.contains(&token),
            "{label}: rejection leaks the token"
        );
        assert!(!text.contains("alice"), "{label}: rejection leaks a claim");
    }

    // And the matrix did not poison the valid path.
    assert!(validator.validate(&valid).await.is_ok());
}

#[tokio::test]
async fn an_unknown_kid_refetches_the_jwks_once_within_the_rate_limit() {
    let server = MockServer::start().await;
    // Exactly two fetches: the initial one, and one refetch for the first
    // unknown kid. The second unknown kid inside the interval must not fetch.
    mount_jwks(&server, &["test-key-1"], Some(2)).await;
    let validator = validator(settings(&server));

    assert!(validator.validate(&sign(&base_claims())).await.is_ok());
    assert_eq!(
        validator
            .validate(&sign_with_kid(&base_claims(), "unknown-a"))
            .await
            .unwrap_err(),
        TokenRejection::UnknownKey
    );
    assert_eq!(
        validator
            .validate(&sign_with_kid(&base_claims(), "unknown-b"))
            .await
            .unwrap_err(),
        TokenRejection::UnknownKey
    );
}

#[tokio::test]
async fn key_rotation_is_picked_up_on_refetch() {
    let server = MockServer::start().await;
    mount_jwks(&server, &["test-key-1"], None).await;
    let mut settings = settings(&server);
    settings.jwks_min_refetch_interval = Duration::ZERO;
    let validator = validator(settings);

    assert!(validator.validate(&sign(&base_claims())).await.is_ok());
    let rotated = sign_with_kid(&base_claims(), "test-key-2");
    assert_eq!(
        validator.validate(&rotated).await.unwrap_err(),
        TokenRejection::UnknownKey
    );

    // The identity provider rotates: the new kid appears in the JWKS.
    server.reset().await;
    mount_jwks(&server, &["test-key-1", "test-key-2"], None).await;
    assert!(
        validator.validate(&rotated).await.is_ok(),
        "a rotated key must be accepted after the refetch"
    );
}

#[tokio::test]
async fn unreachable_jwks_fails_closed_and_recovers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/keys"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    let mut settings = settings(&server);
    settings.jwks_min_refetch_interval = Duration::ZERO;
    let validator = validator(settings);

    let rejection = validator.validate(&sign(&base_claims())).await.unwrap_err();
    assert_eq!(rejection, TokenRejection::KeysUnavailable);
    assert!(rejection.is_server_side());

    // Once the identity provider is back, the same validator serves tokens: a transient
    // outage must not become a permanent lockout.
    mount_jwks(&server, &["test-key-1"], None).await;
    assert!(validator.validate(&sign(&base_claims())).await.is_ok());
}

#[tokio::test]
async fn stale_keys_keep_serving_while_a_background_refresh_fails() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks(&["test-key-1"])))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/keys"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let mut settings = settings(&server);
    settings.jwks_refresh = Duration::ZERO; // every validation is "stale"
    let validator = validator(settings);

    assert!(validator.validate(&sign(&base_claims())).await.is_ok());
    // A different token (cache miss) triggers a background refresh that
    // fails; the cached keys still validate it.
    let mut other = base_claims();
    other["sub"] = json!("bob@acme.example");
    let principal = validator.validate(&sign(&other)).await.unwrap();
    assert_eq!(principal.subject, "bob@acme.example");
}

/// The positive edges of the matrix: an `aud` array that contains us, and
/// `exp` / `nbf` inside the configured leeway (60 s) but not outside it.
#[tokio::test]
async fn audience_arrays_and_leeway_boundaries_are_accepted_exactly_as_configured() {
    let server = MockServer::start().await;
    mount_jwks(&server, &["test-key-1"], None).await;
    let validator = validator(settings(&server));
    let now = get_current_timestamp();

    let mut aud_list_with_us = base_claims();
    aud_list_with_us["aud"] = json!(["api://a", AUDIENCE, "api://b"]);
    assert!(validator.validate(&sign(&aud_list_with_us)).await.is_ok());

    let mut just_expired = base_claims();
    just_expired["exp"] = json!(now - 30);
    assert!(
        validator.validate(&sign(&just_expired)).await.is_ok(),
        "30 s past exp is inside the 60 s leeway"
    );
    let mut too_expired = base_claims();
    too_expired["exp"] = json!(now - 90);
    assert_eq!(
        validator.validate(&sign(&too_expired)).await.unwrap_err(),
        TokenRejection::Expired
    );

    let mut nearly_valid = base_claims();
    nearly_valid["nbf"] = json!(now + 30);
    assert!(
        validator.validate(&sign(&nearly_valid)).await.is_ok(),
        "30 s before nbf is inside the 60 s leeway"
    );
    let mut too_early = base_claims();
    too_early["nbf"] = json!(now + 90);
    assert_eq!(
        validator.validate(&sign(&too_early)).await.unwrap_err(),
        TokenRejection::NotYetValid
    );
}

/// `jku` and `x5u` in a token header name where *the token* says its keys
/// live. They are ignored: only the configured JWKS URL is ever fetched, so
/// a token cannot direct the validator to a key set of its own choosing.
#[tokio::test]
async fn jku_and_x5u_headers_are_ignored_in_favour_of_the_configured_jwks() {
    let server = MockServer::start().await;
    mount_jwks(&server, &["test-key-1"], None).await;
    let mut settings = settings(&server);
    settings.jwks_min_refetch_interval = Duration::ZERO;
    let validator = validator(settings);

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".to_owned());
    header.jku = Some("https://attacker.example/keys".to_owned());
    header.x5u = Some("https://attacker.example/cert.pem".to_owned());
    let token = encode(
        &header,
        &base_claims(),
        &EncodingKey::from_rsa_der(PRIVATE_KEY_DER),
    )
    .unwrap();
    // Validates against the configured JWKS; the header's URLs are never
    // contacted (there is nothing there to contact).
    assert!(validator.validate(&token).await.is_ok());

    let mut foreign_kid = Header::new(Algorithm::RS256);
    foreign_kid.kid = Some("attacker-key".to_owned());
    foreign_kid.jku = Some("https://attacker.example/keys".to_owned());
    let token = encode(
        &foreign_kid,
        &base_claims(),
        &EncodingKey::from_rsa_der(PRIVATE_KEY_DER),
    )
    .unwrap();
    // An unknown kid refetches — the *configured* JWKS, not the header's.
    assert_eq!(
        validator.validate(&token).await.unwrap_err(),
        TokenRejection::UnknownKey
    );
    let fetched = server.received_requests().await.unwrap();
    assert_eq!(fetched.len(), 2, "initial fetch + unknown-kid refetch");
    assert!(
        fetched.iter().all(|request| request.url.path() == "/keys"),
        "every key fetch went to the configured JWKS URL"
    );
}

/// A key the identity provider withdraws must stop vouching for tokens at
/// the next JWKS fetch — not when the validated-token cache entry ages out
/// five minutes later.
#[tokio::test]
async fn withdrawing_a_key_evicts_tokens_it_validated_from_the_cache() {
    let server = MockServer::start().await;
    mount_jwks(&server, &["test-key-1"], None).await;
    let mut settings = settings(&server);
    settings.jwks_min_refetch_interval = Duration::ZERO;
    let validator = validator(settings);

    let under_old_key = sign_with_kid(&base_claims(), "test-key-1");
    assert!(validator.validate(&under_old_key).await.is_ok());
    // Cached now: served without a fetch.
    assert!(validator.validate(&under_old_key).await.is_ok());

    // The identity provider withdraws test-key-1 and publishes test-key-2.
    // A token under the new kid triggers the refetch that observes it.
    server.reset().await;
    mount_jwks(&server, &["test-key-2"], None).await;
    assert!(
        validator
            .validate(&sign_with_kid(&base_claims(), "test-key-2"))
            .await
            .is_ok()
    );

    assert_eq!(
        validator.validate(&under_old_key).await.unwrap_err(),
        TokenRejection::UnknownKey,
        "a token verified by a withdrawn key must not be served from the cache"
    );
}

/// Only RSA signing keys are admitted, and an ambiguous `kid` admits nothing.
#[tokio::test]
async fn jwks_admission_is_rsa_signing_keys_with_unambiguous_kids() {
    let ec_under_same_kid = json!({
        "kty": "EC", "crv": "P-256", "kid": "test-key-1", "use": "sig",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    });
    let mut encryption_only = jwk_with_kid("test-key-1");
    encryption_only["use"] = json!("enc");
    let mut ps256 = jwk_with_kid("test-key-1");
    ps256["alg"] = json!("PS256");

    let cases: Vec<(&str, Vec<Value>, bool)> = vec![
        (
            "an EC entry after the RSA entry under the same kid does not replace it",
            vec![jwk_with_kid("test-key-1"), ec_under_same_kid.clone()],
            true,
        ),
        (
            "an EC entry before the RSA entry under the same kid is not the one kept",
            vec![ec_under_same_kid, jwk_with_kid("test-key-1")],
            true,
        ),
        (
            "an RSA key published for encryption is not a signing key",
            vec![encryption_only],
            false,
        ),
        (
            "an RSA key published for PS256 is not an RS256 key",
            vec![ps256],
            false,
        ),
        (
            "two RSA signing keys under one kid are ambiguous: neither is admitted",
            vec![jwk_with_kid("test-key-1"), jwk_with_kid("test-key-1")],
            false,
        ),
    ];
    for (case, keys, accepted) in cases {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": keys })))
            .mount(&server)
            .await;
        let validator = validator(settings(&server));
        let result = validator.validate(&sign(&base_claims())).await;
        if accepted {
            assert!(result.is_ok(), "{case}: {result:?}");
        } else {
            assert_eq!(result.unwrap_err(), TokenRejection::UnknownKey, "{case}");
        }
    }
}

/// The JWKS size bound is enforced on the declared length *and* while a
/// body with no declared length is being read — the process never buffers
/// an oversized document before refusing it.
#[tokio::test]
async fn oversized_jwks_is_refused_whether_or_not_its_length_is_declared() {
    // Declared: `Content-Length` is over the bound, refused before the body.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b' '; 512 * 1024]))
        .mount(&server)
        .await;
    let declared = validator(settings(&server));
    assert_eq!(
        declared.validate(&sign(&base_claims())).await.unwrap_err(),
        TokenRejection::KeysUnavailable
    );

    // Undeclared: a chunked response that never ends. The validator must
    // abort at the bound; the server records how much it managed to send.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sent_by_server = Arc::clone(&sent);
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") && socket.read(&mut byte).await.unwrap_or(0) > 0 {
            request.push(byte[0]);
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                  Transfer-Encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
        let chunk = vec![b' '; 64 * 1024];
        // Up to 64 MiB, or until the client hangs up.
        for _ in 0..1024 {
            let framed = format!("{:x}\r\n", chunk.len());
            if socket.write_all(framed.as_bytes()).await.is_err()
                || socket.write_all(&chunk).await.is_err()
                || socket.write_all(b"\r\n").await.is_err()
            {
                break;
            }
            sent_by_server.fetch_add(chunk.len(), std::sync::atomic::Ordering::SeqCst);
        }
    });
    let mut chunked = settings(&server);
    chunked.jwks_url = format!("http://{addr}/keys");
    let undeclared = validator(chunked);
    assert_eq!(
        undeclared
            .validate(&sign(&base_claims()))
            .await
            .unwrap_err(),
        TokenRejection::KeysUnavailable
    );
    // Socket buffers absorb a little past the bound; megabytes would mean
    // the body was being collected whole.
    let sent = sent.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        sent < 4 * 1024 * 1024,
        "the validator kept reading past the bound: {sent} bytes"
    );
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

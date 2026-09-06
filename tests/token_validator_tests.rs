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
use mcp_server_devtools::auth::oidc::{JwksLocation, OidcJwksValidator, OidcSettings, Profile};
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

fn settings(server: &MockServer) -> OidcSettings {
    OidcSettings::new(
        Profile::Okta,
        ISSUER,
        AUDIENCE,
        JwksLocation::Direct(format!("{}/keys", server.uri())),
    )
    .with_tenant("acme")
}

fn validator(settings: OidcSettings) -> Arc<OidcJwksValidator> {
    Arc::new(OidcJwksValidator::new(settings, reqwest::Client::new()))
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
    assert_eq!(
        principal.authority,
        PrincipalAuthority::oidc("https://acme.okta.com/oauth2/default")
    );

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
    settings.groups_claim = Some("roles".to_owned());
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
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("jwks.json");
    tokio::fs::write(&file, jwks(&["test-key-1"]).to_string())
        .await
        .unwrap();
    let file_validator = Arc::new(OidcJwksValidator::new(
        OidcSettings::new(
            Profile::Okta,
            ISSUER,
            AUDIENCE,
            JwksLocation::File(file.to_str().unwrap().to_owned()),
        ),
        reqwest::Client::new(),
    ));
    let now = get_current_timestamp();

    let mut expired = base_claims();
    expired["exp"] = json!(now - 600);
    let mut not_yet = base_claims();
    not_yet["nbf"] = json!(now + 600);
    // A correctly signed token whose issue time is in the future would
    // outrun every `revoke all` cut-off and count as freshly minted for
    // writes; it is refused before anything is cached.
    let mut issued_in_future = base_claims();
    issued_in_future["iat"] = json!(now + 600);
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
            "issued in the future",
            sign(&issued_in_future),
            TokenRejection::NotYetValid,
        ),
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
        assert_eq!(
            file_validator.validate(&token).await.unwrap_err(),
            expected,
            "file: {label}"
        );
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
    // An `iat` inside the configured skew (60 s here) is clock drift, not
    // a forgery, and is accepted.
    let mut within_skew = base_claims();
    within_skew["iat"] = json!(now + 30);
    assert!(validator.validate(&sign(&within_skew)).await.is_ok());
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

/// A `kid` is a label, not the key. When the identity provider publishes
/// new material under a kid it used before, tokens verified against the old
/// material must not keep being served from the cache.
#[tokio::test]
async fn republishing_a_kid_with_new_material_evicts_tokens_it_validated() {
    let server = MockServer::start().await;
    mount_jwks(&server, &["test-key-1"], None).await;
    let mut settings = settings(&server);
    settings.jwks_min_refetch_interval = Duration::ZERO;
    let validator = validator(settings);

    let token = sign(&base_claims());
    assert!(validator.validate(&token).await.is_ok());
    assert!(validator.validate(&token).await.is_ok(), "cached");

    // Same kid, different modulus.
    let mut rotated = jwk_with_kid("test-key-1");
    let modulus = rotated["n"].as_str().unwrap().to_owned();
    rotated["n"] = json!(format!("AAAAAAAA{}", &modulus[8..]));
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [rotated] })))
        .mount(&server)
        .await;
    // An unknown kid triggers the refetch that observes the rotation.
    let _ = validator
        .validate(&sign_with_kid(&base_claims(), "test-key-2"))
        .await;

    assert!(
        validator.validate(&token).await.is_err(),
        "a token verified against the old material must be re-verified — and \
         fail — against the new material, not served from the cache"
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
    chunked.jwks = JwksLocation::Direct(format!("http://{addr}/keys"));
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

// ---------------------------------------------------------------------------
// Provider profiles (WP C.1b, plan §3.9): the same validator, a different
// profile, and one fixture per claim-shape gotcha the §3.9 table records.
// Every token below is signed by the same test key; what differs is the
// claim shape each provider actually emits.
// ---------------------------------------------------------------------------

/// Settings for a profile whose issuer lives on the wiremock server, keys
/// wherever the profile's default says (relative to that issuer).
fn profile_settings(profile: Profile, issuer: &str) -> OidcSettings {
    let jwks = profile.default_jwks(issuer.trim_end_matches('/'));
    OidcSettings::new(profile, issuer, AUDIENCE, jwks).with_tenant("acme")
}

async fn mount_jwks_at(server: &MockServer, at: &str, kids: &[&str]) {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks(kids)))
        .mount(server)
        .await;
}

/// Entra: keys are found through the discovery document, `scp` is one
/// space-separated string, and the subject is `oid` — `sub` is pairwise
/// per application and must not be what policy and revocation bind to.
#[tokio::test]
async fn entra_profile_reads_keys_through_discovery_scp_as_a_string_and_oid_as_the_subject() {
    let server = MockServer::start().await;
    let tenant = "1f2e3d4c-0000-4000-8000-000000000000";
    let issuer = format!("{}/{tenant}/v2.0", server.uri());
    Mock::given(method("GET"))
        .and(path(format!(
            "/{tenant}/v2.0/.well-known/openid-configuration"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer,
            "jwks_uri": format!("{}/{tenant}/discovery/v2.0/keys", server.uri()),
            "token_endpoint": format!("{}/{tenant}/oauth2/v2.0/token", server.uri()),
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_jwks_at(
        &server,
        &format!("/{tenant}/discovery/v2.0/keys"),
        &["test-key-1"],
    )
    .await;
    let validator = validator(profile_settings(Profile::Entra, &issuer));

    let now = get_current_timestamp();
    let claims = json!({
        "iss": issuer,
        "aud": AUDIENCE,
        "iat": now, "nbf": now, "exp": now + 300,
        "sub": "AAAAAAAAAAAAAAAAAAAAAPairwisePerApplication",
        "oid": "5d6a4a3b-1111-4222-8333-444444444444",
        "preferred_username": "alice@acme.example",
        "scp": "mcp:tools openid profile",
        "groups": ["8b4f1c00-aaaa-4bbb-8ccc-dddddddddddd", "SRE"],
        "tid": tenant,
        "ver": "2.0",
    });
    let principal = validator.validate(&sign(&claims)).await.unwrap();
    assert_eq!(
        principal.subject, "5d6a4a3b-1111-4222-8333-444444444444",
        "the subject is `oid`, never the pairwise `sub`"
    );
    assert_eq!(principal.scopes, vec!["mcp:tools", "openid", "profile"]);
    assert_eq!(
        principal.groups,
        vec!["8b4f1c00-aaaa-4bbb-8ccc-dddddddddddd", "SRE"]
    );
    assert_eq!(principal.authority, PrincipalAuthority::oidc(&issuer));

    // Discovery is exact: a document answering for another issuer (a
    // multi-tenant endpoint, or the wrong tenant) yields no keys at all.
    let other = MockServer::start().await;
    let configured = format!("{}/{tenant}/v2.0", other.uri());
    Mock::given(method("GET"))
        .and(path(format!(
            "/{tenant}/v2.0/.well-known/openid-configuration"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": format!("{}/{{tenantid}}/v2.0", other.uri()),
            "jwks_uri": format!("{}/common/discovery/v2.0/keys", other.uri()),
        })))
        .mount(&other)
        .await;
    mount_jwks_at(&other, "/common/discovery/v2.0/keys", &["test-key-1"]).await;
    let wrong_tenant = self::validator(profile_settings(Profile::Entra, &configured));
    let mut for_other = claims.clone();
    for_other["iss"] = json!(configured);
    assert_eq!(
        wrong_tenant.validate(&sign(&for_other)).await.unwrap_err(),
        TokenRejection::KeysUnavailable,
        "a discovery document for a different issuer must not supply keys"
    );
    assert!(
        other
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.url.path().ends_with("openid-configuration")),
        "the jwks_uri of a mismatched discovery document is never fetched"
    );
}

/// Entra groups overage: past ~200 groups the token carries no `groups`
/// claim and says so with `_claim_names` / `_claim_sources` (or the older
/// `hasgroups`). Reading that as "no groups" would consult policy with a
/// false membership list; the token is refused instead. A token that
/// simply has no groups is still fine, and app roles are readable as the
/// groups claim.
#[tokio::test]
async fn entra_groups_overage_fails_closed_and_app_roles_can_be_the_groups_claim() {
    let server = MockServer::start().await;
    let issuer = format!("{}/tenant/v2.0", server.uri());
    Mock::given(method("GET"))
        .and(path("/tenant/v2.0/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer,
            "jwks_uri": format!("{}/tenant/discovery/v2.0/keys", server.uri()),
        })))
        .mount(&server)
        .await;
    mount_jwks_at(&server, "/tenant/discovery/v2.0/keys", &["test-key-1"]).await;
    let validator = validator(profile_settings(Profile::Entra, &issuer));

    let now = get_current_timestamp();
    let base = json!({
        "iss": issuer, "aud": AUDIENCE, "iat": now, "exp": now + 300,
        "sub": "pairwise", "oid": "oid-1", "scp": "mcp:tools",
    });
    let mut overage = base.clone();
    overage["_claim_names"] = json!({ "groups": "src1" });
    overage["_claim_sources"] = json!({
        "src1": { "endpoint": "https://graph.microsoft.com/v1.0/users/oid-1/getMemberObjects" }
    });
    let rejection = validator.validate(&sign(&overage)).await.unwrap_err();
    assert_eq!(rejection, TokenRejection::GroupsOverage);
    assert!(
        !rejection.is_server_side(),
        "the fix is at the identity provider, not here"
    );
    assert_eq!(rejection.category(), "groups_overage");

    let mut v1_overage = base.clone();
    v1_overage["hasgroups"] = json!(true);
    assert_eq!(
        validator.validate(&sign(&v1_overage)).await.unwrap_err(),
        TokenRejection::GroupsOverage
    );

    // No groups and no overage marker: a user in no groups, which is a
    // principal policy may still allow by subject or scope.
    let principal = validator.validate(&sign(&base)).await.unwrap();
    assert!(principal.groups.is_empty());

    // `_claim_names` naming some *other* claim is not a groups overage.
    let mut other_claim = base.clone();
    other_claim["_claim_names"] = json!({ "manager": "src1" });
    other_claim["groups"] = json!(["SRE"]);
    assert_eq!(
        validator
            .validate(&sign(&other_claim))
            .await
            .unwrap()
            .groups,
        vec!["SRE"]
    );

    // App roles as the groups claim, and no overage check bites on them.
    let mut settings = profile_settings(Profile::Entra, &issuer);
    settings.groups_claim = Some("roles".to_owned());
    let by_roles = self::validator(settings);
    let mut with_roles = base;
    with_roles["roles"] = json!(["Reader", "Auditor"]);
    assert_eq!(
        by_roles.validate(&sign(&with_roles)).await.unwrap().groups,
        vec!["Auditor", "Reader"]
    );
}

/// Keycloak: keys at `protocol/openid-connect/certs`, `scope` as a
/// string, an `aud` that is only `account` until the client has an
/// audience mapper (refused, not relaxed), group paths from the Group
/// Membership mapper normalised, and nested realm roles reachable as a
/// dotted claim path.
#[tokio::test]
async fn keycloak_profile_requires_a_mapped_audience_and_normalises_group_paths() {
    let server = MockServer::start().await;
    let issuer = format!("{}/realms/acme", server.uri());
    mount_jwks_at(
        &server,
        "/realms/acme/protocol/openid-connect/certs",
        &["test-key-1"],
    )
    .await;
    let validator = validator(profile_settings(Profile::Keycloak, &issuer));

    let now = get_current_timestamp();
    // The shape Keycloak 26 emits without an audience mapper (locked
    // against the real realm in `tests/keycloak_live_tests.rs`): no `aud`
    // at all, `azp` naming the client the token was issued *to*.
    let mut default_token = json!({
        "iss": issuer, "azp": "mcp-devtools",
        "iat": now, "exp": now + 300, "typ": "Bearer",
        "sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "preferred_username": "alice",
        "scope": "openid profile email",
        "groups": ["/engineering", "/engineering/platform"],
        "realm_access": { "roles": ["default-roles-acme", "offline_access", "sre"] },
    });
    assert_eq!(
        validator.validate(&sign(&default_token)).await.unwrap_err(),
        TokenRejection::MissingClaim("aud"),
        "without an audience mapper the token names no audience at all; \
         `azp` is who asked for the token, not who it is for"
    );
    // Older realms add the `account` client as the audience instead.
    default_token["aud"] = json!("account");
    assert_eq!(
        validator.validate(&sign(&default_token)).await.unwrap_err(),
        TokenRejection::WrongAudience
    );

    // With the mapper: `aud` gains our audience (Keycloak keeps `account`).
    default_token["aud"] = json!([AUDIENCE, "account"]);
    let principal = validator.validate(&sign(&default_token)).await.unwrap();
    assert_eq!(principal.subject, "f47ac10b-58cc-4372-a567-0e02b2c3d479");
    assert_eq!(principal.scopes, vec!["email", "openid", "profile"]);
    assert_eq!(
        principal.groups,
        vec!["engineering", "engineering/platform"],
        "the mapper's leading slash is not part of the group name"
    );

    // Realm roles are nested; the claim setting is a path.
    let mut settings = profile_settings(Profile::Keycloak, &issuer);
    settings.groups_claim = Some("realm_access.roles".to_owned());
    let by_realm_roles = self::validator(settings);
    assert_eq!(
        by_realm_roles
            .validate(&sign(&default_token))
            .await
            .unwrap()
            .groups,
        vec!["default-roles-acme", "offline_access", "sre"]
    );
}

/// Auth0: the `iss` claim ends in a slash (the configured issuer may or
/// may not), `aud` is an array of the API identifier and the userinfo
/// URL, `scope` is a string, keys live at `.well-known/jwks.json`, and
/// groups exist only as a namespaced custom claim an Action adds — so
/// nothing is read until one is configured.
#[tokio::test]
async fn auth0_profile_accepts_the_trailing_slash_issuer_and_a_namespaced_groups_claim() {
    let server = MockServer::start().await;
    let issuer_with_slash = format!("{}/", server.uri());
    mount_jwks_at(&server, "/.well-known/jwks.json", &["test-key-1"]).await;

    let now = get_current_timestamp();
    let claims = json!({
        "iss": issuer_with_slash,
        "aud": [AUDIENCE, format!("{issuer_with_slash}userinfo")],
        "iat": now, "exp": now + 300,
        "sub": "google-oauth2|103547991597142817347",
        "azp": "client-id",
        "scope": "openid profile mcp:tools",
        "https://acme.example/groups": ["SRE", "Developers"],
    });
    let token = sign(&claims);

    for configured in [server.uri(), issuer_with_slash.clone()] {
        let validator = validator(profile_settings(Profile::Auth0, &configured));
        let principal = validator.validate(&token).await.unwrap();
        assert_eq!(principal.subject, "google-oauth2|103547991597142817347");
        assert_eq!(principal.scopes, vec!["mcp:tools", "openid", "profile"]);
        assert!(
            principal.groups.is_empty(),
            "no groups claim is configured, so none are read — not even one that looks right"
        );
        assert_eq!(
            principal.authority,
            PrincipalAuthority::oidc(&server.uri()),
            "the authority is the trimmed issuer whichever spelling was configured"
        );
    }

    let mut settings = profile_settings(Profile::Auth0, &server.uri());
    settings.groups_claim = Some("https://acme.example/groups".to_owned());
    let with_groups = self::validator(settings);
    assert_eq!(
        with_groups.validate(&token).await.unwrap().groups,
        vec!["Developers", "SRE"],
        "a claim name with dots and slashes is looked up literally"
    );

    // Trailing-slash tolerance is one origin, two spellings — not a prefix
    // match. A different path under the same host is a different issuer.
    let mut other_path = claims;
    other_path["iss"] = json!(format!("{}/tenant2/", server.uri()));
    assert_eq!(
        with_groups.validate(&sign(&other_path)).await.unwrap_err(),
        TokenRejection::WrongIssuer
    );
}

/// The generic profile is the spec shape: discovery, `sub`, `groups`,
/// values as they come. And the Okta profile still spells `scp` as an
/// array — the string form is accepted everywhere, not traded for it.
#[tokio::test]
async fn generic_profile_uses_discovery_and_every_profile_accepts_both_scope_shapes() {
    let server = MockServer::start().await;
    let issuer = format!("{}/oidc", server.uri());
    Mock::given(method("GET"))
        .and(path("/oidc/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": format!("{issuer}/"),
            "jwks_uri": format!("{}/oidc/jwks", server.uri()),
        })))
        .mount(&server)
        .await;
    mount_jwks_at(&server, "/oidc/jwks", &["test-key-1"]).await;
    let validator = validator(profile_settings(Profile::Generic, &issuer));

    let now = get_current_timestamp();
    let mut claims = json!({
        "iss": issuer, "aud": AUDIENCE, "iat": now, "exp": now + 300,
        "sub": "alice", "scp": "mcp:tools", "scope": ["openid", "mcp:admin"],
        "groups": ["/not-normalised", "SRE"],
    });
    let principal = validator.validate(&sign(&claims)).await.unwrap();
    assert_eq!(principal.subject, "alice");
    assert_eq!(principal.scopes, vec!["mcp:admin", "mcp:tools", "openid"]);
    assert_eq!(principal.groups, vec!["/not-normalised", "SRE"]);

    // A subject claim that is missing is named by the category, never by
    // value; the well-known names survive as themselves.
    let mut settings = profile_settings(Profile::Generic, &issuer);
    settings.subject_claim = "email".to_owned();
    let by_email = self::validator(settings);
    assert_eq!(
        by_email.validate(&sign(&claims)).await.unwrap_err(),
        TokenRejection::MissingClaim("email")
    );
    claims["email"] = json!("alice@acme.example");
    assert_eq!(
        by_email.validate(&sign(&claims)).await.unwrap().subject,
        "alice@acme.example"
    );
}

#[tokio::test]
async fn file_keys_rotate_withdraw_and_fail_closed_even_for_cached_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jwks.json");
    let validator = validator(OidcSettings::new(
        Profile::Okta,
        ISSUER,
        AUDIENCE,
        JwksLocation::File(path.to_str().unwrap().to_owned()),
    ));
    let first = sign_with_kid(&base_claims(), "first");
    let second = sign_with_kid(&base_claims(), "second");
    assert_eq!(
        validator.validate(&first).await.unwrap_err(),
        TokenRejection::KeysUnavailable
    );
    tokio::fs::write(&path, jwks(&["first"]).to_string())
        .await
        .unwrap();
    validator.validate(&first).await.unwrap();
    // Atomic replacement with equal-sized contents: timestamps/length are not identity.
    let next = dir.path().join("next");
    tokio::fs::write(&next, jwks(&["second"]).to_string())
        .await
        .unwrap();
    tokio::fs::rename(&next, &path).await.unwrap();
    validator.validate(&second).await.unwrap();
    assert_eq!(
        validator.validate(&first).await.unwrap_err(),
        TokenRejection::UnknownKey
    );
    for invalid in ["{bad", "[]"] {
        tokio::fs::write(&path, invalid).await.unwrap();
        assert_eq!(
            validator.validate(&second).await.unwrap_err(),
            TokenRejection::KeysUnavailable
        );
        tokio::fs::write(&path, jwks(&["second"]).to_string())
            .await
            .unwrap();
        validator.validate(&second).await.unwrap();
    }
    tokio::fs::write(&path, jwks(&[]).to_string())
        .await
        .unwrap();
    assert_eq!(
        validator.validate(&second).await.unwrap_err(),
        TokenRejection::UnknownKey
    );
    tokio::fs::write(&path, jwks(&["second"]).to_string())
        .await
        .unwrap();
    validator.validate(&second).await.unwrap();
    tokio::fs::remove_file(&path).await.unwrap();
    assert_eq!(
        validator.validate(&second).await.unwrap_err(),
        TokenRejection::KeysUnavailable
    );
}

#[tokio::test]
async fn jwks_fetch_uses_bounded_secure_validated_documents() {
    use mcp_server_devtools::auth::oidc::fetch_jwks;
    assert!(fetch_jwks("http://keys.example/jwks").await.is_err());
    let server = MockServer::start().await;
    mount_jwks(&server, &["test-key-1"], Some(1)).await;
    let body = fetch_jwks(&format!("{}/keys", server.uri())).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        jwks(&["test-key-1"])
    );
    server.reset().await;
    mount_jwks(&server, &[], Some(1)).await;
    assert!(fetch_jwks(&format!("{}/keys", server.uri())).await.is_err());
}

#[test]
fn file_jwks_configuration_is_explicit_and_excludes_remote_override() {
    use mcp_server_devtools::config::{Config, OidcKeys};
    use std::collections::HashMap;
    let mut values: HashMap<String, String> = [
        ("MCP_OIDC_PROFILE", "generic"),
        ("MCP_OIDC_ISSUER", ISSUER),
        ("MCP_OIDC_AUDIENCE", AUDIENCE),
        ("MCP_OIDC_JWKS_FILE", "/keys/jwks.json"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    assert_eq!(
        OidcSettings::from_config(&Config::from_map(values.clone()), OidcKeys::Oidc)
            .unwrap()
            .jwks,
        JwksLocation::File("/keys/jwks.json".to_owned())
    );
    values.insert(
        "MCP_OIDC_JWKS_URL".to_owned(),
        "https://keys.example/jwks".to_owned(),
    );
    assert!(OidcSettings::from_config(&Config::from_map(values), OidcKeys::Oidc).is_err());
}

#[tokio::test]
async fn jwks_fetch_cli_creates_a_private_file_and_refuses_overwrite() {
    let server = MockServer::start().await;
    mount_jwks(&server, &["test-key-1"], None).await;
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("jwks.json");
    let run = || {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-devtools"));
        command
            .args([
                "auth",
                "jwks",
                "fetch",
                "--url",
                &format!("{}/keys", server.uri()),
                "--output",
            ])
            .arg(&output);
        command
    };
    let result = run().output().await.unwrap();
    if cfg!(unix) {
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let original = tokio::fs::read(&output).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&original).unwrap(),
            jwks(&["test-key-1"])
        );
        assert!(!run().output().await.unwrap().status.success());
        assert_eq!(tokio::fs::read(&output).await.unwrap(), original);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                tokio::fs::metadata(&output)
                    .await
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    } else {
        assert!(!result.status.success());
    }
}

#[tokio::test]
async fn file_keys_reject_oversize_directories_and_replaced_key_material() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("jwks.json");
    let validator = validator(OidcSettings::new(
        Profile::Okta,
        ISSUER,
        AUDIENCE,
        JwksLocation::File(path.to_str().unwrap().to_owned()),
    ));
    let token = sign(&base_claims());
    tokio::fs::write(&path, jwks(&["test-key-1"]).to_string())
        .await
        .unwrap();
    validator.validate(&token).await.unwrap();
    let mut rotated = jwk_with_kid("test-key-1");
    let modulus = rotated["n"].as_str().unwrap().to_owned();
    rotated["n"] = json!(format!("AAAAAAAA{}", &modulus[8..]));
    tokio::fs::write(&path, json!({"keys": [rotated]}).to_string())
        .await
        .unwrap();
    assert!(validator.validate(&token).await.is_err());
    tokio::fs::write(&path, vec![b' '; 256 * 1024 + 1])
        .await
        .unwrap();
    assert_eq!(
        validator.validate(&token).await.unwrap_err(),
        TokenRejection::KeysUnavailable
    );
    tokio::fs::remove_file(&path).await.unwrap();
    tokio::fs::create_dir(&path).await.unwrap();
    assert_eq!(
        validator.validate(&token).await.unwrap_err(),
        TokenRejection::KeysUnavailable
    );
}

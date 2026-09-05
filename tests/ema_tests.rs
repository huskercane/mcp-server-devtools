use jsonwebtoken::{Algorithm, EncodingKey, Header};
use mcp_server_devtools::{
    auth::{
        ema::{self, ClientCredentials, ExchangeRequest, OidcExchange, SubjectType},
        oidc::{JwksLocation, OidcJwksValidator, OidcSettings, Profile},
    },
    bootstrap::ServerBuilder,
    config::Config,
    ports::TokenValidator,
};
use rmcp::ServerHandler;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const RESOURCE: &str = "https://mcp.acme.example";
const ISSUER: &str = "https://acme.okta.example/oauth2/mcp";
fn sign(claims: &Value, typ: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".into());
    header.typ = Some(typ.into());
    jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_rsa_der(include_bytes!("fixtures/okta_test_rsa_pkcs1.der")),
    )
    .unwrap()
}
fn claims() -> Value {
    let mut claims: Value =
        serde_json::from_str(include_str!("fixtures/ema/okta-xaa-access-token.json")).unwrap();
    claims["iat"] = json!(jsonwebtoken::get_current_timestamp());
    claims["exp"] = json!(jsonwebtoken::get_current_timestamp() + 300);
    claims
}
async fn validator() -> (MockServer, Arc<OidcJwksValidator>) {
    let server = MockServer::start().await;
    let mut jwk: Value = serde_json::from_str(include_str!("fixtures/okta_test_jwk.json")).unwrap();
    jwk["kid"] = json!("test-key");
    Mock::given(path("/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys":[jwk]})))
        .mount(&server)
        .await;
    let settings = OidcSettings::new(
        Profile::Okta,
        ISSUER,
        RESOURCE,
        JwksLocation::Direct(format!("{}/keys", server.uri())),
    )
    .with_tenant("acme");
    (
        server,
        Arc::new(OidcJwksValidator::new(settings, reqwest::Client::new())),
    )
}
#[tokio::test]
async fn okta_subject_and_actor_history_are_distinct_and_cannot_supply_privileges() {
    let (_server, validator) = validator().await;
    let token = sign(&claims(), "at+jwt");
    let authenticated = validator.authenticate(&token).await.unwrap();
    assert_eq!(authenticated.principal.subject, "00u-alice");
    assert_eq!(authenticated.principal.scopes, ["mcp:tools"]);
    assert_eq!(authenticated.principal.groups, ["Developers"]);
    let actors = authenticated.token.actors.unwrap();
    assert_eq!(actors[0].subject, "agent-current");
    assert_eq!(
        actors[0].issuer.as_deref(),
        Some("https://acme.okta.example")
    );
    assert_eq!(actors[1].subject, "client-original");
    let cached = validator.authenticate(&token).await.unwrap();
    assert!(Arc::ptr_eq(&actors, cached.token.actors.as_ref().unwrap()));
    let mut no_subject = claims();
    no_subject.as_object_mut().unwrap().remove("sub");
    assert!(
        validator
            .authenticate(&sign(&no_subject, "at+jwt"))
            .await
            .is_err()
    );
}
#[tokio::test]
async fn grants_wrong_audiences_and_malformed_actors_are_refused() {
    let (_server, validator) = validator().await;
    // Even a grant with a mistakenly resource-shaped audience must not be a bearer.
    assert!(
        validator
            .authenticate(&sign(&claims(), "oauth-id-jag+jwt"))
            .await
            .is_err()
    );
    for mutation in [
        json!("not-an-object"),
        json!({"sub":""}),
        json!({"sub":"actor", "act":null}),
        json!({"sub":"actor", "iss":12}),
    ] {
        let mut invalid = claims();
        invalid["act"] = mutation;
        assert!(
            validator
                .authenticate(&sign(&invalid, "at+jwt"))
                .await
                .is_err()
        );
    }
    let mut invalid = claims();
    invalid["aud"] = json!(ISSUER);
    assert!(
        validator
            .authenticate(&sign(&invalid, "at+jwt"))
            .await
            .is_err()
    );
    let mut invalid = claims();
    invalid["act"] = json!({"sub":"last"});
    for _ in 0..8 {
        invalid["act"] = json!({"sub":"actor", "act":invalid["act"]});
    }
    assert!(
        validator
            .authenticate(&sign(&invalid, "at+jwt"))
            .await
            .is_err()
    );
}
async fn discovery(server: &MockServer, suffix: &str, profile: bool) {
    Mock::given(path(format!("/.well-known/oauth-authorization-server{suffix}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer":format!("{}{suffix}",server.uri()), "token_endpoint":format!("{}{suffix}/token",server.uri()),
            "authorization_grant_profiles_supported": if profile {vec![ema::GRANT_PROFILE]} else {vec![]},
            "grant_types_supported":[ema::TOKEN_EXCHANGE,ema::JWT_BEARER]
        }))).mount(server).await;
}
async fn exchange_fixture(server: &MockServer) -> String {
    discovery(server, "/idp", false).await;
    discovery(server, "/as", true).await;
    let mut jag: Value =
        serde_json::from_str(include_str!("fixtures/ema/okta-xaa-id-jag.json")).unwrap();
    jag["aud"] = json!(format!("{}/as", server.uri()));
    let jag = sign(&jag, "oauth-id-jag+jwt");
    Mock::given(method("POST")).and(path("/idp/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token":jag,"token_type":"N_A","issued_token_type":ema::ID_JAG,"expires_in":300})))
        .mount(server).await;
    Mock::given(method("POST"))
        .and(path("/as/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"access_token":sign(&claims(),"at+jwt"),"token_type":"Bearer","expires_in":300}),
        ))
        .mount(server)
        .await;
    jag
}
fn form(request: &wiremock::Request) -> HashMap<String, String> {
    url::form_urlencoded::parse(&request.body)
        .into_owned()
        .collect()
}
#[tokio::test]
async fn both_grants_bind_audience_resource_and_independent_client_authentication() {
    let server = MockServer::start().await;
    let jag = exchange_fixture(&server).await;
    let idp = format!("{}/idp", server.uri());
    let issuer = format!("{}/as", server.uri());
    let exchange = OidcExchange::new().unwrap();
    let access = exchange
        .exchange(&ExchangeRequest {
            idp_issuer: &idp,
            resource_issuer: &issuer,
            resource: RESOURCE,
            scope: "mcp:tools",
            identity_assertion: "identity-secret",
            subject_type: SubjectType::IdToken,
            idp_client: ClientCredentials {
                client_id: "idp-client",
                assertion: Some("idp-proof"),
            },
            resource_client: ClientCredentials {
                client_id: "resource-client",
                assertion: Some("resource-proof"),
            },
        })
        .await
        .unwrap();
    let (_jwks, validator) = validator().await;
    assert_eq!(
        validator
            .authenticate(access.expose())
            .await
            .unwrap()
            .principal
            .subject,
        "00u-alice"
    );
    let requests = server.received_requests().await.unwrap();
    let forms: Vec<_> = requests
        .iter()
        .filter(|r| r.method == "POST")
        .map(form)
        .collect();
    assert_eq!(forms[0]["grant_type"], ema::TOKEN_EXCHANGE);
    assert_eq!(forms[0]["requested_token_type"], ema::ID_JAG);
    assert_eq!(
        forms[0]["subject_token_type"],
        "urn:ietf:params:oauth:token-type:id_token"
    );
    assert_eq!(forms[0]["audience"], issuer);
    assert_eq!(forms[0]["resource"], RESOURCE);
    assert_eq!(forms[0]["client_assertion"], "idp-proof");
    assert_eq!(forms[1]["grant_type"], ema::JWT_BEARER);
    assert_eq!(forms[1]["assertion"], jag);
    assert_eq!(forms[1]["client_assertion"], "resource-proof");
    assert!(!forms[1].contains_key("subject_token"));
}
#[tokio::test]
async fn metadata_refuses_unsupported_profiles_mismatched_issuers_and_redirects() {
    let server = MockServer::start().await;
    discovery(&server, "/unsupported", false).await;
    Mock::given(path("/.well-known/oauth-authorization-server/mismatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"issuer":"https://other.example", "token_endpoint":"https://other.example/token"}))).mount(&server).await;
    Mock::given(path("/.well-known/oauth-authorization-server/redirect"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", format!("{}/leak", server.uri())),
        )
        .mount(&server)
        .await;
    let exchange = OidcExchange::new().unwrap();
    for suffix in ["unsupported", "mismatch", "redirect"] {
        assert!(
            exchange
                .verify_resource_issuer(&format!("{}/{suffix}", server.uri()))
                .await
                .is_err()
        );
    }
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|r| r.url.path() != "/leak")
    );
    for url in [
        "http://evil.example",
        "https://user:secret@issuer.example",
        "https://issuer.example?secret=bad",
        "https://issuer.example#x",
    ] {
        assert_eq!(ema::trusted_url(url).unwrap_err(), "invalid_url");
    }
}
#[test]
fn extension_is_opt_in_and_local_mode_does_not_advertise_it() {
    for (enabled, required, expected) in [
        (false, true, false),
        (true, false, false),
        (true, true, true),
    ] {
        let config = Config::from_map(HashMap::from([(
            "MCP_EMA_ENABLED".into(),
            enabled.to_string(),
        )]));
        let server = ServerBuilder::new()
            .config(config)
            .require_inbound_auth(required)
            .build()
            .unwrap();
        let info = serde_json::to_value(server.get_info()).unwrap();
        assert_eq!(
            info["capabilities"]["extensions"][ema::EXTENSION].is_object(),
            expected
        );
    }
    let invalid = Config::from_map(HashMap::from([("MCP_EMA_ENABLED".into(), "tru".into())]));
    assert!(ema::enabled(&invalid).is_err());
}
#[cfg(unix)]
#[tokio::test]
async fn cli_exchanges_refresh_assertion_and_writes_only_private_access_token() {
    use std::os::unix::fs::PermissionsExt;
    let server = MockServer::start().await;
    exchange_fixture(&server).await;
    let dir = tempfile::tempdir().unwrap();
    let identity = dir.path().join("identity");
    let output = dir.path().join("access");
    std::fs::write(&identity, "identity-secret").unwrap();
    let args = vec![
        "auth".to_owned(),
        "exchange".into(),
        "--idp-issuer".into(),
        format!("{}/idp", server.uri()),
        "--issuer".into(),
        format!("{}/as", server.uri()),
        "--resource".into(),
        RESOURCE.into(),
        "--scope".into(),
        "mcp:tools".into(),
        "--idp-client-id".into(),
        "idp-client".into(),
        "--resource-client-id".into(),
        "resource-client".into(),
        "--identity-token-file".into(),
        identity.display().to_string(),
        "--output-token-file".into(),
        output.display().to_string(),
        "--refresh-token".into(),
        "--json".into(),
    ];
    let result = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-devtools"))
        .args(&args)
        .output()
        .await
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&result.stdout).unwrap(),
        json!({"data":{"written":true}})
    );
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let access = std::fs::read_to_string(&output).unwrap();
    assert!(access.starts_with("eyJ"));
    assert!(!String::from_utf8_lossy(&result.stdout).contains(&access));
    let requests = server.received_requests().await.unwrap();
    let first = requests
        .iter()
        .find(|r| r.url.path() == "/idp/token")
        .unwrap();
    assert_eq!(
        form(first)["subject_token_type"],
        "urn:ietf:params:oauth:token-type:refresh_token"
    );
    let second = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-devtools"))
        .args(&args)
        .output()
        .await
        .unwrap();
    assert!(!second.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&second.stdout).unwrap()["error"],
        "output_file_unavailable"
    );
    assert_eq!(std::fs::read_to_string(output).unwrap(), access);
}

#[tokio::test]
async fn rejected_or_oversized_grants_never_reach_resource_token_endpoint() {
    for response in [
        ResponseTemplate::new(400).set_body_json(json!({"error":"invalid_grant","error_description":"identity-secret"})),
        ResponseTemplate::new(200).set_body_json(json!({"access_token":"identity-secret","token_type":"Bearer","issued_token_type":"wrong"})),
        ResponseTemplate::new(200).set_body_string("x".repeat(65_537)),
        ResponseTemplate::new(302).insert_header("Location","https://should-not-be-contacted.invalid/token"),
    ] {
        let server = MockServer::start().await;
        discovery(&server,"/idp",false).await; discovery(&server,"/as",true).await;
        Mock::given(path("/idp/token")).respond_with(response).mount(&server).await;
        let idp = format!("{}/idp",server.uri()); let issuer = format!("{}/as",server.uri());
        let result = OidcExchange::new().unwrap().exchange(&ExchangeRequest {
            idp_issuer:&idp,resource_issuer:&issuer,resource:RESOURCE,scope:"mcp:tools",identity_assertion:"identity-secret",subject_type:SubjectType::IdToken,
            idp_client:ClientCredentials{client_id:"client",assertion:None},resource_client:ClientCredentials{client_id:"client",assertion:None},
        }).await;
        let error = result.err().expect("refused");
        assert!(!error.contains("identity-secret"));
        assert!(server.received_requests().await.unwrap().iter().all(|r|r.url.path()!="/as/token"));
    }
}

#[tokio::test]
async fn resource_router_exposes_discovery_and_requires_the_final_access_token() {
    use mcp_server_devtools::server::{
        auth::{InboundAuth, InboundAuthSettings},
        http::build_app_with_server_and_auth,
    };
    use std::time::Duration;
    let (_jwks, validator) = validator().await;
    let config = Config::from_map(HashMap::from([("MCP_EMA_ENABLED".into(), "true".into())]));
    let server = ServerBuilder::new()
        .config(config)
        .require_inbound_auth(true)
        .build()
        .unwrap();
    let auth = Arc::new(InboundAuth::new(
        Arc::new(validator),
        InboundAuthSettings {
            public_url: RESOURCE.into(),
            authorization_servers: vec![ISSUER.into()],
            required_scope: "mcp:tools".into(),
        },
    ));
    let cancel = tokio_util::sync::CancellationToken::new();
    let app = build_app_with_server_and_auth(
        server,
        auth,
        Duration::from_mins(1),
        Duration::from_secs(30),
        cancel.clone(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::new();
    let metadata: Value = client
        .get(format!(
            "http://{addr}/.well-known/oauth-protected-resource"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(metadata["resource"], RESOURCE);
    assert_eq!(metadata["authorization_servers"], json!([ISSUER]));
    let initialize = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":rmcp::model::ProtocolVersion::LATEST,"capabilities":{"extensions":{ema::EXTENSION:{}}},"clientInfo":{"name":"ema-fixture","version":"1"}}});
    let url = format!("http://{addr}/mcp");
    let no_token = client.post(&url).json(&initialize).send().await.unwrap();
    assert_eq!(no_token.status(), 401);
    assert!(
        no_token.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("resource_metadata=")
    );
    let grant = client
        .post(&url)
        .bearer_auth(sign(&claims(), "oauth-id-jag+jwt"))
        .json(&initialize)
        .send()
        .await
        .unwrap();
    assert_eq!(grant.status(), 401);
    let access = client
        .post(&url)
        .bearer_auth(sign(&claims(), "at+jwt"))
        .header("Accept", "application/json, text/event-stream")
        .json(&initialize)
        .send()
        .await
        .unwrap();
    assert!(access.status().is_success());
    let body = access.text().await.unwrap();
    assert!(body.contains(ema::EXTENSION));
    cancel.cancel();
    task.abort();
}

#[tokio::test]
async fn ema_startup_refuses_disabled_auth_and_misspelled_opt_in() {
    for (flag, expected) in [("true", "requires OIDC"), ("tru", "must be true or false")] {
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-devtools"))
            .args(["serve", "--transport", "http"])
            .env("MCP_AUTH_MODE", "off")
            .env("MCP_EMA_ENABLED", flag)
            .env("MCP_BIND_ADDR", "127.0.0.1")
            .env("PORT", "0")
            .output()
            .await
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
    }
}

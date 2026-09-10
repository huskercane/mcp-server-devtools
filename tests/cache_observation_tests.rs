//! Exercise the real transport and on-disk audit stream together. Keep this in
//! its own test binary because the process audit writer is initialized once.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use mcp_server_devtools::audit::{self, AuditCall};
use mcp_server_devtools::auth::Credentials;
use mcp_server_devtools::config::Config;
use mcp_server_devtools::transport::{
    RequestOptions, build_client, fetch_bitbucket_with_base, maintain_response_cache,
};
use serde_json::Value;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(ttl: &str, limit: &str, explore: bool) -> Config {
    Config::from_map(HashMap::from([
        ("HTTP_CACHE_ENABLED".into(), "true".into()),
        ("HTTP_CACHE_DEFAULT_TTL_SECONDS".into(), ttl.into()),
        ("HTTP_CACHE_MAX_ENTRIES".into(), limit.into()),
        ("HTTP_CACHE_EXPLORATION_ENABLED".into(), explore.to_string()),
    ]))
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn cache_observations_cover_real_lifecycles_without_exposing_content() {
    let directory = tempfile::tempdir().unwrap();
    audit::init(directory.path(), "cache-observation-test");
    let server = MockServer::start().await;
    Mock::given(path("/2.0/forbidden"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("cache-control", "max-age=60, no-store")
                .set_body_json(serde_json::json!({"private": true})),
        )
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(path("/2.0/race"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(50))
                .set_body_json(
                    serde_json::json!({"secret-response": "private-payload".repeat(2000)}),
                ),
        )
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(wiremock::matchers::method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"secret-response": "private-payload".repeat(2000)}),
            ),
        )
        .with_priority(10)
        .mount(&server)
        .await;
    let client = build_client().unwrap();
    let credentials = Credentials::AtlassianApiToken {
        email: "private-user@example.com".into(),
        token: "private-token-value".into(),
    };
    let normal = config("60", "512", false);
    let fetch = |route: &'static str, settings: Config, fresh| {
        let client = &client;
        let credentials = &credentials;
        let base = server.uri();
        async move {
            fetch_bitbucket_with_base(
                &base,
                client,
                credentials,
                &settings,
                route,
                RequestOptions {
                    fresh,
                    ..RequestOptions::default()
                },
            )
            .await
            .unwrap()
        }
    };
    let call = AuditCall::start("bb_get", "first-request".into(), None, None);
    call.scope(fetch("/2.0/first", normal.clone(), false)).await;
    call.complete("success");
    let hit_call = AuditCall::start("bb_get", "hit-request".into(), None, None);
    assert!(
        hit_call
            .scope(fetch("/2.0/first", normal.clone(), false))
            .await
            .cache
            .hit
    );
    hit_call.complete("success");
    assert!(!fetch("/2.0/first", normal.clone(), true).await.cache.hit);
    fetch("/2.0/evict-a", config("60", "1", false), false).await;
    fetch("/2.0/evict-b", config("60", "1", false), false).await;
    fetch("/2.0/idle-expiry", config("1", "512", false), false).await;
    for _ in 0..2 {
        assert!(
            !fetch("/2.0/forbidden", normal.clone(), false)
                .await
                .cache
                .hit
        );
    }
    // Check every sampled decision against its realized behavior; exhaustive
    // bucket tests separately verify probabilities without statistical flakes.
    for _ in 0..32 {
        fetch("/2.0/explore", config("60", "512", true), false).await;
        fetch("/2.0/explore", normal.clone(), true).await;
    }
    tokio::join!(
        fetch("/2.0/race", normal.clone(), false),
        fetch("/2.0/race", normal.clone(), false)
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let maintenance = tokio::spawn(maintain_response_cache(stopped));
    // Shutdown itself must expire idle entries before censoring survivors.
    stop.send(()).unwrap();
    maintenance.await.unwrap();
    tokio::task::spawn_blocking(audit::shutdown).await.unwrap();
    let text = std::fs::read_to_string(
        directory
            .path()
            .join("mcp-server-devtools.cache-observation-test.audit.jsonl"),
    )
    .unwrap();
    for secret in [
        "private-user",
        "private-token",
        "secret-response",
        "private-payload",
        "/2.0/",
        &server.uri(),
    ] {
        assert!(!text.contains(secret), "audit exposed {secret}");
    }
    let rows: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let decisions: HashMap<&str, &Value> = rows
        .iter()
        .filter(|r| r["event"] == "http_cache_decision")
        .map(|r| (r["decisionId"].as_str().unwrap(), r))
        .collect();
    let outcomes: Vec<&Value> = rows
        .iter()
        .filter(|r| r["event"] == "http_cache_outcome")
        .collect();
    assert_eq!(decisions.len(), outcomes.len());
    let mut seen = HashSet::new();
    for outcome in &outcomes {
        let id = outcome["decisionId"].as_str().unwrap();
        assert!(seen.insert(id), "duplicate terminal outcome");
        let decision = decisions[id];
        assert_eq!(outcome["policyVersion"], decision["policyVersion"]);
        assert_eq!(outcome["originCallId"], decision["originCallId"]);
        assert_eq!(
            outcome["observationComplete"],
            outcome["outcome"] != "session_end"
        );
        if outcome["outcome"] == "rejected" {
            assert_eq!(outcome["residencyByteMs"], 0);
            assert_eq!(outcome["estimatedSavedLatencyMs"], 0);
            assert_eq!(outcome["hitCount"], 0);
        }
    }
    for decision in decisions.values() {
        assert_eq!(decision["schemaVersion"], 2);
        assert_eq!(decision["serverVersion"], env!("CARGO_PKG_VERSION"));
        assert!(
            decision["entryBytes"].as_u64().unwrap() < decision["responseBytes"].as_u64().unwrap()
        );
        let action = decision["action"].as_str().unwrap();
        let index = decision["candidateActions"]
            .as_array()
            .unwrap()
            .iter()
            .position(|a| a == action)
            .unwrap();
        assert_eq!(
            decision["actionProbability"],
            decision["candidateProbabilities"][index]
        );
        assert!(decision["ttlMs"].as_u64().unwrap() <= decision["baseTtlMs"].as_u64().unwrap());
    }
    for reason in [
        "expired",
        "invalidated",
        "evicted",
        "replaced",
        "session_end",
    ] {
        assert!(
            outcomes.iter().any(|r| r["outcome"] == reason),
            "missing {reason}"
        );
    }
    let hit = rows
        .iter()
        .find(|r| r["event"] == "http_cache_lookup" && r["outcome"] == "hit")
        .unwrap();
    assert_eq!(hit["hitCount"], 1);
    assert_ne!(hit["callId"], hit["originCallId"]);
    assert_eq!(
        hit["originCallId"],
        decisions[hit["decisionId"].as_str().unwrap()]["callId"]
    );
    assert!(
        rows.iter()
            .filter(|r| r["event"] == "http_cache_ineligible")
            .count()
            >= 2
    );
}

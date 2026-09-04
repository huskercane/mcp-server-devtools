//! Allocation + timing probe for the shared tool-response pipeline
//! (`apply_jq_filter` → `render` → `truncate_for_ai`).
//!
//! Not a pass/fail benchmark — it prints bytes allocated, allocation count, and
//! wall time per stage so regressions in *allocation* (not just speed) are
//! visible. Run with `cargo bench --bench response_pipeline`.
//!
//! Each stage is also measured against the shape it had before the pipeline was
//! de-allocated, so the win stays legible and a regression is obvious.
//!
//! `unsafe` is confined to the `GlobalAlloc` shim below: counting allocations
//! requires a global allocator, and there is no safe way to write one. The
//! crate-wide `unsafe_code = "deny"` still applies to all production code.
#![allow(unsafe_code, clippy::print_stdout, clippy::pedantic)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use mcp_server_devtools::bootstrap::ConfigHandle;
use mcp_server_devtools::config::Config;
use mcp_server_devtools::format::jmespath::apply_jq_filter;
use mcp_server_devtools::format::truncation::truncate_for_ai;
use mcp_server_devtools::format::{OutputFormat, render, to_pretty_json};
use mcp_server_devtools::policy::extractors::{for_tool, grafana, jira};
use mcp_server_devtools::policy::{
    ActionContext, CanonicalPath, CanonicalTarget, ClientIdentity, CredentialLabel,
    EnvironmentClass, FilePolicy, Principal, PrincipalAuthority, RequestRisk, UpstreamAuthority,
    UpstreamIdentity,
};
use mcp_server_devtools::ports::PolicyDecisionPoint;
use mcp_server_devtools::transport::HttpMethod;
use serde_json::{Value, json};

static BYTES: AtomicU64 = AtomicU64::new(0);
static COUNT: AtomicU64 = AtomicU64::new(0);

struct Counting;

// SAFETY: every method forwards to `System` unchanged; the only added work is
// two relaxed atomic counters, which cannot affect allocator invariants.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        BYTES.fetch_add(l.size() as u64, Relaxed);
        COUNT.fetch_add(1, Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if new > l.size() {
            BYTES.fetch_add((new - l.size()) as u64, Relaxed);
        }
        COUNT.fetch_add(1, Relaxed);
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn probe<T>(label: &str, iters: u32, mut f: impl FnMut() -> T) -> T {
    let (b0, c0) = (BYTES.load(Relaxed), COUNT.load(Relaxed));
    let t0 = std::time::Instant::now();
    let mut out = f();
    for _ in 1..iters {
        out = f();
    }
    let dt = t0.elapsed();
    let n = u64::from(iters);
    println!(
        "  {label:<40} {:>9} KB {:>10} allocs {:>8.2} ms",
        (BYTES.load(Relaxed) - b0) / 1024 / n,
        (COUNT.load(Relaxed) - c0) / n,
        dt.as_secs_f64() * 1000.0 / f64::from(iters)
    );
    out
}

/// A Jira-search-shaped response: the payload shape that actually flows through
/// the tool pipeline in production.
fn payload(n: usize) -> Value {
    let items: Vec<Value> = (0..n)
        .map(|i| {
            json!({
                "id": i,
                "key": format!("PROJ-{i}"),
                "self": format!("https://example.atlassian.net/rest/api/3/issue/{i}"),
                "fields": {
                    "summary": format!("Issue number {i} with a reasonably long summary line"),
                    "status": {"name": "In Progress", "id": "3", "category": "indeterminate"},
                    "assignee": {"accountId": format!("acct-{i}"), "displayName": "Alice Example"},
                    "labels": ["backend", "perf", "triage"],
                    "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore.",
                }
            })
        })
        .collect();
    json!({"startAt": 0, "maxResults": n, "total": n, "issues": items})
}

/// TOON exists to save the LLM tokens. That trade only makes sense if the
/// output is actually smaller than JSON for the shapes our vendors return, so
/// measure it rather than assume it: TOON wins big on uniform tabular arrays
/// and can *lose* on deeply nested objects.
fn output_size_comparison() {
    let flat: Vec<Value> = (0..200)
        .map(
            |i| json!({"id": i, "key": format!("PROJ-{i}"), "status": "open", "assignee": "alice"}),
        )
        .collect();
    let cases: Vec<(&str, Value)> = vec![
        (
            "uniform flat rows (TOON's best case)",
            json!({"issues": flat}),
        ),
        ("nested objects (Jira search shape)", payload(200)),
    ];

    println!(
        "  {:<38} {:>10} {:>10} {:>10}",
        "", "compact", "pretty", "TOON"
    );
    for (label, v) in &cases {
        let compact = serde_json::to_string(v).unwrap().len();
        let pretty = to_pretty_json(v).len();
        let toon = render(v, OutputFormat::Toon).len();
        println!(
            "  {label:<38} {:>9}B {:>9}B {:>9}B   TOON is {:.0}% of compact, {:.0}% of pretty",
            compact,
            pretty,
            toon,
            100.0 * toon as f64 / compact as f64,
            100.0 * toon as f64 / pretty as f64,
        );
    }
}

/// A credential set the size a real multi-vendor deployment carries: every
/// vendor this server supports, each with a couple of secrets.
fn realistic_config() -> Config {
    let mut values = std::collections::HashMap::new();
    for vendor in [
        "ATLASSIAN",
        "ZOOM",
        "CIRCLECI",
        "SLACK",
        "POSTMAN",
        "EDX",
        "NEWRELIC",
        "GRAFANA",
        "SONARQUBE",
        "SPLUNK",
        "NINJAONE",
        "WRDS",
    ] {
        values.insert(format!("{vendor}_API_TOKEN"), "x".repeat(40));
        values.insert(
            format!("{vendor}_USER_EMAIL"),
            "someone@example.com".to_owned(),
        );
        values.insert(
            format!("{vendor}_BASE_URL"),
            format!("https://{vendor}.example.com"),
        );
    }
    Config::from_map(values)
}

/// The policy extractors run once per tool call, on the request, before any
/// payload exists — so like the config snapshot they are paid even by a call
/// that returns nothing. They are also the stage most likely to regress
/// quietly: a scanner is easy to write with a `String` per token.
fn extractor_stage() {
    let long_jql = format!(
        "project in (PLAT, WEB, OPS) AND status = Open AND summary ~ \"{}\"",
        "timeout ".repeat(64)
    );
    let query: &[(&str, &str)] = &[
        ("jql", long_jql.as_str()),
        ("maxResults", "100"),
        ("fields", "summary,status"),
        ("expand", "changelog"),
    ];

    // §3.5 canonicalization runs on every outbound request, before any
    // extractor — its allocation is paid by local mode too.
    let search_target = format!(
        "/rest/api/3/search/jql?jql={}&maxResults=100&fields=summary%2Cstatus&expand=changelog",
        url::form_urlencoded::byte_serialize(long_jql.as_bytes()).collect::<String>()
    );
    probe("canonical: short path", 2000, || {
        CanonicalTarget::parse("/rest/api/3/issue/PLAT-12345?fields=summary").ok()
    });
    probe("canonical: dot-segments + escapes", 2000, || {
        CanonicalTarget::parse("/a/./b/../c/%2e%2e/rest/api/3/issue/PLAT%2D1/").ok()
    });
    probe("canonical: search URL (long JQL)", 2000, || {
        CanonicalTarget::parse(&search_target).ok()
    });

    let issue_path = || CanonicalPath::parse("/rest/api/3/issue/PLAT-12345").unwrap();
    let search_path = || CanonicalPath::parse("/rest/api/3/search/jql").unwrap();
    let create_path = || CanonicalPath::parse("/rest/api/3/issue").unwrap();
    probe("jira::extract GET /issue/{key}", 2000, || {
        jira::extract(
            HttpMethod::Get,
            issue_path(),
            &[("fields", "summary")],
            None,
        )
    });
    probe("jira::extract GET /search/jql (long JQL)", 2000, || {
        jira::extract(HttpMethod::Get, search_path(), query, None)
    });
    probe("jira::project_keys_from_jql (long JQL)", 2000, || {
        jira::project_keys_from_jql(&long_jql)
    });
    probe("jira::extract unmapped (default arm)", 2000, || {
        jira::extract(HttpMethod::Post, create_path(), &[], None)
    });
    probe("grafana::query_logs", 2000, || {
        grafana::query_logs(
            "loki-prod",
            &[("query", "{app=\"api\"}"), ("limit", "500"), ("start", "0")],
        )
    });
}

/// The enterprise decision path, per tool call (plan §8 budgets: context
/// build + canonicalization < 30 µs, policy decision < 20 µs for 500 rules).
/// Measured against a 500-rule document so the matcher's cost is visible,
/// not a three-rule best case.
fn policy_stage() {
    let mut document = String::from("version: 1\nrules:\n");
    for index in 0..500 {
        let env = ["qa", "prod", "staging", "dev"][index % 4];
        let group = ["SRE", "Developers", "Contractors", "Auditors"][index % 4];
        document.push_str(&format!(
            "  - id: rule-{index}\n    effect: allow\n    subjects: {{groups: [{group}]}}\n    match:\n      vendor: grafana\n      environment: {env}\n      request_risk: read\n      resource_type: datasource\n      resource_id: [\"ds-{index}\", \"loki-{env}-*\"]\n"
        ));
    }
    let policy = FilePolicy::from_bytes(document.as_bytes()).expect("bench policy compiles");
    let principal = Principal {
        tenant: "acme".to_owned(),
        subject: "sre@acme.example".to_owned(),
        groups: vec!["SRE".to_owned(), "Developers".to_owned()],
        scopes: vec!["mcp:tools".to_owned()],
        authority: PrincipalAuthority::oidc("https://acme.okta.com/oauth2/default"),
    };
    let upstream = UpstreamIdentity {
        label: CredentialLabel::slot(
            mcp_server_devtools::auth::secrets::for_vendor("grafana")
                .next()
                .expect("grafana slot"),
        ),
        vendor: "grafana".to_owned(),
        environment: EnvironmentClass::Qa,
        authority: UpstreamAuthority::Shared,
        provenance: None,
    };
    let arguments =
        json!({ "datasourceUid": "loki-qa-main", "query": "{app=\"api\"}", "limit": 100 });
    let arguments = arguments.as_object().unwrap();

    let context = probe("ActionContext via for_tool (grafana)", 2000, || {
        ActionContext::assemble(
            principal.clone(),
            ClientIdentity::default(),
            None,
            "grafana_query_logs",
            for_tool("grafana_query_logs", Some(arguments), RequestRisk::Read),
            None,
            upstream.clone(),
        )
    });
    // The last rule that matches an SRE/qa/loki-qa-* call is late in the
    // document, so this walks most of the 500 rules.
    probe("FilePolicy::evaluate @ 500 rules", 2000, || {
        policy.evaluate(&context)
    });
}

/// Like [`probe`], for a stage that has to `.await`. Same counters; the
/// closure's future is driven to completion on the current runtime.
async fn probe_async<F, Fut, T>(label: &str, iters: u32, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let (b0, c0) = (BYTES.load(Relaxed), COUNT.load(Relaxed));
    let t0 = std::time::Instant::now();
    let mut out = f().await;
    for _ in 1..iters {
        out = f().await;
    }
    let dt = t0.elapsed();
    let n = u64::from(iters);
    println!(
        "  {label:<40} {:>9} KB {:>10} allocs {:>8.2} µs",
        (BYTES.load(Relaxed) - b0) / 1024 / n,
        (COUNT.load(Relaxed) - c0) / n,
        dt.as_secs_f64() * 1_000_000.0 / f64::from(iters)
    );
    out
}

/// The two §8 budgets on the enterprise request path that nothing above
/// probes: the validated-token cache hit (< 50 µs) and the durable audit
/// append (< 200 µs p99 on local NVMe, with batched fsync). Both run
/// against the production components — the Okta validator primed from a
/// JWKS on wiremock, and the journal adapter on a temp directory — so the
/// numbers are the real path, not a model of it.
///
/// The append here is sequential, one record at a time, which is the
/// *worst* case for the journal's group commit: every record pays its own
/// `sync_data`. Under concurrent calls the writer batches, and the per-record
/// cost falls; read the p99 as "one call on an idle gateway".
fn enterprise_request_path_stage() {
    use std::sync::Arc;

    use mcp_server_devtools::audit::journal::{JOURNAL_FILE_NAME, JournalAuditSink};
    use mcp_server_devtools::auth::oidc::{JwksLocation, OidcJwksValidator, OidcSettings, Profile};
    use mcp_server_devtools::ports::{AuditEvent, AuditEventKind, AuditSink, TokenValidator};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ISSUER: &str = "https://acme.okta.com/oauth2/default";
    const AUDIENCE: &str = "api://mcp-devtools";

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        // -- JWT validation, cache hit --
        let jwks = MockServer::start().await;
        let jwk: Value =
            serde_json::from_str(include_str!("../tests/fixtures/okta_test_jwk.json")).unwrap();
        Mock::given(method("GET"))
            .and(path("/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
            .mount(&jwks)
            .await;
        let validator = Arc::new(OidcJwksValidator::new(
            OidcSettings::new(
                    Profile::Okta,
                    ISSUER,
                    AUDIENCE,
                    JwksLocation::Direct(format!("{}/keys", jwks.uri())),
                )
                .with_tenant("acme"),
            reqwest::Client::new(),
        ));
        let now = jsonwebtoken::get_current_timestamp();
        let claims = json!({
            "sub": "alice@acme.example", "iss": ISSUER, "aud": AUDIENCE,
            "iat": now, "exp": now + 300, "scp": ["mcp:tools"], "groups": ["SRE", "Developers"],
        });
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("test-key-1".to_owned());
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_rsa_der(include_bytes!(
                "../tests/fixtures/okta_test_rsa_pkcs1.der"
            )),
        )
        .unwrap();
        // Prime: the first validation fetches the JWKS and verifies the
        // signature; every one after it is the cache hit under budget.
        validator.validate(&token).await.expect("token validates");
        probe_async("JWT validate: cache hit (budget 50 µs)", 2000, || {
            validator.validate(&token)
        })
        .await
        .expect("cached token validates");

        // -- Durable audit append --
        let dir = tempfile::tempdir().expect("tempdir");
        let journal_dir = dir.path().join("journal");
        if cfg!(windows) {
            std::fs::create_dir_all(&journal_dir).unwrap();
            std::fs::File::create(journal_dir.join(JOURNAL_FILE_NAME)).unwrap();
        }
        let sink = JournalAuditSink::open(&journal_dir).expect("open journal");
        let event = AuditEvent {
            timestamp: "2026-09-02T00:00:00.000Z".to_owned(),
            kind: AuditEventKind::ToolCallIntent,
            request_id: "sha256:0123456789abcdef".to_owned(),
            tool_name: "grafana_query_logs".to_owned(),
            vendor: "grafana".to_owned(),
            principal: Principal {
                tenant: "acme".to_owned(),
                subject: "sre@acme.example".to_owned(),
                groups: vec!["SRE".to_owned()],
                scopes: vec!["mcp:tools".to_owned()],
                authority: PrincipalAuthority::oidc("https://acme.okta.com/oauth2/default"),
            },
            client: ClientIdentity::default(),
            decision: mcp_server_devtools::policy::PolicyDecision::by_rule(
                mcp_server_devtools::policy::PolicyEffect::Allow,
                "sre-read-qa-datasources",
                "v1+sha256:0123456789abcdef",
            ),
            upstream_identity: UpstreamIdentity {
                label: CredentialLabel::slot(
                    mcp_server_devtools::auth::secrets::for_vendor("grafana")
                        .next()
                        .expect("grafana slot"),
                ),
                vendor: "grafana".to_owned(),
                environment: EnvironmentClass::Qa,
                authority: UpstreamAuthority::Shared,
                provenance: None,
            },
            action: None,
            outcome: None,
            duration_ms: None,
            egress: None,
        };
        const APPENDS: usize = 1000;
        let mut latencies = Vec::with_capacity(APPENDS);
        let (b0, c0) = (BYTES.load(Relaxed), COUNT.load(Relaxed));
        for _ in 0..APPENDS {
            let started = std::time::Instant::now();
            sink.append(&event).await.expect("append");
            latencies.push(started.elapsed());
        }
        let (bytes, allocs) = (
            (BYTES.load(Relaxed) - b0) / 1024 / APPENDS as u64,
            (COUNT.load(Relaxed) - c0) / APPENDS as u64,
        );
        latencies.sort_unstable();
        let at = |quantile: f64| latencies[((APPENDS - 1) as f64 * quantile) as usize];
        println!(
            "  {:<40} {bytes:>9} KB {allocs:>10} allocs  p50 {:>7.0} µs  p99 {:>7.0} µs  max {:>7.0} µs",
            "journal append, sequential (budget p99 200 µs)",
            at(0.50).as_secs_f64() * 1_000_000.0,
            at(0.99).as_secs_f64() * 1_000_000.0,
            latencies[APPENDS - 1].as_secs_f64() * 1_000_000.0,
        );
        drop(sink);
    });
}

fn main() {
    println!("=== output size: is TOON earning its CPU? ===");
    output_size_comparison();

    // Stage -1: the enterprise request-path work, which happens before the
    // response pipeline below and so is invisible to every probe in it.
    println!("\n=== stage -1: policy extractors, per tool call (mean of 2000) ===");
    extractor_stage();
    println!("\n=== stage -1b: policy decision, per tool call (mean of 2000) ===");
    policy_stage();
    println!(
        "\n=== stage -1c: enterprise request path, production components (mean of 2000 / 1000) ==="
    );
    enterprise_request_path_stage();

    // Stage 0 runs once per *tool call*, before any payload work — so unlike the
    // stages below it is paid even by a request that returns two bytes.
    println!("\n=== stage 0: per-tool-call config snapshot (mean of 1000) ===");
    let config = realistic_config();
    let handle = ConfigHandle::new(realistic_config());
    probe("BEFORE: deep clone of Config", 1000, || config.clone());
    probe("NOW:    ConfigHandle::snapshot()", 1000, || {
        handle.snapshot()
    });

    for (n, iters) in [(500usize, 20u32), (5000, 4)] {
        let data = payload(n);
        let kb = serde_json::to_string(&data).unwrap().len() / 1024;
        println!("\n=== {n} issues / {kb} KB compact JSON  (mean of {iters}) ===");

        println!(" -- stage 1: jq filter, no filter supplied (the default path)");
        probe("BEFORE: deep clone of the payload", iters, || data.clone());
        let filtered = probe("NOW:    apply_jq_filter(None) borrows", iters, || {
            apply_jq_filter(&data, None)
        });

        println!(" -- stage 2: render");
        probe("BEFORE: eager pretty-JSON, then discard", iters, || {
            let fallback = to_pretty_json(&filtered);
            serde_toon::to_string(&filtered).unwrap_or(fallback)
        });
        let rendered = probe("NOW:    render(Toon), lazy fallback", iters, || {
            render(&filtered, OutputFormat::Toon)
        });
        probe("ref:    render(Json) on same data", iters, || {
            render(&filtered, OutputFormat::Json)
        });
        println!(" -- stage 3: truncate");
        probe("truncate_for_ai (over budget)", iters, || {
            truncate_for_ai(&rendered, None)
        });

        println!("   rendered output: {} KB", rendered.len() / 1024);
    }
}

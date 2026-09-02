//! WP A.9 at the binary boundary: the process role and the health probe.

use std::process::{Command, Stdio};
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;

const STARTUP_MARKER: &str = "listening on streamable-HTTP transport";

/// Start the binary in HTTP mode with `args`, return the child and its port.
async fn start(args: &[&str], env: &[(&str, &str)]) -> (tokio::process::Child, u16) {
    let mut command = tokio::process::Command::new(cargo_bin("mcp-devtools"));
    command
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("MCP_AUTH_MODE")
        .env_remove("MCP_BIND_ADDR")
        .env_remove("MCP_ROLE")
        .env("PORT", "0")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("spawn binary");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let collected = {
        use tokio::io::AsyncReadExt as _;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut collected = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if String::from_utf8_lossy(&collected).contains(STARTUP_MARKER) {
                break String::from_utf8_lossy(&collected).into_owned();
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(!remaining.is_zero(), "timed out waiting for startup");
            match tokio::time::timeout(remaining, stderr.read(&mut buf)).await {
                Ok(Ok(0)) => panic!(
                    "binary exited before startup; stderr:\n{}",
                    String::from_utf8_lossy(&collected)
                ),
                Ok(Ok(read)) => collected.extend_from_slice(&buf[..read]),
                Ok(Err(error)) => panic!("reading stderr failed: {error}"),
                Err(_) => {}
            }
        }
    };
    let (_, rest) = collected
        .split_once("127.0.0.1:")
        .expect("startup line carries the bound address");
    let port: u16 = rest
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .expect("bound port");
    (child, port)
}

fn health_probe(url: &str) -> std::process::Output {
    Command::new(cargo_bin("mcp-devtools"))
        .args(["health", "--url", url, "--timeout-seconds", "2"])
        .output()
        .expect("run health")
}

#[tokio::test]
async fn control_role_serves_health_and_nothing_else() {
    let (_child, port) = start(&["serve", "--transport", "http", "--role", "control"], &[]).await;
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();

    let health = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(health.status(), 200);
    assert!(
        health
            .text()
            .await
            .unwrap()
            .starts_with("mcp-server-devtools v")
    );

    for path in [
        "/mcp",
        "/artifacts/x",
        "/.well-known/oauth-protected-resource",
    ] {
        let response = client.post(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(
            response.status(),
            404,
            "{path} must not exist on the control role"
        );
    }
}

#[tokio::test]
async fn gateway_role_from_env_serves_the_data_plane() {
    let (_child, port) = start(&[], &[("TRANSPORT_MODE", "http"), ("MCP_ROLE", "gateway")]).await;
    let base = format!("http://127.0.0.1:{port}");
    let response = reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/list")
        .body(
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/list",
                "params": { "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": { "name": "t", "version": "0" }
                } }
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

#[test]
fn unknown_role_is_refused_not_defaulted() {
    let output = Command::new(cargo_bin("mcp-devtools"))
        .env("TRANSPORT_MODE", "http")
        .env("PORT", "0")
        .env("MCP_ROLE", "everything")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("MCP_ROLE"), "{stderr}");
}

#[tokio::test]
async fn health_probe_exit_status_reflects_the_banner() {
    let (child, port) = start(&["serve", "--transport", "http"], &[]).await;
    let healthy = health_probe(&format!("http://127.0.0.1:{port}/"));
    assert!(
        healthy.status.success(),
        "{}",
        String::from_utf8_lossy(&healthy.stderr)
    );
    assert!(String::from_utf8_lossy(&healthy.stdout).starts_with("healthy: 200"));

    // A 404 is not healthy, and neither is a closed port.
    let wrong_path = health_probe(&format!("http://127.0.0.1:{port}/nope"));
    assert!(!wrong_path.status.success());
    drop(child);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = listener.local_addr().unwrap().port();
    drop(listener);
    let dead = health_probe(&format!("http://127.0.0.1:{closed}/"));
    assert!(!dead.status.success());
    assert!(String::from_utf8_lossy(&dead.stderr).starts_with("unhealthy:"));
}

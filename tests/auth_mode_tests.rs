//! `MCP_AUTH_MODE` behaviour at the binary boundary (WP 0.4).
//!
//! Two properties, both from `docs/enterprise-product-plan.md` §1:
//!
//! 1. **Fail closed.** The binary refuses to start when it would bind a
//!    non-loopback address with inbound authentication off, when
//!    `MCP_AUTH_MODE` holds a value it does not recognise, or when it names a
//!    mode the build cannot honour yet (`okta`, until Phase A lands).
//! 2. **Local mode unchanged.** With `MCP_AUTH_MODE=off` (or unset — the
//!    default), stdio and loopback HTTP behave **byte-for-byte** as before:
//!    same stdio JSON-RPC bytes, same health banner, same `tools/list`
//!    response body.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;

const BIN: &str = "mcp-devtools";
const STARTUP_MARKER: &str = "listening on streamable-HTTP transport";

/// Base command with a hermetic environment for transport-mode runs.
fn base_command() -> Command {
    let mut command = Command::new(cargo_bin(BIN));
    command
        .env_remove("RUST_LOG")
        .env_remove("MCP_AUTH_MODE")
        .env_remove("MCP_BIND_ADDR")
        .env_remove("LOG_STDERR");
    command
}

/// Run the binary to completion and return `(status_ok, stderr)`.
fn run_to_exit(configure: impl FnOnce(&mut Command)) -> (bool, String) {
    let mut command = base_command();
    command.stdin(Stdio::null()).stdout(Stdio::null());
    configure(&mut command);
    let output = command.output().expect("spawn binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// Fail-closed startup
// ---------------------------------------------------------------------------

#[test]
fn http_refuses_non_loopback_bind_with_auth_off() {
    let (ok, stderr) = run_to_exit(|command| {
        command
            .env("TRANSPORT_MODE", "http")
            .env("PORT", "0")
            .env("MCP_BIND_ADDR", "0.0.0.0");
    });
    assert!(!ok, "must refuse to start; stderr:\n{stderr}");
    assert!(stderr.contains("refusing to start"), "stderr:\n{stderr}");
    assert!(stderr.contains("MCP_AUTH_MODE=off"), "stderr:\n{stderr}");
    assert!(stderr.contains("loopback"), "stderr:\n{stderr}");
}

#[test]
fn http_refuses_okta_mode_until_token_validation_exists() {
    let (ok, stderr) = run_to_exit(|command| {
        command
            .env("TRANSPORT_MODE", "http")
            .env("PORT", "0")
            .env("MCP_AUTH_MODE", "okta");
    });
    assert!(!ok, "must refuse to start; stderr:\n{stderr}");
    assert!(stderr.contains("MCP_AUTH_MODE=okta"), "stderr:\n{stderr}");
}

#[test]
fn stdio_refuses_okta_mode() {
    let (ok, stderr) = run_to_exit(|command| {
        command.env("MCP_AUTH_MODE", "okta");
    });
    assert!(!ok, "must refuse to start; stderr:\n{stderr}");
    assert!(stderr.contains("stdio"), "stderr:\n{stderr}");
    assert!(stderr.contains("MCP_AUTH_MODE=okta"), "stderr:\n{stderr}");
}

#[test]
fn unrecognised_auth_mode_is_refused_not_defaulted_to_off() {
    let (ok, stderr) = run_to_exit(|command| {
        command
            .env("TRANSPORT_MODE", "http")
            .env("PORT", "0")
            .env("MCP_AUTH_MODE", "oauth");
    });
    assert!(!ok, "must refuse to start; stderr:\n{stderr}");
    assert!(stderr.contains("MCP_AUTH_MODE"), "stderr:\n{stderr}");
    assert!(stderr.contains("oauth"), "stderr:\n{stderr}");
}

// ---------------------------------------------------------------------------
// Local mode unchanged — stdio, byte for byte
// ---------------------------------------------------------------------------

/// Drive the stdio transport through initialize → initialized → tools/list
/// and return the raw bytes the server wrote to stdout.
fn stdio_conversation(auth_mode: Option<&str>) -> Vec<u8> {
    let mut command = base_command();
    if let Some(mode) = auth_mode {
        command.env("MCP_AUTH_MODE", mode);
    }
    let mut child = command
        .env_remove("TRANSPORT_MODE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn binary");

    let requests = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"local-mode-test","version":"0.0.0"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        "\n",
    );
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(requests.as_bytes())
        .expect("write requests");
    // stdin dropped here: the server answers both requests, sees EOF, exits.

    let output = child.wait_with_output().expect("wait for binary");
    assert!(
        output.status.success(),
        "stdio run failed (auth_mode={auth_mode:?})"
    );
    let stdout = output.stdout;
    assert!(
        String::from_utf8_lossy(&stdout).lines().count() >= 2,
        "expected two JSON-RPC response lines, got:\n{}",
        String::from_utf8_lossy(&stdout)
    );
    stdout
}

#[test]
fn stdio_is_byte_identical_with_auth_mode_off_and_unset() {
    let unset = stdio_conversation(None);
    let off = stdio_conversation(Some("off"));
    assert_eq!(
        unset,
        off,
        "MCP_AUTH_MODE=off changed stdio behaviour:\nunset: {}\noff:   {}",
        String::from_utf8_lossy(&unset),
        String::from_utf8_lossy(&off)
    );
    // And the conversation actually contains the expected responses.
    let text = String::from_utf8_lossy(&unset);
    assert!(text.contains("\"serverInfo\""), "missing initialize result");
    assert!(text.contains("\"tools\""), "missing tools/list result");
}

// ---------------------------------------------------------------------------
// Local mode unchanged — loopback HTTP, byte for byte
// ---------------------------------------------------------------------------

/// Boot the HTTP transport, fetch the health banner and a stateless
/// `tools/list`, and return both bodies.
async fn http_observables(auth_mode: Option<&str>) -> (String, String) {
    let mut command = tokio::process::Command::new(cargo_bin(BIN));
    command
        .env_remove("RUST_LOG")
        .env_remove("MCP_AUTH_MODE")
        .env_remove("MCP_BIND_ADDR")
        .env("TRANSPORT_MODE", "http")
        .env("PORT", "0")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(mode) = auth_mode {
        command.env("MCP_AUTH_MODE", mode);
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
            assert!(
                !remaining.is_zero(),
                "timed out waiting for startup; stderr:\n{}",
                String::from_utf8_lossy(&collected)
            );
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

    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    let banner = client
        .get(format!("{base}/"))
        .send()
        .await
        .expect("GET /")
        .text()
        .await
        .expect("banner body");
    let tools = client
        .post(format!("{base}/mcp"))
        .header("accept", "application/json, text/event-stream")
        .header("content-type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/list")
        .body(
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": { "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "local-mode-test", "version": "0.0.0"
                    }
                } }
            })
            .to_string(),
        )
        .send()
        .await
        .expect("tools/list")
        .text()
        .await
        .expect("tools/list body");
    (banner, tools)
}

#[tokio::test]
async fn loopback_http_is_byte_identical_with_auth_mode_off_and_unset() {
    let (banner_unset, tools_unset) = http_observables(None).await;
    let (banner_off, tools_off) = http_observables(Some("off")).await;
    assert_eq!(banner_unset, banner_off, "health banner changed");
    assert_eq!(tools_unset, tools_off, "tools/list body changed");
    assert!(banner_unset.starts_with("mcp-server-devtools v"));
    assert!(tools_unset.contains("\"tools\""));
}

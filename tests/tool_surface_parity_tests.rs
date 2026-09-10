//! Golden lock on the **entire** MCP tool surface.
//!
//! Tool names, descriptions, input schemas, and annotations are the crate's
//! public contract with LLM clients, pinned byte-for-byte to the TS reference
//! servers. Changing any of them is a deliberate, called-out change — never an
//! incidental side effect of a refactor.
//!
//! Nothing enforced that before this file existed: `tool_schema_tests` checks
//! the server *identity* and a few `args` round-trips, but no test would have
//! noticed a reworded description, a dropped tool, a changed `annotations`
//! flag, or a schema field silently gaining a default. That is precisely the
//! drift risk when tool registration is reorganised — as it was when the
//! per-integration adapter modules were split out of `tools::mod`.
//!
//! This drives the real binary over stdio and compares the full `tools/list`
//! result against `tests/golden/tool_surface.json`, the same
//! exact-bytes approach `toon_golden_tests` uses for encoder output.
//!
//! **If this test fails and the change was intended**, regenerate with:
//!
//! ```bash
//! cargo run --quiet > /dev/null 2>&1  # ensure the binary is current
//! cargo test --test tool_surface_parity_tests -- --ignored regenerate
//! ```

use std::io::{BufRead, BufReader, Write};
use std::process::{Command as StdCommand, Stdio};

use assert_cmd::cargo::cargo_bin;
use serde_json::Value;

const BIN: &str = "mcp-devtools";
const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/tool_surface.json"
);

/// Drive the binary through initialize → initialized → tools/list and return
/// the `tools` array, normalised for stable comparison.
fn live_tool_surface() -> Value {
    live_exchange(
        "all",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    )["result"]["tools"]
        .clone()
}

fn live_exchange(selection: &str, request: &str) -> Value {
    let mut child = StdCommand::new(cargo_bin(BIN))
        .env_remove("TRANSPORT_MODE")
        .env("MCP_ENABLED_VENDORS", selection)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn binary");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

    for line in [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"parity-test","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        request,
    ] {
        stdin.write_all(line.as_bytes()).expect("write request");
        stdin.write_all(b"\n").expect("write newline");
    }
    stdin.flush().expect("flush");

    let mut reader = BufReader::new(stdout);
    let mut tools = None;
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if let Ok(value) = serde_json::from_str::<Value>(line.trim())
            && value.get("id").and_then(Value::as_u64) == Some(2)
        {
            tools = Some(value);
            break;
        }
        line.clear();
    }

    drop(stdin);
    drop(reader);
    let _ = child.wait();

    tools.expect("exchange returned no response")
}

/// Sort by tool name so router-registration order never makes this flaky.
fn normalise(mut tools: Value) -> Value {
    let arr = tools.as_array_mut().expect("tools is an array");
    arr.sort_by(|a, b| {
        a.get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(b.get("name").and_then(Value::as_str).unwrap_or_default())
    });
    tools
}

#[test]
fn tool_surface_matches_golden() {
    let live = normalise(live_tool_surface());
    let golden: Value = serde_json::from_str(
        &std::fs::read_to_string(GOLDEN).expect("read tests/golden/tool_surface.json"),
    )
    .expect("golden is valid JSON");
    let golden = normalise(golden);

    let live_names: Vec<&str> = live
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .collect();
    let golden_names: Vec<&str> = golden
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .collect();

    // Compare the name set first: a missing or added tool produces a readable
    // failure instead of a thousand-line JSON diff.
    assert_eq!(
        golden_names, live_names,
        "the set of exposed tools changed; if intended, regenerate the golden"
    );

    for (want, got) in golden
        .as_array()
        .unwrap()
        .iter()
        .zip(live.as_array().unwrap())
    {
        let name = want.get("name").and_then(Value::as_str).unwrap_or("?");
        assert_eq!(
            want, got,
            "tool `{name}` drifted from the pinned contract (description, schema, or annotations)"
        );
    }
}

/// Regeneration helper. Run explicitly after an intended contract change:
/// `cargo test --test tool_surface_parity_tests -- --ignored regenerate`
#[test]
#[ignore = "regeneration helper; run explicitly after an intended contract change"]
fn regenerate_golden() {
    let live = normalise(live_tool_surface());
    let pretty = serde_json::to_string_pretty(&live).expect("serialise");
    std::fs::write(GOLDEN, pretty + "\n").expect("write golden");
    println!("regenerated {GOLDEN}");
}

#[test]
fn explicit_session_selection_filters_discovery_and_refuses_disabled_calls() {
    let listed = live_exchange(
        "github,gitlab",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    );
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 21);
    assert!(tools.iter().all(|tool| {
        let name = tool["name"].as_str().unwrap();
        name == "artifact_read" || name.starts_with("github_") || name.starts_with("gitlab_")
    }));
    let called = live_exchange(
        "github,gitlab",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"figma_get_file","arguments":{"file":"fixture"}}}"#,
    );
    assert_eq!(called["error"]["code"], -32602);
    assert!(
        called["error"]["message"]
            .as_str()
            .unwrap()
            .contains("disabled")
    );
}

#[cfg(feature = "ninjaone-db")]
#[test]
fn ninjaone_database_tools_follow_vendor_selection_and_reject_writes() {
    let listed = live_exchange(
        "ninjaone",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    );
    let tools = listed["result"]["tools"].as_array().unwrap();
    let mut names: Vec<_> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .filter(|name| name.starts_with("ninjaone_db_"))
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "ninjaone_db_query_central",
            "ninjaone_db_query_division",
            "ninjaone_db_resolve_division"
        ]
    );
    let called = live_exchange(
        "ninjaone",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ninjaone_db_query_central","arguments":{"environment":"qa5","sql":"DELETE FROM device"}}}"#,
    );
    assert_eq!(called["result"]["isError"], true);
    assert!(
        called["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("is not allowed")
    );
    let disabled = live_exchange(
        "github",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ninjaone_db_query_central","arguments":{"environment":"qa5","sql":"SELECT 1"}}}"#,
    );
    assert_eq!(disabled["error"]["code"], -32602);
    assert!(
        disabled["error"]["message"]
            .as_str()
            .unwrap()
            .contains("disabled")
    );
}

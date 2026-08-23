//! Subprocess helper tests. Exercises the common Unix utilities
//! (`echo`, `false`, `sleep`) that ship with every supported target.

use std::time::Duration;

use mcp_server_devtools::ports::CommandRunner;
use mcp_server_devtools::shell::{
    DEFAULT_TIMEOUT, SystemCommandRunner, execute, execute_with_timeout,
};
use pretty_assertions::assert_eq;

#[tokio::test]
async fn execute_returns_stdout_on_success() {
    let out = execute("echo", &["hello world"], "echo test")
        .await
        .expect("echo should succeed");
    assert_eq!(out.stdout.trim(), "hello world");
}

#[tokio::test]
async fn execute_surfaces_stderr_on_failure() {
    let err = execute("false", &[], "fail test").await.unwrap_err();
    assert!(err.message.to_lowercase().contains("fail test"));
}

#[tokio::test]
async fn missing_binary_yields_error() {
    let err = execute("definitely-not-a-command-xyz123", &[], "run missing bin")
        .await
        .unwrap_err();
    assert!(err.message.to_lowercase().contains("run missing bin"));
}

#[tokio::test]
async fn timeout_kills_long_running_command() {
    let err = execute_with_timeout("sleep", &["10"], "sleep test", Duration::from_millis(50))
        .await
        .unwrap_err();
    assert!(err.message.contains("timed out"));
}

#[test]
fn default_timeout_is_five_minutes() {
    assert_eq!(DEFAULT_TIMEOUT, Duration::from_mins(5));
}

/// Contract test for the outbound adapter. `clone_tests` substitutes a fake for
/// the [`CommandRunner`] port, so something must still prove the *real*
/// implementation spawns a process and reports its output — otherwise the port
/// could drift from the adapter and every clone test would still pass.
#[tokio::test]
async fn system_command_runner_actually_runs_the_program() {
    let out = SystemCommandRunner
        .run("echo", &["via port"], "port contract test")
        .await
        .expect("echo should succeed through the port");
    assert_eq!(out.stdout.trim(), "via port");
}

/// The adapter must map a non-zero exit to the same error shape the port's
/// consumers expect — this is what `clone_tests`' fake reproduces.
#[tokio::test]
async fn system_command_runner_reports_failure_through_the_port() {
    let err = SystemCommandRunner
        .run("false", &[], "port failure test")
        .await
        .unwrap_err();
    assert!(err.message.contains("port failure test"));
}

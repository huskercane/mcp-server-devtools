//! End-to-end clone controller tests. Intercepts the repository-metadata fetch
//! via wiremock and substitutes the [`CommandRunner`] port so the `git`
//! invocation is observable without a real repo, a real network, or a real
//! `git` binary.
//!
//! ## Why there is no `PATH` shim here any more
//!
//! This file used to shadow `git` with a `#!/bin/sh` script by mutating the
//! process-wide `PATH`. That cost three things, all of which the port removes:
//!
//! - `#![allow(unsafe_code)]` — mutating `std::env` is `unsafe` under edition 2024.
//! - `#[serial]` on every test — the mutation was global, so nothing here could
//!   run concurrently with anything else in the file.
//! - `#![cfg(unix)]` on the whole file — a `sh` shim cannot execute on Windows,
//!   so the clone controller had **zero** coverage on the Windows CI runner.
//!
//! These tests now run on every platform in the matrix, in parallel, with no
//! `unsafe`.

use std::collections::HashMap;
use std::sync::Mutex;

use mcp_server_devtools::config::Config;
use mcp_server_devtools::controllers::api::BitbucketContext;
use mcp_server_devtools::controllers::handle_clone;
use mcp_server_devtools::error::{McpError, unexpected};
use mcp_server_devtools::ports::{CommandOutput, CommandRunner};
use mcp_server_devtools::tools::args::CloneArgs;
use mcp_server_devtools::transport::build_client;
use mcp_server_devtools::vendor::bitbucket::BitbucketVendor;
use mcp_server_devtools::workspace::WorkspaceCache;
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// One recorded invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Invocation {
    file: String,
    args: Vec<String>,
    operation: String,
}

/// Test double for [`CommandRunner`]. Records what it was asked to run and
/// returns a scripted outcome instead of spawning anything.
struct FakeCommandRunner {
    outcome: Result<CommandOutput, String>,
    calls: Mutex<Vec<Invocation>>,
}

impl FakeCommandRunner {
    /// A runner that succeeds with empty output.
    fn succeeding() -> Self {
        Self {
            outcome: Ok(CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
            }),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// A runner that fails the way `shell::execute` reports a non-zero exit
    /// with no stderr or stdout — the shape the real adapter produces.
    fn failing_with_exit_code(code: i32) -> Self {
        Self {
            outcome: Err(format!("exit code {code}")),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn invocations(&self) -> Vec<Invocation> {
        self.calls.lock().unwrap().clone()
    }

    /// The single invocation this runner received. Panics if it was not called
    /// exactly once, which is itself the assertion we want.
    fn only_invocation(&self) -> Invocation {
        let calls = self.invocations();
        assert_eq!(calls.len(), 1, "expected exactly one command invocation");
        calls.into_iter().next().unwrap()
    }
}

impl CommandRunner for FakeCommandRunner {
    fn run(
        &self,
        file: &str,
        args: &[&str],
        operation: &str,
    ) -> impl Future<Output = Result<CommandOutput, McpError>> + Send {
        self.calls.lock().unwrap().push(Invocation {
            file: file.to_owned(),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            operation: operation.to_owned(),
        });
        let result = match &self.outcome {
            Ok(output) => Ok(output.clone()),
            Err(detail) => Err(unexpected(format!("Failed to {operation}: {detail}"), None)),
        };
        std::future::ready(result)
    }
}

fn creds() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("ATLASSIAN_USER_EMAIL".into(), "alice@example.com".into());
    m.insert("ATLASSIAN_API_TOKEN".into(), "tok".into());
    m
}

/// Mount the repo-metadata endpoint returning the supplied clone links.
async fn mock_repo_with_clone_links(links: serde_json::Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2.0/repositories/acme/widget"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "links": { "clone": links }
        })))
        .mount(&server)
        .await;
    server
}

fn args_for(target: &TempDir, repo_slug: &str) -> CloneArgs {
    CloneArgs {
        workspace_slug: Some("acme".into()),
        repo_slug: repo_slug.into(),
        target_path: target.path().display().to_string(),
    }
}

#[tokio::test]
async fn successful_clone_prefers_ssh_and_invokes_git() {
    let server = mock_repo_with_clone_links(json!([
        {"href": "https://bitbucket.org/acme/widget.git", "name": "https"},
        {"href": "git@bitbucket.org:acme/widget.git", "name": "ssh"}
    ]))
    .await;

    let clone_root = TempDir::new().unwrap();
    let runner = FakeCommandRunner::succeeding();

    let client = build_client().unwrap();
    let config = Config::from_map(creds());
    let vendor = BitbucketVendor::with_base_url(server.uri());
    let cache = WorkspaceCache::new();
    let ctx = BitbucketContext::new(&client, &config, &vendor, &cache);

    let resp = handle_clone(&ctx, &runner, &args_for(&clone_root, "widget"))
        .await
        .unwrap();

    assert!(resp.content.contains("using SSH"));
    assert!(resp.content.contains("acme/widget"));

    let call = runner.only_invocation();
    assert_eq!(call.file, "git");
    assert_eq!(call.operation, "cloning repository");
    assert_eq!(call.args[0], "clone");
    assert_eq!(call.args[1], "git@bitbucket.org:acme/widget.git");
    assert!(
        call.args[2].ends_with("widget"),
        "clone target should be <target>/<repoSlug>, got {}",
        call.args[2]
    );
}

#[tokio::test]
async fn falls_back_to_https_when_no_ssh_link() {
    let server = mock_repo_with_clone_links(json!([
        {"href": "https://bitbucket.org/acme/widget.git", "name": "https"}
    ]))
    .await;

    let clone_root = TempDir::new().unwrap();
    let runner = FakeCommandRunner::succeeding();

    let client = build_client().unwrap();
    let config = Config::from_map(creds());
    let vendor = BitbucketVendor::with_base_url(server.uri());
    let cache = WorkspaceCache::new();
    let ctx = BitbucketContext::new(&client, &config, &vendor, &cache);

    let resp = handle_clone(&ctx, &runner, &args_for(&clone_root, "widget"))
        .await
        .unwrap();

    assert!(resp.content.contains("using HTTPS"));
    assert_eq!(
        runner.only_invocation().args[1],
        "https://bitbucket.org/acme/widget.git"
    );
}

#[tokio::test]
async fn invalid_slug_is_rejected_before_network() {
    // Intentionally no mocks: reaching the network would 404, but slug
    // validation must short-circuit first.
    let server = MockServer::start().await;
    let clone_root = TempDir::new().unwrap();
    let runner = FakeCommandRunner::succeeding();

    let client = build_client().unwrap();
    let config = Config::from_map(creds());
    let vendor = BitbucketVendor::with_base_url(server.uri());
    let cache = WorkspaceCache::new();
    let ctx = BitbucketContext::new(&client, &config, &vendor, &cache);

    let err = handle_clone(&ctx, &runner, &args_for(&clone_root, "bad/slug"))
        .await
        .unwrap_err();

    assert!(err.message.contains("Invalid repository slug"));
    assert!(
        runner.invocations().is_empty(),
        "no command should run for an invalid slug"
    );
}

#[tokio::test]
async fn existing_subdir_returns_info_not_error() {
    let server = mock_repo_with_clone_links(json!([
        {"href": "git@bitbucket.org:acme/widget.git", "name": "ssh"}
    ]))
    .await;

    let clone_root = TempDir::new().unwrap();
    std::fs::create_dir_all(clone_root.path().join("widget")).unwrap();
    let runner = FakeCommandRunner::succeeding();

    let client = build_client().unwrap();
    let config = Config::from_map(creds());
    let vendor = BitbucketVendor::with_base_url(server.uri());
    let cache = WorkspaceCache::new();
    let ctx = BitbucketContext::new(&client, &config, &vendor, &cache);

    let resp = handle_clone(&ctx, &runner, &args_for(&clone_root, "widget"))
        .await
        .unwrap();

    assert!(resp.content.contains("already exists"));
    assert!(
        runner.invocations().is_empty(),
        "no command should run when the target already exists"
    );
}

#[tokio::test]
async fn git_failure_surfaces_ssh_troubleshooting() {
    let server = mock_repo_with_clone_links(json!([
        {"href": "git@bitbucket.org:acme/widget.git", "name": "ssh"}
    ]))
    .await;

    let clone_root = TempDir::new().unwrap();
    let runner = FakeCommandRunner::failing_with_exit_code(128);

    let client = build_client().unwrap();
    let config = Config::from_map(creds());
    let vendor = BitbucketVendor::with_base_url(server.uri());
    let cache = WorkspaceCache::new();
    let ctx = BitbucketContext::new(&client, &config, &vendor, &cache);

    let err = handle_clone(&ctx, &runner, &args_for(&clone_root, "widget"))
        .await
        .unwrap_err();

    assert!(err.message.contains("Troubleshooting SSH Clone Issues"));
}

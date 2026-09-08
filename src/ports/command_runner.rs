//! Port for running an external program.
//!
//! ## Why this one earns its keep
//!
//! `bb_clone` shells out to `git`. With the controller calling
//! [`crate::shell::execute`] directly, the only way to test it was to mutate
//! the process-wide `PATH` and shadow `git` with a shim script — which forced
//! `tests/clone_tests.rs` to:
//!
//! - opt into `#![allow(unsafe_code)]` (mutating `std::env` is `unsafe` under
//!   edition 2024),
//! - serialize every test in the file behind `#[serial]` plus a path lock,
//!   because the mutation is global, and
//! - `#![cfg(unix)]` the entire file away, since the shim is a `#!/bin/sh`
//!   script — so the clone controller had **no** coverage on the Windows CI
//!   runner at all.
//!
//! Substituting the runner instead removes all three. This is a port with two
//! genuine implementations — [`SystemCommandRunner`] in production and a fake
//! in tests — not a trait invented to satisfy a folder layout.
//!
//! ## Dispatch
//!
//! Return-position `impl Future` keeps this allocation-free: no
//! `Box<dyn Future>`, no `async_trait`. The trait is consequently not
//! object-safe, which is deliberate — callers take `&impl CommandRunner` and
//! monomorphise, so an injected port costs the same as the direct call did.

use std::future::Future;

use crate::error::McpError;

/// What a command produced on success.
///
/// Mirrors the shape the shell helper already returned, so the port adds no
/// translation cost on the production path.
pub type CommandOutput = crate::shell::ShellOutput;

/// Runs an external program with an argument vector.
///
/// Implementations must not route through a shell: arguments are passed to the
/// kernel verbatim so there is no command-injection surface (CWE-78).
pub trait CommandRunner: Send + Sync {
    /// Run `file` with `args`.
    ///
    /// `operation` is a short human-readable description used in error
    /// messages (e.g. `"cloning repository"`).
    fn run(
        &self,
        file: &str,
        args: &[&str],
        operation: &str,
    ) -> impl Future<Output = Result<CommandOutput, McpError>> + Send;
}

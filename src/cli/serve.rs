//! `mcp-devtools serve`: the server, with the transport and process role
//! as flags (plan ADR-010, WP A.9).
//!
//! Running the binary with no arguments is unchanged and reads
//! `TRANSPORT_MODE` and `MCP_ROLE`; this subcommand exists so a container
//! `ENTRYPOINT` can say what it runs without an environment block, and so
//! `--role` is discoverable from `--help`.

use std::process::ExitCode;

use clap::{Args, ValueEnum};

use crate::server::Role;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TransportArg {
    Http,
    Stdio,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RoleArg {
    /// Data plane and control plane in one process.
    All,
    /// The data plane only: `/mcp`, artifacts, token validation, policy.
    Gateway,
    /// The control plane only: health in Phase A; admin API and console later.
    Control,
}

impl From<RoleArg> for Role {
    fn from(role: RoleArg) -> Self {
        match role {
            RoleArg::All => Self::All,
            RoleArg::Gateway => Self::Gateway,
            RoleArg::Control => Self::Control,
        }
    }
}

#[derive(Debug, Args)]
pub struct ServeOpts {
    /// Transport to serve. Defaults to `TRANSPORT_MODE`, then `stdio`.
    #[arg(long, value_enum)]
    pub transport: Option<TransportArg>,
    /// Process role. Defaults to `MCP_ROLE`, then `all`. Only meaningful
    /// for the HTTP transport.
    #[arg(long, value_enum)]
    pub role: Option<RoleArg>,
}

/// Run the server as configured. Never returns while the server runs.
pub async fn dispatch(opts: ServeOpts) -> ExitCode {
    let transport = opts.transport.unwrap_or_else(|| {
        let mode = std::env::var("TRANSPORT_MODE").unwrap_or_default();
        if mode.eq_ignore_ascii_case("http") {
            TransportArg::Http
        } else {
            TransportArg::Stdio
        }
    });
    let result = match transport {
        TransportArg::Stdio => crate::server::run_stdio().await,
        TransportArg::Http => {
            let role = match opts.role {
                Some(role) => Ok(role.into()),
                None => Role::parse(std::env::var(crate::server::http::ROLE_KEY).ok().as_deref()),
            };
            match role {
                Ok(role) => crate::server::run_http_as(role).await,
                Err(reason) => Err(reason.into()),
            }
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fatal: {error}");
            ExitCode::FAILURE
        }
    }
}

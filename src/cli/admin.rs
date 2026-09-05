//! Administrative client. All operations call the audited HTTP boundary
//! through the `AdminClient` port's HTTP adapter (plan §3.10.1).
use crate::{
    admin::HttpAdminClient,
    ports::{AdminClient as _, AdminClientError, AdminMethod, AdminRequest},
};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Debug, Args)]
pub struct Options {
    #[arg(long, env = "MCP_ADMIN_URL")]
    url: String,
    #[arg(long)]
    token_file: PathBuf,
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Debug, Subcommand)]
pub enum Command {
    Policy {
        #[command(subcommand)]
        command: Policy,
    },
    Principals {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        subject: String,
    },
    Sessions {
        #[command(subcommand)]
        command: Inventory,
    },
    Artifacts {
        #[command(subcommand)]
        command: Inventory,
    },
    DenyList {
        #[command(subcommand)]
        command: DenyList,
    },
    /// Run a B.5 report with a JSON request file.
    Report {
        #[arg(value_parser = ["activity", "access-review"])]
        report: String,
        #[arg(long)]
        request: PathBuf,
    },
    /// Run a C.6 named `ReportQuery` from a JSON file.
    Usage {
        #[arg(long)]
        request: PathBuf,
    },
}
#[derive(Debug, Subcommand)]
pub enum Policy {
    Read,
    Validate { file: PathBuf },
    Diff { file: PathBuf },
    Reload,
}
#[derive(Debug, Subcommand)]
pub enum Inventory {
    List,
    Remove { id: String },
}
#[derive(Debug, Subcommand)]
pub enum DenyList {
    Read,
    Replace {
        file: PathBuf,
        #[arg(long)]
        signature: PathBuf,
    },
}

async fn text_file(path: &Path) -> Result<String, &'static str> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|_| "file_unavailable")?;
    if metadata.len() > 1_000_000 {
        return Err("file_too_large");
    }
    tokio::fs::read_to_string(path)
        .await
        .map_err(|_| "file_unavailable")
}
impl Command {
    async fn request(&self) -> Result<(AdminMethod, String, Option<Value>), &'static str> {
        use AdminMethod::{Get, Post, Put};
        let (method, path, body) = match self {
            Self::Policy {
                command: Policy::Read,
            } => (Get, "policy".into(), None),
            Self::Policy {
                command: Policy::Reload,
            } => (Post, "policy/reload".into(), Some(json!({}))),
            Self::Policy {
                command: command @ (Policy::Validate { file } | Policy::Diff { file }),
            } => (
                Post,
                if matches!(command, Policy::Validate { .. }) {
                    "policy/validate"
                } else {
                    "policy/diff"
                }
                .into(),
                Some(json!({"document":text_file(file).await?})),
            ),
            Self::Principals { tenant, subject } => (
                Post,
                "principals/lookup".into(),
                Some(json!({"tenant":tenant,"subject":subject})),
            ),
            Self::Sessions {
                command: Inventory::List,
            } => (Get, "sessions".into(), None),
            Self::Artifacts {
                command: Inventory::List,
            } => (Get, "artifacts".into(), None),
            Self::Sessions {
                command: Inventory::Remove { id },
            } => (Post, "sessions/revoke".into(), Some(json!({"id":id}))),
            Self::Artifacts {
                command: Inventory::Remove { id },
            } => (Post, "artifacts/purge".into(), Some(json!({"id":id}))),
            Self::DenyList {
                command: DenyList::Read,
            } => (Get, "deny-list".into(), None),
            Self::DenyList {
                command: DenyList::Replace { file, signature },
            } => (
                Put,
                "deny-list".into(),
                Some(
                    json!({"document":text_file(file).await?,"signature":text_file(signature).await?.trim()}),
                ),
            ),
            Self::Report { report, request } => (
                Post,
                format!("reports/{report}"),
                Some(serde_json::from_str(&text_file(request).await?).map_err(|_| "invalid_json")?),
            ),
            Self::Usage { request } => (
                Post,
                "usage".into(),
                Some(serde_json::from_str(&text_file(request).await?).map_err(|_| "invalid_json")?),
            ),
        };
        Ok((method, path, body))
    }
}
async fn execute(options: &Options) -> Result<(bool, Value), &'static str> {
    let client = HttpAdminClient::new(&options.url).map_err(AdminClientError::code)?;
    let token = text_file(&options.token_file).await?;
    let token = token.trim();
    if token.is_empty() {
        return Err("empty_token");
    }
    let (method, operation, body) = options.command.request().await?;
    let response = client
        .call(
            token,
            AdminRequest {
                method,
                operation: &operation,
                body: body.as_ref(),
            },
        )
        .await
        .map_err(AdminClientError::code)?;
    Ok((response.is_success(), response.body))
}
pub async fn dispatch(options: &Options) -> ExitCode {
    let (success, value) = execute(options)
        .await
        .unwrap_or_else(|error| (false, json!({"error":error,"error_description":error})));
    if options.json {
        println!("{value}");
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("JSON value")
        );
    }
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

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
    /// Two-person approval (WP D.2): pending proposals and decisions.
    Proposals {
        #[command(subcommand)]
        command: Proposals,
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
    Validate {
        file: PathBuf,
    },
    Diff {
        file: PathBuf,
    },
    Reload,
    /// Install a signed policy: the exact file bytes and the detached
    /// signature produced by `policy sign`.
    Install {
        file: PathBuf,
        #[arg(long)]
        signature: PathBuf,
    },
    /// Ask the running server why the policy in force allows or denies a
    /// call (`POST /admin/policy/explain`): the same inputs as
    /// `mcp-devtools policy explain`, evaluated by the server under its own
    /// configuration, against the policy it is enforcing right now.
    Explain(Box<Explain>),
}
#[derive(Debug, Args)]
pub struct Explain {
    /// The tool the call names, e.g. `slack_channel_history`.
    #[arg(long)]
    tool: String,
    /// The tool's arguments as a JSON object.
    #[arg(long, default_value = "{}")]
    arguments: String,
    /// The caller's subject (`sub`); default `someone@example`.
    #[arg(long)]
    subject: Option<String>,
    /// A group the caller belongs to (repeatable).
    #[arg(long = "group")]
    groups: Vec<String>,
    /// A scope the token carries (repeatable; default `mcp:tools`).
    #[arg(long = "scope")]
    scopes: Vec<String>,
    /// Override the server's configured environment for a what-if:
    /// `prod`, `staging`, `qa`, `dev`.
    #[arg(long)]
    environment: Option<String>,
    /// Tenant label of the principal; default: the token's tenant.
    #[arg(long)]
    tenant: Option<String>,
    /// The client name the caller would report (telemetry only).
    #[arg(long)]
    client_name: Option<String>,
    /// The client version the caller would report.
    #[arg(long)]
    client_version: Option<String>,
}
impl Explain {
    fn body(&self) -> Result<Value, &'static str> {
        let arguments: Value = serde_json::from_str(&self.arguments).map_err(|_| "invalid_json")?;
        if !arguments.is_object() {
            return Err("invalid_json");
        }
        let mut body = serde_json::Map::new();
        body.insert("tool".into(), Value::String(self.tool.clone()));
        body.insert("arguments".into(), arguments);
        for (key, value) in [
            ("subject", &self.subject),
            ("environment", &self.environment),
            ("tenant", &self.tenant),
            ("client_name", &self.client_name),
            ("client_version", &self.client_version),
        ] {
            if let Some(value) = value {
                body.insert(key.into(), Value::String(value.clone()));
            }
        }
        if !self.groups.is_empty() {
            body.insert("groups".into(), json!(self.groups));
        }
        if !self.scopes.is_empty() {
            body.insert("scopes".into(), json!(self.scopes));
        }
        Ok(Value::Object(body))
    }
}
#[derive(Debug, Subcommand)]
pub enum Inventory {
    List,
    Remove { id: String },
}
#[derive(Debug, Subcommand)]
pub enum Proposals {
    List,
    Show {
        id: String,
    },
    Approve {
        id: String,
    },
    Reject {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
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
/// A proposal id as the server mints them; anything else never becomes
/// part of a request path.
fn proposal_id(id: &str) -> Result<&str, &'static str> {
    let hex = id.strip_prefix("p-").ok_or("invalid_id")?;
    if hex.len() == 16 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(id)
    } else {
        Err("invalid_id")
    }
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
            Self::Policy {
                command: Policy::Install { file, signature },
            } => (
                Put,
                "policy".into(),
                Some(
                    json!({"document":text_file(file).await?,"signature":text_file(signature).await?.trim()}),
                ),
            ),
            Self::Policy {
                command: Policy::Explain(explain),
            } => (Post, "policy/explain".into(), Some(explain.body()?)),
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
            Self::Proposals {
                command: Proposals::List,
            } => (Get, "proposals".into(), None),
            Self::Proposals {
                command: Proposals::Show { id },
            } => (Get, format!("proposals/{}", proposal_id(id)?), None),
            Self::Proposals {
                command: Proposals::Approve { id },
            } => (
                Post,
                format!("proposals/{}/approve", proposal_id(id)?),
                Some(json!({})),
            ),
            Self::Proposals {
                command: Proposals::Reject { id, reason },
            } => (
                Post,
                format!("proposals/{}/reject", proposal_id(id)?),
                Some(match reason {
                    Some(reason) => json!({"reason": reason}),
                    None => json!({}),
                }),
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

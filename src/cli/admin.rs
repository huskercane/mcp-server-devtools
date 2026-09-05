//! Administrative client. All operations call the audited HTTP boundary.
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
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
    async fn request(&self) -> Result<(&str, String, Option<Value>), &'static str> {
        let (method, path, body) = match self {
            Self::Policy {
                command: Policy::Read,
            } => ("GET", "policy".into(), None),
            Self::Policy {
                command: Policy::Reload,
            } => ("POST", "policy/reload".into(), Some(json!({}))),
            Self::Policy {
                command: command @ (Policy::Validate { file } | Policy::Diff { file }),
            } => (
                "POST",
                if matches!(command, Policy::Validate { .. }) {
                    "policy/validate"
                } else {
                    "policy/diff"
                }
                .into(),
                Some(json!({"document":text_file(file).await?})),
            ),
            Self::Principals { tenant, subject } => (
                "POST",
                "principals/lookup".into(),
                Some(json!({"tenant":tenant,"subject":subject})),
            ),
            Self::Sessions {
                command: Inventory::List,
            } => ("GET", "sessions".into(), None),
            Self::Artifacts {
                command: Inventory::List,
            } => ("GET", "artifacts".into(), None),
            Self::Sessions {
                command: Inventory::Remove { id },
            } => ("POST", "sessions/revoke".into(), Some(json!({"id":id}))),
            Self::Artifacts {
                command: Inventory::Remove { id },
            } => ("POST", "artifacts/purge".into(), Some(json!({"id":id}))),
            Self::DenyList {
                command: DenyList::Read,
            } => ("GET", "deny-list".into(), None),
            Self::DenyList {
                command: DenyList::Replace { file, signature },
            } => (
                "PUT",
                "deny-list".into(),
                Some(
                    json!({"document":text_file(file).await?,"signature":text_file(signature).await?.trim()}),
                ),
            ),
            Self::Report { report, request } => (
                "POST",
                format!("reports/{report}"),
                Some(serde_json::from_str(&text_file(request).await?).map_err(|_| "invalid_json")?),
            ),
            Self::Usage { request } => (
                "POST",
                "usage".into(),
                Some(serde_json::from_str(&text_file(request).await?).map_err(|_| "invalid_json")?),
            ),
        };
        Ok((method, path, body))
    }
}
async fn execute(options: &Options) -> Result<(bool, Value), &'static str> {
    let base = url::Url::parse(&options.url).map_err(|_| "invalid_url")?;
    let local = match base.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain("localhost")) => true,
        _ => false,
    };
    if !(base.scheme() == "https" || (base.scheme() == "http" && local))
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
        || base.path() != "/"
    {
        return Err("invalid_url");
    }
    let token = text_file(&options.token_file).await?;
    let token = token.trim();
    if token.is_empty() {
        return Err("empty_token");
    }
    let (method, path, body) = options.command.request().await?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_mins(1))
        .build()
        .map_err(|_| "http_unavailable")?;
    let mut request = client
        .request(
            method.parse().map_err(|_| "invalid_method")?,
            base.join(&format!("admin/{path}"))
                .map_err(|_| "invalid_url")?,
        )
        .bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let mut response = request.send().await.map_err(|_| "admin_unreachable")?;
    let success = response.status().is_success();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "invalid_response")? {
        if bytes.len() + chunk.len() > 32 * 1024 * 1024 {
            return Err("response_too_large");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((
        success,
        serde_json::from_slice(&bytes).map_err(|_| "invalid_response")?,
    ))
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

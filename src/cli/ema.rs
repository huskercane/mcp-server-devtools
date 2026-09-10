//! Explicit EMA exchange for a pre-registered client. Tokens are file inputs
//! and a newly created private output file, never command-line values/stdout.
use crate::auth::ema::{ClientCredentials, ExchangeRequest, OidcExchange, SubjectType};
use clap::{Args, Subcommand};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Debug, Args)]
pub struct Options {
    #[command(subcommand)]
    pub command: Command,
}
// Plain comment, not a doc comment: clap renders doc comments into `--help`,
// and this enum's text is CLI-facing surface held to parity.
//
// `ExchangeOptions` is much larger than `JwksOptions`, but clap's `Subcommand`
// derive requires each tuple variant's inner type to implement
// `Args`/`FromArgMatches`, which `Box<ExchangeOptions>` does not — so clippy's
// suggested boxing will not compile here. Fires only on Windows, where the
// variant sizes land either side of the lint threshold.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum Command {
    Exchange(ExchangeOptions),
    /// Capture public signing keys for an offline deployment.
    Jwks(JwksOptions),
}
#[derive(Debug, Args)]
pub struct JwksOptions {
    #[command(subcommand)]
    pub command: JwksCommand,
}
#[derive(Debug, Subcommand)]
pub enum JwksCommand {
    Fetch {
        #[arg(long)]
        url: String,
        /// Must not already exist; deploy with an atomic rename after review.
        #[arg(long)]
        output: PathBuf,
    },
}
async fn fetch_keys(options: &JwksOptions) -> ExitCode {
    let JwksCommand::Fetch { url, output } = &options.command;
    let result = async {
        let body = crate::auth::oidc::fetch_jwks(url).await?;
        let body = std::str::from_utf8(&body).map_err(|_| "JWKS is not UTF-8".to_owned())?;
        write_private(output, body).await.map_err(str::to_owned)
    }
    .await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("JWKS fetch failed: {error}");
            ExitCode::FAILURE
        }
    }
}
#[derive(Debug, Args)]
pub struct ExchangeOptions {
    #[arg(long)]
    pub idp_issuer: String,
    #[arg(long)]
    pub issuer: String,
    #[arg(long)]
    pub resource: String,
    #[arg(long)]
    pub scope: String,
    #[arg(long)]
    pub idp_client_id: String,
    #[arg(long)]
    pub resource_client_id: String,
    #[arg(long)]
    pub identity_token_file: PathBuf,
    /// Input is an `IdP` refresh token (e.g. obtained through SAML SSO).
    #[arg(long)]
    pub refresh_token: bool,
    #[arg(long)]
    pub idp_client_assertion_file: Option<PathBuf>,
    #[arg(long)]
    pub resource_client_assertion_file: Option<PathBuf>,
    /// Must not already exist. Contains the final access token only.
    #[arg(long)]
    pub output_token_file: PathBuf,
    #[arg(long)]
    pub json: bool,
}
async fn read_secret(path: &Path) -> Result<String, &'static str> {
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| "credential_file_unreadable")?;
    let mut bytes = Vec::with_capacity(4096);
    file.take(65_537)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| "credential_file_unreadable")?;
    if bytes.len() > 65_536 {
        return Err("credential_file_too_large");
    }
    let text = String::from_utf8(bytes).map_err(|_| "invalid_credential_file")?;
    if text.trim().is_empty() {
        return Err("invalid_credential_file");
    }
    Ok(text.trim().to_owned())
}
async fn optional_secret(path: Option<&Path>) -> Result<Option<String>, &'static str> {
    match path {
        Some(path) => read_secret(path).await.map(Some),
        None => Ok(None),
    }
}
async fn run(options: &ExchangeOptions) -> Result<(), &'static str> {
    if !cfg!(unix) {
        return Err("private_output_requires_unix");
    }
    match tokio::fs::symlink_metadata(&options.output_token_file).await {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("output_file_unavailable"),
    }
    let identity = read_secret(&options.identity_token_file).await?;
    let idp_assertion = optional_secret(options.idp_client_assertion_file.as_deref()).await?;
    let resource_assertion =
        optional_secret(options.resource_client_assertion_file.as_deref()).await?;
    let client = OidcExchange::new()?;
    let token = client
        .exchange(&ExchangeRequest {
            idp_issuer: &options.idp_issuer,
            resource_issuer: &options.issuer,
            resource: &options.resource,
            scope: &options.scope,
            identity_assertion: &identity,
            subject_type: if options.refresh_token {
                SubjectType::RefreshToken
            } else {
                SubjectType::IdToken
            },
            idp_client: ClientCredentials {
                client_id: &options.idp_client_id,
                assertion: idp_assertion.as_deref(),
            },
            resource_client: ClientCredentials {
                client_id: &options.resource_client_id,
                assertion: resource_assertion.as_deref(),
            },
        })
        .await?;
    write_private(&options.output_token_file, token.expose()).await
}
#[cfg(unix)]
async fn write_private(path: &Path, token: &str) -> Result<(), &'static str> {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .await
        .map_err(|_| "output_file_unavailable")?;
    file.write_all(token.as_bytes())
        .await
        .map_err(|_| "output_write_failed")?;
    file.sync_all().await.map_err(|_| "output_write_failed")
}
/// `async` is kept to match the `#[cfg(unix)]` definition above, which does
/// await; callers `.await` this regardless of platform, so the signatures of
/// the two cfg arms have to agree. Only this arm has nothing to await, which
/// is why the lint fires on Windows alone.
#[cfg(not(unix))]
#[allow(clippy::unused_async)]
async fn write_private(_path: &Path, _token: &str) -> Result<(), &'static str> {
    Err("private_output_requires_unix")
}
pub async fn dispatch(options: &Options) -> ExitCode {
    let options = match &options.command {
        Command::Exchange(options) => options,
        Command::Jwks(options) => return fetch_keys(options).await,
    };
    let result = run(options).await;
    let body = match result {
        Ok(()) => serde_json::json!({"data":{"written":true}}),
        Err(error) => serde_json::json!({"error":error,"error_description":"EMA exchange failed"}),
    };
    if options.json {
        println!("{body}");
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&body).expect("JSON value")
        );
    }
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

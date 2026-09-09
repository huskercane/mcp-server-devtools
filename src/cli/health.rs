//! `mcp-devtools health`: probe a running server's health banner.
//!
//! Exists for the container image (WP A.9): a distroless runtime has no
//! shell and no curl, so the `HEALTHCHECK` is the binary probing itself.
//! Exit status is the whole contract — 0 when the banner answers 2xx, 1
//! otherwise — which is also what a Kubernetes exec probe reads.

use std::process::ExitCode;
use std::time::Duration;

use clap::Args;

#[derive(Debug, Args)]
pub struct HealthOpts {
    /// URL of the health banner. Defaults to `http://127.0.0.1:${PORT:-3000}/`.
    #[arg(long)]
    pub url: Option<String>,
    /// Request timeout in seconds.
    #[arg(long, default_value_t = 3)]
    pub timeout_seconds: u64,
}

/// Probe the banner and map its status to an exit code.
pub async fn dispatch(opts: &HealthOpts) -> ExitCode {
    let url = opts.url.clone().unwrap_or_else(|| {
        let port = std::env::var("PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(3000);
        format!("http://127.0.0.1:{port}/")
    });
    let client = match crate::transport::HttpClient::builder()
        .timeout(Duration::from_secs(opts.timeout_seconds.max(1)))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            eprintln!("health: cannot build HTTP client: {error}");
            return ExitCode::FAILURE;
        }
    };
    match client.get(&url).send().await {
        Ok(response) if response.status().is_success() => {
            println!("healthy: {} {}", response.status().as_u16(), url);
            ExitCode::SUCCESS
        }
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            eprintln!("unhealthy: {status} {url}: {}", body.trim());
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("unhealthy: {url}: {error}");
            ExitCode::FAILURE
        }
    }
}

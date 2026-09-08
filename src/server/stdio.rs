//! Stdio MCP transport. Ported from `startServer('stdio')` in `src/index.ts`.

use rmcp::service::ServiceExt;
use rmcp::transport::io::stdio;
use tracing::info;

use crate::error::McpError;
use crate::server::shutdown;
use crate::tools::DevtoolsServer;

/// Boot the server on the stdio transport, consuming the calling task until
/// the peer disconnects or a shutdown signal is received. Matches TS
/// `startServer('stdio')` + the SIGINT/SIGTERM handlers in
/// `setupGracefulShutdown` (`src/index.ts:411-478`).
pub async fn run_stdio() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Fail closed on a mode this transport cannot honour: stdio has no
    // inbound token to validate, so silently ignoring MCP_AUTH_MODE=oidc
    // would look authenticated while being nothing of the kind.
    match crate::config::AuthMode::parse(std::env::var("MCP_AUTH_MODE").ok().as_deref())? {
        crate::config::AuthMode::Off => {}
        crate::config::AuthMode::Oidc(keys) => {
            return Err(format!(
                "refusing to start: MCP_AUTH_MODE={} is not supported on the stdio \
                 transport (there is no inbound token to validate). Unset MCP_AUTH_MODE \
                 (or set it to \"off\") for local stdio use",
                keys.mode()
            )
            .into());
        }
    }
    crate::transport::raw_response::start_retention_sweeper();
    // Registered before the transport is serving, for the same reason as the
    // HTTP transport: see `shutdown::install`.
    let shutdown_signal = shutdown::install();
    let handler = DevtoolsServer::new().map_err(boxed_err)?;
    // Resolved, then durable, before the first request is read — as the
    // HTTP transport does before it binds.
    handler.resolve_secrets().await.map_err(boxed_err)?;
    handler.journal_startup().await.map_err(boxed_err)?;
    let pending_audit = handler.pending_audit();
    let transport = stdio();
    let service = handler.serve(transport).await?;

    // Cancelling this token tells the rmcp service task to shut down, which in
    // turn makes `service.waiting()` resolve.
    let cancel = service.cancellation_token();
    let shutdown_task = tokio::spawn(async move {
        shutdown_signal.wait().await;
        info!("shutdown signal received; closing stdio transport");
        cancel.cancel();
    });

    let waited = service.waiting().await;
    // Natural exit (peer closed stdio): abort the signal task so it doesn't
    // linger for a signal that will never come.
    shutdown_task.abort();
    crate::tools::drain_pending_audit(&pending_audit).await;
    crate::transport::raw_response::shutdown_and_cleanup().await;
    waited?;
    Ok(())
}

fn boxed_err(err: McpError) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(err)
}

//! MCP inbound adapter for Artifact chunk reads.
//!
//! Hosts the `#[tool_router]` impl block for this integration plus the
//! `run_*` helpers its tools dispatch through. Split out of `tools::mod`,
//! which had grown to hold every integration at once alongside the server
//! type itself.

use super::prelude::*;

#[tool_router(vis = "pub(crate)", router = artifact_router)]
impl DevtoolsServer {
    #[tool(
        description = "Read a resumable byte chunk from a temporary artifact returned by another tool. Data is base64 encoded; continue with nextOffset until eof is true.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn artifact_read(
        &self,
        Parameters(args): Parameters<ArtifactReadArgs>,
    ) -> Result<CallToolResult, RmcpError> {
        use base64::Engine as _;
        let max_bytes = args.max_bytes.unwrap_or(65_536).clamp(1, 1_048_576);
        match crate::transport::raw_response::read_artifact_chunk(
            &args.artifact_id,
            args.offset,
            max_bytes,
        )
        .await
        {
            Ok(Some((metadata, data, next_offset, eof))) => {
                let value = serde_json::json!({
                    "artifactId": metadata.id,
                    "filename": metadata.filename,
                    "offset": args.offset.min(metadata.size),
                    "nextOffset": next_offset,
                    "totalBytes": metadata.size,
                    "eof": eof,
                    "encoding": "base64",
                    "data": base64::engine::general_purpose::STANDARD.encode(data),
                });
                Ok(CallToolResult::success(vec![Content::text(
                    value.to_string(),
                )]))
            }
            Ok(None) => Ok(CallToolResult::error(vec![Content::text(
                "Artifact not found or expired",
            )])),
            Err(err) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to read artifact: {err}"
            ))])),
        }
    }
}

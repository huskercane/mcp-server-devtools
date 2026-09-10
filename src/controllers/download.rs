//! Common metadata-only output for explicit downloads.
use crate::config::Config;
use crate::error::{McpError, api_error};
use crate::transport::{StreamingDiskQuota, StreamingPolicy, raw_response};

pub(crate) fn policy(max_bytes: Option<u64>) -> Result<StreamingPolicy, McpError> {
    let limit = max_bytes.unwrap_or(32 * 1024 * 1024);
    if limit == 0 || limit > crate::constants::data_limits::MAX_STREAMED_ARTIFACT_SIZE {
        return Err(api_error(
            "maxBytes must be between 1 and 536870912",
            Some(400),
            None,
        ));
    }
    let mut policy = StreamingPolicy::new(limit, limit);
    policy.disk = Some(StreamingDiskQuota::server_transaction(
        policy.cancellation.clone(),
    ));
    Ok(policy)
}

pub(crate) fn metadata(
    artifact: &raw_response::StreamedArtifact,
    config: &Config,
) -> serde_json::Value {
    raw_response::retain_download(&artifact.artifact.id);
    serde_json::json!({
        "artifactId": artifact.artifact.id,
        "filename": artifact.artifact.filename,
        "mediaType": artifact.artifact.content_type,
        "bytes": artifact.artifact.size,
        "sha256": artifact.sha256,
        "complete": true,
        "expiresAfterSeconds": config.streaming_artifact_retention().as_secs(),
        "preview": null
    })
}

pub(crate) fn response(value: &serde_json::Value) -> super::api::ControllerResponse {
    super::api::ControllerResponse {
        content: value.to_string(),
        raw_response_path: None,
    }
}

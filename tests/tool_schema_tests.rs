//! Tool-schema sanity: round-trip the `DevtoolsServer`'s advertised info,
//! and verify the `args` types serialise with camelCase keys (TS parity).

use std::collections::HashMap;

use mcp_server_devtools::bootstrap::ServerBuilder;
use mcp_server_devtools::config::Config;
use mcp_server_devtools::tools::args::{
    ArtifactReadArgs, CircleCiLogsArgs, OutputFormatArg, QueryParams, ReadArgs,
    SonarqubeQualityGateArgs, SonarqubeSearchIssuesArgs, UploadArgs, WriteArgs,
};
use rmcp::ServerHandler;
use serde_json::json;

#[test]
fn artifact_read_args_support_resume_offsets() {
    let args: ArtifactReadArgs = serde_json::from_value(json!({
        "artifactId": "artifact-123",
        "offset": 65536,
        "maxBytes": 32768
    }))
    .unwrap();
    assert_eq!(args.artifact_id, "artifact-123");
    assert_eq!(args.offset, 65_536);
    assert_eq!(args.max_bytes, Some(32_768));
}
#[test]
fn server_info_reports_expected_identity() {
    let server = ServerBuilder::new()
        .config(Config::from_map(HashMap::new()))
        .build()
        .unwrap();
    let info = server.get_info();
    assert_eq!(
        info.server_info.name,
        mcp_server_devtools::constants::PACKAGE_NAME
    );
    assert_eq!(
        info.server_info.version,
        mcp_server_devtools::constants::VERSION
    );
    assert!(info.capabilities.tools.is_some());
}

#[test]
fn read_args_uses_camel_case_json() {
    let args: ReadArgs = serde_json::from_value(json!({
        "path": "/workspaces",
        "queryParams": {"pagelen": "25"},
        "jq": "values[*].slug",
        "outputFormat": "json"
    }))
    .unwrap();
    assert_eq!(args.path, "/workspaces");
    assert_eq!(
        args.query_params.as_ref().unwrap().get("pagelen").unwrap(),
        "25"
    );
    assert_eq!(args.jq.as_deref(), Some("values[*].slug"));
    assert_eq!(args.output_format, Some(OutputFormatArg::Json));
}

#[test]
fn write_args_uses_camel_case_json() {
    let args: WriteArgs = serde_json::from_value(json!({
        "path": "/repositories/foo/prs",
        "body": {"title": "new"},
        "queryParams": {"pagelen": "5"},
        "outputFormat": "toon"
    }))
    .unwrap();
    assert_eq!(args.body, json!({"title": "new"}));
    assert_eq!(args.output_format, Some(OutputFormatArg::Toon));
}

#[test]
fn circleci_logs_args_use_camel_case_json() {
    let args: CircleCiLogsArgs = serde_json::from_value(json!({
        "projectSlug": "gh/acme/web",
        "jobNumber": 123,
        "stepNumber": 2,
        "failedOnly": true,
        "condensed": true,
        "contextLines": 5,
        "outputFormat": "json"
    }))
    .unwrap();
    assert_eq!(args.project_slug, "gh/acme/web");
    assert_eq!(args.job_number, 123);
    assert_eq!(args.step_number, Some(2));
    assert!(args.failed_only);
    assert!(args.condensed);
    assert_eq!(args.context_lines, Some(5));
    assert_eq!(args.output_format, Some(OutputFormatArg::Json));
}

#[test]
fn sonarqube_quality_gate_args_use_camel_case_json() {
    let args: SonarqubeQualityGateArgs = serde_json::from_value(json!({
        "projectKey": "my-org_my-repo",
        "pullRequest": "42",
        "ceTaskId": "AbCd-1234",
        "outputFormat": "json"
    }))
    .unwrap();
    assert_eq!(args.project_key.as_deref(), Some("my-org_my-repo"));
    assert_eq!(args.pull_request.as_deref(), Some("42"));
    assert_eq!(args.ce_task_id.as_deref(), Some("AbCd-1234"));
    assert_eq!(args.output_format, Some(OutputFormatArg::Json));
}

#[test]
fn sonarqube_search_issues_args_use_camel_case_json() {
    let args: SonarqubeSearchIssuesArgs = serde_json::from_value(json!({
        "componentKeys": "my-org_my-repo",
        "pullRequest": "42",
        "types": "BUG,VULNERABILITY",
        "resolved": false,
        "pageSize": 25,
        "outputFormat": "json"
    }))
    .unwrap();
    assert_eq!(args.component_keys, "my-org_my-repo");
    assert_eq!(args.pull_request.as_deref(), Some("42"));
    assert_eq!(args.types.as_deref(), Some("BUG,VULNERABILITY"));
    assert_eq!(args.resolved, Some(false));
    assert_eq!(args.page_size, Some(25));
}

#[test]
fn query_params_preserve_ordering() {
    let mut qp = QueryParams::new();
    qp.insert("a".into(), "1".into());
    qp.insert("b".into(), "2".into());
    qp.insert("c".into(), "3".into());
    let s = serde_json::to_string(&qp).unwrap();
    // BTreeMap → alphabetical order, reliable for URL encoding and fixtures.
    assert_eq!(s, r#"{"a":"1","b":"2","c":"3"}"#);
}

#[test]
fn upload_args_use_camel_case_json_and_default_to_failing_on_conflict() {
    let args: UploadArgs = serde_json::from_value(json!({
        "workspaceSlug": "myteam",
        "repoSlug": "project-api",
        "files": [
            {"filename": "a.json", "mimeType": "application/json", "contentBase64": "e30="},
            {"filename": "b.log", "artifactId": "artifact-1"}
        ],
        "onConflict": "replace",
        "outputFormat": "json"
    }))
    .unwrap();
    assert_eq!(args.workspace_slug.as_deref(), Some("myteam"));
    assert_eq!(args.repo_slug, "project-api");
    assert_eq!(args.files.len(), 2);
    assert_eq!(args.files[0].mime_type.as_deref(), Some("application/json"));
    assert_eq!(args.files[0].content_base64.as_deref(), Some("e30="));
    assert_eq!(args.files[1].artifact_id.as_deref(), Some("artifact-1"));
    assert_eq!(
        args.on_conflict,
        Some(mcp_server_devtools::tools::args::ConflictPolicy::Replace)
    );
    assert_eq!(args.output_format, Some(OutputFormatArg::Json));

    let minimal: UploadArgs = serde_json::from_value(json!({
        "repoSlug": "project-api",
        "files": [{"filename": "a.txt", "contentBase64": "eA=="}]
    }))
    .unwrap();
    assert_eq!(minimal.on_conflict, None);
    assert_eq!(
        serde_json::to_value(&minimal).unwrap(),
        json!({
            "repoSlug": "project-api",
            "files": [{"filename": "a.txt", "contentBase64": "eA=="}]
        })
    );
}

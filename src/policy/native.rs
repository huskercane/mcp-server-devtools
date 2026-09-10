//! Native REST read inventory. Resource identifiers remain conservatively
//! unscoped; operators grant these through vendor/tool/path/origin rules.
use super::{ActionDetails, CanonicalPath, NormalizedAction, ResourceScope, ResourceType};

pub(super) fn read(path: CanonicalPath) -> ActionDetails {
    ActionDetails::read(
        NormalizedAction::ReadVendorResource,
        path,
        Vec::new(),
        ResourceType::VendorResource,
        ResourceScope::unscoped(),
    )
}

pub(super) fn endpoint(vendor: &str, path: &str) -> bool {
    let patterns: &[&str] = match vendor {
        "github" => &[
            "/user/repos",
            "/orgs/*/repos",
            "/users/*/repos",
            "/repos/*/*/contents/**",
            "/repos/*/*/pulls",
            "/repos/*/*/pulls/*",
            "/repos/*/*/pulls/*/files",
            "/repos/*/*/issues",
            "/repos/*/*/issues/*",
            "/repos/*/*/actions/runs",
            "/repos/*/*/actions/workflows/*/runs",
            "/repos/*/*/actions/runs/*/jobs",
            "/repos/*/*/actions/jobs/*/logs",
        ],
        "gitlab" => &[
            "/projects",
            "/groups/*/projects",
            "/projects/*/repository/files/*",
            "/projects/*/merge_requests",
            "/projects/*/merge_requests/*",
            "/projects/*/merge_requests/*/diffs",
            "/projects/*/issues",
            "/projects/*/issues/*",
            "/projects/*/pipelines",
            "/projects/*/pipelines/*/jobs",
            "/projects/*/jobs/*/trace",
        ],
        "figma" => &[
            "/v1/files/*",
            "/v1/files/*/nodes",
            "/v1/files/*/components",
            "/v1/files/*/comments",
            "/v1/images/*",
        ],
        "vercel" => &[
            "/v9/projects",
            "/v6/deployments",
            "/v13/deployments/*",
            "/v3/deployments/*/events",
        ],
        "sentry" => &[
            "/api/0/organizations/*/projects",
            "/api/0/organizations/*/issues",
            "/api/0/organizations/*/issues/*",
            "/api/0/organizations/*/issues/*/events/*",
            "/api/0/organizations/*/releases",
        ],
        "snyk" => &[
            "/rest/orgs",
            "/rest/orgs/*/projects",
            "/rest/orgs/*/projects/*",
            "/rest/orgs/*/issues",
        ],
        "mend" => &[
            "/api/v3.0/orgs/*/applications",
            "/api/v3.0/orgs/*/projects",
            "/api/v3.0/projects/*/dependencies/findings/security",
        ],
        "artifactory" => &["/api/repositories", "/api/storage/*/**", "/api/build/*/*"],
        _ => &[],
    };
    patterns.iter().any(|pattern| matches_path(pattern, path))
}

fn matches_path(pattern: &str, path: &str) -> bool {
    let mut parts = path.trim_matches('/').split('/');
    for expected in pattern.trim_matches('/').split('/') {
        if expected == "**" {
            return parts.next().is_some();
        }
        let Some(part) = parts.next() else {
            return false;
        };
        if part.is_empty() || (expected != "*" && expected != part) {
            return false;
        }
    }
    parts.next().is_none()
}

pub(super) fn tool(tool: &str) -> bool {
    TOOLS.contains(&tool)
}

const TOOLS: &[&str] = &[
    "github_get_job_logs",
    "github_list_repositories",
    "github_get_file",
    "github_list_pull_requests",
    "github_get_pull_request",
    "github_get_pull_request_diff",
    "github_list_issues",
    "github_get_issue",
    "github_list_workflow_runs",
    "github_list_workflow_jobs",
    "gitlab_list_projects",
    "gitlab_get_file",
    "gitlab_list_merge_requests",
    "gitlab_get_merge_request",
    "gitlab_get_merge_request_diff",
    "gitlab_list_issues",
    "gitlab_get_issue",
    "gitlab_list_pipelines",
    "gitlab_list_pipeline_jobs",
    "gitlab_get_job_trace",
    "figma_export_images",
    "figma_get_file",
    "figma_get_nodes",
    "figma_list_components",
    "figma_list_comments",
    "vercel_list_projects",
    "vercel_list_deployments",
    "vercel_get_deployment",
    "vercel_get_deployment_logs",
    "sentry_list_projects",
    "sentry_search_issues",
    "sentry_get_issue",
    "sentry_get_event",
    "sentry_list_releases",
    "artifactory_download",
    "artifactory_list_repositories",
    "artifactory_search",
    "artifactory_get_file_info",
    "artifactory_get_build_info",
    "snyk_list_orgs",
    "snyk_list_projects",
    "snyk_list_issues",
    "snyk_get_project",
    "mend_list_applications",
    "mend_list_projects",
    "mend_get_project",
    "mend_list_findings",
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn post_read_classification_is_limited_to_reviewed_endpoints() {
        for (vendor, path, expected) in [
            (
                "artifactory",
                "/api/search/aql",
                ResourceType::VendorResource,
            ),
            (
                "mend",
                "/api/v3.0/orgs/org/projects/summaries",
                ResourceType::VendorResource,
            ),
            ("mend", "/api/v3.0/orgs/org/projects", ResourceType::Unknown),
            ("artifactory", "/api/copy/repo/path", ResourceType::Unknown),
        ] {
            let details =
                ActionDetails::native_post_read(vendor, CanonicalPath::parse(path).unwrap());
            assert_eq!(details.resource_type, expected);
            assert_eq!(details.method, crate::transport::HttpMethod::Post);
        }
    }
    #[test]
    fn only_known_routes_and_tools_are_reads() {
        assert!(endpoint("github", "/repos/owner/repo/actions/jobs/42/logs"));
        assert!(endpoint("gitlab", "/projects/group%2Frepo/issues"));
        assert!(!endpoint("github", "/admin/users"));
        assert!(!endpoint("github", "/repos/owner/repo/issues/1/comments"));
        assert!(!endpoint("unknown", "/projects"));
        assert!(tool("artifactory_download"));
        assert!(!tool("github_delete_repository"));
    }
}

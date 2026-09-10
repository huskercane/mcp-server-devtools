Fetch one GitLab **merge request** by its project-scoped IID — title, description, state, branches, author, reviewers, merge status, and `head_pipeline` (the latest pipeline's id and status, which leads to `gitlab_list_pipeline_jobs`). Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /projects/{project}/merge_requests/{iid}`.

Authenticates with a GitLab access token (`GITLAB_TOKEN`, `read_api` scope) sent as `Authorization: Bearer`.

**Parameters:**
- `project` (required): numeric project id or namespace path (`group/subgroup/project`).
- `iid` (required): the merge request's **IID** — the number shown in the UI and URL (`!12` → `12`, `/-/merge_requests/12`). This is NOT the global `id` returned in some payloads; using the global id yields a 404 or the wrong MR.

For the changed files use `gitlab_get_merge_request_diff`.

**IMPORTANT - Cost Optimization:** use `jq`, e.g. `{title: title, state: state, sha: sha, pipeline: head_pipeline.status, pipelineId: head_pipeline.id, merge: detailed_merge_status}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.gitlab.com/api/merge_requests/#get-single-mr

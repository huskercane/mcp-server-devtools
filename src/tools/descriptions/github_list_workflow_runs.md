List GitHub Actions workflow runs of a repository — the CI history — optionally for one workflow, branch, status, event, or actor. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /repos/{owner}/{repo}/actions/runs`, or `GET /repos/{owner}/{repo}/actions/workflows/{workflowId}/runs` when `workflowId` is given. The response is `{"total_count": N, "workflow_runs": [...]}`; each run carries `id` (pass it to `github_list_workflow_jobs`), `name`, `display_title`, `status` (`queued|in_progress|completed`), `conclusion` (`success|failure|cancelled|…`), `head_branch`, `head_sha`, `event`, `run_number`, `run_attempt`, `created_at`, `updated_at`, and `html_url`. Runs are never served from the local cache, so status is always current.

**Typical flow for a red build:** `github_list_workflow_runs` (`status: "failure"`, find the run `id`) → `github_list_workflow_jobs` (which job and step failed) → `github_get_pull_request` / `github_get_pull_request_diff` for the change under test.

Authenticates with a personal access token (`GITHUB_TOKEN`) sent as `Authorization: Bearer`. Fine-grained tokens need **Actions: read** (and **Metadata: read**) on the repository.

**Parameters:**
- `owner` (required) and `repo` (required), e.g. `octocat` / `hello-world`.
- `workflowId`: numeric workflow id or the workflow file name, e.g. `ci.yml`. Omit for runs of every workflow.
- `branch`: e.g. `main`.
- `status`: a status or conclusion — `completed`, `in_progress`, `queued`, `success`, `failure`, `cancelled`, `timed_out`, `action_required`, `neutral`, `skipped`, `stale`, `requested`, `waiting`, `pending`.
- `event`: triggering event, e.g. `push`, `pull_request`, `workflow_dispatch`, `schedule`.
- `actor`: login of the user who triggered the run.
- `perPage` (1-100, default 30) and `page` (1-based). Pagination is explicit: call again with the next `page`; `total_count` tells you how many runs match.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `workflow_runs[*].{id: id, name: name, status: status, conclusion: conclusion, branch: head_branch}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.github.com/en/rest/actions/workflow-runs#list-workflow-runs-for-a-repository

**Pagination response:** `{data: ..., nextPage: number | null}`. `jq` transforms the original API body before it is placed in `data`; `nextPage` remains available. Pass that number as `page` to continue. A null value means the upstream did not advertise a next page. Lists bypass the local response cache to preserve pagination headers.

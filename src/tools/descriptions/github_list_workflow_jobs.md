List the jobs of one GitHub Actions workflow run, each with its steps and their conclusions — which job and which step failed. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /repos/{owner}/{repo}/actions/runs/{runId}/jobs`. The response is `{"total_count": N, "jobs": [...]}`; each job carries `id`, `name`, `status`, `conclusion`, `started_at`, `completed_at`, `runner_name`, `html_url`, and `steps[]` with `name`, `number`, `status`, and `conclusion` per step. A job's `id` is the value the log endpoint needs. Jobs are never served from the local cache, so status is always current.

Job **log text is not fetched by this tool**: GitHub serves logs through a 302 redirect to a short-lived signed URL on a different host, which this server does not follow yet. Open `html_url` for the log, or use the failing step name from `steps[]` to locate it.

Authenticates with a personal access token (`GITHUB_TOKEN`) sent as `Authorization: Bearer`. Fine-grained tokens need **Actions: read** (and **Metadata: read**) on the repository.

**Parameters:**
- `owner` (required) and `repo` (required), e.g. `octocat` / `hello-world`.
- `runId` (required): the run `id` from `github_list_workflow_runs`, e.g. 30433642.
- `filter`: `latest` (default) for the most recent attempt only, or `all` to include every re-run attempt.
- `perPage` (1-100, default 30) and `page` (1-based). Pagination is explicit: call again with the next `page`.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `jobs[?conclusion=='failure'].{name: name, failed: steps[?conclusion=='failure'].name}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run

**Pagination response:** `{data: ..., nextPage: number | null}`. `jq` transforms the original API body before it is placed in `data`; `nextPage` remains available. Pass that number as `page` to continue. A null value means the upstream did not advertise a next page. Lists bypass the local response cache to preserve pagination headers.

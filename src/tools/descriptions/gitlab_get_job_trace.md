Fetch one GitLab CI job trace through the existing bounded streaming artifact store. Calls `GET /projects/{project}/jobs/{jobId}/trace` with a `GITLAB_TOKEN` bearer credential (`read_api` scope).

- `project`: numeric project ID or namespace path (`group/subgroup/project`).
- `jobId`: positive global job ID from `gitlab_list_pipeline_jobs`.
- `maxBytes`: encoded and decoded byte limit; default 32 MiB, maximum 512 MiB.

Small traces return plain text, including ANSI codes. Larger traces return JSON metadata with `artifactId`, size, SHA-256, expiry, `complete: true`, and bounded head/tail previews. Use `artifact_read` for resumable retrieval. A running job yields the log available at request time. Oversize or incomplete transfers fail without a success handle. Redirect destinations must satisfy the configured download origin allowlist.

`jq` and `outputFormat` are reserved and do not transform the trace. Responses bypass the response cache.

API reference: https://docs.gitlab.com/api/jobs/#get-a-log-file

List a GitLab project's **CI pipelines** — the first step in diagnosing a red build: find the pipeline, then its jobs (`gitlab_list_pipeline_jobs`), then the failing job's log (`gitlab_get_job_trace`). Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /projects/{project}/pipelines`. Each pipeline carries `id` (global — pass it as `pipelineId`), `iid`, `status`, `source`, `ref`, `sha`, `web_url`, and timestamps. Responses are never served from the local cache: pipeline state changes after retries.

Authenticates with a GitLab access token (`GITLAB_TOKEN`, `read_api` scope) sent as `Authorization: Bearer`.

**Parameters:**
- `project` (required): numeric project id or namespace path (`group/subgroup/project`).
- `ref`: branch or tag, e.g. `main`.
- `status`: `created`, `waiting_for_resource`, `preparing`, `pending`, `running`, `success`, `failed`, `canceled`, `skipped`, `manual`, `scheduled`.
- `source`: `push`, `web`, `schedule`, `api`, `merge_request_event`, `parent_pipeline`, …
- `sha`: only pipelines for this commit.
- `orderBy` (`id`, `status`, `ref`, `updated_at`, `user_id`) / `sort` (`asc`, `desc`).
- `perPage` (1–100, default 20) / `page` (1-based).

For a merge request, `gitlab_get_merge_request` returns `head_pipeline.id` directly.

**Pagination:** offset paging; advance `page` until a page comes back empty (GitLab's `x-next-page` header is not surfaced).

**IMPORTANT - Cost Optimization:** use `jq`, e.g. `[*].{id: id, status: status, ref: ref, sha: sha, source: source}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.gitlab.com/api/pipelines/#list-project-pipelines

**Pagination response:** `{data: ..., nextPage: number | null}`. `jq` transforms the original API body before it is placed in `data`; `nextPage` remains available. Pass that number as `page` to continue. A null value means the upstream did not advertise a next page. Lists bypass the local response cache to preserve pagination headers.

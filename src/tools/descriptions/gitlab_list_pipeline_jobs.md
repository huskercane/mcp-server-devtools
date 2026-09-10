List the **jobs** of one GitLab CI pipeline — name, stage, status, duration, failure reason, and the job `id` needed by `gitlab_get_job_trace`. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /projects/{project}/pipelines/{pipelineId}/jobs`. Each job carries `id` (global — pass it as `jobId`), `name`, `stage`, `status`, `failure_reason`, `allow_failure`, `duration`, `web_url`, and `pipeline`. Responses are never served from the local cache.

Authenticates with a GitLab access token (`GITLAB_TOKEN`, `read_api` scope) sent as `Authorization: Bearer`.

**Parameters:**
- `project` (required): numeric project id or namespace path (`group/subgroup/project`).
- `pipelineId` (required): the pipeline's global `id` from `gitlab_list_pipelines` or an MR's `head_pipeline.id`.
- `scope`: ONE status to filter on — `created`, `pending`, `running`, `failed`, `success`, `canceled`, `skipped`, or `manual`. GitLab's repeated `scope[]` form (several statuses at once) is not exposed; call once per status or filter with `jq`. `scope: "failed"` is the usual first call for a red pipeline.
- `includeRetried`: include earlier attempts of retried jobs (default false).
- `perPage` (1–100, default 20) / `page` (1-based).

Bridge jobs (child/multi-project pipeline triggers) are not included; they live under `/bridges`.

**Pagination:** offset paging; advance `page` until a page comes back empty.

**IMPORTANT - Cost Optimization:** use `jq`, e.g. `[*].{id: id, name: name, stage: stage, status: status, reason: failure_reason}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.gitlab.com/api/jobs/#list-pipeline-jobs

**Pagination response:** `{data: ..., nextPage: number | null}`. `jq` transforms the original API body before it is placed in `data`; `nextPage` remains available. Pass that number as `page` to continue. A null value means the upstream did not advertise a next page. Lists bypass the local response cache to preserve pagination headers.

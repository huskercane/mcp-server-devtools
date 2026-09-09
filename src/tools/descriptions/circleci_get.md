Read any CircleCI data via the CircleCI REST API v2. Returns TOON format by default (30-60% fewer tokens than JSON).

Authenticates with a personal API token (`CIRCLECI_TOKEN`) sent as a Bearer token; no per-call auth is needed.

**IMPORTANT - Cost Optimization:**
- ALWAYS use `jq` to filter response fields. Unfiltered responses are expensive.
- To explore a schema, fetch ONE item (or a single list page) with NO jq, then add a jq filter on later calls.

**Project slug:** most project-scoped paths take a `project-slug` of the form `<vcs>/<org>/<repo>` — e.g. `gh/acme/web` (GitHub), `bb/acme/web` (Bitbucket), or `circleci/<org-id>/<project-id>`.

**Listing / "search":** CircleCI has no single search tool — listing is just GETs against the right path:
- `/me` - the authenticated user
- `/project/{project-slug}` - project details
- `/project/{project-slug}/pipeline` - pipelines for a project (`branch` query param to filter)
- `/project/{project-slug}/pipeline/mine` - pipelines you triggered
- `/pipeline/{pipeline-id}` - a single pipeline
- `/pipeline/{pipeline-id}/workflow` - workflows in a pipeline
- `/workflow/{workflow-id}` - a single workflow's status
- `/workflow/{workflow-id}/job` - jobs in a workflow
- `/project/{project-slug}/job/{job-number}` - a single job
- `/insights/{project-slug}/workflows` - workflow insights/metrics
- `/project/{project-slug}/envvar` - project environment variables (names only)

**Linking from a PR / branch (cross-vendor):** CircleCI is keyed by branch, not by pull request. To find the build for a Bitbucket/GitHub PR, take the PR's source branch and call `/project/{project-slug}/pipeline?branch={branch}`, then drill down: latest pipeline `id` → `/pipeline/{id}/workflow` → `/workflow/{workflow-id}/job` (each job has `status` + `job_number`). For *why* a job failed, prefer `/project/{project-slug}/{job-number}/tests` (failed test names + messages, when test results are stored) over raw logs — raw step logs live on CircleCI's v1.1 API / S3 output URLs, outside this v2 base.

**Pagination:** CircleCI uses a `next_page_token` in the response. Pass it back as the `page-token` query param to fetch the next page.

**Deployment monitoring and freshness:** Pipeline, workflow, and job paths (including discovery lists) always fetch upstream and are never stored in the MCP HTTP cache, even if CircleCI sends a long `max-age`. Poll `/pipeline/{id}/workflow`, then `/workflow/{id}` or `/workflow/{id}/job` until the target workflow/jobs reach a terminal status; queued, running, and approval-waiting states are not completion. A pipeline being created does not mean its deployment succeeded. Terminal status reads also remain uncached to observe reruns.

For any other GET, set top-level `fresh: true` to bypass MCP cache lookup and storage and discard the previous entry. For example: `{"path":"/workflow/df722a5b-dd0f-437c-a426-efbda3a7a597/job","fresh":true,"jq":"items[*].{name:name,status:status}","outputFormat":"json"}`. This is a local control, never an upstream query parameter. Do not add `_fresh` timestamps to `queryParams` or the path.

**Response metadata:** GET results have a `data` and `cache` envelope in both formats. `jq` filters the upstream body before it is placed in `data`; metadata is always retained. `cache.hit` reports local MCP cache reuse, `cache.ageMs` is elapsed local cache residence (zero on an upstream fetch), and `cache.fetchedAt` is the UTC timestamp when MCP finished reading that upstream body. Hits retain the original fetch timestamp and do not extend TTL. These fields describe MCP provenance, not when CircleCI last updated its state or whether an upstream proxy cached it. JSON example: `{"data":[{"status":"success"}],"cache":{"hit":false,"ageMs":0,"fetchedAt":"2026-09-09T16:39:07Z"}}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

**JQ examples:** `items[*].{id: id, state: state, created: created_at}`, `items[*].number`, `{login: login, id: id}`

API reference: https://circleci.com/docs/api/v2/

List Vercel **deployments** — the deploy history of a project (or of the whole team/account), so a failed or stale deployment can be found by state, target, or time. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /v6/deployments`. Each deployment carries its `uid` (`dpl_...`), `url`, `state` (`BUILDING`, `ERROR`, `INITIALIZING`, `QUEUED`, `READY`, `CANCELED`), `target`, `created`, and Git `meta` (commit, branch, author). Use `vercel_get_deployment` / `vercel_get_deployment_logs` with the `uid` to drill in.

Authenticates with a Vercel **account token** (`VERCEL_TOKEN`) sent as `Authorization: Bearer`. No per-call auth is needed.

**Scope:** `teamId` (a `team_...` id from Team Settings → General) selects the team; it overrides `VERCEL_TEAM_ID`. When neither is set the request is scoped to the personal account — pass `teamId` for team-owned projects.

**Parameters:**
- `projectId`: project id (`prj_...`) or project name. Omit for every project in scope.
- `app`: application (project) name filter.
- `state`: comma-separated deployment states, e.g. `ERROR` or `ERROR,CANCELED`.
- `target`: `production` or `preview`.
- `limit`: page size 1–100 (default 20) — keep small.
- `since` / `until`: millisecond timestamps as strings bounding creation time.

**Pagination:** the response body carries `pagination.next` / `pagination.prev` (millisecond timestamps); pass `pagination.next` as `until` to page further back in history.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `deployments[*].{uid: uid, state: state, url: url, created: created, commit: meta.githubCommitMessage}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://vercel.com/docs/rest-api/reference/endpoints/deployments/list-deployments

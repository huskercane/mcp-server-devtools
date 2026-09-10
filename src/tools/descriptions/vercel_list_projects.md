List Vercel **projects** in scope — the first step to find a project id or name before listing its deployments. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /v9/projects`. Each project carries its `id` (`prj_...`), `name`, `framework`, linked Git repository (`link`), and `latestDeployments`.

Authenticates with a Vercel **account token** (`VERCEL_TOKEN`) sent as `Authorization: Bearer`. No per-call auth is needed.

**Scope:** `teamId` (a `team_...` id from Team Settings → General) selects the team; it overrides `VERCEL_TEAM_ID`. When neither is set the request is scoped to the personal account, and team-owned projects are not visible — pass `teamId` for team-owned projects.

**Parameters:**
- `search`: name substring filter, e.g. `storefront`.
- `repoUrl`: only projects linked to this Git repository URL.
- `limit`: page size 1–100 (default 20) — keep small.
- `from` / `until`: millisecond timestamps as strings bounding the creation time.

**Pagination:** the response body carries `pagination.next`; pass it as `from` on the next call to fetch the following page. Results are not aggregated automatically.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `projects[*].{id: id, name: name, framework: framework}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://vercel.com/docs/rest-api/reference/endpoints/projects/retrieve-a-list-of-projects

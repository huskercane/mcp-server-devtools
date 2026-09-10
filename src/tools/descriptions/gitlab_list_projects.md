List GitLab **projects** the token can see, or the projects of one group — the starting point for finding a `project` identifier to pass to the other `gitlab_*` tools. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /projects` (or `GET /groups/{groupId}/projects` when `groupId` is set). Each project carries `id`, `path_with_namespace` (use either as `project` elsewhere), `default_branch`, `web_url`, and `last_activity_at`.

Authenticates with a GitLab access token (`GITLAB_TOKEN`, `read_api` scope) sent as `Authorization: Bearer`; `GITLAB_API_BASE` selects GitLab.com (default) or a Self-Managed instance. No per-call auth is needed.

**Parameters:**
- `search`: substring match on project name/path, e.g. `payments`.
- `membership` (default `true`): only projects the token's user belongs to. `false` includes every visible project — on GitLab.com that is enormous, so combine with `search`. Ignored when `groupId` is set.
- `owned`: only projects owned by the user (or the group).
- `groupId`: numeric group id or full group path (`my-org/platform`) to list that group's direct projects instead.
- `orderBy` / `sort`: e.g. `last_activity_at` + `desc` for the most recently active first.
- `perPage` (1–100, default 20) / `page` (1-based).

**Pagination:** offset paging. GitLab's `x-next-page` / `x-total-pages` headers are not surfaced, so advance `page` until a page comes back empty.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `[*].{id: id, path: path_with_namespace, branch: default_branch}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.gitlab.com/api/projects/#list-all-projects

**Pagination response:** `{data: ..., nextPage: number | null}`. `jq` transforms the original API body before it is placed in `data`; `nextPage` remains available. Pass that number as `page` to continue. A null value means the upstream did not advertise a next page. Lists bypass the local response cache to preserve pagination headers.

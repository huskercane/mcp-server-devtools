List a GitLab project's **merge requests** with the common filters — find the MR behind a branch, a failed pipeline, or an author. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /projects/{project}/merge_requests`. Each MR carries its project-scoped `iid` (the `!12` number — pass it to `gitlab_get_merge_request` / `gitlab_get_merge_request_diff`), `title`, `state`, `source_branch`, `target_branch`, `author.username`, `sha`, and `web_url`. Do not confuse `iid` with the global `id`.

Authenticates with a GitLab access token (`GITLAB_TOKEN`, `read_api` scope) sent as `Authorization: Bearer`.

**Parameters:**
- `project` (required): numeric project id or namespace path (`group/subgroup/project`).
- `state`: `opened`, `closed`, `merged`, `locked`, or `all` (GitLab default `all`).
- `sourceBranch` / `targetBranch`: exact branch names.
- `labels`: comma-separated label names (`None` / `Any` are special values).
- `authorUsername`: e.g. `jdoe`.
- `orderBy` (`created_at`, `updated_at`, `title`, `merged_at`) / `sort` (`asc`, `desc`).
- `perPage` (1–100, default 20) / `page` (1-based).

**Pagination:** offset paging; advance `page` until a page comes back empty (GitLab's `x-next-page` header is not surfaced).

**IMPORTANT - Cost Optimization:** use `jq`, e.g. `[*].{iid: iid, title: title, state: state, source: source_branch, author: author.username}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.gitlab.com/api/merge_requests/#list-project-merge-requests

**Pagination response:** `{data: ..., nextPage: number | null}`. `jq` transforms the original API body before it is placed in `data`; `nextPage` remains available. Pass that number as `page` to continue. A null value means the upstream did not advertise a next page. Lists bypass the local response cache to preserve pagination headers.

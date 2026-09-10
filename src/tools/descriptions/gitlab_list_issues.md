List a GitLab project's **issues** with the common filters — by state, label, assignee, author, or free-text search. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /projects/{project}/issues`. Each issue carries its project-scoped `iid` (the `#7` number — pass it to `gitlab_get_issue`), `title`, `state`, `labels`, `assignees`, `author.username`, `milestone`, and `web_url`. Do not confuse `iid` with the global `id`.

Authenticates with a GitLab access token (`GITLAB_TOKEN`, `read_api` scope) sent as `Authorization: Bearer`.

**Parameters:**
- `project` (required): numeric project id or namespace path (`group/subgroup/project`).
- `state`: `opened`, `closed`, or `all` (GitLab default `all`).
- `labels`: comma-separated label names (`None` / `Any` are special values).
- `assigneeUsername` / `authorUsername`: e.g. `jdoe`.
- `search`: full-text match on title and description.
- `orderBy` (`created_at`, `updated_at`, `priority`, `due_date`, …) / `sort` (`asc`, `desc`).
- `perPage` (1–100, default 20) / `page` (1-based).

**Pagination:** offset paging; advance `page` until a page comes back empty (GitLab's `x-next-page` header is not surfaced).

**IMPORTANT - Cost Optimization:** use `jq`, e.g. `[*].{iid: iid, title: title, state: state, labels: labels, assignee: assignees[0].username}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.gitlab.com/api/issues/#list-project-issues

**Pagination response:** `{data: ..., nextPage: number | null}`. `jq` transforms the original API body before it is placed in `data`; `nextPage` remains available. Pass that number as `page` to continue. A null value means the upstream did not advertise a next page. Lists bypass the local response cache to preserve pagination headers.

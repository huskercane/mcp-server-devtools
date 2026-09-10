List issues of a GitHub repository, filtered by state, labels, assignee, creator, or update time. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /repos/{owner}/{repo}/issues`. **Pull requests appear in this list too** — GitHub's issues endpoint returns both; an entry that is a pull request carries a `pull_request` key (with `url`, `html_url`, `merged_at`), a plain issue does not. Filter with `jq: "[?!pull_request]"` for issues only. Each entry carries `number`, `title`, `state`, `user.login`, `labels[].name`, `assignees[].login`, `comments`, `created_at`, `updated_at`, and `html_url`.

Authenticates with a personal access token (`GITHUB_TOKEN`) sent as `Authorization: Bearer`. Fine-grained tokens need **Issues: read** (and **Metadata: read**) on the repository; **Pull requests: read** is needed for the pull-request entries to be included.

**Parameters:**
- `owner` (required) and `repo` (required), e.g. `octocat` / `hello-world`.
- `state`: `open` (default), `closed`, or `all`.
- `labels`: comma-separated label names, e.g. `bug,urgent` (all must match).
- `assignee`: a login, `none` for unassigned, or `*` for any assignee.
- `creator`: login of the author.
- `since`: ISO 8601 timestamp; only issues updated at or after it.
- `sort` (`created|updated|comments`) and `direction` (`asc|desc`).
- `perPage` (1-100, default 30) and `page` (1-based). Pagination is explicit: call again with the next `page`.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `[?!pull_request].{number: number, title: title, labels: labels[*].name}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.github.com/en/rest/issues/issues#list-repository-issues

**Pagination response:** `{data: ..., nextPage: number | null}`. `jq` transforms the original API body before it is placed in `data`; `nextPage` remains available. Pass that number as `page` to continue. A null value means the upstream did not advertise a next page. Lists bypass the local response cache to preserve pagination headers.

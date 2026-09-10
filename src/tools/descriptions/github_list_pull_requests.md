List pull requests of a GitHub repository, filtered by state, head, or base branch. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /repos/{owner}/{repo}/pulls`. Each pull request carries `number`, `title`, `state`, `draft`, `user.login`, `head.ref`, `base.ref`, `created_at`, `updated_at`, and `html_url`. Use `number` with `github_get_pull_request` for merge status and review counts, and with `github_get_pull_request_diff` for the changed files.

Authenticates with a personal access token (`GITHUB_TOKEN`) sent as `Authorization: Bearer`. Fine-grained tokens need **Pull requests: read** (and **Metadata: read**) on the repository.

**Parameters:**
- `owner` (required) and `repo` (required), e.g. `octocat` / `hello-world`.
- `state`: `open` (default), `closed`, or `all`.
- `head`: `user:branch` or `org:branch`, e.g. `octocat:feature-x`.
- `base`: base branch name, e.g. `main`.
- `sort` (`created|updated|popularity|long-running`) and `direction` (`asc|desc`).
- `perPage` (1-100, default 30) and `page` (1-based). Pagination is explicit: call again with the next `page`.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `[*].{number: number, title: title, author: user.login, draft: draft}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.github.com/en/rest/pulls/pulls#list-pull-requests

**Pagination response:** `{data: ..., nextPage: number | null}`. `jq` transforms the original API body before it is placed in `data`; `nextPage` remains available. Pass that number as `page` to continue. A null value means the upstream did not advertise a next page. Lists bypass the local response cache to preserve pagination headers.

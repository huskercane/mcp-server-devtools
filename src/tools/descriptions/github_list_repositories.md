List GitHub repositories for an organization, a user, or the authenticated token's user. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /orgs/{owner}/repos` (`ownerType: "org"`, the default when `owner` is given), `GET /users/{owner}/repos` (`ownerType: "user"`), or `GET /user/repos` when `owner` is omitted (every repository the token can access, including private ones). Each repository carries `full_name`, `private`, `default_branch`, `archived`, `pushed_at`, and `html_url` — use `full_name` to split `owner`/`repo` for the other `github_*` tools.

Authenticates with a personal access token (`GITHUB_TOKEN`) sent as `Authorization: Bearer`; `GITHUB_API_BASE` targets GitHub Enterprise Server (`https://ghe.example.com/api/v3`). Fine-grained tokens need **Metadata: read** on the repositories to list.

**Parameters:**
- `owner`: organization or user login. Omit for the authenticated user's repositories.
- `ownerType`: `org` (default) or `user`.
- `type`: repository filter — org: `all|public|private|forks|sources|member`; user: `all|owner|member`; authenticated user: `all|owner|public|private|member` (not combinable with `visibility`/`affiliation`).
- `visibility` (`all|public|private`) and `affiliation` (`owner,collaborator,organization_member`): authenticated-user listing only; rejected when `owner` is given.
- `sort` (`created|updated|pushed|full_name`) and `direction` (`asc|desc`).
- `perPage` (1-100, default 30) and `page` (1-based). Pagination is explicit: call again with the next `page` until a short page comes back.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `[*].{name: full_name, private: private, default: default_branch}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.github.com/en/rest/repos/repos#list-organization-repositories

**Pagination response:** `{data: ..., nextPage: number | null}`. `jq` transforms the original API body before it is placed in `data`; `nextPage` remains available. Pass that number as `page` to continue. A null value means the upstream did not advertise a next page. Lists bypass the local response cache to preserve pagination headers.

Fetch the **per-file diffs** of a GitLab merge request (paginated) — the unified diff for each changed file, for code review or to see what a failing pipeline is testing. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /projects/{project}/merge_requests/{iid}/diffs`. The response is a JSON list; each entry has `old_path`, `new_path`, `new_file` / `renamed_file` / `deleted_file` flags, and `diff` (unified diff text).

**Upstream truncation is explicit:** GitLab omits or empties `diff` for files it considers too big and marks the entry with `too_large: true` and/or `collapsed: true`; those flags are passed through untouched. When you see them, read the file directly with `gitlab_get_file` at the MR's `sha` instead. Generated-file entries carry `generated_file: true`.

Authenticates with a GitLab access token (`GITLAB_TOKEN`, `read_api` scope) sent as `Authorization: Bearer`.

**Parameters:**
- `project` (required): numeric project id or namespace path (`group/subgroup/project`).
- `iid` (required): the merge request's project-scoped **IID** (`!12` → `12`), not the global id.
- `perPage` (1–100, default 20) / `page` (1-based): files per page. Advance `page` until a page comes back empty.

**Limits:** a page whose rendered diffs exceed the output budget is truncated and spilled to a resumable artifact (`artifact_read`); lower `perPage` or project with `jq` to stay within budget.

**IMPORTANT - Cost Optimization:** list changed files first with `jq: "[*].{file: new_path, new: new_file, deleted: deleted_file, tooLarge: too_large}"`, then fetch diffs page by page.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.gitlab.com/api/merge_requests/#list-merge-request-diffs

**Pagination response:** `{data: ..., nextPage: number | null}`. `jq` transforms the original API body before it is placed in `data`; `nextPage` remains available. Pass that number as `page` to continue. A null value means the upstream did not advertise a next page. Lists bypass the local response cache to preserve pagination headers.

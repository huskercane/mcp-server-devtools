Get the files changed by a GitHub pull request, each with its unified diff `patch`. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /repos/{owner}/{repo}/pulls/{number}/files`. Each entry carries `filename`, `status` (`added|removed|modified|renamed|…`), `additions`, `deletions`, `changes`, `previous_filename` for renames, and `patch` — the unified diff hunk text for that file. **GitHub omits `patch` for binary files and for very large text changes**; such entries still list the file and its counts, so a missing `patch` means "diff not inlined", not "no change". The endpoint returns at most 3,000 files per pull request in total.

This is the per-file JSON endpoint, not the raw `application/vnd.github.diff` media type, so `jq` can pick individual files and the response stays bounded per page.

Authenticates with a personal access token (`GITHUB_TOKEN`) sent as `Authorization: Bearer`. Fine-grained tokens need **Pull requests: read** (and **Metadata: read**) on the repository.

**Parameters:**
- `owner` (required) and `repo` (required), e.g. `octocat` / `hello-world`.
- `number` (required): the pull request number, e.g. 1347.
- `perPage` (1-100, default 30) and `page` (1-based). **Pagination continues via `page`**: a pull request touching more than `perPage` files needs further calls with `page: 2`, `3`, … until a short page comes back. Compare against `changed_files` from `github_get_pull_request`.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `[*].{file: filename, status: status, changes: changes}` first, then `[?filename=='src/lib.rs'].patch` for one file's diff.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`). Diff text renders most faithfully with `outputFormat: "json"`.

API reference: https://docs.github.com/en/rest/pulls/pulls#list-pull-requests-files

**Pagination response:** `{data: ..., nextPage: number | null}`. `jq` transforms the original API body before it is placed in `data`; `nextPage` remains available. Pass that number as `page` to continue. A null value means the upstream did not advertise a next page. Lists bypass the local response cache to preserve pagination headers.

`patchesUnavailable` is true if any entry in this page has no `patch`, including binary files and omitted large changes. It does not establish whether GitHub returned every changed file.

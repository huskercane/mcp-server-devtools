Get one GitHub pull request by number: title, body, state, merge status, branches, and change counts. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /repos/{owner}/{repo}/pulls/{number}`. Beyond the list fields, the detail carries `body`, `merged`, `mergeable`, `mergeable_state`, `merged_by`, `commits`, `additions`, `deletions`, `changed_files`, `review_comments`, `labels`, `requested_reviewers`, and `head.sha` (the commit CI ran against — match it to `head_sha` in `github_list_workflow_runs`). Follow with `github_get_pull_request_diff` for the actual changes.

Authenticates with a personal access token (`GITHUB_TOKEN`) sent as `Authorization: Bearer`. Fine-grained tokens need **Pull requests: read** (and **Metadata: read**) on the repository.

**Parameters:**
- `owner` (required) and `repo` (required), e.g. `octocat` / `hello-world`.
- `number` (required): the pull request number shown in the UI, e.g. 1347 (not the global `id`).

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `{title: title, state: state, mergeable: mergeable, head: head.ref, base: base.ref, files: changed_files}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request

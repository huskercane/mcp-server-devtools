Get one GitHub issue by number: title, body, state, labels, assignees, and milestone. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /repos/{owner}/{repo}/issues/{number}`. The detail carries `body` (Markdown), `state`, `state_reason` (`completed|not_planned|reopened`), `labels[].name`, `assignees[].login`, `milestone.title`, `comments` (count), `closed_at`, `closed_by`, and `html_url`. Because GitHub numbers issues and pull requests from one sequence, a `number` that belongs to a pull request also resolves here and carries a `pull_request` key — use `github_get_pull_request` for its merge status and branches.

Authenticates with a personal access token (`GITHUB_TOKEN`) sent as `Authorization: Bearer`. Fine-grained tokens need **Issues: read** (and **Metadata: read**) on the repository.

**Parameters:**
- `owner` (required) and `repo` (required), e.g. `octocat` / `hello-world`.
- `number` (required): the issue number shown in the UI, e.g. 42 (not the global `id`).

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `{title: title, state: state, body: body, labels: labels[*].name}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.github.com/en/rest/issues/issues#get-an-issue

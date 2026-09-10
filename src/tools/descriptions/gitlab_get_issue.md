Fetch one GitLab **issue** by its project-scoped IID — title, description (Markdown), state, labels, assignees, milestone, due date, and links. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /projects/{project}/issues/{iid}`.

Authenticates with a GitLab access token (`GITLAB_TOKEN`, `read_api` scope) sent as `Authorization: Bearer`.

**Parameters:**
- `project` (required): numeric project id or namespace path (`group/subgroup/project`).
- `iid` (required): the issue's **IID** — the number shown in the UI and URL (`#7` → `7`, `/-/issues/7`). This is NOT the global `id`; using the global id yields a 404 or the wrong issue.

Comments (notes) and related merge requests are separate endpoints and are not fetched here.

**IMPORTANT - Cost Optimization:** use `jq`, e.g. `{title: title, state: state, description: description, labels: labels, assignees: assignees[*].username}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.gitlab.com/api/issues/#single-project-issue

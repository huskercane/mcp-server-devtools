List the **releases** in a Sentry organization — version, creation date, deploy info, and new-issue counts, so "did 1.4.2 introduce this?" can be answered. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /api/0/organizations/{organization}/releases/`. Each release carries `version`, `shortVersion`, `dateCreated`, `dateReleased`, `newGroups` (issues first seen in it), `projects`, and `lastDeploy`.

Authenticates with a Sentry **auth token** (`SENTRY_TOKEN`, scopes `org:read` + `project:read`) sent as `Authorization: Bearer`; `SENTRY_URL` selects the deployment. No per-call auth is needed.

**Parameters:**
- `organization`: organization slug. Omit to use `SENTRY_ORG`.
- `query`: substring match on the version, e.g. `1.4` or a commit SHA prefix.
- `project`: numeric project id (from `sentry_list_projects`) to scope to one project.
- `sort`: `date` (default), `sessions`, `users`, `crash_free_users`, `crash_free_sessions`.
- `cursor`: opaque pagination cursor from a previous call's `nextCursor`.

**Output:** `{"data": [...releases], "nextCursor": "<cursor>" | null}`. Pagination is explicit — pass `nextCursor` back as `cursor`; results are not aggregated.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `[*].{version: version, dateCreated: dateCreated, newGroups: newGroups}` (applied to the page array before wrapping).

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.sentry.io/api/releases/list-an-organizations-releases/

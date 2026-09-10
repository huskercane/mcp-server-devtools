List the **projects** in a Sentry organization — the starting point for finding a numeric project id to pass to `sentry_search_issues` / `sentry_list_releases`. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /api/0/organizations/{organization}/projects/`. Each project carries `id` (numeric, what the other tools' `project` filter expects), `slug`, `name`, `platform`, and `dateCreated`.

Authenticates with a Sentry **auth token** (`SENTRY_TOKEN`, scopes `org:read` + `project:read`) sent as `Authorization: Bearer`; `SENTRY_URL` selects sentry.io, the EU region (`https://de.sentry.io`), or a self-hosted server. No per-call auth is needed.

**Parameters:**
- `organization`: organization slug. Omit to use `SENTRY_ORG`.
- `cursor`: opaque pagination cursor from a previous call's `nextCursor`.

**Output:** `{"data": [...projects], "nextCursor": "<cursor>" | null}`. Pagination is explicit — pass `nextCursor` back as `cursor` for the next page; results are not aggregated.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `[*].{id: id, slug: slug, platform: platform}` (applied to the page array before wrapping).

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.sentry.io/api/organizations/list-an-organizations-projects/

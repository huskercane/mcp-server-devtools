Search Sentry **issues** (grouped errors) across an organization with Sentry's search syntax — "what is broken in production right now". Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /api/0/organizations/{organization}/issues/`. Each issue carries its numeric `id` (pass to `sentry_get_issue` / `sentry_get_event`), `shortId`, `title`, `culprit`, `level`, `status`, `count`, `userCount`, `firstSeen`, `lastSeen`, and `project`.

Authenticates with a Sentry **auth token** (`SENTRY_TOKEN`, scopes `org:read` + `project:read` + `event:read`) sent as `Authorization: Bearer`; `SENTRY_URL` selects the deployment. No per-call auth is needed.

**Parameters:**
- `organization`: organization slug. Omit to use `SENTRY_ORG`.
- `query`: Sentry search syntax, exactly as typed in the Issues page search bar. Default `is:unresolved`. Examples: `is:unresolved level:error`, `is:unresolved release:1.4.2`, `is:unresolved assigned:me`, `error.type:TypeError`.
- `project`: numeric project id (from `sentry_list_projects`) to scope to one project. Omit for all.
- `statsPeriod`: relative window such as `24h`, `7d`, `14d`.
- `environment`: e.g. `production`.
- `sort`: `date` (last seen, default), `new` (first seen), `freq` (event count), `priority`, `user` (affected users).
- `limit`: page size 1-100 (default 25). Keep small.
- `cursor`: opaque pagination cursor from a previous call's `nextCursor`.

**Output:** `{"data": [...issues], "nextCursor": "<cursor>" | null}`. Pagination is explicit — pass `nextCursor` back as `cursor`; results are not aggregated.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `[*].{id: id, title: title, count: count, lastSeen: lastSeen}` (applied to the page array before wrapping).

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.sentry.io/api/events/list-an-organizations-issues/

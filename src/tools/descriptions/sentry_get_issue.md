Get one Sentry **issue** — its title, culprit, status, assignee, event/user counts, first/last seen, and 24h/30d stats. Use it to understand an issue's blast radius; use `sentry_get_event` for the stack trace. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /api/0/organizations/{organization}/issues/{issueId}/`.

Authenticates with a Sentry **auth token** (`SENTRY_TOKEN`, scopes `org:read` + `project:read` + `event:read`) sent as `Authorization: Bearer`; `SENTRY_URL` selects the deployment. No per-call auth is needed.

**Parameters:**
- `organization`: organization slug. Omit to use `SENTRY_ORG`.
- `issueId` (required): the numeric issue id (the `id` field from `sentry_search_issues`, e.g. `5432109876`) — not the short id like `PROJ-1A2`.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `{title: title, culprit: culprit, status: status, count: count, userCount: userCount, firstSeen: firstSeen, lastSeen: lastSeen}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.sentry.io/api/events/retrieve-an-issue/

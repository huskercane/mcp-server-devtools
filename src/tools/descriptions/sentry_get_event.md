Get one **event** of a Sentry issue — the concrete occurrence with its exception/stack trace, breadcrumbs, request, tags, and runtime contexts. This is the "show me the actual crash" call. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /api/0/organizations/{organization}/issues/{issueId}/events/{eventId}/`.

Authenticates with a Sentry **auth token** (`SENTRY_TOKEN`, scopes `org:read` + `project:read` + `event:read`) sent as `Authorization: Bearer`; `SENTRY_URL` selects the deployment. No per-call auth is needed.

**Parameters:**
- `organization`: organization slug. Omit to use `SENTRY_ORG`.
- `issueId` (required): numeric issue id from `sentry_search_issues`, e.g. `5432109876`.
- `eventId`: `latest` (default), `oldest`, or a 32-character hexadecimal event id such as `a1b2c3d4e5f60718a9b0c1d2e3f40516`.

**Size warning:** event bodies are large — stack traces (`entries[?type=='exception']`), breadcrumbs (`entries[?type=='breadcrumbs']`), and `contexts` routinely run to hundreds of KB. The shared 10 MiB response cap applies (a larger body is refused with a size error), and output that exceeds the tool-output limit is spilled to a resumable artifact you can page through with `artifact_read`. **Always pass `jq`** to narrow the body, e.g.:
- `entries[?type=='exception'].data.values[].{type: type, value: value, frames: stacktrace.frames[-5:].{file: filename, fn: function, line: lineNo}}`
- `entries[?type=='breadcrumbs'].data.values[-20:]`
- `{message: message, tags: tags, contexts: contexts}`

Event **attachments** (minidumps, screenshots, log files) are never fetched by this tool — it returns only the event JSON.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.sentry.io/api/events/retrieve-an-issue-event/

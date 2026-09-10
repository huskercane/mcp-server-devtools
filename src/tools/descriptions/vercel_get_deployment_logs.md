Read the **build and runtime log** of a Vercel deployment — the `stdout` / `stderr` lines that explain why a build failed. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /v3/deployments/{deployment}/events` and returns a JSON array of events. Each event carries `type` (`stdout`, `stderr`, `command`, `delimiter`, `exit`, …), `created` (ms timestamp), and `payload` (`text`, `serial`, and for runtime events `statusCode` / `path`).

**Logs are bounded, not streamed.** Each call returns at most `limit` events (default 100, max 1000), and the shared response cap may spill a large page to a resumable artifact. Streaming (`follow=1`) is never requested; to see the end of a long build, call with `direction: "backward"` and a small `limit`, or narrow with `since` / `until`.

Authenticates with a Vercel **account token** (`VERCEL_TOKEN`) sent as `Authorization: Bearer`. No per-call auth is needed.

**Scope:** `teamId` (a `team_...` id from Team Settings → General) selects the team; it overrides `VERCEL_TEAM_ID`. When neither is set the request is scoped to the personal account — a team-owned deployment returns 404 without `teamId`.

**Parameters:**
- `deployment` (required): the deployment id (`dpl_...`) or its hostname, e.g. `storefront-abc123-acme.vercel.app`.
- `limit`: 1–1000 events (default 100).
- `direction`: `forward` (oldest first, default) or `backward` (newest first).
- `builds`: include build logs (default `true`).
- `since` / `until`: millisecond timestamps as strings bounding the events.
- `statusCode`: filter runtime request events by status, e.g. `500` or `5xx`.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `[?type=='stderr'].{at: created, text: payload.text}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://vercel.com/docs/rest-api/reference/endpoints/deployments/get-deployment-events

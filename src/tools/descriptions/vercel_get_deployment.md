Get one Vercel **deployment** by id or hostname — its `readyState`, `url`, `target`, Git metadata, build configuration, and (for failed builds) `errorCode` / `errorMessage`. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /v13/deployments/{deployment}`. For the log lines behind an `ERROR` state, follow up with `vercel_get_deployment_logs`.

Authenticates with a Vercel **account token** (`VERCEL_TOKEN`) sent as `Authorization: Bearer`. No per-call auth is needed.

**Scope:** `teamId` (a `team_...` id from Team Settings → General) selects the team; it overrides `VERCEL_TEAM_ID`. When neither is set the request is scoped to the personal account — a team-owned deployment returns 404 without `teamId`.

**Parameters:**
- `deployment` (required): the deployment id (`dpl_...`) or its hostname, e.g. `storefront-abc123-acme.vercel.app` (no scheme, no path).

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `{id: id, state: readyState, url: url, target: target, error: errorMessage, commit: meta.githubCommitSha}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://vercel.com/docs/rest-api/reference/endpoints/deployments/get-a-deployment-by-id-or-url

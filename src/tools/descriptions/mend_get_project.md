Get one Mend **project** by UUID — its name, the application (former "product") it belongs to, and its last-scan metadata. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `POST /api/v3.0/orgs/{orgUuid}/projects/summaries` with `projectUuids: [projectUuid]`. Find the UUID with `mend_list_projects`.

Authenticates by logging in with `MEND_EMAIL` / `MEND_USER_KEY` / `MEND_ORG_UUID` at `POST /api/v3.0/login` and exchanging its refresh token at `POST /api/v3.0/login/accessToken` for an organization-scoped JWT (sent as `Authorization: Bearer`, refreshed automatically). No per-call auth is needed.

**Parameters:**
- `projectUuid` (required): the project UUID, e.g. `7f2c9e10-3b4d-4e5f-a6b7-c8d9e0f1a2b3`.

**Response envelope:** Mend wraps the project as `{"response": [...], "additionalData": {...}, "supportToken": ...}` — the fields are under `response`.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `response[0].{name: name, lastScan: lastScan}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.mend.io/platform/latest/getting-started-with-mend-api-3-0

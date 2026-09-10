List Mend **projects** — the scanned units (a repository, a build, a container image) that carry findings. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /api/v3.0/orgs/{orgUuid}/projects` for the whole organization (`MEND_ORG_UUID` from config), or `POST /api/v3.0/orgs/{orgUuid}/projects/summaries` with `applicationUuids: [applicationUuid]` when `applicationUuid` is given. Each project carries its `uuid` and `name`; pass the `uuid` to `mend_get_project` or `mend_list_findings` as `projectUuid`.

Authenticates by logging in with `MEND_EMAIL` / `MEND_USER_KEY` / `MEND_ORG_UUID` at `POST /api/v3.0/login` and exchanging its refresh token at `POST /api/v3.0/login/accessToken` for an organization-scoped JWT (sent as `Authorization: Bearer`, refreshed automatically). No per-call auth is needed.

**Parameters:**
- `applicationUuid`: restrict to one application (former "product"), from `mend_list_applications`. Omit for every project in the organization.
- `search`: free-text filter on the project name, e.g. `api-gateway`.
- `limit`: page size, 1..=200 (default 50).
- `cursor`: opaque page cursor from a previous response's `additionalData.cursor`. Omit for the first page.

**Response envelope:** Mend wraps results as `{"response": [...], "additionalData": {"cursor": ..., ...}, "supportToken": ...}`. The items are in `response[]`; when `additionalData.cursor` is present pass it back as `cursor` for the next page. Results are not aggregated across pages.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `response[*].{uuid: uuid, name: name, lastScan: lastScan}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.mend.io/platform/latest/getting-started-with-mend-api-3-0

Optional search, severity, and status filters (where exposed) apply locally to the requested page before `jq`. An empty filtered page does not imply the cursor is exhausted; preserve `additionalData.cursor` when choosing a projection.

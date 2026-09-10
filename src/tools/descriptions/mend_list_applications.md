List the **applications** of the configured Mend organization. In Mend Platform API 3.0 "applications" are the former WhiteSource "products" — the grouping one level above projects. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /api/v3.0/orgs/{orgUuid}/applications`. The organization comes from `MEND_ORG_UUID` in config — it is not an argument. Each application carries its `uuid` and `name`; pass the `uuid` to `mend_list_projects` as `applicationUuid`.

Authenticates by logging in with `MEND_EMAIL` / `MEND_USER_KEY` / `MEND_ORG_UUID` at `POST /api/v3.0/login` and exchanging its refresh token at `POST /api/v3.0/login/accessToken` for an organization-scoped JWT (sent as `Authorization: Bearer`, refreshed automatically). No per-call auth is needed.

**Parameters:**
- `search`: free-text filter on the application name, e.g. `payments`.
- `limit`: page size, 1..=200 (default 50).
- `cursor`: opaque page cursor from a previous response's `additionalData.cursor`. Omit for the first page.

**Response envelope:** Mend wraps results as `{"response": [...], "additionalData": {"cursor": ..., ...}, "supportToken": ...}`. The items are in `response[]`; when `additionalData.cursor` is present pass it back as `cursor` for the next page. Results are not aggregated across pages.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `response[*].{uuid: uuid, name: name}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.mend.io/platform/latest/getting-started-with-mend-api-3-0

Optional search, severity, and status filters (where exposed) apply locally to the requested page before `jq`. An empty filtered page does not imply the cursor is exhausted; preserve `additionalData.cursor` when choosing a projection.

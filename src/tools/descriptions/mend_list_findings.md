List a Mend project's **SCA security findings** — the vulnerable open-source dependencies (CVE, severity, affected library and version, fix availability). Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /api/v3.0/projects/{projectUuid}/dependencies/findings/security`. This is the dependency (SCA) finding set only; SAST, container and license findings are not covered by this tool.

Authenticates by logging in with `MEND_EMAIL` / `MEND_USER_KEY` / `MEND_ORG_UUID` at `POST /api/v3.0/login` and exchanging its refresh token at `POST /api/v3.0/login/accessToken` for an organization-scoped JWT (sent as `Authorization: Bearer`, refreshed automatically). No per-call auth is needed.

**Parameters:**
- `projectUuid` (required): the project UUID from `mend_list_projects`.
- `severity`: comma-separated `critical`, `high`, `medium`, `low` (case-insensitive), e.g. `critical,high`. Omit for all.
- `status`: Local filter on the returned finding status (e.g. `ACTIVE`). Omit for all.
- `limit`: page size, 1..=200 (default 50).
- `cursor`: opaque page cursor from a previous response's `additionalData.cursor`. Omit for the first page.

**Response envelope:** Mend wraps results as `{"response": [...], "additionalData": {"cursor": ..., ...}, "supportToken": ...}`. The finding fields come from the items in `response[]` and the totals from `additionalData`; when `additionalData.cursor` is present pass it back as `cursor` for the next page. Results are not aggregated across pages.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `response[*].{cve: vulnerability.name, severity: vulnerability.severity, lib: component.name, fix: topFix.fixResolution}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.mend.io/platform/latest/getting-started-with-mend-api-3-0

Optional search, severity, and status filters (where exposed) apply locally to the requested page before `jq`. An empty filtered page does not imply the cursor is exhausted; preserve `additionalData.cursor` when choosing a projection.

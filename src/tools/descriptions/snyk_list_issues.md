List Snyk **issues** (vulnerabilities, license problems, code / IaC / cloud findings) in an organization — the findings Snyk has already recorded, without running a scan. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /rest/orgs/{orgId}/issues`. Scope it to one project with `scanItemId` + `scanItemType: "project"` (project UUIDs come from `snyk_list_projects`) to answer "what is failing this repo"; omit the scope to sweep the whole organization.

Authenticates with a Snyk **API token** (`SNYK_TOKEN`) sent as `Authorization: token`. No per-call auth is needed.

**Parameters:**
- `orgId`: organization UUID. Omit to use the server's `SNYK_ORG_ID`; an error is returned when neither is set.
- `scanItemId` + `scanItemType` (`project` or `environment`): restrict to one scan item. Pass both or neither.
- `effectiveSeverityLevel`: comma-separated `low`, `medium`, `high`, `critical` (e.g. `high,critical`).
- `status`: `open` or `resolved`.
- `type`: comma-separated issue types, e.g. `package_vulnerability,license,code,config,cloud`.
- `ignored`: `true` for ignored issues only, `false` to exclude them.
- `updatedAfter` / `createdAfter`: RFC 3339 timestamps, e.g. `2026-08-01T00:00:00Z`.
- `limit`: page size 1-100 (default 20).
- `startingAfter`: cursor for the next page (see below).

**Response shape (JSON:API):** `data[]` entries carry `id`, `type: "issue"`, and `attributes` with `title`, `type`, `status`, `ignored`, `effective_severity_level`, `key`, `created_at` / `updated_at`, `problems[]` (the CVE / CWE / Snyk vuln ids with `source`, `id`, `url`), `coordinates[]` (where it is: `representations[].dependency.package_name` / `package_version`, `resource_path`, and `remedies[]`), and `resolution` (`type`, `resolved_at`) when resolved. `relationships.scan_item.data.id` names the project. Paging continues via `links.next`, a relative URL; extract its `starting_after` query value and pass it as `startingAfter` (pasting the whole `links.next` value is also accepted).

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `data[*].{title: attributes.title, severity: attributes.effective_severity_level, status: attributes.status, pkg: attributes.coordinates[0].representations[0].dependency.package_name, ver: attributes.coordinates[0].representations[0].dependency.package_version}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.snyk.io/snyk-api/reference/issues

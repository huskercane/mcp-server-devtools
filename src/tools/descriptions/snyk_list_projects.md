List the Snyk **projects** in an organization — each monitored manifest (`package.json`, `pom.xml`), container image, or IaC file. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /rest/orgs/{orgId}/projects`. Use it to find the project UUID (`data[].id`) to pass to `snyk_get_project` or as `scanItemId` to `snyk_list_issues`.

Authenticates with a Snyk **API token** (`SNYK_TOKEN`) sent as `Authorization: token`. No per-call auth is needed.

**Parameters:**
- `orgId`: organization UUID (Snyk UI: Org Settings → General → Organization ID). Omit to use the server's `SNYK_ORG_ID`; an error is returned when neither is set.
- `names`: comma-separated exact project names, e.g. `my-org/api:package.json`.
- `targetId`: restrict to one target (the imported repository / image) by UUID.
- `types`: comma-separated project types, e.g. `npm,maven,dockerfile,terraformconfig`.
- `origins`: comma-separated integration origins, e.g. `github,gitlab,cli,ecr`.
- `limit`: page size 1-100 (default 20).
- `startingAfter`: cursor for the next page (see below).

**Response shape (JSON:API):** `data[]` entries carry `id` (project UUID), `type: "project"`, `attributes` (`name`, `type`, `origin`, `status`, `target_file`, `target_reference` (branch), `created`, `settings`, `tags`), and `relationships.target.data.id`. Paging continues via `links.next`, a relative URL; extract its `starting_after` query value and pass it as `startingAfter` (pasting the whole `links.next` value is also accepted).

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `data[*].{id: id, name: attributes.name, type: attributes.type, branch: attributes.target_reference}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.snyk.io/snyk-api/reference/projects

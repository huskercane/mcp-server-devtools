List the Snyk **organizations** the configured API token can access. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /rest/orgs`. Start here: every other `snyk_*` tool is scoped to an organization UUID (`data[].id`), so use this to discover the `orgId` to pass (or set `SNYK_ORG_ID` once in the server configuration).

Authenticates with a Snyk **API token** (`SNYK_TOKEN`) sent as `Authorization: token`; `SNYK_API_BASE` selects the regional host and `SNYK_API_VERSION` the pinned REST `version`. No per-call auth is needed.

**Parameters:**
- `groupId`: restrict to one Snyk group (group UUID).
- `slug`: restrict to the organization with this URL slug, e.g. `my-company`.
- `limit`: page size 1-100 (default 20).
- `startingAfter`: cursor for the next page (see below).

**Response shape (JSON:API):** `data[]` entries carry `id` (the org UUID), `type: "org"`, and `attributes` (`name`, `slug`, `group_id`, `is_personal`). Paging continues via `links.next`, a relative URL; extract its `starting_after` query value and pass it as `startingAfter` (pasting the whole `links.next` value is also accepted).

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `data[*].{id: id, name: attributes.name, slug: attributes.slug}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.snyk.io/snyk-api/reference/orgs

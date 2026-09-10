Get one Snyk **project** by id — its name, type, origin, status, target file / branch, settings, and tags. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /rest/orgs/{orgId}/projects/{projectId}`. Project UUIDs come from `snyk_list_projects` (`data[].id`) or from an issue's `relationships.scan_item.data.id`.

Authenticates with a Snyk **API token** (`SNYK_TOKEN`) sent as `Authorization: token`. No per-call auth is needed.

**Parameters:**
- `orgId`: organization UUID. Omit to use the server's `SNYK_ORG_ID`; an error is returned when neither is set.
- `projectId` (required): project UUID, e.g. `331ede0a-de94-456f-b788-166caeca58bf`.
- `expand`: pass `target` to include the related target (repository / image, with its `display_name` and `url`) inline under `included[]`.

**Response shape (JSON:API):** `data` carries `id`, `type: "project"`, `attributes` (`name`, `type`, `origin`, `status`, `target_file`, `target_reference`, `created`, `settings`, `tags`, `business_criticality`, `environment`, `lifecycle`) and `relationships` (`target`, `organization`, `importer`, `owner`).

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `data.attributes.{name: name, type: type, status: status, branch: target_reference}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://docs.snyk.io/snyk-api/reference/projects

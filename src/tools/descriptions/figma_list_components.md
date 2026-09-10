List the **components published** from a Figma file (a team library or design-system file): component keys, names, descriptions, containing frame/page, and the node id of each. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /v1/files/{key}/components`. `file` is a bare file key or a Figma URL (`https://www.figma.com/design/<key>/Name`). The response's `meta.components[]` entries carry `key` (the library-wide component key), `name`, `description`, `node_id`, `containing_frame`, and `updated_at`. Only components that have been **published** to a library appear; unpublished local components are visible in `figma_get_file`'s `components` map instead.

Authenticates with a Figma **personal access token** (`FIGMA_TOKEN`, sent as `X-Figma-Token`) that needs the `library_content:read` scope (plus `file_content:read` for the file itself). A 404 means the key is wrong or the file is not shared with the token owner; 429 is Figma's rate limit (not retried automatically).

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `meta.components[*].{key: key, name: name, node: node_id}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://developers.figma.com/docs/rest-api/component-endpoints/

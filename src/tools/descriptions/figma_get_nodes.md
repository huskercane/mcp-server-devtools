Read specific **nodes** (frames, components, layers) of a Figma file by id — the way to inspect one part of a design without fetching the whole document. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /v1/files/{key}/nodes?ids=...`. `file` is a bare file key or a Figma URL (`https://www.figma.com/design/<key>/Name?node-id=1-2`). `ids` is required: comma-separated node ids such as `1:2,3:4` — the `node-id=1-2` in a Figma URL is node `1:2`; page and frame ids also come from `figma_get_file` (`document.children[].id`). At most 100 ids per call. The response's `nodes` object is keyed by id, each with a `document` subtree plus the `components` and `styles` it references; a node that does not exist maps to `null`.

`depth` (default `1`, max `4`) is how many levels below each requested node are returned; raise it on one frame rather than on the whole file. `version` selects a version-history entry.

Authenticates with a Figma **personal access token** (`FIGMA_TOKEN`, sent as `X-Figma-Token`) that needs the `file_content:read` scope. A 404 means the key is wrong or the file is not shared with the token owner; 429 is Figma's rate limit (not retried automatically).

**Typical flow:** `figma_get_file` (depth 1, find the page/frame ids) → `figma_get_nodes` with those ids (depth 2-4) → `jq` down to names, text, sizes, and fills.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `nodes.*.document.{name: name, type: type, children: children[*].{id: id, name: name, type: type}}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://developers.figma.com/docs/rest-api/file-endpoints/

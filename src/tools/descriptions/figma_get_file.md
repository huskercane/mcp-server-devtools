Read a Figma file's **document tree** (pages, frames, layers) plus its component and style metadata. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /v1/files/{key}`. `file` is either the bare file key (`AbC123dEf456GhI789jKl0`) or a Figma URL (`https://www.figma.com/design/<key>/Name?node-id=1-2` — `file`, `design`, `proto`, and `board` URLs all work); the key is extracted for you. The response's `document.children[]` are the pages; `components`, `componentSets`, and `styles` map ids to metadata; `name`, `lastModified`, and `version` describe the file.

**Depth is bounded on purpose.** `depth` defaults to `1` (pages only) and is capped at `4`. A full Figma document is often tens of megabytes — responses over 10 MiB are refused, and large ones are spilled to a resumable artifact — so do **not** raise `depth` to explore: start at 1 to see the pages, then call `figma_get_nodes` with the `ids` of the frames you care about to get their subtrees. `ids` (comma-separated node ids, e.g. `1:2,3:4`; a URL's `node-id=1-2` is node `1:2`) restricts the tree to those nodes and their ancestors. `version` selects a version-history entry; `branchData: true` adds `branches[]`.

Authenticates with a Figma **personal access token** (`FIGMA_TOKEN`, sent as `X-Figma-Token`) that needs the `file_content:read` scope. A 404 means the key is wrong or the file is not shared with the token owner; 429 is Figma's rate limit (not retried automatically).

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `document.children[*].{id: id, name: name}` or `{name: name, pages: document.children[*].name}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://developers.figma.com/docs/rest-api/file-endpoints/

List the **comment threads** on a Figma file — design review feedback, questions, and their replies, with authors, timestamps, resolution state, and the node/position each comment is pinned to. Returns TOON format by default (30-60% fewer tokens than JSON).

Calls `GET /v1/files/{key}/comments`. `file` is a bare file key or a Figma URL (`https://www.figma.com/design/<key>/Name`). The response's `comments[]` entries carry `id`, `message`, `user.handle`, `created_at`, `resolved_at` (null while open), `parent_id` (set on replies), `order_id`, and `client_meta` (the pinned `node_id` / `node_offset`). Set `asMd: true` to get `message` rendered as Markdown instead of plain text.

Authenticates with a Figma **personal access token** (`FIGMA_TOKEN`, sent as `X-Figma-Token`) that needs the `file_comments:read` scope. A 404 means the key is wrong or the file is not shared with the token owner; 429 is Figma's rate limit (not retried automatically). Read-only: posting or resolving comments is not supported.

**IMPORTANT - Cost Optimization:** use `jq` to keep only what you need, e.g. `comments[?resolved_at==null].{id: id, by: user.handle, msg: message, node: client_meta.node_id}`.

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://developers.figma.com/docs/rest-api/comments-endpoints/

Search Slack messages across the workspace. Returns TOON format by default (30-60% fewer tokens than JSON).

Full-text search with Slack's query modifiers (`in:#incidents`, `from:@alice`, `after:2026-09-01`, quoted phrases). Each match includes `channel.name`, `user`, `username`, `ts`, `text`, and a `permalink`.

Authenticates with the configured Slack OAuth token (`SLACK_TOKEN`) sent as `Authorization: Bearer`. Calls `search.messages`, which Slack allows only for **user** tokens (`xoxp-…`, `search:read`); a bot token gets `not_allowed_token_type`.

**Parameters:**
- `query` (required): the search expression
- `count`: results per page (max 100)
- `page`: page number
- `sort`: `score` (default) or `timestamp`
- `sortDir`: `asc` or `desc`

**Typical use — just the hits:**
- `jq`: `messages.matches[*].{channel: channel.name, ts: ts, text: text}`

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://api.slack.com/methods/search.messages

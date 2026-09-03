List the Slack channels the token can see. Returns TOON format by default (30-60% fewer tokens than JSON).

Use this to discover a channel's `id` (e.g. `C0123ABCDEF`) for `slack_channel_history`, `slack_channel_info`, and `slack_thread_replies`. Each entry includes `id`, `name`, `is_private`, `is_archived`, `num_members`, and `topic`/`purpose`.

Authenticates with the configured Slack OAuth token (`SLACK_TOKEN`, a bot `xoxb-…` or user `xoxp-…` token) sent as `Authorization: Bearer`. Calls `conversations.list` (read-only; needs the `channels:read` and, for private channels, `groups:read` scopes).

**Parameters:**
- `types`: comma-separated channel kinds — `public_channel` (default), `private_channel`, `mpim`, `im`
- `excludeArchived`: `true` to omit archived channels
- `limit`: page size (Slack caps at 1000; keep it small)
- `cursor`: `response_metadata.next_cursor` from the previous page

**Typical use — find a channel by name:**
- `jq`: `channels[?name=='incidents'].{id: id, name: name}`

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://api.slack.com/methods/conversations.list

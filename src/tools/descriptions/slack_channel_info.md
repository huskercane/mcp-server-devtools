Get one Slack channel's metadata by id. Returns TOON format by default (30-60% fewer tokens than JSON).

Returns `name`, `topic`, `purpose`, `created`, `creator`, `is_private`, `is_archived`, and `num_members` for the channel. Find the id with `slack_list_channels`.

Authenticates with the configured Slack OAuth token (`SLACK_TOKEN`) sent as `Authorization: Bearer`. Calls `conversations.info` (read-only; `channels:read` / `groups:read`).

**Parameters:**
- `channelId` (required): the channel id, e.g. `C0123ABCDEF`

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://api.slack.com/methods/conversations.info

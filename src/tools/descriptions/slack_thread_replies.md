Read the replies in one Slack thread. Returns TOON format by default (30-60% fewer tokens than JSON).

Given a channel id and the parent message's `ts` (the `thread_ts` on a message from `slack_channel_history`), returns the parent and its replies in order.

Authenticates with the configured Slack OAuth token (`SLACK_TOKEN`) sent as `Authorization: Bearer`. Calls `conversations.replies` (read-only; `channels:history` / `groups:history`).

**Parameters:**
- `channelId` (required): the channel id, e.g. `C0123ABCDEF`
- `threadTs` (required): the parent message timestamp, e.g. `1700000000.123456`
- `oldest` / `latest` / `inclusive` / `limit` / `cursor`: as for `slack_channel_history`

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://api.slack.com/methods/conversations.replies

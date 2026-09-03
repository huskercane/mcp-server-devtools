Read the messages in one Slack channel. Returns TOON format by default (30-60% fewer tokens than JSON).

The incident-investigation read: fetch what was said in `#incidents` (or any channel the token can see) in a time window. Each message includes `ts`, `user`, `text`, `thread_ts` (when it has replies — pass it to `slack_thread_replies`), and `reactions`. Find the channel id with `slack_list_channels`.

Authenticates with the configured Slack OAuth token (`SLACK_TOKEN`) sent as `Authorization: Bearer`. Calls `conversations.history` (read-only; `channels:history` / `groups:history`).

**Parameters:**
- `channelId` (required): the channel id, e.g. `C0123ABCDEF`
- `oldest` / `latest`: Unix timestamps (seconds, decimals allowed) bounding the window
- `inclusive`: `true` to include messages exactly at `oldest`/`latest`
- `limit`: page size (Slack caps at 999; keep it small to reduce token costs)
- `cursor`: `response_metadata.next_cursor` from the previous page

**Typical use — messages with text and author only:**
- `jq`: `messages[*].{ts: ts, user: user, text: text}`

**Output format:** TOON (default) or JSON (`outputFormat: "json"`).

API reference: https://api.slack.com/methods/conversations.history

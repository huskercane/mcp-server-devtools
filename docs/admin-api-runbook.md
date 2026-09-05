# Administrative HTTP API

The `all` and `control` roles mount `/admin/*` when inbound authentication is
configured. The gateway role does not mount these operations. Every request
requires a validated, non-revoked bearer token with `mcp:admin`; `mcp:tools`
does not grant administrative access. Do not place a token in a URL.

The admin boundary has its own token bucket (5 requests/second, burst 10 per
subject), independent of the MCP limiter, and four concurrent task slots.
Bodies are limited to 1,000,000 bytes. Mutations append an `admin_mutation`
control record through the durable `AuditSink` before taking effect. A failed
or timed-out append refuses the mutation. An acknowledged record is an intent,
not proof that a subsequent filesystem or backend operation succeeded.
Disconnecting a client does not cancel accepted work; graceful shutdown drains
these tasks with the audit work tracker.

All successful responses have one `data` field. Endpoint errors have string
`error` and `error_description` fields. Authentication and rate-limit errors use
the existing bearer boundary's JSON and HTTP challenge/retry headers.
Unknown request fields are rejected for endpoint-specific request types.

| Method and path | Request | `data` |
|---|---|---|
| GET `/admin/policy` | No body | `version`, exact loaded `document`, `signature` |
| POST `/admin/policy/validate` | `{"document":"YAML"}` | `valid`, `version`, `rules`, `signature_verified:false` |
| POST `/admin/policy/diff` | `{"document":"YAML"}` | `current_version`, `candidate_version`, `current_rules`, `candidate_rules` |
| POST `/admin/policy/reload` | `{}` | `audit_seq`, `changed`, `version` |
| POST `/admin/principals/lookup` | `{"tenant":"…","subject":"…"}` | `tenant`, `subject`, observed `principal` or null, `sessions`, `subject_denied`, `scope` |
| GET `/admin/sessions` | No body | `scope`, `rows` (`id`, `owner`) |
| POST `/admin/sessions/revoke` | `{"id":"…"}` | `audit_seq`, `id`, `scope` |
| GET `/admin/artifacts` | No body | `scope`, `rows` (`id`, `owner`, `size`, `content_type`) |
| POST `/admin/artifacts/purge` | `{"id":"…"}` | `audit_seq`, `id`, `scope` |
| GET `/admin/deny-list` | No body | `version`, exact loaded `document`, `signature` |
| PUT `/admin/deny-list` | `{"document":"YAML","signature":"base64 Ed25519 signature"}` | `audit_seq`, `version` |
| POST `/admin/reports/activity` | Optional `since`, `until`, `subject`, `vendor` | `rows`, `records_read`, `stopped` |
| POST `/admin/reports/access-review` | `{"groups":{"group":["subject"]},"tenant":"…"}` | B.5 access-review `rows` |
| POST `/admin/usage` | C.6 named `ReportQuery`, e.g. `{"report":"totals","window":{}}` | C.6 `Report` (`shape:totals`, `groups`, or `timeline`) |

Validation and diff compile candidate policy bytes but do not establish a
signature or change policy. Reload reads the configured signed bundle and uses
the same verifier as the file watcher. Administrative reload and watcher
stage/journal/commit sequences share one lock.

Deny-list edits replace a complete signed document, preserving the B.4 trust
model: author and sign it with the existing offline revocation tooling, then
submit those exact bytes and their detached signature. The API never receives
or needs the signing private key. A new list is verified before its durable
intent, installed atomically per file, and the exact verified candidate is
applied. A crash between installing the signature and document leaves a
mismatched pair: startup refuses it. Restore a matching signed pair to recover.
The validated-token cache is cleared and process sessions are closed after an
update. The per-request revocation check is authoritative.

`scope:process` is literal. Sessions and artifacts belong to the co-located
`all` process. A separate `control` process returns `admin_backend_unavailable`
for those inventories and principal/session lookup; there is no gateway RPC
or shared session adapter yet. Artifact purge withdraws new reads immediately;
existing read pins delay physical reclamation. Principal lookup reports bounded
recently authenticated token metadata (up to 10,000 principals), not an IdP
user directory or current group membership.

Activity reports require `MCP_AUDIT_JOURNAL_DIR` and a SQLite
`MCP_ROLLUP_STORE`. Their rebuildable projection lives beside the rollup file as
`<rollup-path>.activity.sqlite`, with SQLite WAL sidecars. One background reader
per database consumes the local journal; restart rebuilds the projection from
the source. Queries return `admin_backend_unavailable` until caught up or when
ingestion fails. Run one control reader per projection file. Usage queries
continue through `RollupStore` and preserve C.6's lossy telemetry semantics.

Activity responses contain at most 10,000 rows. `stopped` is null for a complete
query and explicitly names a limit when the window needs narrowing; never
present a truncated report as complete. `records_read` counts projection rows
considered by the query. Access review uses the supplied group snapshot and
active policy, as B.5 does; it is not an IdP membership fetch.

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

Every mutation asks an admission gate (`ports::MutationGate`, plan §3.10.1)
before it appends its intent; `MCP_ADMIN_APPROVALS` selects the adapter. The
default, `off`, admits every mutation, which is the behaviour described above.
When an adapter holds a mutation for a second administrator (plan §3.10.3,
`required`), the endpoint answers `202 Accepted` with
`{"data":{"proposal":"<id>","state":"pending","operation":"…"}}`, where
`operation` is `policy/reload`, `deny-list/replace`, `sessions/revoke`, or
`artifacts/purge`, and appends **no** `admin_mutation` record: nothing has
changed, and the adapter journals the proposal itself. When the gate refuses,
the endpoint answers `409 Conflict` in the ordinary error shape with the gate's
cause as `error` (`approval_self`, `approval_expired`), again with no record.
A deny-list replacement is admitted on the verified candidate bytes and
version, so a held proposal is bound to the exact document submitted, not to
whatever is on disk when it is approved.

Both clients of this API depend on one port, `ports::AdminClient`: a method,
the operation path under `/admin/`, an optional JSON body, and whatever status
and body the boundary answered. The command-line client below uses the HTTP
adapter (`admin::HttpAdminClient`, which owns the URL and transport rules in
the next section). An in-process adapter (`admin::LocalAdminClient`) drives
the same router without a socket — same bearer check, same limiter, same
audit — for embedders and the console (plan §3.10.2). One conformance suite
runs against both adapters, so a client cannot tell which it holds.

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

## Command-line client

`mcp-devtools admin` calls this HTTP API. Supply the service origin with
`--url` (or `MCP_ADMIN_URL`) and a file containing the bearer token with
`--token-file`. The token must have `mcp:admin`. HTTPS is required except
for loopback HTTP; redirects are disabled. The CLI reads the token file on
each invocation, so a projected token can rotate without a persistent CLI
cache. It does not load vendor credentials or resolve vendor secret references.

```sh
mcp-devtools admin --url https://mcp.example.com --token-file /run/admin-token policy read --json
mcp-devtools admin --url https://mcp.example.com --token-file /run/admin-token policy validate policy.yaml --json
mcp-devtools admin --url https://mcp.example.com --token-file /run/admin-token policy diff policy.yaml --json
mcp-devtools admin --url https://mcp.example.com --token-file /run/admin-token policy reload --json
```

Every command supports `--json`, including after the leaf command. Successful
JSON output is the API response envelope, with no prose. API and client runtime
failures produce JSON and a nonzero exit code. Without `--json`, output is pretty
JSON. Standard clap help and argument-usage diagnostics remain text.

The remaining commands, following the same connection options, are:

- `principals --tenant TENANT --subject SUBJECT`
- `sessions list` / `sessions remove ID` (revokes the session)
- `artifacts list` / `artifacts remove ID` (purges the artifact)
- `deny-list read` / `deny-list replace list.yaml --signature list.yaml.sig`
- `report activity --request query.json`
- `report access-review --request query.json`
- `usage --request query.json`

Report request files contain the JSON objects in the API table above. The CLI
limits input files to 1 MB and response bodies to 32 MB; narrow a report window
if its response exceeds that cap. Legacy direct vendor CLI commands retain
their existing enterprise-mode refusal; CF-7 is closed for these admin commands,
not for unaudited direct vendor operations. CF-28's vendor-reference resolution
work remains open; the admin client only needs its explicitly supplied token
file and the server's authenticated boundary.

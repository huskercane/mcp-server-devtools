# Administrative HTTP API

The browser UI and `/admin/proposals` workflows require the Enterprise
executable. Community retains the other admin operations and returns 404 for
proposal routes after authentication. Use `mcp-devtools-enterprise admin` for
proposal commands; Community does not expose them.

The optional browser UI is covered in the [console runbook](console-runbook.md).

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
| PUT `/admin/policy` | `{"document":"YAML","signature":"base64 Ed25519 signature"}` | `audit_seq`, `version` |
| POST `/admin/policy/validate` | `{"document":"YAML"}` | `valid`, `version`, `rules`, `signature_verified:false` |
| POST `/admin/policy/diff` | `{"document":"YAML"}` | `current_version`, `candidate_version`, `current_rules`, `candidate_rules` |
| POST `/admin/policy/reload` | `{}` | `audit_seq`, `changed`, `version` |
| POST `/admin/policy/explain` | `tool` (required), optional `arguments` (object), `subject`, `groups`, `scopes`, `environment`, `tenant`, `client_name`, `client_version` | `policy_version`, the `action` as built, `configured_environment`, `explanation` (`decision`, `unclassified`, `rules`) — the shape `mcp-devtools policy explain --json` prints |
| POST `/admin/principals/lookup` | `{"tenant":"…","subject":"…"}` | `tenant`, `subject`, observed `principal` or null, `sessions`, `subject_denied`, `scope` |
| GET `/admin/sessions` | No body | `scope`, `rows` (`id`, `owner`) |
| POST `/admin/sessions/revoke` | `{"id":"…"}` | `audit_seq`, `id`, `scope` |
| GET `/admin/artifacts` | No body | `scope`, `rows` (`id`, `owner`, `size`, `content_type`) |
| POST `/admin/artifacts/purge` | `{"id":"…"}` | `audit_seq`, `id`, `scope` |
| GET `/admin/deny-list` | No body | `version`, exact loaded `document`, `signature` |
| PUT `/admin/deny-list` | `{"document":"YAML","signature":"base64 Ed25519 signature"}` | `audit_seq`, `version` |
| GET `/admin/proposals` | No body | `rows`: the caller's tenant's proposals, oldest first |
| GET `/admin/proposals/{id}` | No body | `proposal` |
| POST `/admin/proposals/{id}/approve` | `{}` | `proposal` (`state:approved`, `applied_seq`) |
| POST `/admin/proposals/{id}/reject` | `{}` or `{"reason":"…"}` (≤ 512 bytes) | `proposal` (`state:rejected`) |
| POST `/admin/reports/activity` | Optional `since`, `until`, `subject`, `vendor` | `rows`, `records_read`, `stopped` |
| POST `/admin/reports/access-review` | `{"groups":{"group":["subject"]},"tenant":"…"}` | B.5 access-review `rows` |
| POST `/admin/usage` | C.6 named `ReportQuery`, e.g. `{"report":"totals","window":{}}` | C.6 `Report` (`shape:totals`, `groups`, or `timeline`) |

Explain is `mcp-devtools policy explain` (WP B.2) asked of the policy in
force rather than of a file: the action is built exactly as a tool call's
would be — the same extractor, the server-declared risk for the tool, the
upstream identity the credential broker predicts under the server's own
configuration — so the answer is the gateway's, not a workstation's. Only
what arrives with a request is supplied: `subject` (default
`someone@example`), `groups`, `scopes` (default `mcp:tools`), `tenant`
(default: the caller's), and the reporting client; `environment` overrides
the configured `MCP_VENDOR_ENVIRONMENT` for a what-if and
`configured_environment` says what it overrode. An unknown tool or
environment is `400 invalid_request`. Nothing is journaled: an explanation
is a read of the policy, not an action under it.

Validation and diff compile candidate policy bytes but do not establish a
signature or change policy. Reload reads the configured signed bundle and uses
the same verifier as the file watcher. Administrative reload and watcher
stage/journal/commit sequences share one lock. Policy install (`PUT`) is the
mirror of the deny-list replacement below: the exact document bytes and their
detached signature, verified with the configured policy public key and
compiled, are journaled as a `policy/install` intent, written as the configured
policy file and its `.sig` (each atomically, under the same lock), and put in
force — so the watcher finds a file that matches the policy already loaded.
Sign with `mcp-devtools policy sign`; the API never receives the private key.

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
When the approval adapter holds a mutation for a second administrator
(`required`, the section below), the endpoint answers `202 Accepted` with
`{"data":{"proposal":"<id>","state":"pending","operation":"…"}}`, where
`operation` is `policy/reload`, `policy/install`, `deny-list/replace`,
`sessions/revoke`, or `artifacts/purge`, and appends **no** `admin_mutation` record: nothing has
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

## Two-person approval

`MCP_ADMIN_APPROVALS=required` (plan §3.10.3) makes two mutations wait for a
second administrator: policy install (`PUT /admin/policy`) and deny-list
replacement (`PUT /admin/deny-list`). Policy reload, session revoke, and
artifact purge stay one-person by decision — reload applies only what is
already signed on disk, and the other two have a bounded blast radius and are
journaled. `mcp-devtools revoke` remains the offline-signed emergency path.
The setting needs the durable journal (`MCP_AUDIT_JOURNAL_DIR`): proposals
are journal records, and the server refuses to start without one.

The flow, every step a control record before it is a state:

1. The proposer submits the signed candidate to the ordinary endpoint. It
   is verified exactly as a direct install would be, then journaled as an
   `admin_proposal` record — carrying the exact document bytes, the
   signature, the version label it would install as, a `candidate_digest`
   (`sha256:` over the document bytes, a NUL, and the signature text), and
   the expiry — and the endpoint answers `202` with the proposal id. Nothing
   is installed and no `admin_mutation` record is written.
2. A **different** subject in the same tenant calls `approve` with a token
   that satisfies the fresh-token rule for writes
   (`MCP_WRITE_MAX_TOKEN_AGE_SECONDS`, §3.6; a token without an issue time
   or older than the bound is `403 stale_token`). The stored candidate is
   checked against its digest before an `admin_approval` record is made
   durable, and the exact stored bytes are applied through the same path a
   direct call uses, which writes its own `admin_mutation` intent before
   the effect. After the effect, `admin_application` records the proposal ID,
   candidate digest, operation, version and original intent's `applied_seq`.
   Only then does the proposal report `applied_seq`. Repeating a completed
   approval is idempotent: the same answer, no new record, no second apply.
3. `reject` (by anyone in the tenant, the proposer included) journals an
   `admin_rejection` with the bounded reason. A proposal past its TTL
   (`MCP_ADMIN_APPROVAL_TTL_SECONDS`, default one day) reads as `expired` in
   every listing, and the first decision asked of it journals one
   `admin_rejection` with reason `expired`; nothing is applied.

**Service accounts and the two-person rule.** Step 2 checks that the
approver's *subject* differs from the proposer's. Two service accounts in one
tenant satisfy that, so granting `mcp:admin` to two pipeline identities would
let one propose a signed policy and the other approve it, with a
correct-looking journal and nobody in the loop. The control that closes this
is at the boundary, not in the rule: `/admin/*` refuses a principal the
provider positively marks as a machine's (`403 machine_principal`) under the
default `MCP_ADMIN_PRINCIPALS=human-or-unknown`, decided on a validated claim
per provider profile ([identity provider runbook](identity-provider-runbook.md#service-accounts-and-the-administrative-api)).
`MCP_ADMIN_PRINCIPALS=any` opens administration to machines and is refused at
startup together with `MCP_ADMIN_APPROVALS=required`; machine administration
under two-person approval needs an approval predicate that can tell a person
from a pipeline, which does not exist yet (CF-42). Where the profile carries no
marker (a generic provider without `MCP_OIDC_MACHINE_CLAIM`), the gateway
cannot tell and says so at startup; do not grant `mcp:admin` to service
accounts there.

The pending set is a projection of the control journal, rebuilt when a
`control` process starts, so a restart loses no proposal and needs no other
backend. A proposal whose journaled candidate no longer matches its digest —
a journal altered between proposal and approval — is never applied
(`409 proposal_digest_mismatch`). Because the proposal record carries the
candidate, a large policy makes a large journal record (bounded by the
1,000,000-byte encoded admin request limit) that the SIEM forwarder ships like any other.

**Interrupted application and upgrade recovery:** `409 proposal_incomplete`
means a decision/application is in flight or its outcome is uncertain. Poll
`GET /admin/proposals/{id}`; a completed concurrent request will expose
`applied_seq`. Do not automatically resubmit an incomplete approved proposal:
an intent proves authorization, not successful file replacement. A restart
replays explicit completion records by proposal ID and digest, never by a
shared version label. Older approved proposals have no completion record and
therefore also appear without `applied_seq` after upgrade; they are not replayed.

If it stays incomplete, quiesce administration, preserve and verify the signed
journal with `audit verify`, and compare the exact policy/deny-list and detached
signature with the reviewed candidate. Check both disk and the active API state.
A crash between signature and document replacement leaves a mismatched pair
that refuses startup; restore a separately retained known-good signed pair
before restarting. The [state backup helper](release-operations-runbook.md#backup-and-restore)
covers journal/checkpoints/rollups, not policy or deny-list files: retain each
signed document and its detached signature through the deployment backup process. Resolve the underlying storage/audit failure. If the desired
change is still needed, submit a new signed proposal for independent review and
fresh-token approval. Do not edit journal records or infer success from the
version label. There is no automatic exactly-once recovery across filesystem
writes and the journal. A failed/timeout decision append also blocks further
in-process decisions; after a controlled restart the durable journal determines
whether the proposal is pending, decided, or incomplete.

A proposal is `{id, operation, target, candidate_digest, proposer:{tenant,
subject}, created, expires, state}` with `decided_by`, `decided`, `reason`,
and `applied_seq` once they apply; `state` is `pending`, `approved`,
`rejected`, or `expired`; `operation` is `policy/install` or
`deny-list/replace`; ids are `p-` and sixteen hex digits. Listings and
lookups are scoped to the caller's tenant. The endpoint errors, all in the
ordinary shape: `409 approval_self`, `409 approval_expired`,
`409 proposal_decided`, `409 proposal_digest_mismatch`, `409 proposal_incomplete`, `403 stale_token`,
`404 not_found`, `503 audit_unavailable`, and `503 approvals_off` when the
gate is `off`.

Credential rotation has no proposal type: rotation happens in the secret
source (`docs/secret-sources-runbook.md`), not through this API (CF-36).

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
mcp-devtools admin --url https://mcp.example.com --token-file /run/admin-token policy install policy.yaml --signature policy.yaml.sig --json
mcp-devtools admin --url https://mcp.example.com --token-file /run/admin-token policy explain --tool grafana_query_logs --arguments '{"datasourceUid":"loki-qa"}' --group SRE --json
```

`policy explain` takes the flags of `mcp-devtools policy explain` less the
file and `--public-key` (`--tool`, `--arguments`, `--subject`, `--group`,
`--scope`, `--environment`, `--tenant`, `--client-name`, `--client-version`)
and sends them to `POST /admin/policy/explain`; `--arguments` must be a JSON
object (`invalid_json` otherwise, before any request is made).

Every command supports `--json`, including after the leaf command. Successful
JSON output is the API response envelope, with no prose. API and client runtime
failures produce JSON and a nonzero exit code. Without `--json`, output is pretty
JSON. Standard clap help and argument-usage diagnostics remain text.

The remaining commands, following the same connection options, are:

- `principals --tenant TENANT --subject SUBJECT`
- `sessions list` / `sessions remove ID` (revokes the session)
- `artifacts list` / `artifacts remove ID` (purges the artifact)
- `deny-list read` / `deny-list replace list.yaml --signature list.yaml.sig`
- `proposals list` / `proposals show ID` / `proposals approve ID` / `proposals reject ID [--reason TEXT]` (ID is `p-` and sixteen hex digits; anything else is refused before a request is made)
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

## Console client (D.3)

The optional console now authors and signs through the workflow in the
[console runbook](console-runbook.md#author-sign-and-submit-a-policy-d3).
The browser never supplies a bearer or signing key in page content: its
server-side session calls `AdminClient` for validate/diff, signed policy PUT,
and proposal reads/approve/reject. Existing JSON API shapes, configured gate,
freshness/tenant/separation checks, signature verification, durable intent
ordering and fail-closed refusals are unchanged. Proposal review currently
shows metadata and digest only; candidate/signature review uses the offline
handoff. No HTML endpoints were added under `/admin`.

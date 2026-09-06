# Enterprise carry-forward register

Everything M0 deliberately did **not** finish, in one place, so it survives a
branch, a review round, or a change of hands.

An item lands here when the work was scoped out on purpose — because the fix
belongs to a later phase, because it needs a decision we do not have, or
because folding it into the current change would have hidden it. An item is
removed only when it is done, not when it is explained.

Status legend: **open** · **blocked** (needs a decision) · **done**.

Last updated: 2026-09-06, D.0–D.4 closeout (rev 2.29).
[Review findings and recovery decision](phase-d-closeout-review.md), with
fresh gates/probes in `benchmarks/2026-09-06-phase-d-closeout.txt`.
CF-38/41/45 evidence requirements remain open; Gate B remains unrecorded.

Previously updated: 2026-09-06, after D.3 (rev 2.28). Textarea policy authoring,
validated download/offline signing, signed uploads through the configured
MutationGate, and interactive proposal decisions landed; CF-39 is closed.
CF-45 records authoring/review boundaries and unexercised browser evidence.
CF-18's inventory is updated. Fresh gates/allocation evidence is in
`benchmarks/2026-09-06-d3-authoring.txt`. Real-provider proof remains CF-38;
CF-40 is backlog only, offline licensing remains CF-10 and D.5 stays gated.

Also recorded: 2026-09-06, after the authorization extensions addendum
(rev 2.28). CF-42 records client-credentials external evidence and the
undecided machine-principal scope; CF-35 continues to carry EMA client and
tenant evidence. CF-43 and CF-44 record the two deviations found by mapping
the MCP 2026-07-28 security best practices onto this server
([conformance map](mcp-security-best-practices.md)).

Previously updated: 2026-09-06, after D.4 (rev 2.27). Packaging, TLS Compose,
file-backed JWKS and vendored-source offline builds landed; actual local
proof and unchanged allocation evidence are in the D.4 summary. CF-41
records hosted CI/release, portability and operating boundaries. CF-40
remains backlog only, committed separately; shipping profiles are unchanged.
Offline licensing remains blocked on CF-10; OVA remains on request.

Previously updated: 2026-09-05, after D.1 (rev 2.26). ADR-013 accepted;
read-only console, provider/runbook documentation and stage −1f landed.
CF-37/38/39 track topology/session limits, real-provider evidence (including
Entra SPA redemption), and CLI-only approval decisions. CF-18 gains
`src/console`; the Phase D allocation baseline is recorded below. CF-40 adds
the requested build-speed backlog after the D.1 release measurements.

Previously updated: 2026-09-04, after C.1 implementation (rev 2.22). Stable
ext-auth fetched/read, two issuer grants, opt-in resource discovery and
synthetic Okta subject/actor fixtures landed. Full 1,077 tests and all gates
pass. CF-35 tracks real tenant and client evidence; no client interoperability
claim. C.7 signing is still unexercised locally (CF-34). No push/PR.

Previously updated:  2026-09-04, after C.7 (rev 2.21). Native Helm, real SQLite
and signed-journal restore tests and all landing gates passed. Docker daemon
was unavailable; no cluster rollout was run. Sigstore signing cannot be
exercised locally: CF-34 tracks external release evidence. CF-16/33 remain.

Previously updated:  2026-09-04, after C.5 (admin CLI) landed locally on
`feat/phase-c-operations` (plan rev 2.20). CF-7 is closed for the admin
commands; direct vendor CLI operations remain open. CF-28 remains scoped
to those vendor commands. All 1,066 tests and every landing gate passed;
no dependencies or request-path allocation changes.

Previously: 2026-09-04, after C.4 (admin API) landed locally on
`feat/phase-c-operations` (plan rev 2.19). The API has durable mutation
intents, independent scope/rate/task budgets, signed document operations,
process inventories, projected activity reports, and RollupStore usage.
CF-16's shared-state limitation remains explicit; CF-7/CF-28 are next in C.5.
All 1,064 tests and formatting, both clippy feature sets, cargo-deny,
benchmark, and diff gates passed. No dependencies added.

Previously: 2026-09-04, after C.6 (usage rollups, Prometheus metrics,
and per-principal rate limiting) landed on `feat/phase-c-operations`
(plan §0 rev 2.18). CF-16 now records that the limiter is in-process and
therefore single-replica. CF-33 now covers gateway-to-control usage
delivery as well as the existing journal reach/pruning gap. The allocation
baseline gained stage −1d: limiter and known Prometheus series are
allocation-free; Prometheus-plus-channel fan-out is 9 allocations.

Previously: 2026-09-04, after C.3 (SIEM forwarding behind the
`AuditForwarder` port) landed on `feat/phase-c-operations` (plan §0 rev
2.17). Opened CF-32 (TCP syslog carries no acknowledgement; the adapter
detects a closed peer within a grace window and RELP would close the
residual) and CF-33 (in the split topology the control replica reads the
gateway's journal volume rather than receiving the push §3.4 sketches;
one shipper per journal; no prune-after-acknowledgement). The allocation
baseline below gained the C.3 note.

Previously: 2026-09-04, at the start of `feat/phase-c-operations` (plan
§0 rev 2.16): C.2c and C.2d are deferred until a partner asks for a native
cloud adapter, so CF-30 and plan §11 item 8 are now **deferred with
C.2c–d** rather than open; the CSI Secrets Store provider plus `file://`
is the supported path on both clouds meanwhile. Nothing else changed.

Before that: 2026-09-04, after C.2b (the `vault://` secret source)
landed on `feat/phase-c-secret-sources` (plan §0 rev 2.15). CF-30 narrowed
to the two cloud adapters and their placement (§11 item 8), with the
`aws-config` spike named as the input that decision needs. Nothing new
opened: Kubernetes auth and the namespace header are contract-tested
rather than live-tested, which the plan's §3.8 test table now records
rather than a register item, because no CI environment can supply a
cluster or an Enterprise server. The allocation baseline below gained the
C.2b note.

Earlier: 2026-09-04, after C.1b (OIDC provider profiles) landed on
`feat/phase-c-secret-sources` (plan §0 rev 2.14). Opened CF-31 (the
manually triggered Entra and Auth0 live jobs against developer tenants are
not built; those profiles are fixture-locked only). CF-18's reading now
covers `auth/oidc.rs` as it did `auth/okta.rs`. The allocation baseline
gained the C.1b note.

Before that still: 2026-09-04, after C.2a (secret references) landed on
`feat/phase-c-secret-sources` (plan §0 rev 2.13). Opened CF-28 (the
one-shot CLI refuses references rather than resolving them), CF-29
(`NINJAONE_SERVERS` nested credentials take no references), and CF-30 (the
reserved cloud schemes refuse by name until C.2b–d; the placement question
in plan §11 item 8 is still open). The allocation baseline below gained
the C.2a note.

Earlier: 2026-09-03, after the independent review of the Phase B
branch (plan §0 rev 2.8). The review opened CF-23 (checkpoint threat model
and an external retention boundary), CF-24 (policy and revocation are two
signed documents, not one bundle), CF-25 (the §7 metrics are proxies),
CF-26 (the cached `jti` allocation), and CF-27 (behaviours not yet
regression-locked); it added a note to CF-16 (the initialize/revocation
interleaving) and to CF-19 (the parity claim in `docs/configuration.md`
now matches it). Everything else the review found was answered in code,
each with a test that fails on the previous commit: a future `iat` is
refused at authentication; a repeated Slack `channel` key is not
classified; the verifier reports a journal checkpoint with no export and
duplicate exports; the audit signing key may be group-readable (the
Kubernetes projection under `fsGroup` is `root:fsGroup 0440`, which the
owner-only rule refused, so the sample deployment could not start); a
rejected reload is journaled once per refused revision and only once its
record is durable; the `*_loaded` records are appended before the port is
bound and their failure is a startup failure; key files are installed with
a no-replace link and checked and read through one handle; revocation
edits serialize on an advisory lock and `init` never replaces; `policy
explain` builds its context through the builder `call_tool` uses, from
the live configuration and the real broker; CSV cells that a spreadsheet
would evaluate are neutralised; time bounds compare at full precision.

Previously: 2026-09-03, at the Phase B exit. Phase B closed CF-8 (signed
checkpoints) and the emergency-deny half of CF-16 (the revocation list);
CF-18's move list grew by every Phase B module; CF-21 (Slack search
scoping) and CF-22 (access-review scope assumption) were opened; the
allocation baseline table gained the Phase B column. CF-1/CF-13, CF-7,
CF-9, CF-10, CF-11, CF-12, CF-15, CF-17, CF-19, CF-20 are unchanged.

Previously: 2026-09-02, after the independent review of the Phase A
branch. Phase A closed CF-2, CF-3, CF-4, CF-5, CF-6, and CF-14 (each entry
says how) and opened CF-15. The review amended CF-14 (the post-dispatch
half), and opened CF-16 through CF-20: two engineering items (CF-16 session
affinity and emergency deny, CF-17 credential-bootstrap egress), two
decisions owed (CF-18 the ADR-001 code boundary, CF-19 canonical wire bytes
in local mode), and the §8 CI gate (CF-20). CF-1 / CF-13
(resolve-then-attribute) stay open: the Grafana slice's attribution is exact
because Grafana's resolution is observable, so the slice did not need the
general fix; the 14-vendor refactor is still owed. CF-7 (audited CLI), CF-8
(signed checkpoints), CF-9, CF-10, CF-11, CF-12 are unchanged.

What the review changed in code, for the record (each with a test that
fails on the previous commit): SonarQube's `ce/task` lookup and CircleCI's
build-details request go through the transport chokepoint; the outcome
append is cancellation-safe; every egress decision is listed on the
outcome record; the JWKS body is bounded while it is read, only RSA signing
keys with unambiguous `kid`s are admitted, and a withdrawn key evicts the
tokens it validated; the insufficient-scope path logs a category, not the
subject; a vanished policy file reports degraded health while the last good
policy stays in force; the ingress example no longer hashes on
`Mcp-Session-Id`; and the allocation probe gained the two §8 stages it had
no entry for. Two further rounds tightened the same items: the validated
cache is gated on a key generation and evicted on kid *or material* change;
egress records carry a dispatch state (denied / not attempted / cache hit /
attempted with count and result, `cancelled` when a send was in flight);
pending outcome appends are tracked and drained at shutdown; the health
banner shows a fixed category for a failing policy reload.

One parity claim was narrowed: what `tests/auth_mode_tests.rs` proves is
that unset and explicit-`off` modes are **identical to each other** in
protocol behaviour and tool surface — not that either is byte-identical to
pre-Phase-A `main`. The wire bytes did change relative to `main` (CF-19,
which locks the current form); the startup log line gained `auth=` and
`role=` fields; and the in-memory response cache's identity digest now
includes a fixed owner prefix. The last two are neither persisted nor
parsed by anything.

---

## Blocks freezing §3.2 / declaring M0 done

### CF-1 · Resolve-then-attribute credential selection
**Open · Phase A · security-relevant**

`CredentialBroker` *predicts* which credential slot will act, because the
audit intent record is written before dispatch and the credential is resolved
later, inside each controller. The prediction now uses the resolver's own
rules (`ports::credential_broker::slot_label`), but prediction is still the
wrong shape:

- **NinjaOne cannot be predicted at all.** `resolve_auth` prefers an
  in-memory session minted by `ninjaone_login` over configured keys, and a
  `NINJAONE_SERVERS` alias can carry its own credentials chosen per request.
  Neither is visible from `Config`. The broker therefore answers
  `ninjaone/indeterminate` rather than naming a slot it cannot vouch for —
  honest, but it is a hole in attribution, and it is the reviewer's finding,
  not a design choice we would have made.
- **A residual time-of-check gap remains for every vendor**: config or the
  keychain can change between the prediction and the resolution.

*The fix*: resolve an opaque credential handle **once**, before the intent
append, and take the label from that same resolved selection. That requires
credential resolution to move ahead of dispatch across every controller
(14 vendors), which is why it is not an M0 change.

*Do not close by*: adding more per-vendor special cases to `slot_label`. The
registry is the wrong source of truth for something the vendors decide.

### CF-13 · NinjaOne calls served by a cached login session
**Open · Phase A · security-relevant · sub-case of CF-1**

Recorded separately because it is the concrete evidence gap, not just an
architectural preference. A NinjaOne call served by the in-memory session
minted by `ninjaone_login` dispatches with **no attributable credential** in
the record — the broker reports `ninjaone/indeterminate`, which is honest but
is not "which credential acted". Closed by CF-1.

### CF-2 · `constrained_by` for resource semantics
**Done · 2026-09-02 (Phase A, WP A.7) — §3.2 is frozen**

`ActionDetails`/`ActionContext` carry `constrained_by: Option<ResourceConstraint>`
— a typed `(resource_type, ids)` pair in its own namespace. Jira search is
now `resource_type: issue, resource_scope: unscoped,
constrained_by: project[PLAT, WEB]`; the project keys no longer travel in the
issue-id slot. The policy engine matches it with its own rule key
(`constrained_by: { resource_type: project, resource_id: [...] }`, all-of),
so an issue-id rule cannot match a project key and vice versa. The
serialized shape test (`action_context_serialized_shape_is_the_section_3_2_field_list`)
locks the frozen field list; `docs/read-endpoint-inventory.md` decision 3 is
recorded as decided.

### CF-3 · Exact-pin the five range dependencies
**Done · 2026-09-02 (Phase A, first commit)**

`CLAUDE.md` says dependencies are exact-pinned (`=x.y.z`). Five were not
(`atomicwrites`, `rpassword`, `httpdate`, `zstd`, and the three target-gated
`keyring` rows). They are now pinned to exactly what the community lockfile
already resolved (`0.4.4`, `7.5.4`, `1.0.3`, `0.13.3`, `4.1.6`), so the
community `Cargo.lock` did not move. The enterprise lockfile, which had
resolved `keyring 4.2.0`, is re-resolved against the pin as part of the Phase A
exit check (its build is what verifies the library surface anyway).

---

## Deferred by phase

### CF-4 · Wire extractors into the dispatch path
**Done · 2026-09-02 (Phase A, WP A.7)**

`call_tool` builds the `ActionContext` from the tool's JSON arguments
(`extractors::for_tool`), evaluates it against the configured
`PolicyDecisionPoint`, journals the intent with the decision, the policy
version, and the canonical action, and refuses a denial before dispatch.
The transport evaluates the request it is about to send
(`extractors::for_vendor` + `policy::authorize_egress`) inside the call
scope, and journals an egress denial. The Grafana UID validation in the
controller stays as belt-and-braces; the policy path now sees the same
predicate through the extractor.

### CF-5 · Full §3.5 request canonicalization (A.6)
**Done · 2026-09-02 (Phase A, WP A.6)**

`policy::canonical` is the single canonicalizer: RFC 3986 syntax-based
normalization (unreserved escapes decoded once, reserved escapes kept and
uppercased, dot-segments removed, duplicate slashes collapsed, non-`pchar`
bytes re-encoded), absolute URLs refused, query decoded and stably sorted.
The transport builds every outbound URL from the canonical target, so what
policy evaluates is what is sent. Extractors accept only the `CanonicalPath`
newtype, which nothing outside that module can construct — the soundness
caveat this item recorded is now a type-checked fact rather than a
convention. Two deliberate deviations from the §3.5 wording, both documented
in the module: `%2F` is **not** decoded (it would split one segment into two
and misclassify Bitbucket branch paths), and a trailing slash is kept, once
(Django-style APIs such as edX distinguish it; stripping it broke their
tests). Fuzz target: `fuzz/fuzz_targets/canonicalize.rs` (libFuzzer,
nightly to run); the same invariants run on stable in CI over a seeded
corpus in `tests/canonicalization_tests.rs`.

Follow-up recorded as CF-15: CircleCI's signed log-output download
(`transport::fetch_streamed_url`) takes an absolute URL from a vendor
response and bypasses this path entirely.

### CF-6 · Validated `Principal` from token claims
**Done · 2026-09-02 (Phase A, WPs A.1–A.3)**

`call_tool` reads the validated principal the bearer middleware placed in
the request extensions (`DevtoolsServer::principal_for`); stdio and
loopback-without-auth are `local`, and a server built with
`require_inbound_auth` refuses a call that arrives without a principal
instead of running it as `local`. Both audit records carry the validated
subject, tenant, groups, scopes, and authority
(`tests/inbound_auth_tests.rs`).

The sub-point landed with it: `AuditSink::is_available` (the journal answers
`false` once poisoned) and the HTTP health banner answers 503 when the
journal cannot accept records, so a gateway that will refuse every call is
not reported healthy. Local mode without a journal is byte-identical.

### CF-7 · Route CLI subcommands through the audited boundary
**Open for direct vendor operations · Admin commands done in C.5 (rev 2.20)**

`mcp-devtools admin` now calls C.4 over HTTP, including mutations and
reports, and supports `--json` on every command. A real CLI-to-server test
proves its mutation has the server’s durable control record, and journal
failure reaches the CLI as JSON plus a nonzero exit status. It does not
instantiate server handlers or vendor runtimes. This closes CF-7 for admin
commands. The direct vendor operations below remain refused in enterprise
mode until they use an audited boundary.


`mcp-devtools jira post …` reaches the same vendor APIs as the MCP tools with
no journal record. M0 closes the hole by **refusing** operational CLI
subcommands whenever `MCP_AUDIT_JOURNAL_DIR` is set
(`bootstrap::refuse_unaudited_cli`). That is a fail-closed stopgap, not the
answer: the CLI should dispatch through the audited orchestration boundary
like any other caller.

### CF-8 · Per-record signing and checkpoints (B.6)
**Done · 2026-09-03 (Phase B, WP B.6)**

Every line the writer appends extends a SHA-256 chain, and a signed
checkpoint record (Ed25519, `MCP_AUDIT_SIGNING_KEY`, required in okta mode)
carrying the chain value is appended every `MCP_AUDIT_CHECKPOINT_RECORDS`
records, after `MCP_AUDIT_CHECKPOINT_SECONDS` with unsealed records, and at
every clean close; the chain is reconstructed from disk at startup. Each
checkpoint is also handed to the `CheckpointSink` port (a directory adapter
ships; SIEM is C.3), which is what makes a truncated tail detectable.
`mcp-devtools audit verify` recomputes the chain offline and checks
coverage, signatures, and exports (`src/audit/{checkpoint,reader,verify}.rs`,
`tests/audit_checkpoint_tests.rs`). Records are signed per checkpoint, not
per record, as §8 budgets; the records after the last checkpoint are the
documented gap (`docs/audit-reports.md`).

### CF-14 · Journal append has no bound on how long a call can wait
**Done · 2026-09-02 (Phase A, WP A.7) — decision recorded**

Every enforcement-path append goes through `policy::egress::append_bounded`,
capped by `MCP_AUDIT_APPEND_TIMEOUT_MS` (default 5000, clamped to
100–60000). **Decision:** on timeout the call is refused (fail closed; the
vendor is never contacted) and the caller receives the fixed
audit-unavailable refusal, not the transport's own timeout. The record that
was already queued may still be written by the journal's writer thread
afterwards. That is acceptable because of what the record kinds mean, and
the meaning is now written down in the module docs: an **intent** record
proves a call was requested and authorized; only the **outcome** record
proves it was dispatched. An intent with no outcome is "requested, not
dispatched" — exactly the state a timed-out call is in — so the journal
stays truthful without needing to cancel a queued write. The port contract
(`AuditSink::append` = durable or error) is unchanged; the bound is the
enforcement point's, not the sink's.

**Amended after review (2026-09-02).** The reading above holds only for
records written *before* dispatch. The outcome record was going through the
same cancellable wait, so a journal that stalled past the bound *after* the
vendor was contacted could drop the outcome entirely and leave a dispatched
call reading as "requested, not dispatched". `DevtoolsServer::record_outcome`
now gives the append its own task that owns the record: the caller stops
waiting at the bound, the write is never cancelled, and a late
acknowledgement or failure is logged. The pre-dispatch comment no longer
claims the record "was queued" — it may or may not have been, and both
states are truthful because nothing was dispatched.
`tests/audit_journal_tests.rs::a_stalled_outcome_append_is_not_cancelled_by_the_bound`
holds the outcome append behind a gate past the bound and proves the record
lands once the gate opens.

**Second amendment, same day.** A detached append survives its caller, but
not the runtime: a graceful shutdown that completed before the journal
recovered would have aborted it. The appends are now tracked
(`Components.pending_audit`, a `TaskTracker`) and both transports drain
them after serving stops, for up to 30 s (`tools::AUDIT_DRAIN_BOUND`) so a
dead disk cannot hold the process open. And the semantics are stated with
the remaining gap in view, in `policy::egress`: an intent with no outcome
means **"authorized; dispatch not evidenced"** — a refused call before
dispatch, or a death / unrecovered journal after it, and the operator log
says which. It never means "known not to have been dispatched".
`pending_outcome_appends_are_tracked_for_shutdown_to_drain` proves the
tracker holds the append and the drain completes once the journal does.

### CF-16 · Session affinity past one replica; emergency deny
**Open · Phase C (scaling) / Phase B (revocation)**

C.4 amendment (rev 2.19): the admin API's `SessionStore` and `ArtifactStore`
inventory ports wrap the real process-local managers. Role `all` can list,
revoke, and purge its own state. A separate control process returns an
explicit backend-unavailable error; it cannot claim a gateway's inventory
is empty or revoke state it cannot reach. Shared/RPC adapters remain this
item's scaling work. Observed principals are bounded token metadata, not
live IdP membership. Activity reports use a rebuildable SQLite projection;
its adjacent `.activity.sqlite` file is rebuildable from the journal.


Two things the review showed the Phase A deployment example implied but
could not deliver:

- **Affinity.** The ingress example hashed upstream selection on the
  `Mcp-Session-Id` header. That cannot pin a legacy session to the pod that
  created it — the initialize request has no id, the id is generated in the
  response, and the next request's hash of that id lands on an unrelated
  pod — and it sent every stateless request (same empty key) to one pod.
  The annotation is removed; the example runs one replica and says so.
  Scaling needs an affinity mechanism established by the initialize
  *response* (ingress cookie affinity, if the MCP clients in use keep
  cookies) or a shared session store (plan §3.4). Decide when Phase C
  scopes horizontal scaling; the plan's §3.4 "Sessions" row is corrected.
- **Emergency deny — done (Phase B, WP B.4).** The revocation list
  (`auth::revocation`, `MCP_REVOCATION_FILE`, signed with the policy key,
  required in okta mode) is the control: `mcp-devtools revoke subject|token|all`
  rewrites and re-signs it, every gateway applies it within one poll on
  every request regardless of the validated-token cache, clears the cache,
  and closes the revoked subjects' sessions (all principal sessions when
  the `not_before` cut-off moves). Deleting the policy file still keeps the
  last good policy in force, by design. Only the affinity half of this item
  stays open, for Phase C.
- **Interleaving, noted by the Phase B review (not fixed, by decision).** An
  `initialize` that authenticated before a revocation committed can bind
  its session after the close-sessions sweep ran, leaving a session bound
  to a revoked subject. That session is an object, not access: every
  request re-authenticates and is checked against the list *before* the
  session binding is consulted (`server::auth::require_bearer`, then
  `session::enforce_session_owner`), so a token for a revoked subject is
  refused whichever session it names, and a token issued after a
  `not_before` cut-off is legitimately valid and reuses a session bound to
  its own subject. Nothing the revocation withdrew is reachable through
  the stale binding. A revocation generation on bindings would close the
  cosmetic gap; do it when session affinity (above) is designed, since
  both touch the binding step.
- **Rate limiting (C.6).** The per-principal token bucket is deliberately
  in-process and keyed by validated subject. With several gateway replicas,
  each replica grants its own budget, so the configured rate is multiplied
  by replica count. Move it behind the shared session/scaling design (or a
  dedicated limiter port) before raising the gateway replica count.

### CF-17 · Credential-provider bootstrap traffic is outside the egress policy
**Open · Phase B (with the vendor read profiles)**

Zoom's OAuth token exchange (`vendor::zoom::token`) and `NinjaOne`'s console
login and MFA steps (`vendor::ninjaone::session`) send requests with a
direct `reqwest` client. They are tool-triggered, so the review is right
that "control plane" does not describe them; they are classified in
`policy::egress` as *credential-provider bootstrap*: their origins come
only from configuration, never from a request, and they carry no
tool-supplied path. That is a documented exemption, not an oversight.
Resolve by routing them through a separately classified chokepoint (an
`egress` record of kind `credential_bootstrap`, origin checked against the
configured host) when those vendors get read profiles. The JWKS fetch and
health probes remain control-plane traffic and stay exempt.

### CF-15 · Response-provided absolute URLs bypass canonicalization
**Open · Phase B (with the CircleCI read profile)**

`transport::fetch_streamed_url` downloads CircleCI's signed log-output URL
exactly as the vendor response supplied it: no credential is attached, but
no canonicalization, host pinning, or egress policy applies either. Every
other outbound request goes through `CanonicalTarget` and the configured
base. Resolve when CircleCI gets a read profile: either pin the host to an
allowlist derived from the CircleCI base URL, or fetch the artifact through
the authenticated API path instead.

### CF-9 · `POST /rest/api/3/issue/bulkfetch`
**Blocked · needs its own review**

Proposed as a second POST-as-read downgrade. **Not approved.** It needs
Atlassian's actual request schema confirmed, an extractor, defined
malformed-body behaviour, and adversarial tests, reviewed on its own.
`POST /rest/api/3/issue` stays `write`.

---

### CF-28 · The one-shot CLI does not resolve secret references
**Open · Phase C (C.2a)**

C.5 amendment (rev 2.20): admin commands read their explicit bearer-token
file on each invocation and call the authenticated server; they never load
vendor configuration. Tests run them with enterprise mode and an unresolved
vendor reference present. They need no duplicate SecretSource resolver.
The direct vendor commands described below remain open.

`DevtoolsServer::resolve_secrets` is the async step that turns `file://…`
references into values before the server binds; `CliRuntime::load` is
synchronous and one-shot, so `mcp-devtools jira|bb|conf …` do not run it.
Rather than send a reference upstream as if it were the token, or fail the
first call as "credential missing", `bootstrap::refuse_unresolved_references`
refuses the subcommand up front and names the reference. Closed by giving
the CLI paths the same startup step (they already share `refuse_unaudited_cli`,
so the seam exists) — most naturally when CF-7 routes them through the
audited boundary, since that is the same "the CLI is a client of the
server's composition" change.

### CF-29 · Credentials nested in `NINJAONE_SERVERS` accept no references
**Open · Phase C (C.2a)**

The reference syntax applies to every top-level configuration value
(`Config::secret_references` walks `shared` and every vendor section). A
per-server `password` or `totpSecret` inside the `NINJAONE_SERVERS` JSON
value is resolved later through `auth::resolve_configured_secret_async`
with the raw field value, which the snapshot never saw; a `file://` there is
refused by name at use, not expanded. Closing it means either teaching the
reference walk to descend into that one JSON document (the registry
deliberately does not describe those rows — `auth/secrets.rs` explains why)
or moving NinjaOne's per-server credentials to top-level keys. Decide when
NinjaOne gets a read profile, with CF-1/CF-13.

### CF-30 · The cloud secret schemes refuse by name until C.2c–d, and their placement is undecided
**Deferred with C.2c–d · 2026-09-04 (plan rev 2.16); reopens when a partner asks for a native adapter**

C.2c and C.2d are deferred until a design partner asks for `awssm://` or
`azkv://` natively. Until then the supported path on both clouds is the
CSI Secrets Store provider plus `file://` (`deploy/k8s/secrets-csi.yaml`),
which rotates without a restart. The placement decision below (plan §11
item 8) is deferred with them; the `aws-config` spike stays the input it
needs. The rest of this entry is kept as the state it reopens into.

`awssm://` and `azkv://` parse today and fail startup with
`no adapter for `awssm://` is compiled into this binary`, which is the
typed error §3.8 asks for. C.2b (rev 2.15) closed the Vault third of this
item: the `secrets-vault` feature exists, is on by default, and
`SecretResolver::from_config` registers the adapter from `MCP_VAULT_*`.
The `secrets-aws` / `secrets-azure` features and the adapters behind them
are C.2c–d, and §11 item 8 — features in the community crate, or the
enterprise crate — is still to decide before C.2c starts. Vault did not
force the question because it added no dependency; the AWS and Azure SDK
trees are the case where it matters, and the `aws-config` spike C.2c
opens with (dependency count, binary size) is the input the decision
needs.

### CF-31 · Entra and Auth0 profiles are proven against fixtures, not tenants
**Open · Phase C (C.1b); needs a developer tenant of each**

§3.9 asks for the Keycloak container *and* "a manually triggered live job
against a developer tenant of each" for Entra and Auth0. The container
job exists (`tests/keycloak_live_tests.rs`, the `keycloak` job in
`rust.yml`) and paid for itself on its first run — the Keycloak fixture
had assumed `aud: "account"` and the real realm emits no `aud` at all.
The Entra and Auth0 profiles are locked against wiremock fixtures written
from the documented claim shapes (`tests/token_validator_tests.rs`), which
is exactly the position the Keycloak fixture was in. Closing this needs a
developer tenant of each with a client credential in a repository secret,
a `workflow_dispatch` job that obtains a real token (client credentials
for Entra with an app role; an M2M application for Auth0 with the API
audience) and validates it through the profile, and a run against each
before Gate A if the partner is on either provider (plan §11 item 2). Until
then a claim-shape drift at Entra or Auth0 is found by the partner, not by
CI.

### CF-32 · TCP syslog has no acknowledgement; RELP would
**Open · Phase C (C.3); a second syslog adapter when a partner's relay speaks RELP**

The `syslog+tls://` adapter can only know that the peer is still there:
it checks before writing to a reused connection (a zero-wait read) and
listens for a close or a TLS alert for 50 ms after every flushed batch
(`audit::forward::syslog::POST_WRITE_GRACE`), then acknowledges. A
receiver that takes the bytes and dies inside that window without
writing them loses that batch, and nothing re-sends it — the shipper's
cursor has moved. The runbook therefore steers the receiver to a
**local relay with a disk queue** (rsyslog, syslog-ng), where the window
holds only what a `close` can carry, and the relay's own retries cover
the WAN. RELP (rsyslog's Reliable Event Logging Protocol; syslog-ng has
no client, rsyslog has `omrelp`/`imrelp`) acknowledges per message and is
the adapter that closes the gap properly: same port, a `relp+tls://`
scheme, a per-batch ack. HEC and the JSON endpoint already acknowledge
(`2xx` after the whole body), so this item is syslog-only.

### CF-33 · Split topology: journal and usage delivery to control; one shipper per journal; no pruning
**Open · Phase C (C.7 or when a partner runs the split topology)**

§3.4 sketches the gateway *pushing* audit to `control` and retaining its
journal until acknowledged. C.3 built the acknowledgement (the control
side's cursor) and the forwarding, but not the push: in
`--role control` the shipper reads the gateway's journal *file*
(`MCP_AUDIT_FORWARD_JOURNAL_DIR`, a read-only mount of the gateway's
volume; `deploy/k8s/control.yaml` shows it) and keeps its cursor on its
own volume (`MCP_AUDIT_FORWARD_STATE_DIR`). That needs storage readable
from another pod — `ReadWriteMany`, or a single node — and it is one
shipper per journal, so several gateway replicas need several control
shippers or a fan-in that does not exist. The journal is also one
append-only file with no rotation, so "retain until acknowledged" is
"retain": pruning up to the acknowledged sequence — a rotation the
verifier understands (the chain and checkpoints span files) — is not
built. Decide with the affinity half of CF-16 when horizontal scaling is
scoped; until then `--role all` and the single-replica split are the
tested shapes.

C.6 has the analogous usage gap: only a process that serves the control
plane attaches the bounded channel to its `RollupStore`, while a pure
`gateway` process is where tool calls produce usage. There is no push or
shared queue between them, so a split deployment's control database stays
empty. `MCP_ROLE=all` is the supported complete-rollup shape until the
gateway pushes usage to control (bounded and lossy by the `UsageSink`
contract), or a shared store/queue adapter is selected with the scaling
work above.

## Decisions we owe someone

### CF-34 · External release signing and deployment evidence
**Open · next authorized release / deployment**

C.7 implements CycloneDX source inventory and Sigstore signing plus immediate
verification of the container digest and release files in `release.yml`.
Signing cannot be exercised locally; no signature, publication, or external
verification is claimed. On the next authorized release, retain the workflow
run, SBOM and bundles, then independently run `cosign verify` with the exact
workflow certificate identity and GitHub OIDC issuer, plus `verify-blob` for
archives/SBOM. See `docs/release-operations-runbook.md`. Helm lint/render and
real local journal/checkpoint/SQLite restore pass; a real cluster rollout,
upgrade and rollback remain deployment evidence. CF-16/33 are not closed by
packaging: the chart enforces one replica and documents split-state gaps.

### CF-35 · EMA external client/tenant evidence and actor policy scope
**Open · external runs required before interoperability claims**

C.1's stable source is ext-auth `fb374c7db2b34f18ca9183882e0beecdf661892b`,
fetched/read 2026-09-04. `docs/ema-runbook.md` names the exact E01–E16 checks
for Claude web, Claude desktop, Claude Code, VS Code and each claimed Codex
surface. Every row is unrun. Retain client/OS/build/org settings, real issuer
metadata and policy, redacted exchanges and audit references. In particular,
prove real AS grant signature/audience/resource/client binding/replay refusal,
Okta XAA claim transformations, renewal/revocation, and session account
isolation. Local wiremock forms, signed fixtures and HTTP routing do not prove
those external behaviors. Generic Keycloak is not a substitute for Okta XAA.

The configured external issuer remains the AS; the server never accepts a
raw ID-JAG as a bearer. Its existing validator retains bounded actor identities
in TokenFacts, current actor first; subject/groups/scopes remain top-level.
Actor-aware local policy and actor fields in the frozen audit schema require
an explicit subsequent design. The exchange adapter is portable; the optional
file-output CLI helper is Unix-only until a private Windows ACL writer exists.
This is a protocol helper, not an implementation of external clients' SSO,
SAML bootstrap, private-key-JWT creation or automatic credential refresh.

### CF-36 · Credential rotation has no approval type
**Open · recorded at D.2 exit (2026-09-05) · design decision, not a defect**

The D.2 row of the plan listed "credential rotation" among the mutations
two-person approval might gate. It has no API target: upstream credentials
rotate in the secret source (§3.8, `docs/secret-sources-runbook.md`) and
the server only observes the new value on its next refresh. Gating it here
would mean either an API that writes secrets (which ADR-009 and the
secret-source design refuse) or a proposal that merely records an intent
someone else carries out elsewhere. The approval adapter therefore gates
policy install and deny-list replacement only; reload, session revoke, and
artifact purge stay one-person by the §3.10.3 decision. Revisit only if a
partner's rotation runs through this server rather than their vault.

### CF-37 · Console topology and browser-session lifecycle

**Open · D.1 (rev 2.26); follow-up owner: control-plane/session work.**
The console uses the local admin router. Sessions/artifacts show the `all`
process's inventory with `scope:process`; separate `control` cannot list a
gateway's inventory and renders `admin_backend_unavailable`. No aggregated
split-topology inventory was added; CF-16/33 remain prerequisites.

Browser console sessions and pending logins are bounded in-memory maps on
`control ×1`. A restart loses them and requires re-login. They are neither
persisted nor shared across replicas. The Sessions page lists MCP sessions,
not console sessions; no console-session listing or individual admin
revocation UI/API exists. Logout affects only the current browser session.
Session TTL follows `expires_in` (clamped 1 minute–12 hours, default 1 hour),
not JWT `exp`; API calls still enforce actual expiry/revocation. Health and
unsubmitted forms check local session presence without probing the API.

Close with a defined cross-process inventory/session port and proof over a
split deployment, or explicitly retain the single-control/re-login model;
any console-session administration needs its own scoped endpoint and tests.

### CF-38 · Console IdP registrations are not real-tenant proof

**Open · D.1 (rev 2.26); follow-up owner: IdP integration/design partner.**
Every console registration section in `identity-provider-runbook.md` is
unproven against a real tenant: Okta native/SPA, Entra SPA, Keycloak public,
Auth0 SPA, and generic. Validator fixtures, a Keycloak validator container,
and wiremock PKCE tests do not prove browser sign-in/client registration.
In particular, Entra's `openid api://<resource-app-id>/mcp:admin` scope form
needs tenant evidence. Microsoft's documented SPA redemption requires an
Origin header; D.1's server-side token exchange sends none, so that flow is
expected to fail until the registration/exchange design is resolved.
Keycloak/generic receive RFC 8707 `resource` in both requests; whether the
target provider honors it must be proven independently of audience mappers.

ADR-013 and §11 item 11 are resolved as design decisions, not interoperability
claims. Close per profile with recorded registration settings, a real browser
callback, correct audience/admin scope, and an authenticated admin call;
for Entra also settle and test the code-redemption compatibility gap.
No token values should appear in the evidence.

### CF-39 · D.2 console proposal decisions

**Done · D.3 (rev 2.28, 2026-09-06).** The proposal inventory links to an
escaped metadata/digest review page with approve/reject forms. Both decisions
call the existing authenticated API through `AdminClient`, preserving the
Origin/session checks and configured gate. Local real-HTTP tests exercise
required signed uploads without effects, self/stale/other-tenant refusal,
durable proposal → approval → mutation ordering, repeat approval without a
second effect, rejection and repeat-decision refusal, and observed expiry.
The offline verifier accepts the signed console journal. Existing D.2
restart and tampered-digest coverage remains active; no API or gate semantics
were replaced. Browser/real-provider evidence and candidate-review limits are
CF-38/42, not claims made by closing the interactive-controls work item.

### CF-40 · Faster builds for development and validation

**Open · D.1 follow-up (2026-09-05); owner: engineering/build tooling.**
The D.1 native release builds took 9m 54s without console and 6m 31s with
console on the same host, sequentially. These are observations with different
cache states, not evidence that console improves build time. The release
profile uses optimization level 3, thin LTO and one codegen unit; the first
run also compiled release dependencies.

Backlog: measure clean and incremental build times, then evaluate a separate
fast optimized development profile with LTO disabled and more codegen units.
Document when to use ordinary `cargo build`, the existing bench profile
(already LTO-off with 16 codegen units), and the shipping release profile.
Inspect dependency/cache reuse across the default, headless and console
validation runs before changing their orchestration.

Keep shipping release settings, binary-size comparisons and allocation
baselines reproducible; faster iteration must not remove required landing
gates. This work is independent of D.4 and is not a prerequisite for it.
Close with before/after timings on the same host and feature set, explicit
cache conditions, documented commands, and passing applicable gates. No
build-profile or gate changes are included in this backlog entry.

### CF-41 · D.4 operating evidence and packaging boundaries

**Open · D.4 follow-up (2026-09-06); owner: release/operations.**
D.4 adds version/checksum-pinned cargo-deb 3.7.0 and cargo-generate-rpm
0.21.0, a hardened systemd unit, TLS Compose, file-backed JWKS, and a
checksummed vendored-source release archive. The D.4 benchmark summary
records actual local test results; adding a workflow is not hosted CI proof.
The new hosted package/Compose jobs and tag-triggered release publication
still need execution evidence. The Rust workflow now supports manual runs
on a branch without opening a PR. Sigstore publishing evidence remains CF-34.

Justified design deviations: packages reuse the existing static musl image
binary, avoiding distro libc/keychain dependencies. They are x86_64 with
WRDS and Vault, without OS keychain or the optional console; native release
archives and shipping/benchmark profiles keep their existing settings.
Additional architectures/console package variants require separately tested
release products. Installation does not auto-start a remotely reachable
service; the initial protected environment is unauthenticated loopback only.
The package proof uses real systemd in non-privileged rootless Podman,
with the shipped unit's protections intact. PID 1 gets mount capability only
inside the subordinate user namespace, while the service gets none. Bare-metal
systemd, upgrade/rollback across distro versions, package repositories and
distro signing infrastructure are not claimed by a fresh-container install.

JWKS uses bounded async request-time reads and content hashes instead of a
timer watcher: this catches atomic replacement and withdrawal before a warm
validation-cache hit, with no timestamp/size blind spot. Only changed content
is parsed/installed. File errors clear trust rather than retaining stale keys;
no network fallback. The tradeoff is file I/O on each authentication; the
remote-JWKS cache allocation/latency probe does not measure that path. A
separate offline-file latency budget/load study remains unproven. The fetch
CLI reuses the Unix-only private-output writer from `auth exchange`;
non-Unix capture is a remaining portability item (file validation has no Unix
gate). File transfer freshness and emergency withdrawal are operator
responsibilities; neither a local file nor the fetch helper can discover a later IdP change across a gap.

The vendor archive covers Cargo dependencies and embedded assets, not the
Rust toolchain or OS/C build prerequisites. A disconnected mirror deployment,
real internal IdP issuance/console flow, and a disconnected Sigstore trust-root
ceremony remain operating evidence to obtain. File-backed validation does not
make PKCE discovery/token exchange or vendor APIs network-independent. Existing
Dockerfile base images still use tags; release images and the new runtime/test
pins are immutable, but a rebuild needs reviewed/mirrored build inputs.
Offline licence support remains blocked on CF-10; OVA remains on request.
CF-40 is backlog only and was committed separately; no build-speed work lands
with D.4. D.3 authoring and CF-39 interactive approvals subsequently landed
in rev 2.28. D.5 delegation, CF-36 credential rotation and CF-38 provider
evidence remain outstanding.

### CF-45 · D.3 authoring review and browser evidence boundaries

**Open · D.3 (rev 2.28, 2026-09-06); owner: console/partner evidence.**
**Closeout (rev 2.29):** reproduced and fixed duplicate application handoff,
intent-as-completion restart recovery and unbounded chunked token-response
accumulation. Explicit `admin_application` records bind completion to proposal
ID/digest and original intent sequence. Approved proposals without completion
fail closed (`proposal_incomplete`), including legacy approvals after upgrade;
operators reconcile disk, active state and signed journal before a new proposal.
An uncertain decision append blocks retries until a controlled restart projects
the durable outcome. This does not provide an atomic transaction across the
journal and two signed files. A crash between file replacements can require
restoring a known-good signed pair. See the admin and console runbooks.
Concurrent HTTP and interrupted-projection tests are local evidence, not a
power-loss/disk-durability campaign or multi-control replica support. Startup
projection trusts the protected local journal; sequence checking and candidate
digests do not replace offline cryptographic checkpoint verification with retained
keys/anchors during recovery. No new startup checkpoint-authentication guarantee
is claimed.

The initial authoring scope uses existing API operations and adds no editor
widget or dependency. Deliberate boundaries:

- Diff displays current/candidate rule descriptions and versions from the
  existing API, not a line-by-line patch or parser diagnostics. Validation
  only establishes syntax/rules; it does not establish signature validity.
  The active policy can change between preview and upload/approval; there is
  no optimistic-concurrency base-version precondition. Review the target and
  candidate digest before deciding.
- Existing proposal reads expose metadata/digest, not stored candidate and
  signature bytes. Reviewers obtain those through the offline signing handoff
  and compare the adapter's digest (document + NUL + trimmed signature).
  A future tenant-scoped candidate-read/diff API requires separate scope;
  this phase does not bypass `AdminClient` to read the journal.
- Native file selection needs a small first-party script to JSON-escape exact
  signed UTF-8 bytes across HTML form newline normalization, avoiding a new
  multipart parser/dependency. No-script JSON paste uses the same endpoint.
  File-helper bounds are 256 KiB policy / 1 KiB signature; the console also
  applies the existing 2 MiB encoded form bound, which heavily escaped input
  can hit sooner. Drafts are not persisted, and larger inputs use the CLI.
- HTTP/markup and actual server-side signed-byte round-trip tests passed;
  an optional local Node/minimal-DOM harness exercised the helper's exact
  CRLF/BOM/non-ASCII and malformed-file paths. No browser was run, so native
  file-picker behavior, htmx debounce/swap and download UX are not end-to-end
  browser proof. The existing htmx asset/digest remains unchanged. A real IdP
  tenant and fresh-token re-login UX remain unexercised (CF-38), and no hosted
  CI run is claimed. Obtain partner/browser evidence before claiming it.

**Landing-gate deviation:** a clean isolated checkout exposed that the existing
TLS forwarding tests' five PEM inputs were ignored by the global `*.pem` rule.
The public test CA/server/client certificates and two leaf keys, explicitly
identified as throwaway public fixtures by `tests/fixtures/tls/README.md`, are
now included through five narrow `.gitignore` exceptions. No production key or
CA private key was added. Local gates therefore use reproducible repository
inputs; this is not hosted-CI evidence.

These are review/evidence follow-ups, not a request to implement D.5, offline
licensing, an editor widget, build-speed work (CF-40), or new shipping profiles.

### CF-42 · Client-credentials external evidence and machine-principal scope

**Open · AE-2 follow-up (2026-09-06); owner: engineering + operations.**
The [authorization extensions addendum](enterprise-auth-extensions.md) proposes
`MCP_CLIENT_CREDENTIALS_ENABLED` as an opt-in advertisement setting. Local
configuration and wire tests can be completed here; the acceptance evidence
that cannot is the external half — a real authorization server issuing a
client-credentials or RFC 7523 private-key-JWT token, followed by an allowed
tool call and a policy-denied call through the real HTTP path, plus credential
rotation and reacquisition at the client/AS boundary. This is the client
credentials sibling of CF-35 and carries the same rule: a fixture issuer
establishes local behaviour, never that a particular tenant or MCP client
implements the extension. No support claim for any provider/client pair until
the pair is run.

The extension is specified in `specification/draft/oauth-client-credentials.mdx`
only — there is no stable file, unlike EMA. Operator documentation must say so;
a draft extension is a weaker support commitment and may change under us.

Scope still undecided, and blocking before the flag is enabled anywhere an
administrator can reach: whether a machine principal is admitted at `/admin/*`
at all. D.2's four-eyes rule refuses self-approval on subject equality within a
tenant (`src/approvals/mod.rs:291`, `:312`), which two service accounts in one
tenant satisfy, so `MCP_ADMIN_APPROVALS=required` would admit a fully machine
approval chain with a correct-looking journal. The control that stands today is
scope, not the approval rule: `/admin/*` requires `mcp:admin`
(`src/server/auth.rs:172`), so this needs an operator to have granted that scope
to two service accounts — plausible for automated policy deployment, and
unwarned against. Note the exposure does not wait on the proposed flag: the flag
is advertisement only, and a client-credentials token from the configured issuer
already validates today. The proposed default is refusal at the
administrative router on a validated claim; a stronger approval predicate would
be a D.2 change with its own tests. Related: machine principals are currently
indistinguishable from employees in the D.1 access review, and the existing
rate limiter was sized for human request profiles.

### CF-43 · The outbound network posture is not written down

**Open · MCP security best practices (2026-09-06); owner: operations.**
The [conformance map](mcp-security-best-practices.md) records that we enforce
https-or-loopback on every control-plane fetch (`require_https_unless_loopback`,
`src/auth/oidc.rs:495`) and never follow redirects, but do not resolve and
range-check against the private and reserved ranges RFC 9728 §7.7 lists. The
spec asks for that blocking and, in the same breath, warns against hand-rolled
IP validation because of encoding tricks — so the control it actually
recommends is an egress proxy enforcing network policy, which belongs in the
deployment and not in this binary.

The residual risk is narrow rather than absent. Attacker-controlled URLs cannot
reach these paths: tool arguments cannot name a host (`src/policy/canonical.rs`),
and the only URLs fetched come from operator configuration or from a discovery
document served by the configured issuer over TLS and checked against it. The
realistic case is a compromised or misconfigured identity provider naming, say,
`https://169.254.169.254/...` as its `jwks_uri`.

What is missing is documentation, not code. No runbook states the outbound
posture: `docs/air-gap-runbook.md` covers offline transfer, JWKS provisioning
and vendored builds, and every other occurrence of "egress" under `docs/` means
the *policy* chokepoint in `src/policy/egress.rs`, not network policy. The
deviations section of the conformance map is currently the only place the
control is named. It should say: restrict gateway egress to the identity
provider, the SIEM, and the configured vendor hosts, and block the instance
metadata endpoint (`169.254.169.254`). A Helm `NetworkPolicy` is the obvious
home once the chart from C.7 grows one.

### CF-44 · Community-mode HTTP has no inbound credential

**Open (decision, not defect) · MCP security best practices (2026-09-06); owner: engineering.**
The MCP security best practices say a server intended to run locally should use
`stdio`, or — if it serves HTTP — require an authorization token or a Unix
domain socket. With `MCP_AUTH_MODE=off` we do neither: the loopback bind is the
trust boundary, and `validate_startup_security` (`src/server/http.rs:1198`)
already refuses to start with a non-loopback bind in that mode. Browser-driven
DNS rebinding is blocked by the loopback `Origin` allowlist, but any local
process running as any user on the host can call every tool with the operator's
full vendor credential set.

This is the deliberate community posture from plan §1.2 and it is defensible —
`stdio` is the default local transport and is reachable only by the client that
spawned it. It is recorded here because it is the one place our posture is
weaker than a spec `SHOULD`, and an assessment should say so rather than let a
reader infer parity.

Open question, if it is ever worth closing: a static local token read from
configuration, or a Unix domain socket listener. Both add a configuration
surface to the community path that currently has none, which is the reason not
to do it by default. No work is planned; this exists so the answer to "why
doesn't local HTTP require a token?" has a citation.

### CF-10 · ADR-002: the enterprise licence
**Model decided 2026-09-05 · enterprise agreement and contribution terms remain open**

The owner selected Apache-2.0 for the current community crate and proprietary
commercial licensing for separate enterprise extensions. See [licensing policy](licensing.md).
Counsel still needs to finalize the enterprise agreement and contribution terms
before external enterprise contributions are accepted. This decision does not
restrict earlier ISC copies or existing community functionality.

Knock-on: `mcp-devtools-enterprise/deny.toml` carries
`private = { ignore = true }` so cargo-deny does not fail on the crate's own
unclassifiable all-rights-reserved `LICENSE`. Remove that line once the crate
carries a real SPDX `license` field.

### CF-11 · WP 0.2 and WP 0.3
**Open** — still unstarted from the M0 work-package list.

### CF-18 · Where the OIDC validator and the file policy engine live (ADR-001)
**Amended 2026-09-05 · current crate remains community; future enterprise extensions are separate**

The licensing decision supersedes the proposed move below: all code currently
in this crate, including secure remote access and existing administration and
operations features, stays community under Apache-2.0. Future proprietary
extensions belong in the separate enterprise repository. ADR-001 is amended;
CF-10 retains only the enterprise legal-text and contribution-term work.
The earlier analysis below is retained as decision history.

**Decision 2026-09-03.** The community repository is private for now, so
the boundary ADR-001 draws — "the community binary never links enterprise
code" — has no external party on the other side of it. Option 1 (move)
would today cost a second binary with its own CI, release train, image,
and manifests; a change of trial artifact between Gate A and Gate B;
roughly half the integration suite leaving the crate that exercises the
wire path; two-repo changes for every feature that touches a port and its
implementation; and a split allocation gate — and it would deliver
nothing that runs differently. The secure remote slice therefore stays in
this crate (option 2 in practice), ADR-001 stays as written but
amended-pending, and the private enterprise crate begins with the control
plane in Phase C. Revisit if and when the community repository is opened,
together with the licence text (CF-10), since whether "enterprise" means
the control plane or the whole secure slice is what decides what moves.
Every module involved sits behind a port or a CLI boundary, so a later
move is the same file move it is today.

**Amended 2026-09-03 (Phase B).** Phase B added to the public crate, for
the same reason Phase A did (the enterprise crate has no runtime, and Gate A
runs the community image): `policy::signing`, `policy::bundle`,
`auth::revocation`, `audit::{checkpoint,reader,verify,export,metrics}`,
the `ports::checkpoint_sink` port, and the `policy`, `revoke`, and `audit`
CLI groups. Each is a self-contained module behind a port or a CLI
boundary, so option 1 ("move") is still a file move plus the composition
in `server::http` and `bootstrap`. The list of what would move is now long
enough that option 2 ("amend ADR-001") deserves a fresh look: everything
here is what makes remote deployment *safe*, not what makes it
*administrable* (Phase C/D).

**Amended 2026-09-05 (Phase D, ADR-012).** D.2 is the first item the
licensing policy names as a possible proprietary extension, and it landed
here behind ports so that a later move is a file move: `approvals/mod.rs`
(the `ApprovalGate` adapter, both `MutationGate` and `ProposalRegistry`),
`server/admin/proposals.rs` (the `/admin/proposals` endpoints), the
`Proposals` group in `cli/admin.rs`, and `bootstrap/approvals.rs` (the
`MCP_ADMIN_APPROVALS` selection). The ports (`ports::mutation_gate`,
`ports::proposals`), the `admin_proposal` / `admin_approval` /
`admin_rejection` record kinds, and `PUT /admin/policy` are community.
D.1 adds `src/console` (login, sessions, pages and router), together with
`console/` templates/static assets and the `server::http` composition wiring,
to the would-move inventory. **D.3 (rev 2.28)** adds
`src/console/authoring.rs`, the routes in `src/console/mod.rs`,
`console/templates/{authoring,proposal,mutation_result}.html`, the links in
`console/templates/{policy,proposals}.html`, and
`console/static/policy-upload.js`. Coverage moves with it: D.3 portions of
`tests/console_tests.rs` and `tests/console_upload_script_test.cjs`.
Closeout regression coverage in `tests/approval_recovery_tests.rs` and the D.2
port/API tests moves with the approvals implementation as well.
Existing `AdminClient` and mutation/proposal ports remain the community seams;
`tests/admin_api_tests.rs` retains shared signed-install/fail-closed coverage.
The move
must happen **before** the repository is opened; until then it is a
licence label.

ADR-001 says enterprise code lives in the private repository and "the
community binary never links enterprise code". The Phase A branch ships
`auth::okta::OktaJwksValidator`, `policy::engine::FilePolicy`, the bearer
middleware, and the `MCP_AUTH_MODE=okta` composition in the public ISC
crate, and the community binary runs them. The review is right that this
contradicts the decision as written. The plan is not self-consistent here,
though: its own §3.7 table places the bearer middleware and the
`MCP_OKTA_*` / `MCP_POLICY_FILE` configuration in community files, and the
Phase A work packages do not say which repository A.1 or A.7 land in.

Two ways to make it consistent; the choice is a licensing decision, not an
engineering one:

1. **Move.** `auth::okta`, `policy::engine`, `server::auth`, and the
   `okta` startup path go to `mcp-devtools-enterprise`; the community crate
   keeps the ports (`TokenValidator`, `PolicyDecisionPoint`, `AuditSink`),
   the core types, `StaticValidator`, `AllowAll`, canonicalization, the
   call scope, and the journal. The enterprise binary composes them. Cost:
   the vertical-slice tests move with the code, and the community binary
   loses `MCP_AUTH_MODE=okta`.
2. **Amend ADR-001.** Define "enterprise code" as the control plane (admin
   API, console, SIEM forwarding, revocation, rollups) and keep the secure
   remote slice — validating a token, enforcing a file policy — in the
   community crate as the thing that makes remote deployment safe at all.

Recommendation: decide with CF-10, since the answer depends on what the
enterprise licence is meant to cover. Until then, nothing else should be
added to the public crate that the private crate is supposed to own.

### CF-19 · Canonical wire bytes in local mode
**Blocked · owner decision · recommendation: keep**

Since CF-5, the transport builds every outbound URL from the canonical
target in every auth mode, so what policy evaluates is what is sent. The
review notes that this changes the bytes local mode puts on the wire
relative to `main` before Phase A: query keys are sorted, values are
decoded once and re-encoded as `application/x-www-form-urlencoded` (a
space is `+` whether the tool wrote `+` or `%20`; `~` is `%7E` either
way), dot-segments and duplicate slashes are resolved, unreserved escapes
are decoded. `tests/transport_tests.rs::wire_bytes_are_the_canonical_form`
now locks those exact bytes so any further drift is a deliberate diff.

The alternative — preserve the tool's spelling in local mode and
canonicalize only when enforcing — would make the community suite stop
testing the enterprise wire path and put two URL builders in the
transport. Recommendation: keep one wire form. Every upstream this server
talks to parses its query string with form-urlencoded semantics, and the
tool-supplied spelling was never a contract with any of them. If the owner
wants the byte-preserving mode anyway, it is a `RequestOptions` flag on
the transport plus a second `url_under` — a day's work — and this entry is
where that decision is recorded.

The Phase B review found `docs/configuration.md` still claiming that with
enterprise mode off the server "behaves byte-for-byte as before"; that
sentence now says what the tests prove (unset and `off` are identical to
each other) and points here for the wire-byte differences.

### CF-20 · §8 budgets as a CI gate
**Open · Phase B**

§8 promises "a CI smoke run that fails on a > 20 % regression against the
checked-in baseline". Phase A has the harness (`benches/response_pipeline`)
and, after review, stages for every budget except the admin API; it does
not have the CI comparison. The gate today is the per-phase rule in
`CLAUDE.md`, run by hand and recorded in the table below. Building the
comparison means committing a baseline file, a release-profile CI job that
runs the probe, and a diff step with the 20 % threshold; the numbers must
be allocation counts, not wall time, because the CI runners are not stable
enough for a timing threshold.

### CF-21 · Slack `search.messages` cannot be scoped from the request
**Open · revisit with the partner's Slack workflow**

`search.messages` is classified as an *unscoped* channel read (WP B.1):
an `in:#channel` modifier is a ranking hint to Slack, not a bound the
gateway can rely on, so the shipped profile gives search to incident
commanders only. Extracting `in:` clauses as a `constrained_by: channel`
would let a rule allow "search, but only inside these channels" — only if
Slack guarantees `in:` is exclusive, which its documentation does not
state. Decide with a test against a real workspace, not from the docs.
Also open: search needs a *user* token, and whether the shared-identity
model (ADR-006) extends to a shared user token is a Gate A/B question.

### CF-22 · The access review assumes the default required scope
**Open · Phase C (admin API)**

`mcp-devtools audit export access-review` (WP B.5) builds one principal
per member holding `MCP_REQUIRED_SCOPE`'s default, so a rule whose
`subjects.scopes` names another scope is not reflected. The review is of
people; scopes are a property of tokens the identity provider mints. When
the admin API (C.4) can read the identity provider's scope assignments, the
review should take them as input rather than assume.

### CF-23 · The checkpoint threat model, and an external retention boundary
**Open · Phase C.3 (SIEM forwarder) — and a documentation commitment now**

What the chain and the checkpoints prove, stated exactly, from the Phase
B review. The chain and coverage checks are sound: recovery and
verification hash the same complete line bytes, torn tails are truncated
first, and each checkpoint signs the chain value before its own line.
Against that, an adversary holding the **audit signing key** can rewrite
from sequence 1 and re-sign every checkpoint; detection then depends on an
independently retained *old* checkpoint that the rewritten history no
longer matches. And an adversary who can write the **export directory**
can remove or rewrite the copies along with the journal.

The design therefore protects against modification of the journal file by
someone who does not hold the signing key, when an auditor holds a
trusted public key; and against truncation only when checkpoints are
retained somewhere the gateway's host cannot alter. The Kubernetes example
exports to `/journal/checkpoints` on the same volume as the journal
(`deploy/k8s/config.yaml`), which gives the first property and not the
second; its README now says so. Claiming "tamper-evident against a
compromised host" needs a remote or WORM `CheckpointSink` (object storage
with object lock, or a SIEM that keeps its own copy) — the C.3 forwarder —
and until then the deployment notes must not claim it.

### CF-24 · Policy and revocation are two signed documents, not one bundle
**Open · decide with Phase C's admin API (C.4)**

The plan's §3.6 row describes the deny-list as "part of the policy
bundle". The implementation (WPs B.3 and B.4) is two independent files
with two watchers, two version labels, two commits, and two `*_changed`
records. A deployment that updates both — a policy that stops relying on
a group, and a revocation for the people who had it — can therefore
expose the new policy with the old list for up to one poll, or the
reverse. The review asked that this be recorded rather than left implied:

- there is no joint generation or transaction across the pair, and no
  ordering guarantee between their reloads;
- revocation is edited with a separate CLI (`revoke …`), not pushed as
  part of a policy publish;
- "bundle hash in every audit event" (B.3) means the **policy document's**
  hash in the decision's `policy_version`; the revocation list's version is
  on `revocation_*` and `revoked_token_rejected` records only, and no
  record carries a combined policy-plus-revocation state hash.

Acceptable for Phase B: the two documents answer different questions and
a stale-by-one-poll pairing fails closed on the revocation side (a subject
revoked under either document is refused). If the admin API takes over
publishing, publish the pair as one signed generation and stamp both
versions on every decision.

### CF-25 · The §7 trial metrics are proxies, not the measurements they are named after
**Open · Gate B evidence**

`mcp-devtools audit report metrics` (B.7) computes the §7 figures from the
journal alone, and each is an inference: `revocation_window_ms` attributes
a refusal to the **latest** `revocation_changed` record, which may be an
unrelated change; `deny_after_allow_ms` is the interval to *any* later
denial for the subject, including a resource, default, or stale-token
denial; `cross_environment_attempts` infers intent from an allow in
another environment. `docs/audit-reports.md` calls them proxies. Keep the
product language equally qualified, and treat the true measurements —
which need the identity provider's event timestamps and a correlation
between a control record and the refusals it caused — as Gate B's to
collect with the partner, not as something the journal can produce.

### CF-26 · The JWT cache hit's ninth allocation
**Open · next allocation pass**

The Phase B baseline records the JWT cache hit at 9 allocations against
Phase A's 8: the cached `Authenticated` carries `TokenFacts.token_id:
Option<String>`, cloned on every hit so the revocation list can name the
`jti`. `Option<Arc<str>>`, or handing out the cached result by `Arc`,
removes it with no architectural change. Under the 20 % gate; recorded so
the next pass takes it rather than rediscovering it.

### CF-27 · Behaviours the review found unit-tested only, or not locked
**Open · fold into the next WP that touches each area**

The Phase B review listed behaviours whose guarantees were asserted in
prose or unit tests only. This round locked most of them in integration
tests (`tests/token_validator_tests.rs`, `tests/revocation_tests.rs`,
`tests/phase_b_slack_slice_tests.rs`, `tests/audit_checkpoint_tests.rs`,
`tests/policy_signing_tests.rs`, `tests/policy_explain_tests.rs`,
`tests/audit_report_tests.rs`). Still open:

- **Checkpoint write poisoning.** A checkpoint whose journal write fails
  poisons the writer like any record; no fault-injection test drives that
  path end to end.
- **Concurrent `keygen` to one path.** The no-replace link is exercised
  single-threaded; a two-process race is not.
- **Initialize / revocation interleaving.** Recorded under CF-16 with the
  reasoning for not building a barrier test; add one if the binding step
  gains a generation.
- **Timing-sensitive watcher tests.** The bundle watcher tests poll with
  deadlines and the time-bound checkpoint test sleeps ~1.5 s. They pass
  reliably locally; if CI flakes, inject the tick (`WATCH_INTERVAL`) or the
  clock rather than lengthening the sleeps.

### CF-12 · Expression digest strength
**Open · revisit when a policy needs it**

Search expressions (JQL, LogQL) are retained in `query_attributes` as
`sha256:<64 bits>/<length>` — a correlation handle, deliberately not a
commitment. If a policy or an investigation workflow ever needs to *prove*
which expression ran, that needs a full-width digest and a reviewed decision
about what else is stored alongside it.

---

## Allocation baseline (for the next phase's comparison)

Re-run after the Phase B review round (rev 2.8): every stage's byte and
allocation count is identical to the table below (JWT cache hit 9, journal
append 6, extractor stages unchanged); the review's fixes touched the
authentication path only by one integer comparison and the Slack
extractor by an iterator, neither of which allocates.

Per `CLAUDE.md`'s per-phase allocation gate. Numbers from
`cargo bench --bench response_pipeline` at the **Phase B** boundary
(2026-09-03), with the Phase A figure alongside. Gate result: **no stage
moved except one**, and that one by a single allocation — the JWT cache
hit went from 8 to 9 allocations because the cached entry now carries the
token's `jti` (an `Option<String>`) so the revocation list can name it;
12.5 %, under the 20 % threshold, and on an enterprise-only stage. The
journal append is unchanged at 6 allocations after hoisting the writer's
per-batch boundary buffer (a first cut had added one); its wall time
gained the per-line SHA-256 (p50 11 µs vs 8 µs, p99 18–31 µs across two
runs vs 11 µs, max ≈ 100 µs vs 65 µs on a local SSD), still an order of
magnitude inside the 200 µs p99 budget. Every community-path stage (0–3)
and every extractor stage is byte-for-byte what Phase A recorded.

| Stage | Bytes | Allocations | Phase A |
|---|---|---|---|
| −1 `canonical`: short path + query | <1 KB | 4 | 4 |
| −1 `canonical`: dot-segments + escapes | <1 KB | 1 | 1 |
| −1 `canonical`: search URL, long JQL | <1 KB | 10 | 10 |
| −1 `jira::extract` GET `/issue/{key}` | <1 KB | 6 | 6 |
| −1 `jira::extract` GET `/search/jql` (long JQL) | 1 KB | 17 | 17 |
| −1 `jira::project_keys_from_jql` (long JQL) | <1 KB | 9 | 9 |
| −1 `jira::extract` unmapped (default arm) | <1 KB | 1 | 1 |
| −1 `grafana::query_logs` | <1 KB | 10 | 10 |
| −1b `ActionContext` via `for_tool` (Grafana; enterprise only) | <1 KB | 21 | 21 |
| −1b `FilePolicy::evaluate` @ 500 rules (enterprise only) | 0 | 5 | 5 |
| −1c JWT validate, cache hit (enterprise only; §8 budget 50 µs) | 1 KB | **9** | 8 — 3.7 µs (was 3.5) |
| −1c journal append, sequential (enterprise only; §8 budget p99 200 µs) | 1 KB | 6 | 6 — p50 11 µs, p99 18–31 µs, max ≈ 100 µs (chain hash per line) |
| −1d rate-limit check, known subject (enterprise only) | 0 | 0 | new in C.6 |
| −1d `PrometheusUsageSink::record`, known series (enterprise only) | 0 | 0 | new in C.6 |
| −1d Prometheus + bounded-channel fan-out (enterprise only) | <1 KB | 9 | new in C.6 |
| −1e observed principal, known unchanged (enterprise only) | 0 | 0 | new in C.4 |
| 0 `ConfigHandle::snapshot()` | 0 | 0 | 0 |
| 1 `apply_jq_filter(None)` | 0 | 0 | 0 |
| 2 `render(Toon)` @ 500 issues | 1736 KB | 19 032 | 19 032 |
| 3 `truncate_for_ai` | 39 KB | 4 | 4 |
| 2 `render(Toon)` @ 5000 issues | 16 547 KB | 190 035 | 190 035 |

Re-run after C.2a (2026-09-04, rev 2.13): every stage's byte and
allocation count is identical to the table below (JWT cache hit 9, journal
append 6, `ConfigHandle::snapshot()` 0, every extractor and render stage
unchanged; journal append p50 11 µs, p99 16 µs). C.2a's only request-path
change is in `Config::get_for`: one byte dispatch to decide "not a
reference" (`secrets::is_reference`) before returning the borrowed value,
and a hash lookup into the attached snapshot only for an actual reference —
no allocation on either branch, which is why stage 0 and the extractor
rows (all of which read configuration) did not move. Secret fetches run
on the refresher task and at startup, never per call (§8, "Secret
resolution (C.2)"). A probe row for "get_for through a resolved
reference" is worth adding when the probe next gains stages (CF-20).

Re-run after C.1b (2026-09-04, rev 2.14): every stage's byte and
allocation count is identical to the table above (JWT cache hit 9 at
3.7 µs, journal append 6 at p50 11 µs / p99 19 µs / max 86 µs; every
extractor and render stage unchanged). C.1b's request-path changes are
in the validator's cached-principal clone and nowhere else: the principal's
`authority` is now an `Arc<str>` issuer shared by every principal the
validator produces (a refcount increment, not an allocation — which is why
the cache hit did not move to 10), and claim-shape work (scope string
splitting, group-path normalisation, discovery) runs on the uncached
validation path and the key fetch only. The `Profile` comparison for the
Keycloak audience hint sits on the rejection path.

Re-run after C.2b (2026-09-04, rev 2.15): every stage's byte and
allocation count is identical to the table above (JWT cache hit 9 at
3.8 µs, journal append 6 at p50 11 µs / p99 15 µs / max 91 µs; every
extractor and render stage unchanged). C.2b adds nothing to the request
path at all: the Vault adapter is called from the refresher and at
startup only, and a `vault://` value is read from the same snapshot a
`file://` value is (`Config::get_for`, the one-byte scheme dispatch C.2a
recorded). `SecretResolver::from_config` runs once in
`ServerBuilder::build`.

Re-run after C.3 (2026-09-04, rev 2.17): every stage's byte and
allocation count is identical to the table above (JWT cache hit 9 at
3.7 µs, journal append 6 at p50 11 µs / p99 16 µs / max 101 µs; every
extractor and render stage unchanged). C.3 adds nothing to the request
path: the shipper is a background task on the control plane that
*reads* the journal file, the adapters are called from it only, and the
append path gained no branch — the one new thing the writer's callers
see is `Role::serves_control`, evaluated once at startup. The health
banner reads one more `Mutex<Option<&'static str>>`. The syslog and HTTP
adapters allocate per batch (one frame buffer, one body), never per
request. No new probe row: nothing here runs on the request path.

Re-run after C.6 (2026-09-04, rev 2.18): every pre-existing stage's byte
and allocation count is identical to the table above (JWT cache hit 9 at
3.79 µs; journal append 6 at p50 12 µs / p99 37 µs / max 149 µs; every
extractor and render stage unchanged). Stage −1d adds the three C.6
request-path operations: a token-bucket check for an existing subject is
0 bytes / 0 allocations; recording into an existing Prometheus series is
0 / 0; fan-out to Prometheus plus the bounded rollup channel is <1 KB / 9
allocations. The fan-out cost is the owned usage event sent across the
task boundary (tenant, subject, tool, vendor, environment, decision, risk,
and outcome); it is new functionality rather than growth in an existing
stage, and remains non-blocking. No pre-existing row moved, so the 20 %
regression gate passes.

Notes for the Phase C comparison:

- The Slack extractors (`slack::channel_history` and friends) have no
  probe row yet; they are shaped like `grafana::query_logs` (one canonical
  path from plain segments, one id, an allowlisted attribute list) and
  should land at or under its 10. Add the row when the probe next gains
  stages (CF-20 is still the CI comparison).
- Revocation checks are two hash-set lookups and one integer compare per
  request, on the middleware path, allocation-free; the revoked-token
  refusal path allocates only for its control record.
- Checkpoints cost one SHA-256 update per line on the writer thread and
  one extra write+sync per 256 records (or per minute), off the request
  path.

### Phase A baseline (2026-09-02), kept for the record

| Stage | Bytes | Allocations | M0 |
|---|---|---|---|
| −1 `canonical`: short path + query (every outbound request) | <1 KB | 4 | new — replaces a `format!` join (1–2) |
| −1 `canonical`: dot-segments + escapes | <1 KB | 1 | new |
| −1 `canonical`: search URL, long JQL | <1 KB | 10 | new |
| −1 `jira::extract` GET `/issue/{key}` (canonical input) | <1 KB | 6 | 6 |
| −1 `jira::extract` GET `/search/jql` (long JQL) | 1 KB | 17 | 17 |
| −1 `jira::project_keys_from_jql` (long JQL) | <1 KB | 9 | 9 |
| −1 `jira::extract` unmapped (default arm) | <1 KB | 1 | 1 |
| −1 `grafana::query_logs` | <1 KB | 10 | 11 |
| −1b `ActionContext` via `for_tool` (Grafana; enterprise only) | <1 KB | 21 | new |
| −1b `FilePolicy::evaluate` @ 500 rules (enterprise only) | 0 | 5 | new |
| −1c JWT validate, cache hit (enterprise only; §8 budget 50 µs) | 1 KB | 8 | new (review) — 3.5 µs |
| −1c journal append, sequential (enterprise only; §8 budget p99 200 µs) | 1 KB | 6 | new (review) — p50 8 µs, p99 11 µs, max 65 µs on a local SSD |
| 0 `ConfigHandle::snapshot()` | 0 | 0 | 0 |
| 1 `apply_jq_filter(None)` | 0 | 0 | 0 |
| 2 `render(Toon)` @ 500 issues | 1736 KB | 19 032 | 19 032 |
| 3 `truncate_for_ai` | 39 KB | 4 | 4 |
| 2 `render(Toon)` @ 5000 issues | 16 547 KB | 190 035 | 190 035 |

Notes recorded at the Phase A boundary:

- Canonicalization is the one new cost on the community path. It is paid
  once per outbound request, in place of the string join it replaced, and
  is what makes the extractors sound (CF-5); ~2 extra allocations per
  request is the price of that and is accepted.
- The 500-rule decision allocates only for the `PolicyDecision` it returns
  (rule id, version, reason). Rule matching itself is allocation-free.
- The −1c stages run the production components (the Okta validator primed
  from a JWKS on wiremock; the journal adapter on a temp directory). The
  append is sequential, one record at a time, which is the journal's worst
  case — every record pays its own `sync_data`; under concurrent calls the
  writer batches. Read the p99 as "one call on an idle gateway", and
  re-measure on the partner's storage class before quoting it (Gate A).
- The review added the egress list to the outcome record and a per-call
  `EgressRecord` on the scope, with a dispatch state the transport fills in
  (denied / not attempted / cache hit / attempted with attempt count and
  final result), so "authorized" and "sent" are distinct facts. All of it
  is enterprise-only (no scope, no record), so no stage in this table
  moved; the cost is two or three allocations per outbound request inside
  an enforcing scope.
- The §8 CI comparison itself is CF-20.


Re-run after C.4 (2026-09-04, rev 2.19): every existing allocation count
and byte count is unchanged from C.6. JWT cache hit: 9 allocations, 5.46 µs;
journal append: 6 allocations, p50 16 µs / p99 44 µs / max 88 µs. Timing
figures are observed wall-clock results, not a claim of unchanged latency;
both remain within their absolute budgets. Stage −1e measures the new
principal-inventory request-path operation: a known unchanged principal is
0 bytes / 0 allocations. Nested BTreeMaps allow borrowed tenant/subject
lookups and deterministic bounded eviction; only new/changed metadata is
cloned. Admin requests, projection ingestion, and initial inventory fills
are outside that steady-state probe.


Re-run after C.5 (2026-09-04, rev 2.20): all allocation counts and bytes
remain identical to C.4, including stage −1e at zero. The new CLI is a
one-shot HTTP client and adds no work to the MCP request path. JWT cache hit was 5.48 µs (9 allocations); journal append was p50 17 µs,
p99 62 µs, max 578 µs (6 allocations). Both absolute p99/cache-hit budgets
hold; no allocation regression was observed.


Re-run after D.0 (2026-09-05, rev 2.24): every stage's byte and allocation
count is identical to the 2026-09-05 compliance-review baseline
(`benchmarks/2026-09-05-claude-compliance.txt`). The admission gate is
consulted only on admin mutations and the `AdminClient` adapters are
clients of the boundary, so neither touches the MCP request path. JWT
cache hit 5.22 µs (9 allocations); cached actor chain 5.49 µs (8); journal
append p50 16 µs / p99 22 µs / max 129 µs (6). Both absolute budgets hold.


Re-run after D.2 (2026-09-05, rev 2.25): every stage's byte and allocation
count is again identical to the compliance-review baseline. The approval
adapter runs only on admin mutations and decisions, and its projection is
built once at startup; the MCP request path is untouched. JWT cache hit
3.74 µs (9 allocations); cached actor chain 3.95 µs (8); journal append
p50 11 µs / p99 15 µs / max 89 µs (6). Both absolute budgets hold.


Re-run after C.7 (2026-09-04, rev 2.21): all allocation counts and bytes
remain identical to C.5; no production Rust request-path changes. JWT cache
hit: 9 allocations / 15.97 µs; journal: 6 allocations, p50 45 µs / p99 133 µs /
max 251 µs. Known principal, limiter and Prometheus series remain zero.
Absolute cache-hit and journal p99 budgets pass; timings are observations.
The full gate exposed a C.4 test race: the watcher can legitimately reload
before the admin request. The corrected test proves the failed append keeps
the old policy and that whichever reload wins has earlier durable evidence.


Re-run after C.1 (2026-09-04, rev 2.22): every existing allocation count
and reported KB value matches C.7. JWT validate cache hit is 9 allocations /
1 KB / 3.78 µs; journal append is 6 allocations / 1 KB, p50 11 µs / p99 15 µs /
max 74 µs. Known-principal observation, limiter hit and known Prometheus
series remain zero. No material allocation regression; absolute timing
budgets pass. Timings are observations, not a comparative speedup claim.

New probe `C.1 JWT authenticate: cached actor chain`: 8 allocations / 1 KB /
3.89 µs for a two-actor chain. This calls `authenticate` directly, whereas the
existing 9-allocation row calls `validate` through its additional future;
these are different entry points, not evidence that actor support saves an
allocation. The signed chain is an Arc slice, so cache hits share it rather
than cloning actor strings. Tokens without actors carry None. TokenFacts has
an additional optional Arc field; KB reporting is rounded down, not exact
byte equality. Initial verification/exchange/SSO are outside this hit probe.


Re-run after the CLAUDE.md compliance follow-up (2026-09-05): every existing
stage allocation count and reported KB value matches C.1 and the table above.
JWT validation cache hit: 9 allocations / 1 KB / 3.69 µs; cached actor-chain
authentication: 8 / 1 KB / 3.99 µs. Journal append: 6 / 1 KB, p50 11 µs,
p99 15 µs, max 71 µs. Both absolute budgets hold. Known rate-limit subjects,
metric series, unchanged principals, config snapshots, and no-filter jq
remain 0 bytes / 0 allocations; fan-out stays at 9 allocations. TOON rendering
remains 19,032 allocations / 1,736 KB for 500 issues and 190,035 / 16,547 KB
for 5,000 issues; truncation remains 4 / 39 KB. No measured allocation
regression crosses the 20% phase-exit threshold.

The follow-up adds no MCP-facing schema/description changes. It moves trusted
integer quota maps to FxHashMap and small metric outcome collections to
SmallVec; both crates were already in the lockfile at the exact versions now
pinned directly. Admin projection batching is bounded and reuses its vector;
its contention/peak memory are outside the response-pipeline probe.
See the [full fresh output](benchmarks/2026-09-05-claude-compliance.txt) and
[compliance review](claude-compliance-review.md) for scope and validation.


### Phase D baseline · D.1 console (2026-09-05, rev 2.26)

`cargo bench --bench response_pipeline --features console` and the default
feature run both match **all 31 existing rows** in
[`benchmarks/2026-09-05-claude-compliance.txt`](benchmarks/2026-09-05-claude-compliance.txt):
allocation counts and reported KB are unchanged, including both payload
sizes and every BEFORE/reference row. KB is rounded down by the existing
probe; this is not a claim of exact sub-KB byte equality or unchanged timing.
The feature-off run explicitly prints stage −1f as skipped.

**New stage −1f, Phase D baseline:** `console::ActivityPage::complete` with
1,000 `ActivityRow`s, rendered through askama: **432 KB / 9 allocations /
0.18 ms mean of 100 renders**, producing **231,639 bytes of HTML**.
The rows and page are built before the counter starts; the probe covers
HTML rendering, excluding report reads, JSON decoding, and fixture creation.
It does not allocate a separate formatted string per row. Preserve this
fixture when comparing future template changes.

Console-enabled JWT cache hit was 4.53 µs; cached actor-chain authentication
was 4.53 µs; journal append was p50 12 µs / p99 32 µs / max 279 µs.
The cache-hit (<50 µs) and journal p99 (<200 µs) budgets hold. Timings are
observations on this host, not a comparative speedup claim.

Full console probe output, dependency trees, release-size comparison and
landing-gate results are in
[`benchmarks/2026-09-05-d1-console.txt`](benchmarks/2026-09-05-d1-console.txt).


### Phase D baseline · D.4 packaging/air-gap (2026-09-06, rev 2.27)

Both `cargo bench --bench response_pipeline` and its `--features console`
run passed. All **31 earlier rows** match the D.1 summary's reported KB and
allocation counts exactly. Console stage −1f remains **432 KB / 9 allocations**
for 1,000 rows, 0.18 ms mean and 231,639 HTML bytes. No material regression;
integer KB reporting is not sub-KB equality or a timing-stability claim.
Default/console JWT cache hits: 4.06 / 3.77 µs; journal p99: 37 / 16 µs,
within the existing absolute budgets. No release or benchmark profile changes.
The opt-in file-JWKS I/O path is not measured by the remote cache probe (CF-41).
Full outputs, all landing gates and actual package/Compose/offline proof are
in [the D.4 summary](benchmarks/2026-09-06-d4-packaging.txt).


### Phase D baseline · D.3 policy authoring (2026-09-06, rev 2.28)

Every landing gate passed using bash scripts and isolated Cargo output:
both builds; default/no-default/console clippy with warnings denied; full
tests (1,108 default / 1,127 console, two existing ignored in each); formatting,
cargo-deny and diff checks. Both allocation probes match all 31 prior D.4
rows at reported KB/allocation precision, including reference rows and both
payload sizes. Stage −1f remains **432 KB / 9 allocations**, 0.21 ms mean,
231,639 HTML bytes for 1,000 activity rows. JWT cache-hit means are 3.84 /
4.18 µs; journal p99 is 49 / 18 µs (default / console), within the stated
budgets. Timings are observations, not an exact-latency-equality claim.
No allocation regression was found. Profiles and dependency graph are unchanged.

Raw outputs, final gate results, the clean-checkout TLS-fixture correction,
and exact local proof limits are in
[`benchmarks/2026-09-06-d3-authoring.txt`](benchmarks/2026-09-06-d3-authoring.txt).
CF-45 retains authoring/review/browser boundaries, CF-38 real-provider evidence;
no hosted CI or real-tenant proof is claimed. CF-40 stays backlog only, offline
licensing remains CF-10 and D.5 remains gated.

### Phase D baseline · D.0–D.4 closeout (2026-09-06, rev 2.29)

All CLAUDE.md landing gates passed through bash scripts: both builds;
default/no-default/console Clippy with warnings denied; full default and
console tests (**1,114 / 1,134 passed**, two existing ignored in each);
formatting, cargo-deny, and diff checks. The optional Node upload-helper
harness also passed. Both allocation probes match **all 31 earlier rows**
from D.3 at reported KB/allocation precision. Console stage −1f remains
**432 KB / 9 allocations**, 0.22 ms mean, 231,639 HTML bytes for 1,000 rows.
Default/console JWT cache-hit means are 4.38 / 4.22 µs; journal p99 is
40 / 28 µs, within the stated absolute budgets. No allocation regression
was found. Integer KB and variable timings do not imply exact sub-KB or
latency equality. Profiles and Cargo dependencies are unchanged.

[Fresh raw evidence](benchmarks/2026-09-06-phase-d-closeout.txt) and the
[closeout review](phase-d-closeout-review.md) describe the three reproduced
findings and fixes, including explicit completion and fail-closed incomplete
approval recovery. The probe excludes admin completion appends, proposal
history, login exchange and file-JWKS I/O. CF-38/41/45 remain open for their
stated evidence/operating limits; no real-browser, real-provider or hosted-CI
proof is claimed. Gate B remains unrecorded, CF-40 backlog only, offline
licensing blocked on CF-10, and D.5 gated.

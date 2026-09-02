# Enterprise carry-forward register

Everything M0 deliberately did **not** finish, in one place, so it survives a
branch, a review round, or a change of hands.

An item lands here when the work was scoped out on purpose — because the fix
belongs to a later phase, because it needs a decision we do not have, or
because folding it into the current change would have hidden it. An item is
removed only when it is done, not when it is explained.

Status legend: **open** · **blocked** (needs a decision) · **done**.

Last updated: 2026-09-02, after the independent review of the Phase A
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
**Open · Phase A/B**

`mcp-devtools jira post …` reaches the same vendor APIs as the MCP tools with
no journal record. M0 closes the hole by **refusing** operational CLI
subcommands whenever `MCP_AUDIT_JOURNAL_DIR` is set
(`bootstrap::refuse_unaudited_cli`). That is a fail-closed stopgap, not the
answer: the CLI should dispatch through the audited orchestration boundary
like any other caller.

### CF-8 · Per-record signing and checkpoints (B.6)
**Open · Phase B**

The journal is durable (`sync_data` per batch; the journal directory and
every ancestor it creates synced at startup) and tamper-*evident* by
contiguous sequence, but not tamper-*proof*. Signed checkpoints every N
records or T seconds are B.6.

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
- **Emergency deny.** Deleting the policy file keeps the last good policy
  in force, indefinitely (documented in `policy::engine`; health reports
  the degraded state). That is deliberate — a gateway must not fail open
  or turn into an outage because a file went missing — but it means there
  is no file-level "stop everything". Today's answer is to publish a
  document that denies (`rules: []`) or drain the pod. The deny-list and
  `revoke-all` (plan §3.6) are the real control and belong to Phase B.

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

## Decisions we owe someone

### CF-10 · ADR-002: the enterprise licence
**Blocked · counsel · hard M0 exit criterion**

Source-available / BSL / commercial, plus a CLA, must be decided **before any
external contribution lands**. It cannot be retrofitted.

Knock-on: `mcp-devtools-enterprise/deny.toml` carries
`private = { ignore = true }` so cargo-deny does not fail on the crate's own
unclassifiable all-rights-reserved `LICENSE`. Remove that line once the crate
carries a real SPDX `license` field.

### CF-11 · WP 0.2 and WP 0.3
**Open** — still unstarted from the M0 work-package list.

### CF-18 · Where the Okta validator and the file policy engine live (ADR-001)
**Blocked · owner + counsel (with CF-10) · before any external contribution**

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

### CF-12 · Expression digest strength
**Open · revisit when a policy needs it**

Search expressions (JQL, LogQL) are retained in `query_attributes` as
`sha256:<64 bits>/<length>` — a correlation handle, deliberately not a
commitment. If a policy or an investigation workflow ever needs to *prove*
which expression ran, that needs a full-width digest and a reviewed decision
about what else is stored alongside it.

---

## Allocation baseline (for the next phase's comparison)

Per `CLAUDE.md`'s per-phase allocation gate. Numbers from
`cargo bench --bench response_pipeline` at the **Phase A** boundary
(2026-09-02), with the M0 figure alongside where the stage existed then.
Gate result: no pre-existing stage moved; the new stages are additive and,
apart from canonicalization, run only on enterprise paths.

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

Notes for the Phase B comparison:

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

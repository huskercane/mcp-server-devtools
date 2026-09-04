# Enterprise carry-forward register

Everything M0 deliberately did **not** finish, in one place, so it survives a
branch, a review round, or a change of hands.

An item lands here when the work was scoped out on purpose — because the fix
belongs to a later phase, because it needs a decision we do not have, or
because folding it into the current change would have hidden it. An item is
removed only when it is done, not when it is explained.

Status legend: **open** · **blocked** (needs a decision) · **done**.

Last updated: 2026-09-04, after C.1b (OIDC provider profiles) landed on
`feat/phase-c-secret-sources` (plan §0 rev 2.14). Opened CF-31 (the
manually triggered Entra and Auth0 live jobs against developer tenants are
not built; those profiles are fixture-locked only). CF-18's reading now
covers `auth/oidc.rs` as it did `auth/okta.rs`. The allocation baseline
below gained the C.1b note.

Previously: 2026-09-04, after C.2a (secret references) landed on
`feat/phase-c-secret-sources` (plan §0 rev 2.13). Opened CF-28 (the
one-shot CLI refuses references rather than resolving them), CF-29
(`NINJAONE_SERVERS` nested credentials take no references), and CF-30 (the
reserved cloud schemes refuse by name until C.2b–d; the placement question
in plan §11 item 8 is still open). The allocation baseline below gained
the C.2a note.

Before that: 2026-09-03, after the independent review of the Phase B
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
**Open · Phase A/B**

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

### CF-30 · No `secrets-*` Cargo features exist yet, and the reserved schemes refuse by name
**Open · Phase C (C.2b–d)**

`vault://`, `awssm://`, and `azkv://` parse today and fail startup with
`no adapter for `vault://` is compiled into this binary`, which is the
typed error §3.8 asks for. The `secrets-vault` / `secrets-aws` /
`secrets-azure` features, the adapters behind them, and the `SecretResolver`
registration in `bootstrap/` are C.2b–d. §11 item 8 (whether those adapters
live here under features or in the enterprise crate) is still to decide
before C.2b starts; C.2a itself — port, `file://`, snapshot, refresher —
is in the community crate under the CF-18 reading, and is not a tier
differentiator.

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

### CF-18 · Where the OIDC validator and the file policy engine live (ADR-001)
**Deferred · decided 2026-09-03: option 2 in practice while the repository is private · revisit at open-sourcing, with CF-10**

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

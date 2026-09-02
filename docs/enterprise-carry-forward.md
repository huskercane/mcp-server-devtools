# Enterprise carry-forward register

Everything M0 deliberately did **not** finish, in one place, so it survives a
branch, a review round, or a change of hands.

An item lands here when the work was scoped out on purpose — because the fix
belongs to a later phase, because it needs a decision we do not have, or
because folding it into the current change would have hidden it. An item is
removed only when it is done, not when it is explained.

Status legend: **open** · **blocked** (needs a decision) · **done**.

Last updated: 2026-09-02, after a sixth review pass (journal backpressure
timing, fsync-after-truncate fixed directly — see CF-14 and the journal
durability fix in the same commit).

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
**Open · Phase A · blocks the §3.2 freeze**

Jira search emits `resource_type: issue` with a scope built from *project*
keys. That is coherent for a human reading it, but a generic policy engine
has no way to know which permission namespace the ids belong to — it can
look project keys up in an issue-id allowlist and reach a confident wrong
answer, or collide an issue-rule id with a project identifier.

*The fix*: model the constraint as its own dimension —
`resource_type: issue, constrained_by: project[PLAT, WEB]` — rather than
leaving the reader to infer it.

`docs/read-endpoint-inventory.md` decision 3 records the current
representation as **provisional for this reason**. §3.2 must not be declared
frozen until this lands.

### CF-3 · Exact-pin the five range dependencies
**Open · M0 baseline compliance · own reviewed commit**

`CLAUDE.md` says dependencies are exact-pinned (`=x.y.z`). Five are not:

| Dependency | `Cargo.toml` |
|---|---|
| `atomicwrites` | `"0.4.4"` |
| `rpassword` | `"7"` |
| `httpdate` | `"1"` |
| `zstd` | `"0.13"` |
| `keyring` | `"4.1.6"` (three target-gated rows) |

This is not cosmetic: the community lock holds `keyring 4.1.6` while the
enterprise lock resolved **`keyring 4.2.0`**, so the two repositories build
different code from the same source. Guiding constraint 7 ("baseline stays
pinned") is not currently true.

*The fix*: pin all five with `=`, update both lockfiles deliberately, in one
commit that does nothing else.

---

## Deferred by phase

### CF-4 · Wire extractors into the dispatch path
**Open · Phase A**

`policy::extractors` is exercised by tests and the allocation bench, but
`call_tool` does not build an `ActionContext` from it yet. Until it does, the
Grafana UID validation that protects dispatch lives in
`controllers::grafana`, not in policy.

### CF-5 · Full §3.5 request canonicalization (A.6)
**Open · Phase A · must land before extractors gate production traffic**

`extractors::normalize_path` does the tool-level minimum: leading slash,
trailing-slash trim, duplicate-slash collapse. Percent-decoding, dot-segment
resolution, and fuzzing are A.6. An extractor claiming a scope from a path
that has not been fully canonicalized is only as sound as the canonicalizer
in front of it.

### CF-6 · Validated `Principal` from token claims
**Open · Phase A**

Every audit event currently carries `Principal::local()`. Phase A replaces it
with the validated principal from `context.extensions`
(`docs/spikes/rmcp-extensions.md`).

Sub-point from a review pass: today both transports refuse `AuthMode::Okta`
outright (`src/server/stdio.rs`, `src/server/http.rs:489`), so there is no
live path where a client is told "healthy" while the journal it needs is
unwritable — `/health` always answers before any Okta-gated call could exist.
Once this item lands and `/health` on the HTTP transport can mean something
under real auth, `health()` (`src/server/http.rs:285`) should reflect journal
availability rather than always returning 200; do it as part of this item,
not before Okta is real.

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
**Open · Phase A/B · needs a design decision, not a one-line fix**

`AuditSink::append` (`src/audit/journal.rs:257-280`) has no timeout on either
the bounded-channel `send().await` or the ack `acked.await`. A sustained
stall on the underlying disk (the module's own doc already calls
`sync_data` "unbounded in practice" — full disk, page reclaim, FUSE, network
storage) parks every in-flight `tools/call` on that wait instead of
returning `AUDIT_UNAVAILABLE_MESSAGE`; the caller sees whatever the
transport's own timeout produces instead of a clean fail-closed refusal.

Not a quick fix: a naive `tokio::time::timeout` around `send().await` is
safe (nothing was enqueued, refuse cleanly), but the same wrapper around
`acked.await` is not — the record can already be queued and later written by
the dedicated writer thread after the caller has been told the call was
refused. That is still fail-closed (the vendor is never called), but it
changes what "the journal has a record for a refused call" means and needs
to be a reviewed decision, not an incidental one, given the module's stated
RPO = 0 / no-degraded-mode invariant.

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
`cargo bench --bench response_pipeline` at the M0 boundary.

| Stage | Bytes | Allocations |
|---|---|---|
| −1 `jira::extract` GET `/issue/{key}` | <1 KB | 6 |
| −1 `jira::extract` GET `/search/jql` (long JQL) | 1 KB | 17 |
| −1 `jira::project_keys_from_jql` (long JQL) | <1 KB | 9 |
| −1 `jira::extract` unmapped (default arm) | <1 KB | 1 |
| −1 `grafana::query_logs` | <1 KB | 11 |
| 0 `ConfigHandle::snapshot()` | 0 | 0 |
| 1 `apply_jq_filter(None)` | 0 | 0 |
| 2 `render(Toon)` @ 500 issues | 1736 KB | 19 032 |
| 3 `truncate_for_ai` | 39 KB | 4 |
| 2 `render(Toon)` @ 5000 issues | 16 547 KB | 190 035 |

Stage −1 is new in M0 (the policy extractors); stages 0–3 are unchanged from
the previous boundary, and the M0 work does not touch that code.

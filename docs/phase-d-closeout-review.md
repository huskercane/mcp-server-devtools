# Phase D closeout review — September 6, 2026

Reviewed D.0–D.4 on `feat/phase-d-administration`, starting at `1d0b21c`
(`07afa7c` plus the independently committed authorization-extension/security
documentation). The initial index and working tree were clean. That documentation
is preserved; no authorization-extension implementation, dependency, shipping
feature selection, release/benchmark profile change, or PR is included.

## Confirmed findings and fixes

1. **Concurrent approval could apply twice.** The decision mutex protected the
   approval append but ended before the API applied the candidate. A second
   `approve` saw `approved` without `applied_seq` and received another candidate.
   `approval_does_not_hand_out_a_second_application_before_completion` failed on
   the original implementation: both concurrent port calls succeeded. Approved
   but incomplete proposals now return `409 proposal_incomplete`; only the first
   decision receives a candidate. Completed approvals retain idempotent success.
   The HTTP regression checks one mutation and completion, including after restart.
2. **Restart confused intent with completion and could match the wrong proposal.**
   Replay matched an `admin_mutation` to the first approved entry with the same
   operation/version. Version labels are not unique, and that record precedes
   file writes. The regression reproduced `applied_seq = 3` for an intent without
   an effect. Completion now requires an `admin_application` record after the
   effect, carrying proposal ID, digest, operation, version, and original intent
   sequence. Same-version proposals cannot borrow each other's completion.
   Interrupted/failed application and legacy approvals without completion remain
   incomplete; automatic reapplication is refused. Decision append uncertainty
   also blocks another in-process decision until restart resolves the journal.
   This recovery tradeoff is substantive decision-log revision **2.29**.
3. **The token-response limit did not bound chunked accumulation.** The console
   checked Content-Length and checked the body after `response.bytes()` finished.
   A real loopback chunked response sent 65,537 bytes and withheld EOF; the
   regression timed out instead of refusing at 64 KiB. The reader now checks each
   chunk before extending the buffer. The initial sandbox socket refusal was
   not counted as reproduction; the loopback-enabled run reproduced the defect.

No exactly-once transaction across the audit journal and signed file pair is
claimed. A successful effect followed by a failed completion append is uncertain
and requires reconciliation. A crash between signature and document replacement
can leave a mismatched pair that refuses startup. The admin and console runbooks
now describe polling, evidence preservation, signed-state reconciliation,
known-good pair restoration, and a new independently reviewed proposal if needed.
The projection reads the locally protected journal. Journal startup checks JSON
and sequence continuity and reconstructs the chain; it does not cryptographically
validate old checkpoints. Candidate digest checks are not authentication of an
arbitrarily rewritten journal. Offline verification with retained public keys and
external checkpoint anchors remains required when reconciling or restoring state.

Older completed approvals have no explicit completion record: after upgrade they
also require reconciliation, rather than inferring completion from old intents.

## Review coverage

| Area | Implementation and evidence checked | Remaining boundary |
|---|---|---|
| D.0 composition | HTTP AdminClient refuses redirects and invalid remote bases; LocalAdminClient invokes the authenticated router. Both carry signed JSON strings unchanged and run the shared conformance suite. Bootstrap selects Direct/ApprovalGate; admin install verifies before gate admission. | Alternate custom port implementations are responsible for their contracts. |
| D.2 decisions | Tenant-scoped lookup, different-subject approval, fresh issue-time requirement at API, pending expiry, digest recheck, signature re-verification at install. Approval/rejection/expiry append before effects; audit failure refuses application. New port and HTTP regressions cover concurrent handoff, incomplete restart, failed appends, completed restart/idempotency, same-version isolation and actual file-replacement failure after intent. | Single control process; no multi-writer protocol. No automatic retry of an uncertain effect. Expiry is observed on decision, not swept; rejection permits proposer withdrawal. |
| D.3 authoring | Preview/download/upload/decisions use AdminClient. Download validates and returns submitted bytes. JSON-escaped file uploads preserve UTF-8 BOM, CRLF, non-ASCII and trailing newline bytes; malformed UTF-8 is refused by helper. Existing HTTP tests sign the downloaded bytes and exercise direct/required installation and byte-different signature refusal. | Native form newline normalization makes the downloaded candidate authoritative signing input. Structural diff, offline candidate handoff, no optimistic base-version precondition, and input bounds remain CF-45. |
| D.1 console | PKCE S256, one-use cookie-bound state, callback issuer check, bounded server-side sessions, Secure/HttpOnly/Strict session cookie, redirect refusal, authenticated per-operation API calls. CSP, Origin/Fetch-Metadata CSRF guard, no-store/nosniff/frame/referrer headers, escaped askama output and textContent error rendering checked. Token-response streaming limit fixed. | Login's API 503 allowance is not identity-validation proof; subsequent operations still enforce bearer validation. No ID-token/nonce validation claim. Session TTL and provider UX limits remain CF-37/38. |
| Request bounds | Admin body reader caps encoded JSON at 1,000,000 bytes and admits four concurrent operations; console form extractors cap encoded forms at 2 MiB. File helper caps policy at 256 KiB and signature at 1 KiB. Token response capped at 64 KiB while streaming. | Limits apply to different representations; escaping can hit an encoded bound first. Proposal history/candidate retention and offline-file JWKS load are not measured by the allocation probe. |
| D.4 packaging | Reviewed systemd/package scripts, file-JWKS fail-closed reads, and prior recorded local package/Compose/offline proof. Existing file-JWKS tests run with the full suites. | No new package installation, Compose, offline build, hosted CI or release publication exercised in this closeout. Prior evidence remains historical, with CF-41's portability and operating limits explicit. |

Standard mutex guards do not cross awaits in the reviewed decision/session paths.
The async decision mutex deliberately spans durable appends; policy/deny-list
mutation locks span verification, intent and file installation to exclude watcher
interleaving. Those control-plane locks and blocking-worker copies are correctness
costs, not changes to the tool request pipeline. Completion snapshots proposal
metadata rather than cloning its full candidate. No speculative optimization was
introduced; CF-40 stays backlog only.

## Validation and exit status

All landing gates passed: both builds, all three Clippy modes, **1,114 default /
1,134 console tests passed** (two existing ignored in each), formatting,
cargo-deny and diff checks. Both probes match all 31 earlier D.3 allocation
rows; console rendering remains **432 KB / 9 allocations** for 1,000 rows.
The optional Node helper check also passed.

Fresh landing-gate and both-feature allocation evidence is recorded in
[the closeout evidence](benchmarks/2026-09-06-phase-d-closeout.txt), compared with
[the D.3 baseline](benchmarks/2026-09-06-d3-authoring.txt). The existing real HTTP
console test verifies the new completion records with the signed offline verifier.
The optional Node harness is a minimal DOM test, not a real browser test.

The D.0–D.4 exit checklist now names the recorded exclusions (CF-36/37/38/41/45)
and separates the still-gated D.5 exit. CF-39's interactive controls stay complete;
CF-45 remains open for browser/review evidence and recovery limitations. No
real-provider tenant, real browser, power-loss campaign, hosted CI, or hosted
release proof is claimed. CF-38 and CF-41 remain open. **Gate B is not satisfied**:
its partner trials, commercial and security evidence remain unrecorded. Offline
licensing is still blocked on CF-10; D.5 stays behind §11 item 4.

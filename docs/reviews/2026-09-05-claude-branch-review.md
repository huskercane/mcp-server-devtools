> Archived original review, written on 2026-09-05 against commit `66f5de1`.
> Findings, line references, and validation results below describe that pre-fix
> snapshot. See the [follow-up](../claude-compliance-review.md) for corrections.

# CLAUDE.md compliance review

Branch: `feat/phase-c-operations`, HEAD `66f5de1`. Compared with local `main`, with targeted inspection of the current tree. No repository files were changed. The pre-existing working-tree deletion of `.codex` was left alone.

**Assessment: moderate compliance debt, with one high-priority correctness blocker.** Toolchain and basic checks are in good shape. A numerical percentage would be misleading: the rules mix hard gates, architectural requirements, and performance recommendations, and this was a targeted review rather than an exhaustive audit of every function.

## Findings

1. **High — admin deny-list reads deadlock (new on this branch).** `src/server/admin.rs:295` acquires `list.mutation`, then line 296 attempts to acquire the same non-reentrant Tokio mutex while the first guard is still alive. Shadowing does not release that guard before the second acquisition. A configured `GET /admin/deny-list` hangs and prevents deny-list mutations. Each detached handler retains an admin semaphore permit (`src/server/admin.rs:115`); four such requests can exhaust the four-permit admin budget. This violates correctness and lock-scope requirements. Remove the duplicate acquisition and add an HTTP regression test with a timeout. Existing tests exercise replacement and CLI parsing, but do not exercise a successful GET. This finding is established by code inspection; the existing suite passing does not cover it.

2. **Medium — required CI gates are missing (inherited).** `.github/workflows/rust.yml:66` runs Clippy and tests, but no workflow runs `cargo fmt --all -- --check` or `cargo deny check`. `CLAUDE.md:20` lists formatting and dependency auditing as CI gates. `deny.toml:3` even says the audit is not wired into CI. Add the two checks so the documented requirement is enforced.

3. **Medium — synchronous filesystem I/O on a Tokio worker (inherited, retained in modified code).** `src/bootstrap/watcher.rs:90` calls `reloadable`, which calls the synchronous global-config reader; line 98 loads the configuration synchronously again. `src/config/global.rs:37` uses `std::fs::read`. The earlier `tokio::fs::read` does not make those subsequent reads asynchronous. Parse/reuse the bytes already read, or offload validation and config loading together with `spawn_blocking`.

4. **Medium — activity ingestion holds a broad database lock (new).** `src/audit/activity_sqlite.rs:82` locks the shared SQLite connection before reading and transforming up to 1,000 journal records. File reads, JSON parsing/serialization, and inserts all happen under the lock; report queries use the same connection mutex at line 120. This conflicts with the short-critical-section guidance. Read and prepare a bounded batch before taking the connection lock, then perform the transaction. The code already runs on `spawn_blocking`, so this is contention debt, not a standard mutex crossing an await. No latency regression was measured in this review.

5. **Medium — ports and orchestration are not consistently separated.** New admin orchestration directly uses concrete `FilePolicy` staging/commit operations (`src/server/admin.rs:203`, `:227`, `:240`) rather than a policy-administration port. Existing `src/ports/credential_broker.rs:110` also contains the concrete configuration/keychain adapter. This falls short of CLAUDE.md's rigorous hexagonal separation requirement. Move concrete adapters out of ports and place policy administration behind an explicit boundary, or document a qualifying performance/correctness tradeoff. This is architectural debt, not evidence that those operations produce incorrect results.

6. **Low — the literal zero-warning requirement is not met.** `cargo deny check --disable-fetch` exits successfully, but emits 17 duplicate-dependency warning groups. `deny.toml:38` intentionally configures multiple versions as warnings. Resolve dependency duplication where practical, or explicitly reconcile the documented zero-warning rule with the intended audit policy. This is not a failed license/advisory gate or proof of a vulnerability.

## What complies and what was verified

- Rust 1.96.0, edition 2024, rust-version 1.96, exact dependency pins, and the crate-derived VERSION constant match the instructions.
- Default build: passed.
- No-default-features build: passed.
- Strict all-target Clippy: passed.
- Formatting check: passed.
- Full local test suite: passed, 1,077 tests passed and two ignored across unit/integration/doc-test summaries. Environment-gated live tests can also return early without a live service; this is not a claim of live-provider certification.
- Dependency audit against the local cached database: configured checks passed, with the 17 warning groups above. Advisory freshness was not revalidated because fetching was disabled.
- No production unsafe blocks or unsafe-code opt-outs were found in the source search.
- Allocation baselines and successive phase comparisons are recorded in `docs/enterprise-carry-forward.md:948` and `:1020` onward. The fan-out clone cost is explicitly measured and documented, so it should not be treated as an unexplained regression. The allocation benchmark was not rerun for this review.
- Tool description files and `tests/golden/tool_surface.json` are unchanged relative to local main. Local parity tests pass; the external TS references were not independently re-audited.

Fix the deny-list deadlock first, then enforce the missing CI gates and remove watcher blocking I/O. Architectural and lock-scope cleanup can follow in focused changes.

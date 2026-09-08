# Edition extraction validation — September 8, 2026

The owner accepted the [edition boundary](edition-boundary-proposal.md) and CF-40
build work. Community keeps its Apache-2.0 secure gateway, existing admin API/CLI
and operations. Approval implementation, proposal endpoints/CLI and the console
now live in the sibling `mcp-devtools-enterprise` repository. Shared ports and
signed mutation application remain in Community.

## Implementation

- `GateFactory` supplies the approval adapter with the actual configured audit
  sink. `HttpEdition` selects startup adapters; `AdminExtension` executes behind
  the existing authentication, limiter, body/task budgets and durable task scope.
- Community refuses `MCP_ADMIN_APPROVALS=required` and console activation; it
  never silently falls back to direct approval behavior. Proposal routes are
  absent there, while other admin routes remain authenticated and usable.
- Enterprise has its own executable, CLI composition, optional console,
  default/headless feature matrix, CI, container and DEB/RPM/archive preparation.
  Defaults activate the core default feature flag as well as its capabilities;
  headless builds still disable all core defaults.
- Both manifests preserve release opt-level 3, thin LTO, one codegen unit and
  symbol stripping. The new `dev-fast` profile, matching dependency pins and CI
  caches are described in [build performance](build-performance.md).
- Docker cache use is content-checked per crate so COPY's preserved timestamps
  cannot make changed source look fresh to Cargo. Failed builds do not certify
  new content; unchanged dependencies remain cached. A focused Python regression
  test covers backdated source/templates, unchanged content, and failed retries.

## Recorded local checks

| Check | Result |
|---|---|
| Community default build, all-target Clippy and tests | Passed; 1,113 tests passed, two existing ignores |
| Community headless build and all-target Clippy | Passed |
| Community dependency audit | Advisories, bans, licenses and sources passed |
| Enterprise default build, all-target Clippy and tests | Passed; 43 tests |
| Enterprise headless build, all-target Clippy and tests | Passed; 21 tests |
| Enterprise headless console all-target Clippy | Passed |
| Enterprise dependency audit | Advisories, bans, licenses and sources passed |
| Enterprise upload helper | Passed (exact signed bytes and malformed/oversized inputs) |
| Docker source-cache regression | Passed |
| Enterprise dev-fast headless build | Passed |
| Community dependency direction | No Enterprise, askama or rust-embed packages in its resolved graph |
| Workflow YAML, shell syntax, package source paths, diff checks | Passed |

The shared allocation probe's **31 rows match** the September 6 closeout.
The console probe reports **444 KB / 8 allocations**, with **233,723 HTML bytes**
for 1,000 rows. A fresh run of the exact pre-extraction `9d6b54c` snapshot produces
those same numbers. The older 432 KB / 9 allocations / 231,639-byte log is stale
relative to the starting source; this is not an extraction regression. All moved
console assets/templates are byte-identical to that starting source.

The build-profile samples and their limitations are recorded in
[the timing evidence](benchmarks/2026-09-08-build-profiles.txt). In particular,
the incremental edit was comment-only and the initial clean release sample
shared the host with an early check; no hosted CI speed claim is made.

## Shipping artifacts

The final source-cache-checked static image built successfully. Isolated
`--network none --read-only` version/help checks passed; the extracted x86-64
binary is static PIE and stripped. DEB and RPM generation passed. DEB contents,
RPM paths and RPM header/payload digests were checked; both contain the expected
binary, systemd service, Community license and extraction provenance. The RPM
has an explicit package license label because Cargo uses `license-file`.
The archive and SHA256 manifest were also generated. Nothing was installed on
the host. RPM/DEB installation and upgrades on supported distributions are still
external deployment evidence, not implied by package inspection.

Local image: `mcp-devtools-enterprise:edition-review`, ID
`sha256:85e867b09a08e77fcb27aff13afb14cc7e25955aa305b2886f63667b8c17f519`.
Review artifacts are in `/tmp/enterprise-edition-artifacts/` on this host.

[Edition gate evidence](benchmarks/2026-09-08-edition-extraction.txt) and
[artifact checks](benchmarks/2026-09-08-enterprise-artifacts.txt) retain the
commands/results. The image proves the shipping Rust sources and profile;
subsequent packaging-only metadata fixes do not change that binary.

## Publication and external evidence

No push, public release, history rewrite, host package installation or external
message was performed. Git history still contains the extracted implementations
in `9d6b54cd417e9198f2dc9999893997b8d6f54cda` (Phase D, PR #17). Opening the
existing Community history would expose them. Publication needs a reviewed
history/export decision and a prior-distribution/ownership review; previous
permissions are preserved. Enterprise carries a hashed extraction inventory and
Community/third-party notices; commercial agreement/contribution terms remain
CF-10.

Hosted Enterprise checks require a full companion Community commit in
`COMMUNITY_REF` (or the manual input) and `COMMUNITY_READ_TOKEN` while Community
is private. The baseline revision file is provenance, not a claim that the old
commit already exposes the new interfaces. Both local checkouts must land before
configuring that hosted revision. No hosted CI, release signing, real-browser,
real-provider, partner-trial or Gate B acceptance is claimed. CF-31/34/35/38/41/42/45
retain their applicable external evidence requirements; D.5 remains demand-gated.

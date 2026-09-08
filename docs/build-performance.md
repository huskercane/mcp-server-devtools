# Build performance and validation

CF-40, September 8, 2026. Both editions keep shipping release settings unchanged:
opt-level 3, thin LTO, one codegen unit, stripped symbols.

| Command | Use |
|---|---|
| `cargo check --locked` | Fast type checking; no executable linking. |
| `cargo build --locked` | Ordinary debug development and test iteration. |
| `cargo build --locked --profile dev-fast` | Optimized local runs: opt-level 2, no LTO, 16 codegen units, incremental compilation, line tables. Never package this output. |
| `cargo bench --locked --bench response_pipeline` | Allocation/performance comparisons at the existing bench settings: opt-level 3, no LTO, 16 codegen units. |
| `cargo build --locked --release` | Shipping artifacts and binary-size comparisons only. |

Use the same features for before/after comparisons. Community has no `console`
feature; console validation and its allocation probe now run in Enterprise.
The Enterprise default includes `console`; headless-with-console uses
`--no-default-features --features console,wrds,secrets-vault`.

For sequential development across sibling repositories, optionally set
`CARGO_TARGET_DIR` to an absolute shared build directory. Cargo fingerprints keep
incompatible features and profiles separate; only matching dependency artifacts
are reused. Do not run both builds concurrently against that directory: Cargo
will serialize them on its build lock. The Enterprise lockfile is seeded from
the Community baseline to avoid unrelated transitive dependency upgrades. Its
default feature also activates the Community `default` flag: matching enabled
functionality without that flag still produces a different Cargo fingerprint.
`--no-default-features` continues to disable all Community defaults.

CI caches registry/git downloads and target artifacts by OS, architecture,
job, toolchain and lockfile, with a commit-specific save key. Within a job,
default build/Clippy/tests run together before headless checks, preserving
feature/dependency reuse. All prior checks remain, and headless Clippy is explicit.
Hosted cache hit rates and wall times require an actual hosted run.

## Measurement protocol

Use an immutable source snapshot, a dedicated target directory and identical
features (`--no-default-features` for the first comparison). Record host/toolchain,
cache state, elapsed wall time and peak RSS. A clean profile means no artifacts
for that profile, with the registry already populated; it is not a network or
cold filesystem-cache benchmark. Record no-op builds and a controlled source edit
separately. Do not compare the pre-extraction gateway with the extracted gateway
to attribute all improvement to the build profile.

The September 8 comparison uses the pre-extraction Community baseline, including
its same headless feature graph, for both profiles. Release and dev-fast source
edits append a comment to the same library file to force a crate rebuild without
changing behavior. Results and limitations are recorded in the extraction
validation record. Profile settings alone are not proof of a speedup.

Run both editions' landing checks with `bash scripts/ci/check-editions.sh`
from Community (optional first argument: Enterprise checkout path). It uses a
shared target directory and stops at the first failure; no required check is
skipped to make the reported runtime shorter.

## September 8 measurements

| Build (same snapshot/features) | Release | dev-fast |
|---|---:|---:|
| Clean profile, populated registry | 367.55 s | 220.78 s |
| No-op build | 0.31 s | 0.30 s |
| Comment-only library edit | 232.17 s | 5.99 s |

[Raw evidence and cache conditions](benchmarks/2026-09-08-build-profiles.txt).
The comment-only result reflects incremental reuse; substantial code edits may
rebuild more. The initial release clean sample overlapped an early `cargo check`,
so its clean-build comparison is exploratory. Subsequent source-edit/dev-fast
samples were sequential without competing agent compilation. These single local
samples are not CI guarantees. Clean dev-fast peak RSS was 2,306,232 KiB versus
1,861,068 KiB for release; faster compilation does not imply lower peak memory.

The resolved Linux feature graphs differ only in `winnow`'s `simd` feature
among shared packages when Enterprise enables the console. Template dependencies
can therefore still invalidate some shared artifacts; aligning default flags
does not promise that every core build is reusable across all feature sets.

## Container cache correctness

Enterprise uses persistent registry and target caches with `sharing=locked`.
A rebuild exposed Cargo's mtime assumption: Docker COPY can restore changed
source files older than a previous compilation, and Cargo can incorrectly report
them fresh. `scripts/release/with-source-cache.sh` hashes each crate's source,
manifest, toolchain and console assets before using the cache, touches that
crate's entry points when content differs, and commits fingerprints only after
a successful build. Unchanged dependencies remain cached. The regression check
backdates changed source and template files and verifies failure/retry behavior.

The first guarded build intentionally distrusts pre-existing target artifacts;
subsequent matching-content builds reuse them. This is a correctness condition,
not a reason to remove shipping release optimizations.

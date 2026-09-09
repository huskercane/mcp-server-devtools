# Repository instructions

Read [CLAUDE.md](CLAUDE.md) for the project conventions, pinned toolchain,
architecture requirements, and validation gates. Follow the worktree guidance
below for local Cargo commands.

## Worktrees and build disk usage

Before running Cargo locally, use one shared target directory for this repository's
worktrees. Run this setup in each shell (or include it in each build command's shell):

```bash
export CARGO_TARGET_DIR="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")/target"
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_INCREMENTAL=0
```

- The target path resolves to the main checkout's `target/` from any linked
  worktree. Do not create a separate target directory per worktree by default.
  If the user supplies a target directory, respect it and use the same absolute
  path across worktrees. Request sandbox access if needed to build there.
- These local settings disable debug information and incremental caches to
  reduce disk usage. Debugging has less detail and incremental rebuilds may be
  slower. Override deliberately when debugging; keep release and benchmark
  profiles unchanged. The custom `dev-fast` profile has its own settings and
  is not covered by the DEV/TEST debug overrides.
- Shared Cargo builds serialize on the target-directory lock. Run build, test,
  and Clippy commands sequentially; coordinate with other worktree users before
  cleaning or executing a shared binary that another build could replace.
- Prefer `cargo check --locked` for intermediate compilation checks. Run the
  required CI gates for code changes, but do not rebuild for documentation-only
  edits or rerun passing checks without a relevant change.
- Check available disk space before a full rebuild. Old dependency versions,
  feature combinations, and integration-test binaries can accumulate even in
  a shared target directory.
- To reclaim all generated build artifacts after builds/tests have stopped:

  ```bash
  cargo clean --target-dir "$CARGO_TARGET_DIR"
  ```

  This also removes release and benchmark binaries from that target directory;
  the next build starts cold. It preserves source files, `Cargo.lock`, and the
  downloaded Cargo registry cache. Clean only the intended build directory;
  do not delete worktrees, configuration, or fuzz corpora as build cleanup.


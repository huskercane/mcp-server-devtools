#!/usr/bin/env bash
# Run the shared and proprietary gates sequentially to reuse Cargo artifacts.
set -euo pipefail
community_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
enterprise_root=${1:-"$community_root/../mcp-devtools-enterprise"}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$community_root/target"}
cd "$community_root"
cargo fmt --all -- --check
cargo build --locked
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --no-default-features
cargo clippy --locked --no-default-features --all-targets -- -D warnings
cargo deny --locked check --deny warnings
cargo bench --locked --bench response_pipeline
cd "$enterprise_root"
cargo fmt --all -- --check
cargo build --locked
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --no-default-features
cargo clippy --locked --no-default-features --all-targets -- -D warnings
cargo test --locked --no-default-features
cargo clippy --locked --no-default-features --features console --all-targets -- -D warnings
cargo deny --locked check --deny warnings
node tests/console_upload_script_test.cjs
python3 tests/build_cache_test.py
cargo bench --locked --bench response_pipeline

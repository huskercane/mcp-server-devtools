#!/usr/bin/env bash
# An empty Cargo home proves the archive supplies dependencies, not the host cache.
set -euo pipefail
archive="$(cd "${1:?archive directory required}" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
(cd "$archive" && sha256sum -c mcp-devtools-vendor.tar.gz.sha256)
tar -xzf "$archive/mcp-devtools-vendor.tar.gz" -C "$work"
mkdir -p "$work/cargo-home"
cd "$work/mcp-devtools-source"
CARGO_HOME="$work/cargo-home" CARGO_TARGET_DIR="$work/target" CARGO_NET_OFFLINE=true \
  cargo build --frozen --offline --no-default-features --features wrds,secrets-vault
"$work/target/debug/mcp-devtools" --version

#!/usr/bin/env bash
# Input must be the static musl binary extracted from the release Dockerfile.
set -euo pipefail
binary="${1:?static binary required}"
output="${2:?output directory required}"
mkdir -p target/release "$output"
file "$binary" | grep -Eq 'static[ -]pie linked|statically linked'
cp "$binary" target/release/mcp-devtools
cargo deb --no-build --no-strip --output "$output/mcp-devtools.deb"
cargo generate-rpm --output "$output/mcp-devtools.rpm"
(cd "$output" && sha256sum mcp-devtools.deb mcp-devtools.rpm > packages.sha256)

#!/usr/bin/env bash
set -euo pipefail
output="${1:?output directory required}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
case "$output/" in
  "$(git rev-parse --show-toplevel)/"*) echo "archive output must be outside the source tree" >&2; exit 1 ;;
esac
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
source_dir="$work/mcp-devtools-source"
mkdir -p "$source_dir/.cargo"
# Includes new source files during local validation; release runs on a clean checkout.
git ls-files --cached --others --exclude-standard -z | tar --null -T - -cf - | tar -xf - -C "$source_dir"
(cd "$source_dir" && cargo vendor --locked vendor > .cargo/config.toml)
tar -C "$work" -czf "$output/mcp-devtools-vendor.tar.gz" mcp-devtools-source
(cd "$output" && sha256sum mcp-devtools-vendor.tar.gz > mcp-devtools-vendor.tar.gz.sha256)

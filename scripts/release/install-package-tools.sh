#!/usr/bin/env bash
set -euo pipefail
root="${1:?installation root required}"
mkdir -p "$root/src"
root="$(cd "$root" && pwd)"
while read -r name version checksum; do
  archive="$root/src/$name-$version.crate"
  curl --fail --silent --show-error --location "https://static.crates.io/crates/$name/$name-$version.crate" -o "$archive"
  printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check
  tar -xf "$archive" -C "$root/src"
  cargo install --locked --path "$root/src/$name-$version" --root "$root"
done <<'PINS'
cargo-deb 3.7.0 a40a401a79fd1bd9d2cb41fd783d0c80f3504f657002bfae49dfd55049dce8f8
cargo-generate-rpm 0.21.0 3187e19f0e00274b3b24f017559038722388889bd1a2ecd2281cd748e7d52ec6
PINS

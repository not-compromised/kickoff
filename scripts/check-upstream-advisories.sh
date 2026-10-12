#!/usr/bin/env bash
# cargo deny excludes path sources from RustSec and registry yanked checks.
# Audit the same pinned vendor versions as registry roots as well.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp Cargo.lock "$work/Cargo.lock"
python3 scripts/advisory-exceptions.py --output "$work/deny.toml"
mkdir "$work/src"
touch "$work/src/lib.rs"
cat > "$work/Cargo.toml" <<'MANIFEST'
[package]
name = "kickoff-vendor-advisory-check"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
MANIFEST
while IFS=$'\t' read -r crate version archive_hash patch_hash; do
    [[ "$crate" == \#* ]] && continue
    printf '%s = { version = "=%s", default-features = false }\n' "$crate" "$version" >> "$work/Cargo.toml"
done < vendor/crates.tsv
# A fresh runner has not necessarily queried the index for patched crates.
cargo metadata --manifest-path "$work/Cargo.toml" --format-version 1 > /dev/null
cargo deny --manifest-path "$work/Cargo.toml" check advisories --hide-inclusion-graph

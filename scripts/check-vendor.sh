#!/usr/bin/env bash
# The vendored iroh is upstream iroh 1.3.0 plus exactly one patch (design §3.4).
# Rebuilds that tree from the crates.io archive and vendor/iroh-1.3.0.patch,
# both pinned by SHA-256, and fails on any difference from vendor/iroh-1.3.0.
# Uses Cargo's registry cache when it holds the archive; otherwise downloads it.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

crate=iroh
version=1.3.0
# The crates.io checksum Cargo.lock recorded for iroh 1.3.0 before vendoring.
crate_sha256=885787b892b5e2507c701f132ecbd45d2bad4bbb75157a19427087c16dadb833
# The reviewed patch. Changing it means changing this pin in the same review.
patch_sha256=ac21e8abb0110a4a94147e06e92a0f9b34a3009fb29f5e494abb1b602912b0d3

vendored="vendor/$crate-$version"
patch_file="vendor/$crate-$version.patch"

fail() { echo "check-vendor: $*" >&2; exit 1; }

sha256() { sha256sum "$1" | cut -d' ' -f1; }

[ "$(sha256 "$patch_file")" = "$patch_sha256" ] ||
    fail "$patch_file is not the reviewed patch (SHA-256 mismatch)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

archive="$work/$crate-$version.crate"
cached=$(find "${CARGO_HOME:-$HOME/.cargo}/registry/cache" -name "$crate-$version.crate" \
    -path '*index.crates.io-*' 2>/dev/null | head -n 1 || true)
if [ -n "$cached" ]; then
    cp "$cached" "$archive"
else
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --output "$archive" "https://static.crates.io/crates/$crate/$crate-$version.crate"
fi
[ "$(sha256 "$archive")" = "$crate_sha256" ] ||
    fail "the $crate $version archive does not match the crates.io checksum"

tar -xzf "$archive" -C "$work"
expected="$work/$crate-$version"
patch --quiet --batch --forward -p1 -d "$expected" < "$patch_file" ||
    fail "the patch does not apply cleanly to upstream $crate $version"

if ! diff -r "$expected" "$vendored"; then
    fail "$vendored differs from upstream $crate $version plus $patch_file"
fi
echo "ok: $vendored is upstream $crate $version plus $patch_file"

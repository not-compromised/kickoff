#!/usr/bin/env bash
# Every vendor tree must equal its pinned crates.io archive plus audited patch.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
fail() { echo "check-vendor: $*" >&2; exit 1; }
sha256() { sha256sum "$1" | cut -d' ' -f1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
while IFS=$'\t' read -r crate version archive_hash patch_hash; do
    [[ "$crate" == \#* ]] && continue
    patch_file="vendor/$crate-$version.patch"
    [ "$(sha256 "$patch_file")" = "$patch_hash" ] || fail "$patch_file has an unreviewed hash"
    archive="$work/$crate-$version.crate"
    cached=$(find "${CARGO_HOME:-$HOME/.cargo}/registry/cache" -name "$crate-$version.crate" \
        -path '*index.crates.io-*' 2>/dev/null | head -n 1 || true)
    if [ -n "$cached" ]; then
        cp "$cached" "$archive"
    else
        curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
            --output "$archive" "https://static.crates.io/crates/$crate/$crate-$version.crate"
    fi
    [ "$(sha256 "$archive")" = "$archive_hash" ] || fail "$crate $version upstream hash mismatch"
    tar -xzf "$archive" -C "$work"
    expected="$work/$crate-$version"
    patch --quiet --batch --forward -p1 -d "$expected" < "$patch_file" || fail "$crate patch does not apply"
    diff -r "$expected" "vendor/$crate-$version" || fail "$crate vendor differs from upstream plus patch"
    echo "ok: $crate $version is upstream plus its audited patch"
done < vendor/crates.tsv

#!/usr/bin/env bash
# The proving gate: every step must pass, and the script exits non-zero on the
# first failure. Runs every SI-n test by running the whole workspace suite.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

step() { printf '\n== %s\n' "$*"; }

step "unsafe guard"
# unsafe_code is forbidden in the workspace lints; this catches the ways around
# that: an unsafe block or item anywhere, a crate attribute re-allowing it, and
# a member crate that does not inherit the workspace lints at all.
pattern='\bunsafe[[:space:]]*(\{|fn\b|impl\b|trait\b|extern\b)|(allow|expect|warn)\([^)]*\bunsafe_code\b|unsafe_code[[:space:]]*=[[:space:]]*"(allow|warn)"'
if hits=$(grep -rnE --include='*.rs' --include='*.toml' "$pattern" \
    --exclude-dir=target --exclude-dir=.git --exclude=check.sh . ); then
    printf '%s\n' "$hits"
    echo "unsafe guard: unsafe code or an unsafe_code override found" >&2
    exit 1
fi
for manifest in crates/*/Cargo.toml bins/*/Cargo.toml; do
    if ! awk '/^\[lints\]/{in_lints=1; next} /^\[/{in_lints=0} in_lints && /^workspace[[:space:]]*=[[:space:]]*true/{found=1} END{exit !found}' "$manifest"; then
        echo "unsafe guard: $manifest does not inherit [workspace.lints]" >&2
        exit 1
    fi
done
echo ok

step "cargo fmt --check"
cargo fmt --all --check

step "cargo clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings

step "cargo test"
cargo test --workspace --locked

step "cargo deny"
cargo deny check --hide-inclusion-graph

printf '\nall checks passed\n'

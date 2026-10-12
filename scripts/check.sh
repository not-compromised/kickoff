#!/usr/bin/env bash
# The proving gate: every step must pass, and the script exits non-zero on the
# first failure. Runs every SI-n test by running the whole workspace suite,
# the design §7 latency tests in a release build, and then every mutant in
# mutants.toml, each of which must fail its test (SI-33).
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
for manifest in crates/*/Cargo.toml bins/*/Cargo.toml xtask/Cargo.toml; do
    if ! awk '/^\[lints\]/{in_lints=1; next} /^\[/{in_lints=0} in_lints && /^workspace[[:space:]]*=[[:space:]]*true/{found=1} END{exit !found}' "$manifest"; then
        echo "unsafe guard: $manifest does not inherit [workspace.lints]" >&2
        exit 1
    fi
done
echo ok

step "vendored iroh (design §3.4)"
# Upstream iroh 1.3.0 plus the one reviewed patch, nothing else.
scripts/check-vendor.sh

step "cargo fmt --check"
cargo fmt --all --check

step "cargo clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings

step "cargo test"
cargo test --workspace --locked

step "release latency (design §7)"
# Debug builds assert only loose ceilings; these assert the §7 budgets
# (p50 <= 100 us, p99 <= 500 us game to game; <= 2 us codec plus filter;
# <= 50 ns for the send guard on an approved destination).
cargo test --release --locked -p kickoff-session --test budget
cargo test --release --locked -p kickoff-net --test latency
cargo test --release --locked -p kickoff-net --lib send_guard_on_an_approved_destination_within_budget
cargo test --release --locked -p kickoff-vlan --test hot_path

step "cargo deny"
cargo deny check --hide-inclusion-graph

step "mutants (SI-33)"
# Each registered mutant's test must pass on the plain build and fail with the
# mutant; then a release build with a mutant enabled must be refused.
cargo run --locked -q -p kickoff-xtask -- mutants
cargo run --locked -q -p kickoff-xtask -- release-guard

printf '\nall checks passed\n'

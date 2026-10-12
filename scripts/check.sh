#!/usr/bin/env bash
# The proving gate: every step must pass, and the script exits non-zero on the
# first failure. Runs every SI-n test by running the whole workspace suite,
# the design §7 latency tests in a release build, and then every mutant in
# mutants.toml, each of which must fail its test (SI-33).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

step() { printf '\n== %s\n' "$*"; }

step "dated advisory exceptions (design §8.3)"
deny_config=$(mktemp)
trap 'rm -f "$deny_config"' EXIT
python3 scripts/advisory-exceptions.py --output "$deny_config"
python3 -m unittest discover -s scripts/tests -v

step "unsafe guard"
# unsafe_code is forbidden in the workspace lints; this catches the ways around
# that: an unsafe block or item anywhere, a crate attribute re-allowing it, and
# a member crate that does not inherit the workspace lints at all.
pattern='\bunsafe[[:space:]]*(\{|fn\b|impl\b|trait\b|extern\b)|(allow|expect|warn)\([^)]*\bunsafe_code\b|unsafe_code[[:space:]]*=[[:space:]]*"(allow|warn)"'
if hits=$(grep -rnE --include='*.rs' --include='*.toml' "$pattern" \
    --exclude-dir=target --exclude-dir=.git --exclude-dir=vendor --exclude=check.sh . ); then
    printf '%s\n' "$hits"
    echo "unsafe guard: unsafe code or an unsafe_code override found" >&2
    exit 1
fi
# Upstream dependencies may use unsafe; our audited patch may not add it.
if hits=$(awk '/^\+[^+]/{print FILENAME ":" FNR ":" substr($0,2)}' vendor/*.patch | grep -E "$pattern"); then
    printf '%s\n' "$hits"
    echo "unsafe guard: a vendored patch adds unsafe code" >&2
    exit 1
fi
for manifest in crates/*/Cargo.toml bins/*/Cargo.toml xtask/Cargo.toml; do
    if ! awk '/^\[lints\]/{in_lints=1; next} /^\[/{in_lints=0} in_lints && /^workspace[[:space:]]*=[[:space:]]*true/{found=1} END{exit !found}' "$manifest"; then
        echo "unsafe guard: $manifest does not inherit [workspace.lints]" >&2
        exit 1
    fi
done
echo ok

step "vendored transport dependencies (design §3.4)"
# Each dependency is upstream 1.3.0 plus its audited patch, nothing else.
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
cargo test --release --locked -p kickoff-session --test budget -- --nocapture
cargo test --release --locked -p kickoff-net --test latency -- --nocapture
cargo test --release --locked -p kickoff-net --lib send_guard_on_an_approved_destination_within_budget -- --nocapture
cargo test --release --locked -p kickoff-vlan --test hot_path -- --nocapture

step "cargo deny"
python3 scripts/advisory-exceptions.py --output "$deny_config"
cargo deny --config "$deny_config" check --hide-inclusion-graph
scripts/check-upstream-advisories.sh

step "mutants (SI-33)"
# Each registered mutant's test must pass on the plain build and fail with the
# mutant; then a release build with a mutant enabled must be refused.
cargo run --locked -q -p kickoff-xtask -- mutants
cargo run --locked -q -p kickoff-xtask -- release-guard

printf '\nall checks passed\n'

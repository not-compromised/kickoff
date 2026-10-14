# Developing Kickoff

Spec: [design.md](design.md). Standing security rules: [SECURITY-INVARIANTS.md](SECURITY-INVARIANTS.md).

## Workspace

| Crate | Role | Milestone |
|---|---|---|
| `crates/wire` | LAN header, fragments, join and control messages, tickets | M2 |
| `crates/vlan` | game-facing LAN: codec, filter, adapters (`Mem`, `NsTap`) | M2 (`Mem`), M3 (`NsTap`) |
| `crates/net` | iroh door and session endpoints, fragmentation, egress policy | M2 |
| `crates/session` | admission owner, roster, pump, budgets | M2 |
| `crates/ipc` | authenticated, versioned local channels | M2 (Linux), M7 (Windows) |
| `crates/local` | shared Linux kernel authentication and ancillary-refusing transport | M2 (Linux) |
| `crates/secret` | `Secret<T>`, process hardening, Linux identity storage | M2 |
| `crates/budget` | shared saturating token arithmetic; rates and charging order stay local | M2 |
| `crates/send-guard` | the registry called by vendored iroh before IP sends | M2 |
| `bins/kickoffd` | Linux listener facade and hardened IPC worker; commands refuse until adapters exist | M2 startup, M6 adapters |
| `crates/{store,parse,maps,game}`, `bins/kickoff` | placeholders | M5, M6 |
| `xtask` | the SI-33 harness: mutant runner, release guard check, policy test | M2 |

M2 crates and Linux daemon IPC startup are implemented. Game, map and session
application adapters are not wired; the daemon refuses their commands. The
store, parse, maps and game crates remain placeholders, and the CLI reports
that it is not implemented yet.

## Checks

```
scripts/check.sh
```

Runs the dated advisory exception policy and its Python tests, the unsafe guard, the upstream-plus-patch vendor comparison, `cargo fmt --check`, clippy with `-D warnings`, the whole
test suite (every `si_n_*` test and the SI-33 policy test), the design §7
latency tests in a release build, both cargo-deny scans, and then every mutant.
The dated-exception owner is `advisory-exceptions.toml`;
`scripts/advisory-exceptions.py` validates it before either advisory scan.
The registry mirror in `scripts/check-upstream-advisories.sh` also covers
the pinned path dependencies that the root RustSec scan cannot match.
Run cargo through `mise exec --` so the pinned toolchain
(`rust-toolchain.toml`) is used.

The release latency step asserts the §7 budgets that debug builds only
approximate: game to game p50 ≤ 100 µs and p99 ≤ 500 µs
(`kickoff-session --test budget`), net's share of it inside the same budget
(`kickoff-net --test latency`), and codec plus filter ≤ 2 µs per datagram
(`kickoff-vlan --test hot_path`), and the send guard on an approved
destination ≤ 50 ns per send (`kickoff-net --lib
send_guard_on_an_approved_destination_within_budget`). These time the wall
clock, so the step runs one test at a time and needs a machine that other work
does not saturate. A latency failure also reports the total time the test's
threads spent waiting for a CPU during the run. That figure is diagnostic
context only: it is summed over all threads and the whole run, so it cannot
show that any single slow datagram was caused by contention. Treat every
failure as a possible regression until a rerun on an idle machine passes.

### Mutants (SI-33)

A mutant is a cargo feature `mutant-si<N>-<slug>` on the crate that holds a
protection; under `#[cfg(feature = ...)]` or `cfg!(...)` it removes exactly
that protection. Each is registered in `/mutants.toml` with the test that
must fail against it:

```
[[mutant]] si = "SI-18", crate = "kickoff-net", feature = "mutant-si18-...", test = "si_18_...", note = "what is removed"
```

`test` is a test function name; `test_crate` names the package holding it
when that is not `crate`. A feature may enable other crates' mutants when a
test is held by two layers at once (`mutant-si23-unbudgeted-ingress`), so the
test is proven against the removal of both. `[[unmutated]]` records an SI
test no flag can falsify, with the reason; `[[pending]]` records an M2 row or
named mutant whose code has not landed. No pending entries remain after
integrating the M2 branches; that policy alone does not replace the design
review or prove every budget is applied at the specified granularity.

```
cargo run -p kickoff-xtask -- mutants [FILTER...]   # each test: pass plain, fail mutated
cargo run -p kickoff-xtask -- release-guard         # release builds refuse mutants
cargo run -p kickoff-xtask -- policy                # the SI-33 report
```

The mutation run stops at the first failed row, including a passing mutated
test or a build/discovery failure. Later rows receive no verdict.

`xtask/tests/si_33_policy.rs` parses `docs/SECURITY-INVARIANTS.md` and fails
if a row held in M2 has no `si_<n>_` test or no registered mutant, if a
mutant named in its Mutant column is not registered, if a registered mutant's
feature or test does not exist, if a crate declares a mutant nobody runs, if
an `si_<n>_` test of an M2 row has neither a mutant nor an `[[unmutated]]`
reason, or if a `[[pending]]` entry is no longer missing.

Every crate with mutant features uses `scripts/mutant-guard.rs` as its build
script (`build = "../../scripts/mutant-guard.rs"`). It refuses the build when
any `mutant-*` feature is on and debug assertions are off or the profile is
`release`; it reads Cargo's feature variables, so a new mutant needs no list.

### Target directories

Give every worktree its own target directory: the default `target/` inside
it, or a `CARGO_TARGET_DIR` no other checkout uses. Two worktrees sharing one
target directory overwrite each other's test binaries whenever their sources
or feature sets differ, and a test can then run a binary built from the other
branch: tests pass or fail for code that is not on disk. The mutant runner
makes this worse, since it rebuilds crates with and without each feature.

## Conventions

- `unsafe_code` is forbidden workspace-wide. `scripts/check.sh` also fails on
  any `unsafe` block or item, any `allow(unsafe_code)`, and any member crate
  that does not inherit `[workspace.lints]`.
- The panic family is denied in every crate: `unwrap_used`, `expect_used`,
  `panic`, `indexing_slicing`, `arithmetic_side_effects`, truncating casts and
  friends. `#[test]` functions and `#[cfg(test)]` modules may unwrap, index
  and panic (`clippy.toml`). Integration test files that need more start with
  a file-level `#![allow(...)]` naming each lint.
- A test that enforces an invariant is named after it: `si_30_...`.
- Dependencies are pinned with `=` in `[workspace.dependencies]`; `Cargo.lock`
  is committed.

## NOTES

Deviations from design draft 2 §2.3 and open spec questions, found while
scaffolding M2.

### Deviations

1. **Receives that can end return `Result`.** `Lan::recv`, `Door::next_join`,
   `SessionNet::accept` and `Link::recv_lan` return `Result<_, _>` instead of a
   bare value. The tap dies with its gamebox and links and endpoints close, so
   an infallible signature would force the implementation to hang or panic.
2. **Tickets and keys are `Secret`.** `Session::invite` returns
   `Result<Secret<Ticket>, _>` (a guest gets `NotHost`; encoding can exceed
   2 KiB); `session::join` takes `Secret<Ticket>`; `Door::request_join` takes
   `&Secret<Ticket>`; `net::door` takes `&secret::key::IdentityKey`. §6.4 and SI-30
   require it, and iroh's `SecretKey` implements both `Debug` and `Serialize`.
3. **Shared value types live in `wire`.** `LanDatagram`, `PeerSlot`,
   `Generation`, `PeerRef`, `MapId`, `AdmitPass` and `ApprovalId` are in `wire`:
   `net` and `vlan` both need `LanDatagram`, and `net` should not depend on the
   tap adapters. `ApprovalId` is re-exported by session and IPC; only the
   session owner mints it. See [wire codec and port ownership](../crates/wire/README.md#codec-and-port-ownership)
   for the shared codecs and compiled denylist.
4. **`Admitted { session_addr, pass: AdmitPass }`**, so a guest dials with
   `dial(admitted.session_addr, admitted.pass)`.
5. **`Link::peer() -> PeerRef`** exposes the (identity, slot, generation) the
   design says a link carries.
6. **`JoinAttempt::answer(Result<Admitted, JoinRefused>)`** is how the host
   replies; §2.3 names `JoinAttempt` without a reply path.
7. **`CtlStream` uses sealed message types.** Receive uses `WireMessage`;
   send requires `PublicWireMessage`, excluding secret-bearing Join requests.
   `MAX_LEN` bounds each type: join 4 KiB, control 64 KiB.
8. **The L2 frame codec is in `vlan`.** Both workspace layout (§2.2) and
   module interface (§2.3) use that owner.
9. **iroh default features are off.** Kept `tls-ring`. Dropped `portmapper`,
   which maps router ports over UPnP/PCP/NAT-PMP and advertises them as extra
   candidates, against §3.4 and SI-31; dropped `metrics` and
   `fast-apple-datapath`.
10. **`vlan::mem_tap() -> (Adapter, MemGame)`**: `MemGame` is the in-process
    game end, which sends and receives raw Ethernet frames so the `Mem` adapter
    runs the same codec and filter as the taps. `WinTap(SvcLease)` waits for M7.
11. **`[profile.release]`**: §7 sets no profile, so these are picks:
    `opt-level = 3`, fat LTO, `codegen-units = 1`, `panic = "abort"`,
    `overflow-checks = true`. Abort is fail-closed: the peer-facing network
    dies with kickoffd (SI-12) rather than serving with a half-updated
    admission table. The cost is that any reachable panic is a remote crash,
    which the panic lints exist to prevent.

### Interface choices

- LAN frames carry a `PeerSlot`; net and session authenticate its generation
  before delivery, and `Lan::reset_peer` clears the slot's flows before reuse.
- The host publishes the admission owner's current set through
  `SessionNet::set_admitted`; the handshake hook and each later layer re-check it.
- `Secret::expose` requires the kind's designated consumer token. Wire's token
  has a private constructor: other crates cannot expose a stored ticket or
  substitute another owner. Capabilities hold private `Secret<CapValue>` data;
  callers use invitation-kind inspection and protected join copies.
- Wire owns secret-bearing serialization and transmission. Tickets remain
  opaque; Join frames hold `Secret<FrameBody>` and expose bytes only inside
  wire's private owner closure while writing. Recipient authority and the
  public nonsecret encoders are indexed in
  [wire secret transmission](../crates/wire/README.md#secret-transmission).
- `IdentityKey` shares one `Secret<SecretKey>` allocation. Identity persistence,
  public identity and signing operations stay inside its owner. Binding an iroh
  endpoint copies the key only inside that adapter, clears address-lookup
  callbacks and disables key logging. `KeyEndpoint` supplies connection
  operations without iroh's raw-key accessor or `Deref`.
- Linux kickoffd applies the facade core policy as its first application action,
  before probe dispatch, arguments, runtime or trust. The genuine exec crash
  probe still gates listening; it is spawned through `posix_spawn` so every
  descriptor the daemon inherited is closed in it, since safe Rust cannot own
  a leaked descriptor to mark it close-on-exec. The worker becomes nondumpable
  with zero limits before its runtime. Which host crash configurations start
  and which refuse is the table in design §6.4; the gate's tests run on the
  host's own `core_pattern`, and the zero-hard-limit test expects the outcome
  that pattern implies. Runtime/loader work before Rust `main` remains outside
  this startup-order proof.
- Host Leave and Kick completion belongs to the session task set; dropping a
  caller's future does not cancel an accepted operation. See
  [session lifecycle](../crates/session/README.md#lifecycle-and-deadline-boundaries).
- `Session::approvals()` holds the pending set in a watch receiver. Slow readers
  can recover it even if they missed `ApprovalRequested` on the event stream.
- `paste` (RUSTSEC-2024-0436, unmaintained) arrives through iroh 1.3.0 →
  netwatch → netdev → netlink-packet-core. It is a compile-time proc-macro, so
  `advisory-exceptions.toml` owns its rationale and dates. Both advisory gates
  generate cargo-deny ignores only after checking UTC expiry, issue date and
  the 90-day cap. `deny.toml` has no active ignores by itself. Revisit on each
  iroh bump.
- Linux identity storage is implemented in `secret::identity` for M2. Its
  handle-relative writes and staged publication can move behind `store` in M5.
  Daemon startup and session wiring still belong to the application milestones.

### Harness (SI-33) notes

1. Networking policy owners and the pending-handshake cap regression are
   indexed in [net egress policy](../crates/net/README.md#egress-policy).
   SI-33 checks the registry; running the full gate establishes dynamic proof
   for the current source revision.
2. SI-22's local half is covered by `kickoff-secret`: file and directory modes,
   hostile names and damaged state, read isolation from another uid, and local
   revocation before identity replacement. Remote revocation notices are M10.
3. **Layered protections.** Where several layers each hold a rule alone, an
   end-to-end test survives any single layer's removal. Each layer then has
   its own mutant and a test that drives that layer alone (SI-18's six
   admission layers, SI-29's scope and connect guard); the end-to-end test is
   `[[unmutated]]` with that reason, or gets a feature that removes every
   layer at once.
4. The SI-31 leaked-endpoint test binds separate loopback hosts and supplies
   a synthetic host view. Its unbound mutant requires another non-loopback
   IPv4 interface to expose address enumeration; the test fails if it cannot
   establish that difference instead of skipping the mutant.
5. See [admission lifetime bounds](../crates/net/README.md#admission-lifetime-bounds)
   for the absolute two-second Hello window after TLS, including stream and
   accept-queue waiting. TLS has a separate five-second bound.
6. **Hot-path bench.** §7 names criterion. A criterion bench measures but
   cannot fail the gate, so `vlan/tests/hot_path.rs` is a release-mode timing
   test with the same ≤ 2 µs budget instead, and no bench dependency was
   added. The §7 "generation check" part of that row is not in it: the
   generation checks live in `net` and `session` and are covered by the
   end-to-end latency tests.
7. **SI-33's release half** (tests and mutants ran against the artifact hash
   in the release record) belongs to the release pipeline (M11a). The M2
   gate checks the source tree only.

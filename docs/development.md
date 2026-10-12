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
| `crates/secret` | `Secret<T>` | M2 |
| `crates/{store,parse,maps,game}`, `bins/{kickoffd,kickoff}` | placeholders | M5, M6 |
| `xtask` | the SI-33 harness: mutant runner, release guard check, policy test | M2 |

M2 crates are implemented; placeholder crates (store, parse, maps, game) and
the binaries return a typed `NotImplemented` error and hold `Infallible`
until their milestone, so no stub can panic.

## Checks

```
scripts/check.sh
```

Runs the unsafe guard, `cargo fmt --check`, clippy with `-D warnings`, the whole
test suite (every `si_n_*` test and the SI-33 policy test), the design §7
latency tests in a release build, `cargo deny check`, and then every mutant.
Run cargo through `mise exec --` so the pinned toolchain
(`rust-toolchain.toml`) is used.

The release latency step asserts the §7 budgets that debug builds only
approximate: game to game p50 ≤ 100 µs and p99 ≤ 500 µs
(`kickoff-session --test budget`), net's share of it inside the same budget
(`kickoff-net --test latency`), and codec plus filter ≤ 2 µs per datagram
(`kickoff-vlan --test hot_path`).

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
named mutant whose code has not landed.

```
cargo run -p kickoff-xtask -- mutants [FILTER...]   # each test: pass plain, fail mutated
cargo run -p kickoff-xtask -- release-guard         # release builds refuse mutants
cargo run -p kickoff-xtask -- policy                # the SI-33 report
```

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
   `&Secret<Ticket>`; `net::door` takes `&Secret<SecretKey>`. §6.4 and SI-30
   require it, and iroh's `SecretKey` implements both `Debug` and `Serialize`.
3. **Shared value types live in `wire`.** `LanDatagram`, `PeerSlot`,
   `Generation`, `PeerRef`, `MapId` and `AdmitPass` are in `wire`, not `vlan`:
   `net` and `vlan` both need `LanDatagram`, and `net` should not depend on the
   tap adapters.
4. **`Admitted { session_addr, pass: AdmitPass }`**, so a guest dials with
   `dial(admitted.session_addr, admitted.pass)`.
5. **`Link::peer() -> PeerRef`** exposes the (identity, slot, generation) the
   design says a link carries.
6. **`JoinAttempt::answer(Result<Admitted, JoinRefused>)`** is how the host
   replies; §2.3 names `JoinAttempt` without a reply path.
7. **`CtlStream::{send, recv}` are generic over a sealed `WireMessage`**, whose
   `MAX_LEN` bounds each message type (join 4 KiB, control 64 KiB).
8. **The L2 frame codec is in `vlan`** as §2.3 says; §2.2 lists it under
   `wire`. One of the two should change.
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

### Open questions

1. **Generation in the filter.** §3.1 keys filter flows by (identity,
   generation, 5-tuple), but `LanDatagram` carries only `PeerSlot`, so `vlan`
   cannot see a generation. Proposal: `LanDatagram.peer: PeerRef`.
2. **How the host's session endpoint learns admissions.** The handshake hook
   in `net` must accept only keys holding a live pass, but the admission owner
   is in `session` and `net::session()` takes no handle to it. Proposal: pass
   an admission gate (`Arc<dyn AdmissionGate>`) to `net::session` for
   `Role::Host`.
3. **Tickets across `ipc`.** `kickoff join <ticket>` must move a ticket from
   the CLI to kickoffd, but `Secret` cannot be serialized. Proposal: `ipc` owns
   the one function that writes a `Secret<Ticket>` into a channel frame.
4. **"Only the single consumer can expose it" (§6.4).** `Secret::expose` is
   public, so any holder can read any secret. Enforcing one consumer per
   secret type needs a per-type wrapper whose `expose` is private to its
   consumer's crate.
5. **Lagging event receivers.** `Session::events` is a tokio broadcast, which
   drops old events for a slow receiver. A dropped `JoinPrompt` would leave a
   bearer guest waiting until its deadline; prompts may need their own channel.
6. **`paste` (RUSTSEC-2024-0436, unmaintained)** arrives through iroh 1.3.0 →
   netwatch → netdev → netlink-packet-core. It is a compile-time proc-macro, so
   `deny.toml` ignores it with that reason. Revisit on each iroh bump.

### Harness (SI-33) notes

1. **Pending M2 rows.** The policy runs green only because `mutants.toml`
   lists what draft 3 assigns to M2 but this branch does not implement:
   SI-7's `SO_PEERPIDFD` check and ancillary-data refusal, SI-29's vendored
   send guard, SI-30's `harden_process`, and SI-41's approval objects. M2 is
   not done while `[[pending]]` has entries.
2. **SI-22 in M2.** Its Held column says "M2 (local)", but no M2 crate stores
   the identity key or the trust list (`store` is M5), so there is nothing to
   test or mutate. Should SI-22's local half move to M5?
3. **Layered protections.** Where several layers each hold a rule alone, an
   end-to-end test survives any single layer's removal. Each layer then has
   its own mutant and a test that drives that layer alone (SI-18's six
   admission layers, SI-29's scope and connect guard); the end-to-end test is
   `[[unmutated]]` with that reason, or gets a feature that removes every
   layer at once.
4. **Machine-dependent mutant.** `mutant-si31-unbound` fails its test only on
   a machine with an interface address outside the bound one that the test
   strips (a CGNAT or `10.75/16` address, such as Tailscale's). On a machine
   with a single interface, bound and unbound advertise the same address and
   the mutant survives, which fails the gate. CI needs such an interface, or
   the test needs a synthetic one (netns, M3).
5. **The `Hello` deadline** is 5 s in `session` and in `net`'s handshake
   deadline; draft 3 says 2 s. The mutants and tests hold for either value.
6. **Hot-path bench.** §7 names criterion. A criterion bench measures but
   cannot fail the gate, so `vlan/tests/hot_path.rs` is a release-mode timing
   test with the same ≤ 2 µs budget instead, and no bench dependency was
   added. The §7 "generation check" part of that row is not in it: the
   generation checks live in `net` and `session` and are covered by the
   end-to-end latency tests.
7. **SI-33's release half** (tests and mutants ran against the artifact hash
   in the release record) belongs to the release pipeline (M11a). The M2
   gate checks the source tree only.

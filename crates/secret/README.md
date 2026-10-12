# kickoff-secret

`Secret<T>`, process hardening, the identity key at rest, and the
diagnostics schema (design §3.4, §6.4, SI-22, SI-30).

- `Secret<T>` implements none of `Debug`, `Display`, `Serialize`, `Clone` or
  `PartialEq`. The value lives in one heap allocation and is wiped on drop.
  `expose(|v| ...)` is the only read; `ct_eq` is the only comparison and runs
  in constant time for equal-length inputs.
- `Secret::new` requires `T: Wipe`, so every secret type states how it is
  wiped. Implemented for `String`, `Vec<u8>`, `Box<[u8]>`, `[u8; N]` and
  `iroh_base::SecretKey` (which zeroizes itself; a compile-time check fails
  if an iroh bump drops that).
- `diag` builds diagnostics records from closed key tables and typed values.
  Nothing in it takes a string, so a log line, argv, path, peer name or
  ticket cannot enter an export. A report holds at most `MAX_FIELDS` fields.

- `harden_process()` sets `RLIMIT_CORE` to 0 (soft and hard) and clears
  `PR_SET_DUMPABLE`. kickoffd calls it first in `main` and refuses to start
  if it fails. Not dumpable means no core dump at all, even through a
  core-pattern pipe, and no `/proc/<pid>/mem` or `ptrace` access for other
  processes of the same user.
- `identity` (Linux): `IdentityStore::{open, open_in, load_or_create, reset,
  trust_list, save_trust}` and `TrustList::{state, trusted, trust, revoke}`.
  The key lives in `$XDG_DATA_HOME/kickoff/state/identity` (0600, in a 0700
  directory), the trust list in `state/trust`. Both files carry a magic and
  a format version. Every state operation holds `state.lock` with a kernel
  flock and a local mutex; reset holds it across trust revocation and key
  publication. A trust list remembers its loaded snapshot, so `save_trust`
  rejects stale edits as `Raced`. Reload after saving or after a race.

```
open_in(base)  base: absolute, ours, no g/o write (may be reached by symlink)
  kickoff/     created 0700, or ours with no g/o write, never a symlink
  state/       created 0700, or exactly 0700 and ours, never a symlink
  state.lock   regular, ours, 0600, single link; held throughout each transaction
load_or_create read identity: O_NOFOLLOW|O_NONBLOCK, fstat on the handle:
               regular, ours, 0600, exactly one key   else UnsafePath/Damaged
               missing: identity.new O_EXCL 0600 -> fsync -> rename NOREPLACE
reset          revoke the old key in trust (saved first) -> new key replaces old
```

Tests: `si_30_secret_has_no_debug_display_serialize` (trait probes that fail
if any impl is added, including a conditional one), `si_30_secret_wiped_on_drop`,
`si_30_diagnostics_render_only_schema_keys_and_typed_values`,
`si_30_hardened_process_leaks_no_secret_to_a_core_dump_or_proc_mem`, and in
`tests/si_22.rs`: key created 0600 in a 0700 directory and reloaded; a key
file with the wrong mode, a symlink, a FIFO or a directory refused untouched;
a state directory with the wrong mode, a symlink or a file refused untouched;
a damaged key refused, not replaced; reset revokes the old key's trust
entries; a real second uid (`unshare --map-auto`) cannot read the key while
the same reader as our uid can.

## NOTES

1. **No redacting `Debug`.** The M2 brief asked for Debug/Display that
   redact; design §6.4 and SI-30 say `Secret` implements neither, proven by a
   test. This follows the design: a type that holds a secret writes its own
   redacting `Debug` (see `kickoff_ipc::TicketText`) instead of deriving one
   through a `Secret` that prints `<redacted>`.
2. **Integration: `Secret::new` needs `T: Wipe`.** The scaffold's
   `Secret::new` had no bound. Any crate that wraps its own type must
   implement `kickoff_secret::Wipe` for it. `kickoff-wire` wraps `Ticket`,
   so it needs, for example:
   ```rust
   impl kickoff_secret::Wipe for Ticket {
       fn wipe(&mut self) {
           self.cap.session_id.0 = [0; 16];
           self.cap.nonce.0 = [0; 16];
           self.cap.sig = iroh_base::Signature::from_bytes(&[0; 64]);
       }
   }
   ```
   (`zeroize` would make the writes volatile; the drop happens right after.)
3. **Moves of inline values.** `Secret::new(value)` moves `value` into the
   box. For a `String` or `Vec` only the pointer moves; for an inline array
   the caller's stack copy is not wiped. Build inline secrets inside the
   secret where it matters.
4. **The crash test reads, it does not crash a dumpable child.** A child
   holds a fresh canary `Secret`. Unhardened, its parent (this test, same
   uid) reads the canary from `/proc/<pid>/mem`: the control that proves the
   reader works. Hardened, the same read is `PermissionDenied`,
   `/proc/<pid>/limits` shows a core limit of 0/0, and after `abort()` the
   kernel's wait status says no core was dumped (that bit is set for file
   and pipe dumps alike, so systemd-coredump is covered without querying
   `coredumpctl`). A crashing control is avoided on purpose: on a desktop
   with systemd-coredump it would store a real dump and raise a crash
   notification on every run. Yama `ptrace_scope` 2 or 3 would fail the
   control, and the test with it; it does not skip.
5. **`harden_process` is `Unsupported` off Linux**, so kickoffd does not start
   on Windows until M7 adds the equivalent.
6. **SI-22 lives here for M2.** Design §3.4 says the identity key is
   "created through `store`", but `store` is M5. The key is a `Secret`, so
   its at-rest form is kept here, behind a small interface that `store` can
   absorb later. Choices made:
   - "Every trust entry for the old identity" is read as every entry naming
     the old key. `reset` marks it `Revoked`, adding a revoked entry if none
     named it, and saves the trust list before the new key replaces the old
     one, so a crash in between fails closed.
   - A revoked entry stays in the list, so the key is not trusted again by
     accident; `TrustList::trust` (an explicit user action) re-trusts it.
   - A damaged key file is refused, never replaced, and `reset` refuses too:
     the user removes the file. There is no CLI for that yet.
   - The owner check (a key file owned by another uid) has no test: making
     such a file in our own 0700 directory needs root. The mode, type and
     symlink checks share its code path and its mutant.
   - The key comes from `getrandom` into a zeroizing buffer rather than from
     `SecretKey::generate`, which leaves its seed on the stack.
   - Concurrent creators return the same published identity. A controlled
     overlap test pauses the first writer before rename and confirms the
     second waits; another test holds the lock from a different process.
     A stale trust snapshot cannot overwrite a reset revocation.
   - This supplies SI-22's local M2 storage. Remote revocation notices remain M10.

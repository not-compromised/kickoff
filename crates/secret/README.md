# kickoff-secret

`Secret<T>` and the diagnostics schema (design §6.4, SI-30).

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

Tests: `si_30_secret_has_no_debug_display_serialize` (trait probes that fail
if any impl is added, including a conditional one), `si_30_secret_wiped_on_drop`,
`si_30_diagnostics_render_only_schema_keys_and_typed_values`.

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

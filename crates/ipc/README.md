# kickoff-ipc

Local channels between Kickoff's own processes (design §2.7). Linux in M2;
Windows pipes in M7.

```
client (kickoff, kickoff-ui)                 kickoffd
RuntimeDir::open   $XDG_RUNTIME_DIR/kickoff  RuntimeDir::open
                   0700, ours, no symlink
connect::<Role>  ─ SO_PEERCRED uid + exe ─►  Server::bind   bind() exclusive, 0600
  (nothing sent until the server passes)     accept  ─ slot ─ SO_PEERCRED uid + exe
  Hello{KO, version, role}  ───────────────►         version and role served?
  ◄─────────────────────────  Welcome{version, ok | version | role}
call(R::Command) ─ frame ≤ 4 KiB ─────────►  recv: rate ─ length ─ body ─ decode for role
  ◄──────────────────── reply ≤ 8 KiB ──────  reply: allowed for role?
```

## Interface

- `RuntimeDir::{open, open_in, socket_path}`.
- `Trust::{kickoffd, clients, same_user, for_uid}`: who may be at the other
  end (one uid plus a set of executables, compared by inode).
- `Server::{bind(&dir, trust), accept, health}`; `Channel::{role, peer, recv, reply}`.
- `connect::<R>(&dir, &trust) -> Client<R>`; `Client::{call, server}`. `R` is
  `role::{Cli, UiMain, Overlay}`, and `Client<R>::call` takes only
  `R::Command`, so CLI code cannot build a UI command.
- Commands: `CliCommand`, `UiCommand`, `OverlayCommand`. Replies: `Done`,
  `Refused(Refusal)`, `Invite(TicketText)` (never to the overlay),
  `Report(diag::Report)`.
- `TicketText` is a `Secret<String>` restricted to 1..=2048 ASCII letters
  and digits.

## Invariants and their tests

| SI | Test |
|---|---|
| SI-7 (Linux) | `tests/si_7.rs`: private directory (mode, owner, symlink, file, public or relative base), exclusive socket (file, symlink, live fake server), caller with another uid, caller running another executable, fake server started first (gets zero bytes), and `si_7_second_uid_refused` with a real second uid |
| SI-10 | `tests/si_10.rs`: version mismatch refused before a pipelined command reaches the daemon; client refuses a server of another version and sends nothing more |
| SI-3 | `tests/si_3.rs`: every command variant classified (exhaustive match) against a denylist; the one text argument refuses paths, URLs, options and escapes, on the wire too |
| SI-23 (pipe) | `tests/channel.rs` and `src/frame.rs`: oversize frame refused from its header before the body is read or allocated, stalled frame, request rate, channel slots |
| SI-30 | `tests/si_30.rs`: a canary ticket crosses the socket intact while every type holding it, every reply and error, prints none of it (any 8-character window, any case) |

Each was checked by removing its mitigation and watching the test fail.

`si_7_second_uid_refused` runs a copy of the test binary as the first
subordinate uid through `unshare --map-auto` (util-linux, `newuidmap` with
file capabilities, and a `/etc/subuid` entry; no root). Without those it
fails with a message saying so; it does not skip (SI-33).

## NOTES

Deviations from draft 2 and the M2 scaffold, and open questions.

1. **`Server::bind` and `connect` take a `Trust`;** `connect` is generic over
   the role instead of taking a `ChannelRole`. The daemon passes
   `Trust::clients()`, clients pass `Trust::kickoffd()`. Tests use
   `same_user` and `for_uid` to stand in for installed binaries and for a
   second uid.
2. **A dead socket of ours is replaced.** §2.7 says "no unlink-and-retry".
   Taken literally, a kickoffd killed with SIGKILL (which SI-12 tests do)
   leaves a socket that blocks every later start. `bind` removes only a
   socket that we own, inside our 0700 directory, that refuses connections;
   a live server, a file, a symlink or another owner's socket is `Squatted`.
3. **The executable check uses `/proc/<pid>/exe` from `SO_PEERCRED`, not a
   pidfd.** `SO_PEERPIDFD` has no safe wrapper in rustix 1.1.5, and `unsafe`
   is forbidden. Residual: if the caller exits and its pid is reused by one of
   our own Kickoff binaries between connect and check, the check passes. Only
   a same-uid process can arrange that, which §6.1 puts outside the boundary.
   A caller whose pid is not visible (another pid namespace) is refused.
4. **Hand-written codec instead of postcard.** Keeps `Serialize` off every
   type that holds a `Secret` (SI-30), and gives strict decoding (no trailing
   bytes, canonical booleans, counts checked before reading) in one file.
5. **A ticket does cross this channel.** `kickoff join <ticket>` and the UI's
   join flow must hand the ticket to kickoffd. It travels as `TicketText`; the
   overlay can neither send nor receive one. SI-9's "no raw ticket" applies to
   the webview, which is not an IPC peer.
6. **Budgets for the Linux socket are not in §6.3.** Chosen: requests ≤ 4 KiB,
   replies ≤ 8 KiB, hello 5 bytes, 16 channels, 32 requests/s per channel,
   1 s to finish a frame once its first byte arrives, 1 s handshake, 1 s
   write. An idle channel may wait for its next request indefinitely.
7. **`$XDG_RUNTIME_DIR` itself must be ours with no group or other access**,
   and not a symlink.
8. **Installed binaries** are `kickoffd`, `kickoff` and `kickoff-ui` next to
   the running executable. Packaging must keep them in one directory; if the
   Tauri binary gets another name, change `CLIENT_BINARIES` in `trust.rs`.
9. **`Server::accept` does the handshake inline**, so a same-uid caller that
   connects and stalls delays the next accept by up to 1 s. Other uids are
   refused before anything is read.
10. **`Channel::recv` is not cancel-safe**: dropping it mid-frame misaligns
    the stream, and the channel then refuses or closes.

Questions for the design:

- Should a role be tied to an executable (`Cli` only from `kickoff`,
  `UiMain` and `Overlay` only from `kickoff-ui`)? Today any trusted client
  binary may claim any served role.
- Is `ToggleOverlay` a kickoffd command (the CLI asks the daemon, which tells
  the UI) or should `kickoff --toggle-overlay` talk to the UI directly?
- `Report` replies carry `diag` fields; should `doctor` gain a `PathType` row
  for the socket itself?

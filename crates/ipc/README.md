# kickoff-ipc

Local channels between Kickoff's own processes (design §2.7). Linux in M2;
Windows pipes in M7.

```
client (kickoff, kickoff-ui)                 kickoffd
RuntimeDir::open   $XDG_RUNTIME_DIR/kickoff  RuntimeDir::open
                   0700, ours, no symlink
connect::<Role>  ─ uid + pidfd-pinned exe ►  Server::bind   bind() exclusive, 0600
  (nothing sent until the server passes)     accept  ─ slot ─ uid + pidfd-pinned exe
  every read: recvmsg, no control room;      every read: MSG_CTRUNC closes the channel
  Hello{KO, version, role}  ───────────────►         version and role served?
  ◄─────────────────────────  Welcome{version, ok | version | role}
call(R::Command) ─ frame ≤ 4 KiB ─────────►  recv: rate ─ length ─ body ─ decode for role
  ◄──────────────────── reply ≤ 8 KiB ──────  reply: allowed for role?
```

## Hardened daemon

`kickoffd` runs two modes of the same installed executable. Its facade creates
and owns the listening socket. Before reading any client bytes it checks the
same uid, installed executable inode and live kernel pidfd. It passes the
untouched accepted stream and one connection lease over an inherited, unnamed
Unix socketpair to its direct child. The facade drops its accepted-stream
copy immediately. Client hello, tickets, commands and replies enter userspace
only in the worker.

The worker is nondumpable and keeps both core limits at zero. It authenticates
its control socket's creator as its live, allowlisted direct parent, retaining
the kernel pidfd. It checks each transferred stream's kernel client identity
again before the normal version handshake. Client-side `SO_PEERCRED` and
`SO_PEERPIDFD` still identify the live facade that created the listener after
the accepted stream moves to the worker. No executable descriptor supplied by
a peer counts as identity proof.

The private protocol carries the shared `PROTOCOL_VERSION` before every tag.
A wrong version closes all received descriptors before they are used. It
permits one ready tag without descriptors, followed by one connection tag with
exactly two descriptors. Both must be connected Unix
streams; the lease must be unnamed and created by that same facade. Unknown
tags, credentials, truncated ancillary data, extra or missing descriptors and
wrong descriptor types close the control channel. External streams retain
`DataOnly`: every external ancillary message closes the channel. They never
use the descriptor-transfer reader.

At most 16 transferred connections, including pending handshakes, exist at
once. Lease EOF releases a facade slot. The worker watches both control EOF and
the facade pidfd even while clients are idle; either closes every transferred
stream. Dropping the facade kills and reaps its direct worker. The facade alone
owns socket-path cleanup, guarded by the inode it created. Abrupt facade death
can leave its dead pathname; a later bind refuses it until it is explicitly
removed.

The facade stays dumpable so clients can inspect its actual executable. Its
core soft and hard limits are **one byte**, not zero: Linux's piped core handler
ignores zero, but treats one as its recursion sentinel and skips the handler.
File-backed dumps refuse a limit below the format's minimum before creating a
file. This is a [Linux kernel convention](https://code.googlesource.com/linux/torvalds/linux/+/18ded910b589839e38a51623a179837ab4cc3789/fs/coredump.c#579),
not a portable hardening interface. Before listening, the facade execs a
secret-free probe with a clean environment, null stdio and private scratch cwd.
The child refuses inherited descriptors beyond stdio, verifies dumpability,
and aborts. The parent's kernel wait status must show SIGABRT without a core
and no scratch files. A wrong exit, core, or three-second timeout refuses
startup and reaps the child. This probes the running kernel and handler; a
handler configuration change after startup still requires a restart.

Same-user malware remains outside the design's boundary. A ptrace-compromised
facade can steal descriptors or IPC authority during handoff; keeping payloads
out of its memory does not prevent that. The worker's memory and secrets remain
nondumpable. M2 verifies this IPC seam, including installed daemon startup;
commands in the binary return `Refused(Failed)` until final adapters exist.

## Interface

- `RuntimeDir::{open, open_in, socket_path}`.
- `Trust::{kickoffd, clients, same_user, for_uid}`: who may be at the other
  end (one uid plus a set of executables, compared by inode). The check
  takes the peer's uid and pid from `SO_PEERCRED`, pins the process with
  `SO_PEERPIDFD`, reads `/proc/<pid>/exe`, and counts the answer only if the
  pidfd still names a running process.
- `Server::{bind(&dir, trust), accept, health}`; `Channel::{role, peer, recv, reply}`.
  `Server` is for a dumpable in-process endpoint. The hardened daemon uses
  `Facade::{spawn, run}` and `Worker::{inherit, from_control, accept}` instead.
  The executable calls `run_core_probe_if_requested` first in its worker entry.
  `Facade::spawn` accepts a command only for its own executable inode.
- `connect::<R>(&dir, &trust) -> Client<R>`; `Client::{call, server}`. `R` is
  `role::{Cli, UiMain, Overlay}`, and `Client<R>::call` takes only
  `R::Command`, so CLI code cannot build a UI command.
- Commands: `CliCommand`, `UiCommand`, `OverlayCommand`. Only `UiCommand`
  has `Decide { approval: ApprovalId, allow }` (the native dialog path);
  draft 2's `Approve(EndpointId)` is no longer a command. Replies: `Done`,
  `Refused(Refusal)`, `Invite(TicketText)` (never to the overlay),
  `Report(diag::Report)`.
- `TicketText` is a `Secret<wire::TicketTextValue>` restricted to 1..=2048 ASCII letters
  and digits.

## Invariants and their tests

| SI | Test |
|---|---|
| SI-7 (Linux) | `tests/si_7.rs`: private directory (mode, owner, symlink, file, public or relative base), exclusive socket (file, symlink, live fake server), caller with another uid, caller running another executable, fake server started first (gets zero bytes), `si_7_second_uid_refused` with a real second uid, `si_7_recycled_pid_refused` (the caller exits and a trusted binary takes its pid before the check), and `si_7_descriptors_from_a_caller_close_the_channel_and_are_closed` (with the hello and after it). `../local/src/stream.rs`: descriptors and credentials close the channel at the read |
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

1. **Shared kernel transport owner.** [kickoff-local](../local/README.md)
   owns `Trust` and `DataOnly`; IPC reexports the credential interface. Tests
   may configure ordinary channel trust, but a ticket write independently
   requires the canonical installed recipient. No custom trust constructor
   grants secret transmission authority. Secret-bearing IPC also refuses a
   kernel peer in the sender's own process.
2. **Every name collision fails closed.** `bind` never unlinks an existing
   name, including a dead socket left by a killed process. A graceful owner
   removes only its own socket inode on drop. Recovery from an ungraceful exit
   requires explicit removal of the stale name before starting a daemon.
3. **`SO_PEERPIDFD` comes from `nix`, liveness from `poll`.** rustix 1.1.5
   has no `SO_PEERPIDFD` wrapper; `nix` 0.31.3 (`socket` feature only) has a
   safe one used by the shared local authentication owner. IPC also uses nix
   for its private control pair. The design names
   `pidfd_send_signal(pidfd, 0)` for the liveness check, but rustix's
   `Signal` cannot be 0 without `unsafe`; a pidfd polls readable once its
   process has exited, so "not readable" answers the same question (and also
   refuses a zombie). Kernels before 6.5 have no `SO_PEERPIDFD`: every peer
   is refused there. A caller whose pid is not visible (another pid
   namespace) is refused.
4. **Private postcard representations.** Each implemented role has its own
   fixed enum. Public secret-bearing commands implement no serde traits.
   Tickets borrow the protected receiving frame during decode; enum payloads
   reject trailing bytes, noncanonical values, unknown diagnostic keys and
   over-limit reports. The fixed version handshake precedes postcard decoding.
   Protocol version 3 replaces the earlier custom command layout.
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
   Tauri binary gets another name, change `CLIENT_BINARIES` in
   [`kickoff-local::trust`](../local/src/trust.rs).
9. **`Server::accept` does the handshake inline**, so a same-uid caller that
   connects and stalls delays the next accept by up to 1 s. Other uids are
   refused before anything is read.
10. **Cancelled I/O fails closed.** Dropping a polled `Client::call`,
    `Channel::recv` or `Channel::reply` before completion makes that endpoint
    permanently unusable. Later operations return `Closed`, so a held reply cannot
    answer another command and a partial frame cannot become a new request.
    Dropping an unpolled future leaves the endpoint usable. Completed calls,
    receives and replies preserve normal sequential use. Drop the endpoint
    and reconnect after cancellation; an already dispatched command is not
    rolled back.
11. **Ancillary data is refused by giving it no room.** Every read is a
    `recvmsg` with a zero-length control buffer, on both ends. The kernel
    then closes any `SCM_RIGHTS` descriptors itself (they never enter this
    process) and sets `MSG_CTRUNC`, which closes the channel. Credentials
    (`SCM_CREDENTIALS`, `SCM_PIDFD`) reach a reader only if it enables
    `SO_PASSCRED` or `SO_PASSPIDFD`; these sockets never do, so a caller's
    credential message is dropped by the kernel and cannot be refused or
    observed on the real socket. `si_7_credentials_close_the_channel` turns
    `SO_PASSCRED` on to prove that, if credentials ever arrived, the read
    would refuse them.
12. `ApprovalId` is the shared opaque 16-byte type in `kickoff-wire`, re-exported
    by `ipc` and `session`. Only session's admission owner mints an id and
    decides whether it is still current. Its byte conversion is the local
    channel encoding, with no effect on peer message formats.
13. **`PROTOCOL_VERSION` is 3**: role commands use private postcard enums.
    The fixed version handshake refuses earlier custom command layouts before
    decoding or a side effect.

Questions for the design:

- Should a role be tied to an executable (`Cli` only from `kickoff`,
  `UiMain` and `Overlay` only from `kickoff-ui`)? Today any trusted client
  binary may claim any served role.
- Is `ToggleOverlay` a kickoffd command (the CLI asks the daemon, which tells
  the UI) or should `kickoff --toggle-overlay` talk to the UI directly?
- `Report` replies carry `diag` fields; should `doctor` gain a `PathType` row
  for the socket itself?

Redacted for publication: machine names, paths and addresses replaced with generic terms.

# Round 2 resolution

Input: `r2-sol.md` (Sol 6.1, against draft 2). Section A: 27 RESOLVED, 44 PARTIAL. Section B: R2-1 to R2-15, of which R2-1 and R2-2 are critical. Section C: rebuttal verdicts. Section D: milestone-order changes. Output: `docs/design.md` draft 3 and `docs/SECURITY-INVARIANTS.md` (SI-n, now with a mutant per row).

## Outcome counts

| Outcome | Section A partials (44) | Section B findings (15) |
|---|---|---|
| Resolved structurally (the class is unreachable, and a row with a mutant enforces it) | 31 | 10: R2-2, R2-3, R2-4, R2-5, R2-6, R2-7, R2-8, R2-11, R2-12, R2-14 |
| Resolved, with the claim narrowed and the remainder recorded as a residual risk (design §6.5) | 11 | 3: R2-9, R2-10, R2-13 |
| Owner decision, with a recommendation, and the claim narrowed until it is decided | 2 (FILE-13, PRIV-17, Windows part) | 2: R2-1 (decision 5), R2-15 (decision 24) |
| Rebutted | 0 | 0 |

Section C: NET-1 and NET-4 hold as Sol found; **NET-15 is conceded**, and draft 3 removes "can only break the dial". Section D: all seven changes are applied (§7 below).

## 1. Classes

By the maintainer's rule, the findings were classified before they were fixed: a class that appears twice appears a third time. Round 2 adds six classes to round 1's A to K (design §6.2).

| Class | Root cause in draft 2 | Structural rule in draft 3 | Findings |
|---|---|---|---|
| L | A sandbox inherited ambient authority: display sockets, open descriptors, inherited handles | **Authority is enumerated, not inherited.** Allowlists of descriptors, handles, mounts and protocol globals; everything else is closed or absent | R2-2, R2-4, R2-5, FILE-13, FILE-15, PRIV-17 |
| M | A contained component's statement was trusted as a verdict | **Contained components produce data, never verdicts.** The helper holds pipes only; `store` hashes; labels authorize nothing | R2-6, FILE-16, FILE-17, FILE-18, FILE-19 |
| N | The game was not modelled as an attacker of its own install, resources and desktop | **The game is an attacker.** Read-only copy generations, the online install absent, cgroup limits, gamescope; Windows contained mode or a disclosed residual | R2-1, R2-2, R2-7, R2-8 |
| O | Authority was not tied to the lifetime of the thing it authorizes | **Every grant is held through a handle to its subject**: cgroup, pidfd, service-held process handle, generation lease | R2-3, R2-7, FILE-3, FILE-8, FILE-21, FILE-22, PRIV-4, PRIV-10, PRIV-16, PRIV-19, NET-1, NET-3, NET-12 |
| P | A dependency chose destinations or did pre-authentication work outside Kickoff's policy | **The egress guard sits on the send path; budgets sit before the handshake on every endpoint** | R2-9, R2-10, R2-13, PRIV-25, PRIV-26, NET-7, NET-9, NET-10, NET-15, NET-18 |
| Q | Agreement or freshness was mistaken for trust | **Approval binds inputs; freshness is persisted state** | R2-11, R2-12, PRIV-7, PRIV-8, PRIV-20, PRIV-21, PRIV-22 |

Findings that are specification gaps inside existing classes rather than new classes: PRIV-3, PRIV-6, PRIV-23, PRIV-24, PRIV-28, PRIV-29, PRIV-30, FILE-10, FILE-11, FILE-20, NET-11, PRIV-14, PRIV-27, PRIV-18, R2-14 and R2-15.

**Tests that would pass without their mitigation** (Sol's cross-cutting observation) are a class of their own. Every SI row now names a mutant: the mitigation removed. SI-33 refuses a release in which a mutant passes its test.

## 2. R2-2: gamescope verdict

**Adopted**, as a nested compositor in its own sandbox, behind a Kickoff allowlist filter and a compositor security context (design §3.2.1). Evidence, all gathered on the reference machine on 2026-10-11 with read-only commands, scratch scripts and source clones at the pinned versions:

| Question | Finding | Evidence |
|---|---|---|
| Is draft 2's exposure real? | Yes, on both protocols. Host Xwayland `:0` accepts a client with no cookie and offers XTEST. The host Wayland socket offers 71 globals, including virtual keyboard and pointer, two data-control protocols (read the clipboard without focus), screencopy, toplevel export, layer shell and global shortcuts | (V) `xq.py`; `wlglobals.py` → `globals-host.txt` |
| Does the gamebox's network namespace help? | No. A pathname socket bind-mounted into `unshare -rn` still connects. Only the mount view decides | (V) `abs.py` |
| Is gamescope available? | `gamescope 3.16.28-1` in Arch `extra`, not installed | (V) `pacman -Si gamescope` |
| What does gamescope ask of the host? | 18 globals; 10 are mandatory: compositor, subcompositor, xdg_wm_base, linux-dmabuf, viewporter, presentation, relative pointer, pointer constraints, shm, seat | (V) `WaylandBackend.cpp:2005, 2813` and its bind list |
| What does it send back to the host? | One toplevel window with a title and icon, a cursor, dmabuf buffers, pointer lock while focused, and **the game's X11 clipboard and primary selection**. That last one is a write-only, game-to-host path: the Wayland backend never reads host offers | (V) `steamcompmgr.cpp:5958-6003`, `WaylandBackend.cpp:1305-1336`; no data-offer listener in the backend |
| Does Hyprland gate that clipboard write? | No. `set_selection` is accepted from any client without checking focus or serial | (V) Hyprland v0.56.2 `DataDevice.cpp:248-262` |
| What can the game reach inside gamescope? | gamescope's own Xwayland (XTEST there affects only the game's own windows), gamescope's EIS socket and gamescope's Wayland socket, which exist only in gamescope's sandbox unless Kickoff mounts them. Gamescope unsets `WAYLAND_DISPLAY` for children | (V) `main.cpp:1034, 1075-1097`; `InputEmulation.cpp` |
| Does it need a child, PipeWire or SDL? | It runs without a child command. Without PipeWire it only warns. The SDL backend copies the **host** clipboard into the game, so it is rejected | (V) `steamcompmgr.cpp:8516-8545`, `main.cpp:1100`, `SDLBackend.cpp:666` |
| Can the host connection be restricted? | Yes, twice over. Hyprland hides all but a whitelist of globals from security-context clients (`ProtocolManager.cpp:348-403`, `Compositor.cpp:262-266`). On the reference machine the flatpak security-context socket offers 40 globals and none of the dangerous ones. All 10 of gamescope's mandatory globals are among the 40 | (V) source; `globals-secctx.txt` |
| What does Kickoff's filter remove beyond that? | The two clipboard globals (gamescope's write path), the toplevel-icon global, and anything a future compositor whitelist adds. 14 globals pass | design §3.2.1 |

What a compromised game can do to the host afterwards: draw one window, receive input while focused, and lock the pointer while focused. A second exploit (Xwayland or gamescope) lands in the display sandbox: no home, no network, a 14-global host connection. That is recorded in §6.5.

**What M0 must verify** (design §3.2.5): (f) XTEST, virtual-keyboard, clipboard read and write, capture, toplevel enumeration and layer-shell probes against canary host apps, with no host effect; (g) the game's descriptor inventory is stdio only; (k) a registry dump through WlFilter equals the 14 globals; and from M1, (a) the game boots under gamescope through the filter on Hyprland, and (m) the frame time and input-latency cost against the budget in design §7. If gamescope cannot run the game, decision 4 holds Linux rather than mounting host display sockets.

Rejected alternatives:
- Bind-mounting host sockets with a Wayland-only filter: XTEST on X11 remains.
- A bare Xwayland per game: it needs a Wayland compositor of its own, which is what gamescope is.
- Xephyr or Xvfb with streaming: slow, and still X11 inside.
- The SDL backend: host clipboard into the game.
- The flatpak security context alone: compositor-dependent, and it still passes the clipboard.

## 3. R2-1: options for Windows game containment

Ban safety against a **compromised** game cannot hold on Windows while the game runs as the player. On Linux it holds, because the online install is not in the gamebox.

| Option | What it is | Security | Cost | Player experience |
|---|---|---|---|---|
| **A. Contained account** | The elevated install creates a hidden local standard account. kickoff-svc logs it on with S4U, sets **Low integrity** and starts the copy in the player's session. The WFP permit is bound to that account and process (SI-40) | Low integrity blocks writes to the online install, launcher files and the player's registry even where ACLs allow Users (no-write-up), and blocks input injection, hooks and messages into the player's windows (UIPI). The separate profile keeps launcher tokens, browser data and the online game's config and saves unreadable and unshared. Residual: files readable by every local account | Large. Account creation, an S4U launch path in the service, Kickoff holding an Epic refresh token, a `LaunchGame` pipe command. Steam copies probably do not work (cross-user Steam IPC, U). That Rocket League and EOS run at Low integrity is the main unknown (W1b) | One "Sign in with Epic". One UAC at install. Disk about 0 with hardlinks (hardlinked files stay readable through the Users ACE, and Low integrity prevents writes through them) |
| B. Windows Sandbox or Hyper-V VM | The game in a VM with GPU partitioning | Strong | Huge; Pro editions only; poor GPU performance | Not viable for players; **rejected** |
| C. Same-user copy with disclosure | The copy runs as the player | Kickoff causes no ban risk, but a compromised game can modify the online install and read launcher tokens: the same exposure as today's manual map swapping, without Kickoff's own writes | Small | No admin needed for solo; a residual-risk notice at install and per session |
| D. Stock only with disclosure | The online install, launched by the launcher without anti-cheat; no copy | Peer packets still reach the online game, so a compromised game is still the online install. No custom maps | Smallest (draft 2's path) | Leaves the target player (Lethamyr's maps on Windows) with nothing |
| E. No Windows peer sessions | — | — | — | Windows players excluded |

**Recommendation** (decision 5): build and verify **A** in the Windows spike W1, which runs beside M1. It is the only option that gives both priorities: security, and the audience requirement that arrived during this round. If W1 shows A cannot work, the owner chooses between:
- **C**, for solo and catalog maps, with disclosure, and peer maps only from hosts the player marks trusted. This is my pick, because it serves the audience at a residual equal to today's practice.
- **D**, if Windows players' ban exposure outweighs serving them.

The owner's own machines are Linux and contained in every option. Until decision 5 is made and verified, SI-34 is scoped to Linux, and design §1.2 claim 3 says so.

## 4. Section A partials

| Id | Outcome | Resolution in draft 3 | Invariant |
|---|---|---|---|
| FILE-3 | Resolved | Stock mode: the service binds the permit to one process it holds by handle, matched on image file ID, SID, logon session and an exact `-noeac` element read from the process; ETW revokes on a second instance (§3.3) | SI-40 |
| FILE-8 | Resolved | Immutable generations; launches, `set_map` and `reset_map` hold a lease; GC needs the exclusive lock; concurrency test with barriers (§5.3) | SI-39 |
| FILE-10 | Resolved | NTFS on fixed volumes only; `FileRenameInfoEx` with POSIX semantics after a flush; read-back of the slot's file ID and hash after any failure; VM injects sharing violations and disk full; ADS and ACLs are not carried, because staging creates new files (§5.3) | SI-4 |
| FILE-11 | Resolved, narrowed | Ordering: file `fsync`, rename, parent `fsync`; marker-name publication and deletion. A crash-state model enumerates POSIX-permitted post-crash states. The claim excludes real power-loss testing (§5.3, §9) | SI-4 |
| FILE-13 | Linux resolved; Windows decision | Linux: gamescope display sandbox and filter (R2-2). Windows: decision 5 | SI-34, SI-35 |
| FILE-15 | Resolved | Exact LPAC attributes, handle list, child-process policy, suspended creation, Job before resume, kill-on-close; Linux descriptor sweep with type checks; startup-phase kill test (§5.6) | SI-15, SI-36 |
| FILE-16 | Resolved | No writable handle in the helper; kickoffd counts bytes. The game's prefix is a capped tmpfs inside the game cgroup; refresh disk is reserved first (§5.3, §6.3) | SI-23, SI-37, SI-38 |
| FILE-17 | Resolved | `store` hashes while writing; the helper reports no hash; commit compares `store`'s hash (§5.2) | SI-37 |
| FILE-18 | Resolved | UE3 fixtures for offset and count arithmetic; the supported (version, licensee) table measured in M1; a forged "compatible" result authorizes nothing (§5.1) | SI-15, SI-37 |
| FILE-19 | Resolved | kickoffd compares the receipt's claimed hash with its own; no "tested" label exists; tests for failed and mismatched receipts and source mutation (§5.5) | SI-37 |
| FILE-20 | Resolved, narrowed | No core dumps (dumpable 0, core limit 0, WER excluded); broker stderr to `/dev/null`; a crash canary test. Residual: the one-time code is visible in the game's argv to the same user (§6.4) | SI-30 |
| FILE-21 | Resolved | Lease contract: caller SID, logon session and kickoffd handle; the service derives the target game itself (§3.3) | SI-8, SI-40 |
| FILE-22 | Resolved | The service checks the exact argv of the bound instance, not an argv builder; the VM test launches externally with substrings and quoting (§3.3) | SI-40 |
| PRIV-3 | Resolved | `/DEPENDENTLOADFLAG:0x800`; a CI import audit; DLL planting beside the installer, in the working directory and in `%TEMP%` for every name an ETW trace saw; repair and upgrade included (§3.3) | SI-6 |
| PRIV-4 | Resolved | As FILE-21, plus `SERVICE_CONTROL_SESSIONCHANGE` revocation | SI-8, SI-40 |
| PRIV-6 | Resolved | A complete pipe state machine; stateful fuzzing of command sequences (§3.3) | SI-8 |
| PRIV-7 | Resolved | Installers embed their record and refuse below the persisted highest version or `min_safe_version`; repair is allowed; anti-rollback survives uninstall (§8.4) | SI-25 |
| PRIV-8 | Resolved | Provenance approval (`cargo vet`, a signed tag, approved toolchain and vendor diffs, test evidence on the exact hash) on top of reproduction (§8.4) | SI-26, SI-27 |
| PRIV-10 | Resolved | Device, registry and ACL change subscriptions during a lease, plus a 5 s re-check; the VM mutates state after opening (§3.3) | SI-28 |
| PRIV-14 | Resolved | Immutable approvals (R2-14); a sign-in window with no capabilities (§2.7, §4.4) | SI-9, SI-41 |
| PRIV-16 | Resolved | Instance and user binding (R2-3). Residual: the ETW detection window, measured (§3.3) | SI-40 |
| PRIV-17 | Linux resolved; Windows decision | As FILE-13 | SI-34, SI-35 |
| PRIV-18 | Resolved | The shared-server option is withdrawn; a dedicated relay host with an egress firewall and a canary probe (§8.5, decision 12) | SI-32 |
| PRIV-19 | Resolved | Game death: cgroup kill (Linux) and the service's handle wait (Windows); a ledger written before every install step, with VM interruption tests (§3.2.2, §3.3) | SI-12, SI-38 |
| PRIV-20 | Resolved, narrowed | Root epochs, recovery-key-signed rotations, persisted highest epoch, hardware-token custody (decision 27). Lost recovery key: out-of-band re-bootstrap only (§8.4) | SI-25, SI-26 |
| PRIV-21 | Resolved | Freshness only from verified unexpired records; persisted highest values; clock-rollback detection; explicit expired-record and stale behaviour (§8.4) | SI-25 |
| PRIV-22 | Resolved | Players never evaluate a fetched recipe: AUR pins are independent of GitHub; builders build from the signed tag (§8.4) | SI-24 |
| PRIV-23 | Resolved | Frontend `osv-scanner`, pinned and Authenticode-checked NSIS and WebView2, tap advisories, response deadlines, expiring exceptions (§8.3) | SI-27 |
| PRIV-24 | Resolved | Side-by-side versions, a single `ImagePath` switch with rollback, VM interruption at each step (§8.4) | SI-10 |
| PRIV-25 | Resolved, narrowed | The send guard covers transport-generated destinations. Residual: bounded encrypted probes (§3.4) | SI-29 |
| PRIV-26 | Resolved, narrowed | Issuer accounting, audience-scoped vouchers, revocation, limits before admission. An open relay is abuse-limited, not access-controlled (§8.5) | SI-32 |
| PRIV-27 | Resolved, narrowed | A revocation notice signed by the old key; a two-device test. Backups of the Linux key file are the owner's; reset is the remedy (§3.4) | SI-22 |
| PRIV-28 | Resolved | A retention test with a controlled clock; relay-only has no IP transport, so no direct packets across reconnects or route changes (packet capture) (§6.4) | SI-29, SI-30 |
| PRIV-29 | Resolved | `JoinRequest` and `Hello` deadlines, awaiting-request caps, Ping and Pong idle close (§4.5, §6.3) | SI-23 |
| PRIV-30 | Resolved | Checks bound to the exact artifact hash, mutants, platform scope; the owner owns incidents with response deadlines; emergency stop locally and through `min_safe_version` (§8.3, §8.4) | SI-33 |
| NET-1 | Resolved | Windows instance binding (R2-3); Linux was already resolved | SI-11, SI-40 |
| NET-3 | Resolved | As FILE-21 | SI-8, SI-40 |
| NET-7 | Resolved, narrowed | Budgets before the handshake on both endpoints, `retry`, per-source caps; the leaked-endpoint flood test. Floods can delay new joins (§3.4, §6.3) | SI-23 |
| NET-9 | Resolved, narrowed | As PRIV-26 | SI-32 |
| NET-10 | Resolved, narrowed | Admitted peers can share the endpoint, and its candidates register before the hook. The privacy claim holds only for relay-only sessions; "Anyone with the link" sessions are relay-only (§3.4, decision 19) | SI-31 |
| NET-11 | Resolved | WFP layers, weights, hard actions, IPFORWARD blocks and forwarding disabled on the adapter, all specified; a VM arbitration matrix with ICS and firewall rules (§3.3) | SI-11, SI-40 |
| NET-12 | Resolved | The service ends the lease on game exit; pasta and the namespace are in the game cgroup (§3.2.2, §3.3) | SI-12, SI-38 |
| NET-15 | Resolved, narrowed; rebuttal conceded | The send guard and the destination policy bound the network effects before authentication; the ticket-authenticity statement is rewritten (§3.4, §4.2) | SI-29 |
| NET-18 | Resolved, narrowed | The promise is narrowed: after the handshake, invalid traffic cannot starve bound and trusted identities; a pre-handshake flood can delay all new joins (§6.1, §6.5) | SI-23 |

## 5. Section B findings

| Id | Sev | Outcome | Resolution in draft 3 | Invariant |
|---|---|---|---|---|
| R2-1 | critical | Owner decision 5; claim narrowed | Options and recommendation in §3 above. SI-34 holds on Linux; on Windows only under option A; §1.2 claim 3 states the platform split | SI-34 |
| R2-2 | critical | Resolved | gamescope display sandbox, WlFilter (14 globals), security context; host X11 never mounted (§2 above, design §3.2.1) | SI-35 |
| R2-3 | high | Resolved | Lease contract; service-held instance handle; user-SID WFP condition; ETW single-instance revocation; full WFP layer and arbitration table; stock mode removed if binding fails (design §3.3) | SI-40, SI-8, SI-11 |
| R2-4 | high | Resolved | Startup descriptor sweep and type checks, Landlock ABI ≥ 6 with every right handled, startup probes for create, write, truncate, rename and unlink; a narrow supervisor that parses nothing hostile (design §2.1) | SI-36, SI-1 |
| R2-5 | high | Resolved | The helper holds pipes only; exact LPAC and Job policy; suspended start; kill on parent death (design §5.6) | SI-15, SI-36, SI-37 |
| R2-6 | high | Resolved | `store` writes and hashes; commit compares its own hash; a dishonest-helper test (design §5.2) | SI-37 |
| R2-7 | high | Resolved | Game cgroup (memory including the tmpfs prefix, pids), `cgroup.kill`, rlimits, pasta inside the cgroup; disk I/O bandwidth is a stated residual (design §3.2.2) | SI-38 |
| R2-8 | high | Resolved | Manifest-bound immutable generations, full validation, the bootstrap policy, atomic publication, leases, maintenance exclusion, no obsolete files (design §5.3) | SI-39, SI-2 |
| R2-9 | high | Resolved, narrowed | Budgets before and after the handshake on the session endpoint; the leaked-endpoint test; relay-only for bearer sessions; the address claim narrowed (design §3.4) | SI-23, SI-31 |
| R2-10 | high | Resolved, narrowed | Send-path guard (vendored iroh hook); gamebox deny set from host addresses and connected subnets, recomputed on route change; no host DNS forwarder; pasta mappings explicit. Residual: bounded probes (design §3.2.4, §3.4) | SI-29, SI-14 |
| R2-11 | high | Resolved | Provenance approval separate from reproduction; trusted toolchain acquisition by hash; both builders isolated, with the second builder as a VM without credentials for the maintainer's other systems (design §8.4, decision 11) | SI-26, SI-27 |
| R2-12 | high | Resolved | Root epochs; freshness state; explicit expired-record rules; manual-installer checks; `min_safe_version` behaviour when withheld (staleness shown, decision 16) (design §8.4) | SI-25, SI-26 |
| R2-13 | high | Resolved, narrowed | Issuer accounting, audience scoping, revocation by restart, limits before admission, shared-server option withdrawn, egress isolation (design §8.5) | SI-32 |
| R2-14 | medium | Resolved | Immutable single-use approvals with invalidation, one pending per kind, a dialog rate limit (design §4.4) | SI-41 |
| R2-15 | medium | Owner decision 24; SI-1 narrowed | An explicit broker: fixed argv, scrubbed environment, serialized against the launcher and its lock, stdout into a `Secret`, stderr discarded, no dumps; tested with fake expired credentials in M0 before any real account. Default (a) states legendary's `user.json` refresh as SI-1's one exception; (b) is a Kickoff-own sign-in (design §6.4) | SI-1, SI-30 |

## 6. Section C rebuttals

- **NET-1** (no denylist for 9014-9088): holds, as Sol found. `GamePorts` stays measurement-based.
- **NET-4** (no guest-to-guest forwarding in draft 1): holds, with the ambiguity conceded. The 3-node test stays.
- **NET-15**: conceded. "Can only break the dial" is removed. A substituted ticket leads to a different, untrusted host, which the join dialog's fingerprint and trusted-friend match expose, and dials before authentication are bounded by the send guard (design §3.4, §4.2).

## 7. Section D milestone changes, applied (design §10)

| Sol's change | Draft 3 |
|---|---|
| 1. Containment probes before a real account or hostile map | **M0** (no game, no account) gates M1. It covers display authority, inherited descriptors, descendants, resource budgets, pasta mappings and authentication-state writes (the broker against fake credentials) |
| 2. M3 and live M4 depend on minimum copy protections | **M5a** (generations, manifest validation, EAC policy, leases, owned prefix base, fail-closed launch) precedes M3 and M4 |
| 3. An early Windows copy, authentication and instance-isolation spike | **W1** beside M1: W1a in VMs (contained account, compromised-game probe, instance binding, WFP arbitration, LPAC), W1b on a GPU PC (boot under the contained token, Steam copy, hardlinks). M7 depends on W1a; M8 on W1 and decision 5 |
| 4. M6 depends on tested parser confinement on both platforms | **M6a** precedes M6 and M14; it includes the writable-handle and dishonest-helper cases |
| 5. Split M11 | **M11a** (bootstrap verifier, isolated builders, provenance approval, reproducibility, root and freshness state machine, signing route) can start beside M3; **M11b** completes distribution after M10 |
| 6. Relay vouchers before M12's claim | M12's row now requires issuer quotas, active revocation, voucher replay and pre-authentication flood tests (SI-32) |
| 7. Real peer sessions gated on compromised-game tests | A gate above the table: M4, M9 and any hand-delivered alpha need SI-34 to SI-36 and SI-38 (Linux), or SI-34 in contained mode or the shipped decision 5 disclosure (Windows) |

## 8. Interaction with the owner's 2026-10-11 audience requirement

- **R2-1's recommendation changed.** Draft 2's default ("stock maps only on Windows") fails the new target player, so contained mode A, which serves both priorities, is recommended over D.
- **First-install trust (PRIV-1) now needs signing for a public link.** Smart App Control blocks unsigned installers outright (decision 10, with SignPath Foundation's free open-source signing as the first option).
- **The maintainer's own server drops out of distribution and the relay**, which removes an exposure of the maintainer's other services: downloads move to GitHub Releases and a static landing page.
- **Solo play needs no networking component**, so the LAN driver and service install only on first multiplayer use (least privilege).
- **https invite links** keep the ticket in the URL fragment (design §4.2).
- **The map catalog** is a signed, reviewed list; downloads come from authors' sites on the player's machine; images are decoded in `kickoff-parse` (design §5.7).

## 9. M2 impact

M2's scope is unchanged: `wire`, `vlan::Mem`, the `net` door and session endpoints, `session` admission and budgets, `ipc` on Linux, and `secret`. The changes below are the only ones a round-2 finding requires in those crates. Everything else in draft 3 lands in later milestones; see "Not M2" at the end.

**`wire`:** no change. No message, header, ticket or close code changes. The `Hello` deadline and the Ping/Pong idle close use existing messages.

**`vlan::Mem`:** no change.

**`net` (door and session endpoints):**
1. **Interface:** `net::session(relays, bind: SessionBind, role)` with `enum SessionBind { Direct(IfaceAddr), RelayOnly }`, replacing `bind: IfaceAddr` (R2-9). `RelayOnly` builds the endpoint with no IP transport and with QAD probes off, so it owns no UDP socket.
2. **Dependency:** iroh 1.3.0 is vendored under `vendor/iroh-1.3.0` with one patch, wired with `[patch.crates-io]`. The patch is a call to `SendGuard::admit(dst)` in `socket/transports/ip.rs` `poll_send` before the first packet to each destination (R2-10). A CI check compares the vendor tree with the upstream crate hash plus that patch.
3. **New internal module:** `net::egress::SendGuard`, implementing the §3.4 policy: global or connected-subnet only; not the host's own addresses, gateway, resolver, loopback, link-local, 100.64/10, 10.75/16, multicast or broadcast; port ≥ 1024 and not on the denylist; ≤ 8 unvalidated destinations per remote, ≤ 4 new per second; a per-connection cache; recomputed on route change. In-process tests drive it through a recording seam; packet capture comes in M3.
4. **Behaviour:** the session endpoint gets the same pre-handshake policy as the door: ≤ 16 pending `Incoming`, `retry` for unvalidated addresses, ≤ 8 handshakes per second per source and ≤ 64 per second overall. The door holds ≤ 16 connections awaiting `JoinRequest`, ≤ 2 per identity.
5. **Tests:**
   - SI-29: guard unit tests (malicious NAT-traversal candidates on own address, gateway, resolver, low ports, more than 8 destinations, interface change), plus `mutant-si29-no-send-guard`.
   - SI-31, rewritten: the leaked-endpoint test. An admitted peer passes the endpoint on; an outsider completes a rejected handshake and records candidates; relay-only shows none. Plus `mutant-si31-unbound`.
   - SI-23 additions: a leaked-endpoint flood with fresh identities; handshakes that never send `JoinRequest` or `Hello`.

**`session` (admission and budgets):**
1. **Interface:** `Command::Approve(id)` becomes `Command::Decide { approval: ApprovalId, allow: bool }`. `SessionEvent::ApprovalRequested(Approval)` is added. New types: `Approval { id, action, peer: Fingerprint, generation }`, `ApprovalId` (128-bit random, opaque) and `enum ApprovalAction { AdmitBearer, InstallMap { map: MapId } }` (R2-14). `InstallMap` is used from M6; the type lands now so the enum does not change again.
2. **Behaviour:**
   - Approvals are created only by the admission owner and consumed atomically. A kick, a reconnect, a map change, the end of the session or a 60 s timeout invalidates them.
   - One approval is pending per kind; a second bearer `JoinRequest` while one is pending is refused at the door.
   - `Hello` within 2 s on the session endpoint.
   - The host sends `Ping` every 5 s and closes a link with no `Pong` for 15 s (PRIV-29).
3. **Tests:**
   - SI-41 (object part): approvals raced against kick, reconnect, map change and session end; old ids authorize nothing. Plus `mutant-si41-approve-by-peer`.
   - SI-23: silent and idle connections count against fixed caps. Plus `mutant-si23-no-hello-deadline`.
   - SI-18 to SI-20: mutants added (`mutant-si18-no-gen-check`, `mutant-si19-trust-overrides-kick`, `mutant-si20-nonatomic-nonce`); SI-21 gets a link-to-link-route mutant.
4. **Budget table changes** (design §6.3) to carry into config constants: the rows for both endpoints before the handshake, the door after the handshake, the session endpoint after the handshake, and approvals.

**`ipc` (Linux):**
1. **Caller authentication:** use `SO_PEERPIDFD`. Read the peer's `exe` through `/proc/<pid>`, then confirm the pidfd is still live (`pidfd_send_signal(pidfd, 0)`), so a recycled PID cannot pass (SI-7).
2. **No ancillary data on client channels:** a message with `SCM_RIGHTS`, credentials or `MSG_CTRUNC` closes the channel after closing any received descriptors.
3. **Role enums:** the UI main-window role gains `Decide { approval: ApprovalId, allow: bool }`, used only by the native dialog path. The overlay role does not get it.
4. **Tests (SI-7):** PID-recycle and ancillary-data cases, plus `mutant-si7-pid-not-pidfd` and `mutant-si7-accept-ancillary`.
5. **Hardening integration:** Linux denies executable inspection of a nondumpable peer. An inspectable, secret-free listener facade therefore authenticates callers and transfers untouched sockets over its private inherited control pair to the nondumpable worker. Clients verify the kernel's listener identity; the worker pins the facade's lifetime and rechecks callers. Private descriptor capabilities have exact counts and types, a live connection cap and no public ingress. The real installed daemon modes and a ticket round-trip test cover this composition, alongside control, descriptor, lifetime and budget mutants.

**`secret`:**
1. **Interface:** `Secret<T>` loses `Clone`, if it has it, and zeroizes on drop. `secret::harden_process()` sets `PR_SET_DUMPABLE 0` and `RLIMIT_CORE 0` in the kickoffd worker before secrets exist. The inspectable facade uses both core limits set to 1 and a real startup crash probe, because 0 alone does not suppress a Linux piped core handler. No host core-handler configuration changes, and failed suppression verification refuses startup. Design §6.4 records the kernel mechanism.
2. **Tests (SI-30):**
   - the compile-fail test adds `Clone`;
   - a crash test: a child holding a canary crashes, and no core file or coredumpctl entry exists;
   - `mutant-si30-dumpable`.

**Test harness (SI-33):**
- Cargo features `mutant-si<N>-<slug>` in the M2 crates for SI-3, SI-7, SI-18 to SI-23, SI-29, SI-30, SI-31 and SI-41.
- `scripts/check.sh` runs each mutant and expects its test to fail.
- A release check refuses any build with a mutant feature enabled.
- The policy test parses the new **Mutant** and **Scope** columns of `SECURITY-INVARIANTS.md`.
- SI-3 gets `mutant-si3-path-field`.

**Invariants M2 must turn green:** SI-3, SI-7 (Linux), SI-10 (channels), SI-18 to SI-23, SI-29 (tickets and the guard unit), SI-30 (types and hardening), SI-31, SI-33 and SI-41 (the approval object). New to M2 since draft 2: SI-41, the mutants, and the SI-29 guard unit.

**Not M2** (listed so the build swarm does not pull them in):
- the Landlock and descriptor sweep (M3 and M5);
- `store::Staged` (M5);
- `parse` pipes and LPAC (M6a);
- WFP and instance binding (W1a and M7);
- the identity revocation notice (M10, `wire` gains a type then);
- relay vouchers (M12, `wire` gains a type then);
- the packet-capture half of SI-29 (M3).

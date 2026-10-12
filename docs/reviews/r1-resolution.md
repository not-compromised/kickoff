Redacted for publication: machine names, paths and addresses replaced with generic terms.

# Round 1 resolution

Inputs: `r1-sol-files.md` (FILE-1..22), `r1-sol-priv.md` (PRIV-1..30) and `r1-sol-net.md` (NET-1..19): 71 findings, of which FILE-1, FILE-2 and PRIV-1 are critical. Output: `docs/design.md` draft 2 and `docs/SECURITY-INVARIANTS.md` (SI-n).

The findings were grouped into classes before anything was fixed. For each class, the revision picks one structural change that makes the whole class unreachable, rather than a check for each instance. Most classes were found independently by two or three of the reviews (for example FILE-21, PRIV-4 and NET-3; FILE-13 and PRIV-17; NET-9 and PRIV-26). By the maintainer's rule, a class that appears twice will appear a third time.

## Classes

| Class | Root cause in draft 1 | Structural mitigation (design §) | Findings |
|---|---|---|---|
| A | Ban safety rested on reacting to a modified **shared** install: a proof built from passive signals, restore triggers, and manifest-aware recovery | **Offline copy.** Kickoff writes only into its own copy, which no launcher can start and which lacks the EAC bootstrap. The online install is a read-only type and a Landlock-denied path (§5.3) | 11 |
| B | Writes addressed by path; a privileged process writing into user-reachable trees | **`store` is the only writer.** Handle-relative, exclusive staging, atomic commit. kickoff-svc writes no files, and the installer refuses user-writable locations (§2.3, §3.3, §5.3) | 7 |
| C | Local socket, pipe and webview with no caller authentication or versioning | **Authenticated, exclusive, versioned, role-scoped channels.** Leases are connections; approvals happen in native dialogs (§2.7) | 8 |
| D | Peer reachability decided by port numbers in a namespace shared with every host service | **Peers land in a namespace that holds only the game** (Linux gamebox). On Windows, **WFP admits only the game's image** on the Kickoff interface. The peer-facing network dies with its owner (§3.2, §3.3) | 7 |
| E | Session authority not bound to identity and connection generation | **One admission owner.** Every resource carries (identity, generation); revocation dominates trust; roles are directional (§4.3, §4.4) | 5 |
| F | Resource budgets applied after allocation | **Charge before allocate**, with fixed-capacity queues, tables and pools (§6.3) | 7 |
| G | Bootstrap, update and third-party binary trust anchored on the download server or on install-time checks | **The download server and build inputs are untrusted.** An offline-signed release record with an independently delivered root; reproduced builds; the driver re-verified at use (§8.3, §8.4, §3.3) | 9 |
| H | Hostile formats, and the game itself, parsed or run with the user's full authority | **kickoff-parse** (no filesystem, network or exec) for every hostile format, and the **gamebox** for the game (§5.6, §3.2) | 5 |
| I | Untrusted data choosing outbound destinations | **One egress policy**: compiled relay map, compiled importer origins checked on redirects and the connected address, filtered direct addresses (§3.4, §5.7) | 3 |
| J | Secrets and metadata leaving through unstructured output; addresses disclosed before admission | **Typed secrets and schema-built diagnostics**; session endpoint known only to admitted peers (§6.4, §3.4) | 4 |
| K | A public relay sharing a host and trust with the maintainer's other services | **Isolated relay** admitting enrolled identities, with per-identity and aggregate caps (§8.5) | 4 |
| — | Invariants were not release requirements | `SECURITY-INVARIANTS.md` plus the release gate (§9) | 1 |
| | | **Total** | **71** |

## Options evaluated

| Option | Verdict | Evidence |
|---|---|---|
| a. Dedicated offline game copy | **Adopted on both platforms.** On Linux it is a reflink copy. On Windows it is a full copy, and its launch path is an owner decision | `/home` is btrfs `subvol=/@home`, `compress=zstd:3`, with 3.0 TB free; the install is 41 GB in 20,953 files, none NOCOW (`findmnt`, `df`, `du`, `lsattr -R`). A reflink of 2000 files took 24 ms with 0 exclusive bytes (`btrfs filesystem du`). Windows: no reflink on NTFS; ~41 GB copy (L) |
| b. Rootless network namespace for the game | **Adopted (the gamebox)**, run through native umu rather than the Heroic flatpak | pasta and slirp4netns are not installed; `passt` (extra) and `umu-launcher` (multilib) are available. Landlock is active and unprivileged user namespaces are enabled. The flatpak shares `~/.local/share/umu` with the host. Wine with taps and nft already worked in `unshare -rn` (captured evidence, not published). M1 checks (a)-(e) in §3.2 cover the portal fact; the fallback needs owner decision 4 |
| c. Hostile parsers in an unprivileged, limited helper | **Adopted (kickoff-parse)**. Hot-path fixed formats stay in-process under `forbid(unsafe)` with fuzzing | §5.6 |
| d. First-install trust | **Both**: Authenticode for Windows, plus the root fingerprint published independently of the download server. The cost (Azure Artifact Signing about $9.99/month, or OV $150-300/year plus a token) is owner decision 10. Until then, the owner hands builds over directly | §8.4 |

## Findings

Rebuttals are partial: each rejects one claim within a finding and accepts the rest.

| Id | Sev | Class | Resolution | Invariant |
|---|---|---|---|---|
| FILE-1 | critical | A | Online launches cannot reach Kickoff's bytes: Kickoff writes only the copy, which no launcher can start (§5.3) | SI-1 |
| FILE-2 | critical | B | kickoff-svc no longer writes files. Windows map writes are user-mode `store` writes into a user-owned copy (§3.3, §5.3) | SI-4, SI-6 |
| FILE-3 | high | A | `NoEac` is removed. Kickoff launches the game itself, from the copy, with an exact `-noeac` argv element and a pidfd (§5.3, §8.1) | SI-2 |
| FILE-4 | high | A | The proof's lifetime no longer matters, because writes never touch a file an EAC process can load (§5.3) | SI-2 |
| FILE-5 | high | A | No stock digest is needed for safety. The Epic digest is SHA-1 (`mf.py:12-13`), which corrects draft 1's SHA-256 claim; it is used only to refresh the Windows copy (§5.1, §5.3) | SI-1 |
| FILE-6 | high | A | Updates and Verify act only on the online install, which Kickoff never writes; a build change rebuilds the copy (§5.3) | SI-1 |
| FILE-7 | high | A | No recovery state can leave the online install modified, because Kickoff never modifies it (§5.3) | SI-1 |
| FILE-8 | high | A | No leases and no restore. One per-copy writer lock; every intermediate state is stock or a verified map, neither of which matters for ban safety (§5.3) | SI-3 |
| FILE-9 | high | B | Exclusive random staging names through `store`; nothing is written through an existing name (§2.3) | SI-4 |
| FILE-10 | high | B | `ReplaceFileW` is dropped. Commit is a handle-relative POSIX-semantics rename, user-mode, inside the copy (§5.3) | SI-4 |
| FILE-11 | high | B | Claim narrowed. The store's fault seam injects at every syscall, and staging debris is removed by prefix (§5.3, §9) | SI-4 |
| FILE-12 | high | A | Textures go only into the copy, from a compiled table; the online install is never touched (§5.3) | SI-1, SI-17 |
| FILE-13 | high | H | "Wine sandboxing" claim removed. Linux: the gamebox mount and network view, plus per-map approval. Windows: stated residual risk (§3.2, §6.5) | SI-14, SI-16 |
| FILE-14 | high | I | Egress policy: HTTPS, exact origins, redirects re-checked, connected address must be global, no cookies (§5.7) | SI-29 |
| FILE-15 | high | H | Zip entries stream fd-to-fd in kickoff-parse with no path materialized; HTML is decoded there to text fields (§5.6) | SI-15 |
| FILE-16 | high | F | zstd runs in kickoff-parse with an 8 MiB window, compressed and output caps and an idle deadline; disk reservation and quota (§5.2, §6.3) | SI-15, SI-23 |
| FILE-17 | high | B | Snapshot ingest into immutable objects, verified on every use, with private staging per fetch and prefix-verified resume (§5.1, §5.2) | SI-4, SI-5 |
| FILE-18 | medium | H | `licensee` is now compatibility metadata only, structurally validated in kickoff-parse; textures come from a compiled table (§5.1) | SI-15, SI-17 |
| FILE-19 | medium | H | Claim 9 now says "saved". The receipt is validated in kickoff-parse against a snapshot; `source` confers no trust (§1, §5.5) | SI-16 |
| FILE-20 | medium | J | `Secret<T>` cannot be printed; diagnostics come from a schema; the exchange code never touches a file (§6.4) | SI-30 |
| FILE-21 | medium | C | The pipe caller is bound to SID and logon session; it is LAN-only, and a lease ends with its connection (§2.7, §3.3) | SI-7, SI-8 |
| FILE-22 | medium | A | The EAC-on option is removed from the design, protocol and decisions; no type can express it (§4.5, §11) | SI-2, SI-3 |
| PRIV-1 | critical | G | Authenticode plus a root fingerprint delivered independently; the installer embeds the root; hand-delivered alpha until signing exists (§8.4, decision 10) | SI-24 |
| PRIV-2 | high | B | No privileged writes into discovered paths. Discovery is read-only and user-mode, and slot ids are a fixed constant (§3.3, §5.3) | SI-4, SI-6 |
| PRIV-3 | high | B | Protected install directory; unsafe pre-existing directories refused; quoted `ImagePath`; `SetDefaultDllDirectories` (§3.3) | SI-6 |
| PRIV-4 | high | C | Token, SID, logon session and integrity checks; leases per connection (§2.7) | SI-7, SI-8 |
| PRIV-5 | high | C | `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, no create-instance right for clients; clients verify the server's token and image (§2.7) | SI-7 |
| PRIV-6 | high | C | The map byte stream is removed from the service. The pipe is a fixed five-message set with frames ≤ 1600 bytes and deadlines (§3.3, §6.3) | SI-3, SI-23 |
| PRIV-7 | high | G | `requireSignedVersion` enabled (confirmed default false: `config.rs:116`), plus a signed record with platform-bound artifacts (§8.4) | SI-25 |
| PRIV-8 | high | G | Isolated builder with no credentials for the maintainer's other systems; `--locked --offline`; two builders must reproduce before signing (§8.4) | SI-26, SI-27 |
| PRIV-9 | high | G | `SetupCopyOEMInfW` stages only, and `DiInstallDevice` installs on our device alone (§3.3) | SI-28 |
| PRIV-10 | high | G | Device, package, signer, `AllowNonAdmin` and ACL re-verified at every `LanOpen`; drift refuses (§3.3) | SI-28 |
| PRIV-11 | high | A | Same as FILE-3 and FILE-4: no proof lifetime matters (§5.3) | SI-2 |
| PRIV-12 | high | A | No `NeedsRepair` state can expose online play, because online files are never modified (§5.3) | SI-1 |
| PRIV-13 | high | D | The root fallback is deleted. Linux needs no root, and ships no pkexec, polkit or setuid binary (§3.2, §8.1) | SI-13 |
| PRIV-14 | high | C | Webview capabilities per window, strict CSP, text-only rendering, native approval dialogs, deep links parsed in Rust (§2.7) | SI-9 |
| PRIV-15 | high | C | 0700 runtime directory, exclusive bind, `SO_PEERCRED` plus exe check, client checks the server (§2.7) | SI-7 |
| PRIV-16 | high | D | The gamebox namespace holds only the game; on Windows, WFP is keyed on the app image (§3.2, §3.3) | SI-11 |
| PRIV-17 | high | H | Same as FILE-13 (§3.2, §6.5) | SI-14, SI-16 |
| PRIV-18 | high | K | Separate isolated relay deployment with nothing shared with CI or release staging (§8.5, decision 12) | SI-32 |
| PRIV-19 | medium | D | Session resources die with kernel objects (non-persistent tap in a namespace, dynamic WFP session). Install-time resources are recorded in a ledger and removed in reverse (§3.2, §3.3) | SI-12 |
| PRIV-20 | medium | G | Release and recovery roles split; the recovery key signs root rotations only (§8.4) | SI-26 |
| PRIV-21 | medium | G | Sequence, expiry, highest-seen state, a stale banner and `min_safe_version` (§8.4) | SI-25 |
| PRIV-22 | medium | G | PKGBUILD in this repository with pinned hashes and `validpgpkeys`; root delivered independently (§8.4) | SI-24 |
| PRIV-23 | medium | G | Exact pins (`=1.3.0`), `--locked`, pinned xwin SDK and CRT, cargo-deny and audit on PRs and weekly (§3.4, §8.3) | SI-27 |
| PRIV-24 | medium | C | Versioned channels and state; upgrade order quiesce → stop → stage → replace → start (§2.7, §8.4) | SI-10 |
| PRIV-25 | medium | I | Deep-link grammar ≤ 2 KiB, parsed in Rust; egress policy for relays, addresses and importers (§2.7, §3.4, §5.7) | SI-29 |
| PRIV-26 | medium | K | Token reclassified as abuse friction. Enrolled identities and vouchers, with per-identity and aggregate caps (§8.5) | SI-32 |
| PRIV-27 | medium | E | Per-device key, owner-only ACL, DPAPI on Windows; reset revokes trust (§3.4) | SI-22 |
| PRIV-28 | medium | J | Schema-built diagnostics with an export preview and retention; privacy consequences stated (§6.4) | SI-30 |
| PRIV-29 | medium | F | Pre-handshake caps, reassembly caps, a pipe deadline; no restore path exists to starve (§6.3) | SI-23 |
| PRIV-30 | medium | — | `SECURITY-INVARIANTS.md` with a release gate that refuses missing or skipped rows (§9) | SI-33 |
| NET-1 | high | D | The gamebox removes shared-namespace delivery; `GamePorts` is not configurable; flows are keyed by generation (§3.1, §3.2). **Partial rebuttal:** adding 9014-9088 to the denylist protects nothing. Those are remote PsyNet server ports the local game connects *to* (draft 1 §3.1 says so); no local service listens on them, and inside the gamebox there is nothing else to reach | SI-11 |
| NET-2 | high | D | The loopback proxy is gone. Peer-facing sockets exist only in the gamebox, where no other local process lives (§3.2) | SI-11 |
| NET-3 | high | C | Same as PRIV-4 (§2.7, §3.3) | SI-7, SI-8 |
| NET-4 | high | E | Guests accept no incoming connections; the session hook admits only door-issued passes (§3.4, §4.4). **Partial rebuttal:** draft 1 never fanned guest datagrams out to other guests. §2.4's fan-out applied to datagrams from the host's own game (`vlan.recv`); guest datagrams went only to `vlan.deliver`. Draft 2 makes this structural (no link-to-link path) and tests it | SI-21 |
| NET-5 | high | E | Revocation dominates trust and tickets; generation checks at delivery (§4.4) | SI-18, SI-19 |
| NET-6 | high | E | One live connection per identity, replaced only through reconnect with a generation bump (§4.4) | SI-18, SI-23 |
| NET-7 | high | F | `Incoming::refuse`, `retry` and `ignore` before TLS (`connection.rs:133-219`); at most 16 pending; the session endpoint is unknown to outsiders (§3.4, §6.3) | SI-23 |
| NET-8 | high | F | Charge before reassembly; header validated before allocation; reassembly caps; the per-port socket table is gone with the proxy (§3.4, §6.3) | SI-23 |
| NET-9 | high | K | Same as PRIV-26. `accept_conn_limit` is confirmed unimplemented (`server.rs:486`), so counting happens in our `AccessControl` (§8.5) | SI-32 |
| NET-10 | medium | J | Door/session split: only admitted peers learn the session endpoint, whose specific bind limits candidates (confirmed in `socket.rs:1922-1956`) (§3.4) | SI-31 |
| NET-11 | medium | D | Kickoff never edits Windows Firewall rules. A WFP block plus an app-scoped permit on the Kickoff interface only (§3.3) | SI-11 |
| NET-12 | medium | D | Fail closed by lifetime. The `store=active` claim is corrected: the WFP block persists, the permit is dynamic and the tap is non-persistent (§3.2, §3.3) | SI-12 |
| NET-13 | medium | E | Atomic nonce states, monotonic deadlines, and refusal of tickets from another session (§4.4) | SI-20 |
| NET-14 | medium | J | Tickets are `Secret`; bound invites by default; the bearer prompt shows the verified fingerprint and warns that the link is transferable (§4.2, §6.4) | SI-30 |
| NET-15 | medium | I | Ticket relay URLs used only when they match the compiled map; addresses filtered (§3.4). **Partial rebuttal:** that the signature does not cover `EndpointAddr` is not a separate weakness. TLS pins the door identity (the review lists this as sound), so altered addresses can only break the dial, and anyone able to alter a ticket can mint a whole new one. Ticket authenticity rests on the channel that carried it, which §4.2 now states | SI-29 |
| NET-16 | medium | F | Control, stream-open and map-request budgets. Transfer scheduling uses the host's own game state, never peers' reports (§3.4, §6.3) | SI-23 |
| NET-17 | medium | F | Global host egress charged per emitted copy; discovery payload capped; attempts counted (§6.3) | SI-23 |
| NET-18 | medium | F | Separate queue for bound and trusted identities after the handshake; per-identity and global invalid limits (§6.3) | SI-23 |
| NET-19 | medium | K | Complete listener inventory; metrics on localhost or off (default 9090, confirmed in `defaults.rs:16`). The "no presence" claim is narrowed: the door runs only while hosting and reveals presence then (§6.4, §8.5) | SI-32 |

## Review notes outside the numbered findings

- **Missing track JSON evidence** (raised by all three reviews): accepted. Draft 2's status block says how (V) claims without a retained artifact are handled, and each milestone re-runs the (V) claims it depends on.
- **Lethamyr download endpoint** (FILE review): accepted. The retained response is a 404, and §5.7 now marks the endpoint (U).
- **Open questions** in the reviews are answered in the sections cited above. Those that need the owner are in design §11: decision 5 (Windows launch path), 10 (signing) and 12 (relay).

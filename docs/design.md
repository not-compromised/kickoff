# Kickoff design

Status: draft 3, 2026-10-11. Revises draft 2 against the round-2 security review (`docs/reviews/r2-sol.md`: 44 partial resolutions, new findings R2-1 to R2-15, rebuttal verdicts and milestone-order changes) and adds the maintainer's audience requirement: an ordinary player gets from one link to a custom map with no technical steps. How every round-2 item was handled: `docs/reviews/r2-resolution.md` (round 1: `r1-resolution.md`). The standing security rules and the tests that enforce them are in `docs/SECURITY-INVARIANTS.md`; they are release requirements.

**Evidence tags.** **(V)** verified by a command, a source line at the pinned version, or a scratch experiment; **(L)** likely, from public documentation or source without a local test; **(U)** unverified. Linux (V) checks ran read-only on "the reference Linux machine" (Arch, kernel 7.2, btrfs `/home`, Hyprland 0.56.2, AMD RX 9060 XT, Heroic flatpak). Evidence logs were captured on the maintainer's machines and are not published. Each milestone re-runs every (V) it depends on.

Changes from draft 2:
- **Audience and onboarding** are a goal next to security: one link, solo maps in two clicks, a built-in map browser, measurable first-run targets, GPL-3.0 and free (§1, §5.7, §8.4).
- **Game display (Linux):** the game draws into a nested **gamescope** compositor in its own sandbox. It sees only gamescope's Xwayland. The host Wayland server is reached only by gamescope, through a 14-global allowlist filter plus a compositor security context. Host X11 is never mounted (R2-2, §3.2).
- **Gamebox resources and egress:** one cgroup with memory and process limits, torn down with `cgroup.kill`; an ephemeral tmpfs prefix; an egress deny set derived from the host's own addresses and connected subnets, recomputed on route changes; DNS through a public resolver instead of a host forwarder (R2-7, R2-10).
- **Contained components produce data, never verdicts.** `kickoff-parse` never holds a writable file. Its output streams through a pipe to kickoffd, which writes, caps and hashes it (R2-5, R2-6).
- **Authority is enumerated at startup:** descriptor sweep, Landlock ABI 6 or later with every right handled, typed checks on received descriptors (R2-4).
- **Game copies are immutable, manifest-validated generations** with leases. Windows copies use hardlinks where the user may create them (R2-8, §5.3).
- **Windows LAN permits are bound to one game process and one user**, held by a service handle; WFP layers and arbitration are specified (R2-3). A **contained-game mode** (a separate low-integrity account) is proposed for Windows custom maps. Until it is verified, ban safety against a compromised game is not claimed on Windows (R2-1, §8.2).
- **Transport egress guard** at the socket send path, through audited iroh and noq transport patches; budgets on the session endpoint; the address-disclosure claim is narrowed (R2-9, R2-10).
- **Approvals** are immutable, single-use objects (R2-14).
- **Release:** provenance approval is separate from reproduction; root epochs and freshness state; anti-rollback for manual installers (R2-11, R2-12). Distribution moves to GitHub Releases and a static landing page; the self-hosted download server of draft 2 hosts nothing.
- **Relay:** vouchers charged to their issuer, revocation by restart, limits before admission, the shared-server option removed (R2-13).
- **Legendary authentication** goes through an explicit broker; SI-1 is narrowed for legendary's own session refresh unless Kickoff gets its own Epic sign-in (R2-15, §6.4).
- **Milestones:** containment probes (M0) before any real account or custom map; minimum copy protections (M5a) before M3 and M4; a Windows spike (W1) beside M1; parser confinement (M6a) before any peer format; release-trust spikes (M11a) early; real peer sessions gated on the compromised-game suite (§10).

## 1. Goal

Anyone who plays Rocket League on PC can play custom maps, alone or with friends, from one link, with no technical knowledge and at no cost, ever. Kickoff is free software under GPL-3.0. It is built for the player in a Discord server who asks "where can I play the maps Lethamyr makes for his videos?" and should get back one link that works.

Priorities, in order. Where two conflict, the design looks for one that serves both; any trade-off that remains is decided by the maintainer, recorded, and never taken silently.
1. **Security.** Kickoff never exposes a user to a Rocket League ban, and nothing a map, website or peer sends can reach the rest of the machine. Where a platform cannot yet contain the game, §1.2 says so.
2. **One link to playing.** Solo custom maps come first; multiplayer builds on the same path.
3. **Better than Rocket LAN** for multiplayer.
4. **Performance.**

Non-goals: interop with Rocket LAN (only its public documents are used); mods in online matches; anything that needs anti-cheat off for online play; Discord's Social SDK, which is proprietary and cannot be linked into a GPL-3.0 program without a licence exception.

### 1.1 First-run targets

Measured on a fresh Windows 11 PC with Rocket League installed from Epic, and on a Linux desktop that runs the game through Heroic. Clicks are counted from opening the link; time excludes downloads.

| Target | Windows | Linux | Depends on |
|---|---|---|---|
| Link to a solo custom map in game | ≤ 7 clicks and ≤ 3 minutes | ≤ 5 clicks after the package installs | code signing (§8.4), copy mode (§5.3) |
| Typed commands, manual file copies, settings to change | 0 | 0 | — |
| BakkesMod, a command line, port forwarding or networking knowledge | not needed | not needed | — |
| SmartScreen or Smart App Control warnings | 0 | — | signed installer (§8.4) |
| UAC prompts | 1 at install; 1 more the first time you play with friends | 0; no root anywhere | Windows game mode (§8.2) |
| Firewall prompts | 0 | 0 | firewall rule (§3.3) |
| Opening Kickoff to a solo map | 2 clicks: choose a map, Play | 2 clicks | catalog (§5.7) |
| Joining a friend | click an https invite link, then Join | same | §4.2 |
| Extra disk for the game copy | about 0 where the install allows hardlinks, else about 41 GB | about 0 (reflink) | §5.3 |

### 1.2 Claims, and the design choice behind each

The invariant columns are the authoritative SI-33 claim/platform mapping. `—` means the claim is not made in that mode. Windows same-user includes stock mode; contained mode is option A (§8.2). Scope checks run now; exact-artifact release evidence lands in M11.

| # | Claim | Design choice that delivers it | Invariants Linux | Invariants Windows contained | Invariants Windows same-user |
|---|---|---|---|---|---|
| 1 | Runs on Windows and on Linux (Heroic/umu); one link per platform | One L2 codec with two tap adapters (§3.2, §3.3); a landing page with one download button per platform (§8.4) | SI-10 | SI-10 | SI-10 |
| 2 | Kickoff never puts a modified file where an anti-cheat session can load it | Kickoff writes only immutable copy generations that no launcher knows about and that lack the EAC bootstrap. The online install is read-only to Kickoff: a Landlock rule on Linux, read-only handles on Windows (§5.3). One stated exception on Linux: legendary refreshing its own login session, as it does on every normal Play (§6.4) | SI-1, SI-2, SI-3, SI-39 | SI-1, SI-2, SI-3, SI-39 | SI-1, SI-2, SI-3, SI-39 |
| 3 | A malicious map or peer cannot get you banned by modifying your game | **Linux:** the game runs in the gamebox, where the online install is not mounted and the copy is read-only (§3.2). **Windows:** only in contained mode (§8.2). Otherwise this is a residual risk, shown at install and when a session starts | SI-34 | SI-34 | — |
| 4 | A malicious map cannot read your files or control your desktop | **Linux:** the gamebox shows the game only its copy, an ephemeral prefix, a render node, a restricted audio socket and gamescope's own display server (§3.2). **Windows:** contained mode only (§8.2) | SI-14, SI-34, SI-35, SI-36 | SI-34, SI-36 | — |
| 5 | Peers can reach only the Rocket League process Kickoff started | Linux: peer traffic exists only inside the gamebox network namespace. Windows: a WFP permit bound to one game process, one user and one image, held by a service handle and removed when that process exits (§3.3). The wire carries UDP tuples, never Ethernet or IP (§3.1) | SI-11, SI-12 | SI-11, SI-12, SI-40 | SI-11, SI-12, SI-40 |
| 6 | A crash or game update never leaves anything to repair | Nothing is written to the online install. A new game build gets a new copy generation (§5.3) | SI-4, SI-5 | SI-4, SI-5 | SI-4, SI-5 |
| 7 | No accounts beyond your game account | Invites are https links that open Kickoff, or offer the download if it is missing (§4.2) | SI-20 | SI-20 | SI-20 |
| 8 | Smallest privileged surface | Linux: no root at install or at run time. Windows: solo play needs no driver or service; multiplayer adds one SYSTEM service that holds the tap and WFP filters and never touches a file (§3.3) | SI-13 | SI-6, SI-8 | SI-6, SI-8 |
| 9 | Lower relay dependence | Direct QUIC paths after admission, with an egress guard on every transport send (§3.4) | SI-29, SI-31 | SI-29, SI-31 | SI-29, SI-31 |
| 10 | Maps reach friends as the exact bytes the host has | Content addressing and whole-file BLAKE3, computed by kickoffd itself (§5.2) | SI-5, SI-37 | SI-5, SI-37 | SI-5, SI-37 |
| 11 | Game traffic never waits behind a map download | QUIC datagrams for LAN traffic; transfers yield to the host's own measured game state (§3.4) | SI-23 | SI-23 | SI-23 |
| 12 | A compromised download host cannot fake the first install, push an update or silently freeze updates | Authenticode on Windows and independent package pins on Linux for the first install; an offline-signed release record with root epochs, sequence and expiry after that (§8.4) | SI-24, SI-25, SI-26 | SI-24, SI-25, SI-26 | SI-24, SI-25, SI-26 |
| 13 | Open, reproducible and reviewed | Approved inputs, two isolated builders, signing bound to provenance and test evidence (§8.4) | SI-26, SI-27, SI-33 | SI-26, SI-27, SI-33 | SI-26, SI-27, SI-33 |
| 14 | Diagnostics carry no secrets | Allowlisted schema; secrets are a type that cannot be printed; no core dumps (§6.4) | SI-30 | SI-30 | SI-30 |
| 15 | A built-in map browser that credits authors | A signed catalog of map pages; downloads come from the author's own site, on your machine (§5.7) | SI-29 | SI-29 | SI-29 |


### 1.3 First-run journeys

**Windows**, with the recommended design (contained mode, §8.2, and a signed installer):

| Step | What the player sees | Prompts | Design choice |
|---|---|---|---|
| 1 | Clicks a link in Discord: the landing page, or an invite link `…/join#<ticket>` | — | Static GitHub Pages site: no cookies, no analytics. The ticket stays in the URL fragment, which browsers never send to the server (§4.2) |
| 2 | "Download for Windows" | browser download | Signed installer from GitHub Releases |
| 3 | Opens it | UAC, "verified publisher" | No wizard pages. One elevated install: the app in Program Files and the contained game account. The LAN driver and service are not installed yet |
| 4 | "Sign in with Epic" | Epic's own sign-in page | A Kickoff window with no app permissions, limited to Epic's sign-in pages. Rocket League is free on Epic, so any Epic account works (L) |
| 5 | "Getting your game ready" | — | Finds the install read-only and builds a copy generation (hardlinks: seconds; otherwise a progress bar) |
| 6 | Map browser | — | Lethamyr's and community maps (§5.7) |
| 7 | Play | — | Downloads from the author's site, verifies, fetches the texture pack if the map needs it, launches the copy |
| Later | "Play with friends": host, or open an invite | one UAC, once | Installs the LAN adapter, service and a firewall rule for Kickoff only (§3.3) |

Some earlier choices make steps harder, and each is still open:
- Signing was deferred. An unsigned installer shows a SmartScreen warning, and Smart App Control blocks it outright with no override (§8.4).
- Hand-delivered alpha builds do not scale to a public link.
- Draft 2's default of stock maps only on Windows leaves the target player with nothing to do (§8.2).
- Kickoff's rule against editing firewall rules (NET-11) produces a Windows Firewall prompt the first time a player hosts (§3.3).
- Launching an offline copy needs the player's Epic sign-in inside Kickoff, because no launcher will start a copy (§8.2).

**Linux:** install `kickoff-bin` from the AUR (an AppImage for other distributions is under consideration, §8.1). Kickoff finds Heroic's install read-only and uses its existing Epic login (§6.4), so there is no second sign-in. Then the map browser and Play.

**Solo first.** Solo play needs no LAN adapter, relay, peer or network listener. Multiplayer adds the LAN adapter (Windows), an invite link and a session.

## 2. Architecture

### 2.1 Processes

```
┌──────────────────────────── user session ─────────────────────────────┐ ┌ Windows, SYSTEM ┐
│ kickoff-ui (Tauri)   kickoff (CLI)                                    │ │ kickoff-svc     │
│        │ authenticated local socket / pipe (§2.7)                     │ │  tap + WFP      │
│        ▼                                                              │ │  game-instance  │
│ kickoffd ── iroh: door + session endpoints, egress guard ─────────────┼►│  binding        │
│   │  └── pipes only ──► kickoff-parse (sandboxed, one job each)       │ │  no files       │
│   └── typed socketpair ──► kickoff-gamebox (Linux supervisor)         │ └─────────────────┘
│        cgroup game-<id>: memory.max, pids.max, cgroup.kill            │
│        ├─ display sandbox: gamescope + its Xwayland                   │
│        │     └─ WlFilter (kickoff-parse) ──► host Wayland (security context)
│        ├─ pasta (internet for the gamebox)                            │
│        └─ gamebox: user+net+mnt+pid+ipc ns; kick0 tap; nft            │
│             bwrap: copy ro · tmpfs prefix · render node ·             │
│                    gamescope X socket · restricted audio socket       │
│             umu → Proton → RocketLeague.exe -noeac                    │
└───────────────────────────────────────────────────────────────────────┘
```

- **kickoffd** owns sessions, networking, the library and the copies, and runs as the user. Linux separates its local listener facade from its hardened worker. The facade authenticates callers without reading their payload and transfers their sockets through a private inherited control pair. Kernel peer credentials continue to identify the listener creator, so clients can verify the facade's executable while the worker remains nondumpable. Facade death closes transferred channels; worker death terminates the facade. Both suppress core dumps through the distinct policies in §6.4. The worker's startup order is fixed (SI-36):
  1. Close every descriptor except the supervisor socketpair, checked to be an `AF_UNIX` stream pair; reopen stdio on `/dev/null`.
  2. Start `kickoff-gamebox`, which needs mounts and namespaces that Landlock forbids.
  3. Apply Landlock, requiring ABI 6 or later (Linux 6.12 or later; ABI 10 on the reference machine, V `landlock_create_ruleset` version query). Every filesystem right of the running ABI is handled, including truncate and device ioctl. Writes are allowed only beneath `~/.local/share/kickoff` and `$XDG_RUNTIME_DIR/kickoff`. TCP connect is allowed to port 443 only, and abstract Unix sockets and signals are scoped. Below ABI 6, kickoffd refuses to start and `kickoff doctor` explains why.
  4. Set `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE 0` and `RLIMIT_CORE 0`.
  5. Probe the online root: a create, write, truncate, rename and unlink must each fail, or kickoffd exits.
  6. Start the async runtime. Descriptors received later are type-checked: the tap must answer `TUNGETIFF` with `IFF_TAP` and name `kick0`. Anything else is closed and the launch fails.
  It runs as a systemd user unit with `Delegate=yes`, so it can create the game cgroup. It exits 60 s after the last session and the last client go away.
- **kickoff-gamebox** (Linux) is a small supervisor. It accepts four typed messages from kickoffd: `Launch{generation: u32, slot: u8, auth: LaunchAuth}`, `Stop`, `Status` and `Shutdown`. It never receives peer data, and parses nothing hostile; its only variable inputs are two integers and an allowlisted argument set (§6.4). It builds the gamebox and the display sandbox (§3.2), owns the cgroup, maintains the egress deny set from host netlink, and keeps the compositor security-context listener. It is not under Landlock, because Landlock would forbid the mounts that bwrap makes; that is why its interface is this narrow.
- **kickoff-parse** runs one hostile-format job per process. It holds no file, socket or process authority, only pipes (§5.6). The long-lived `LaunchLog` and `WlFilter` jobs run the same way.
- **kickoff-ui** is Tauri 2 and talks only to kickoffd. Its webview is treated as compromised (§2.7).
- **kickoff** is the CLI: `join`, `host`, `library add`, `doctor`, `stop --all`, `--toggle-overlay`.
- **kickoff-svc** (Windows, multiplayer only) holds the tap device and the WFP filters, and binds the permit to one game process (§3.3). In contained mode it also starts the game under the contained account (§8.2). It performs no file operation.

### 2.2 Rust workspace

```
kickoff/crates/
  wire/     postcard messages, LAN header, tickets, confined secret transmission (forbid(unsafe))
  vlan/     game-facing L2 codec, filter + adapters NsTap, WinTap, Mem
  net/      iroh door and session endpoints, fragmentation, egress policy and send guard
  session/  admission (identity × generation), approvals, roster, pump, budgets
  store/    the only module that writes or opens game-reachable files
  parse/    hostile-format decoders + the sandbox that runs them (incl. WlFilter)
  maps/     library, transfer, catalog, sources (decoding goes through parse)
  game/     install discovery (read-only), copy generations, gamebox + display sandbox launch, state
  ipc/      local channels: peer authentication, versioned role-scoped commands
  local/    shared Linux kernel authentication and ancillary-refusing transport
  secret/   Secret<T>, process hardening, diagnostics schema
vendor/iroh-1.3.0/   upstream plus one audited send-guard patch (§3.4)
vendor/noq-1.3.0/    upstream plus one audited stable send-context patch (§3.4)
bins/  kickoffd  kickoff  kickoff-parse  kickoff-gamebox  kickoff-svc
ui/  site/ (landing page)  packaging/  tests/
```

Wire keeps secret serialization and each borrowed transport write within its
designated consumer (§6.4). Public byte encoders accept only nonsecret message
types. Local transmission requires a fixed installed-peer capability; a Join
transmission verifies its immutable issuing door before opening a QUIC stream.

### 2.3 Module interfaces

Each module is deep: a small interface over the hard part. Adapter seams have
at least two adapters. The sketches below describe module responsibilities;
the crate READMEs record their implemented M2 interfaces. Wire's designated
transmission owner keeps serialized secrets within the §6.4 consumer, while
VLAN generation resets are coordinated by session's admission owner.

**`vlan`** hides the frame codec (ARP answered locally, MAC synthesis, IPv4/UDP build and checksums), the filter and adapter I/O.
```rust
pub struct LanDatagram { pub peer: PeerSlot, pub bcast: bool, pub src_port: u16, pub dst_port: u16, pub payload: Bytes }
pub fn open(adapter: Adapter, cfg: LanConfig) -> Result<Lan>;  // NsTap(OwnedFd) | WinTap(SvcLease) | Mem
impl Lan {
    pub async fn recv(&self) -> LanDatagram;    // from the local game, already filtered
    pub fn deliver(&self, d: LanDatagram);      // to the local game; filtered, never blocks, drops on overload
    pub fn health(&self) -> LanHealth;
}
```

**`net`** hides iroh, the relay map, fragmentation, path events, candidate scoping and the egress guard.
```rust
pub enum SessionBind { Direct(IfaceAddr), RelayOnly }   // draft 2: bind: IfaceAddr (R2-9)
pub async fn door(id: &SecretKey, relays: &RelayMap) -> Result<Door>;          // persistent identity, relay-only
pub async fn session(relays: &RelayMap, bind: SessionBind, role: Role) -> Result<SessionNet>; // fresh key per session
impl Door {
    pub async fn next_join(&self) -> JoinAttempt;                              // host: authenticated id + JoinRequest
    pub async fn request_join(&self, t: &Ticket, r: JoinRequest) -> Result<Admitted>; // guest
}
impl SessionNet {
    pub fn addr(&self) -> EndpointAddr;        // bound interface address + QAD public address, or relay only
    pub async fn dial(&self, host: EndpointAddr, pass: AdmitPass) -> Result<Link>;  // guest
    pub async fn accept(&self) -> Link;        // host: only ids admission issued a pass to
}
impl Link {   // carries the (identity, generation) it was admitted under
    pub fn send_lan(&self, d: &LanDatagram);
    pub async fn recv_lan(&self) -> LanDatagram;  // budget charged before reassembly
    pub fn ctl(&mut self) -> &mut CtlStream;
    pub async fn open_blob(&self) -> Result<(SendStream, RecvStream)>;
    pub fn path(&self) -> PathStatus;
}
```
Adapters: real iroh, and iroh in-process with `RelayMode::Disabled` for tests. Every IP send of either adapter passes `net::egress::SendGuard` (§3.4).

**`session`** hides admission, approvals, capabilities, generations, reconnect, budgets and the pump.
```rust
pub async fn host(door: &Door, net: SessionNet, lan: Lan, opts: HostOpts) -> Result<Session>;
pub async fn join(door: &Door, net: SessionNet, lan: Lan, ticket: Ticket) -> Result<Session>;
impl Session {
    pub fn invite(&self, kind: InviteKind) -> Ticket;               // host only
    pub fn events(&self) -> broadcast::Receiver<SessionEvent>;      // includes ApprovalRequested(Approval)
    pub async fn command(&self, c: Command) -> Result<()>;          // Kick, PickMap, Leave, Decide{approval, allow}
}
pub struct Approval { pub id: ApprovalId, pub action: ApprovalAction, pub peer: Fingerprint, pub generation: Gen }
pub enum ApprovalAction { AdmitBearer, InstallMap { map: MapId } }
```
Draft 2's `Approve(id)` named a peer; `Decide` names one immutable approval object (§4.4, R2-14).

**`store`** hides handle-relative opening, unnamed staging, durability ordering, atomic commit and verify-at-use. It is the only module allowed to call filesystem write APIs (a clippy `disallowed_methods` lint enforces this).
```rust
pub fn open(kind: RootKind) -> Result<Root>;        // fixed set: Library, Copies, PrefixBase, State
pub fn online(path: &Path) -> Result<ReadOnlyRoot>; // opened read-only; the type has no write method
impl Root {
    pub fn stage(&self, cap: u64) -> Result<Staged>;        // unnamed until commit; counts and hashes every byte
    pub fn replace(&self, name: &RelName, from: Source) -> Result<()>;   // Source: Object | Clone(ReadOnlyRoot, RelName)
    pub fn open_read(&self, name: &RelName) -> Result<File>;
}
impl Staged {   // implements Write; refuses bytes beyond `cap`
    pub fn commit_new(self, name: &RelName, expect: Blake3) -> Result<Committed>; // only if store's own hash == expect
}
```
`RelName` is a validated relative name: components of `[A-Za-z0-9._-]`, with no `..`, no empty components and no leading dot. Display names never become paths.

**`game`** hides discovery, launcher metadata, copy generations, gamebox launch and game state.
```rust
pub fn discover() -> Vec<OnlineInstall>;                         // read-only
pub fn generation_for(i: &OnlineInstall) -> Result<Generation>;  // reuses or builds a validated generation
impl Generation { pub fn lease(&self) -> Result<Lease>; }        // a leased generation is never refreshed or deleted
impl Lease {
    pub fn set_map(&self, map: &Bundle) -> Result<()>;           // writes only the slot of this generation
    pub fn reset_map(&self) -> Result<()>;
    pub fn launch(&self, auth: LaunchAuth) -> Result<GameBox>;   // the only way Kickoff starts the game
}
impl GameBox { pub fn lan(&self) -> Adapter; pub fn state(&self) -> impl Stream<Item = GameState>; }
```

**`parse`** hides the decoders and their sandbox.
```rust
pub fn run<J: Job>(job: J, input: impl Read, limits: Limits) -> Result<J::Output>;   // bounded data out
pub fn stream<J: StreamJob>(job: J, input: impl Read, sink: &mut Staged, limits: Limits) -> Result<()>;
```
`stream` pumps the helper's output pipe into a `Staged` file that kickoffd owns. The helper never sees a file handle and never reports a hash (R2-5, R2-6).

### 2.4 Data flow (guest's game to host's game)

```
guest RL ─UDP→ kick0 ─frame→ tap fd ─codec+filter→ vlan.recv → pump → link.send_lan ══QUIC datagram══►
host link.recv_lan (charged, generation-checked) → pump → vlan.deliver ─filter+codec→ tap fd → kick0 → host RL
```
On the host, the pump routes between each guest link and the local LAN only. No link-to-link path exists in the code, so a guest's datagram can never reach another guest. Broadcasts from the host's game fan out to every guest link. Broadcasts from a guest go only to the host's game.

### 2.5 Threading and async model

- One tokio runtime in kickoffd. Each link gets one task for `recv_lan` and one for control. One task drains each tap fd (`AsyncFd`).
- The hot path is a codec plus a filter. Its only shared state is an `ArcSwap` admission snapshot. Payloads are `Bytes` and are never copied after the read.
- Hashing runs on a bounded blocking pool of 2 threads. Each `kickoff-parse` job has one pump task that moves pipe bytes into `store`; at most 2 jobs run at a time (§6.3).
- The Windows service runs one overlapped-I/O thread on the tap, one pipe task, and one wait on the bound game process handle.

### 2.6 Decisions and rejected alternatives

| Decision | Evidence | Rejected |
|---|---|---|
| Sessions run an offline copy; the online install is never written | Removes the reactive-restore class (FILE-1 and 10 related findings). A reflink of 2000 files took 24 ms with 0 exclusive bytes (V, `cp -a --reflink=always` + `btrfs filesystem du`) | In-place swap plus restore (draft 1) |
| Copies are immutable generations validated against the launcher's manifest | Per-file reflinks are not a whole-tree snapshot (R2-8); hashing each file against the manifest catches a mixed build | Trusting the build label in launcher metadata |
| Linux game in a rootless gamebox namespace | Wine ran inside `unshare -rn` with taps; nft worked in an unprivileged user+net namespace (V) | Loopback proxy in the host namespace (NET-1, NET-2); root tap fallback (PRIV-13) |
| The game's display is nested gamescope; the host compositor is reached through an allowlist filter and a security context | The host's Xwayland accepts unauthenticated clients and offers XTEST; the host Wayland socket offers virtual keyboard, data-control and screencopy (V, §3.2) | Bind-mounting host X11/Wayland sockets (draft 2, R2-2); gamescope's SDL backend, which copies the host clipboard into the game (`SDLBackend.cpp:666`, V) |
| kickoff-svc keeps only LAN and instance binding | A SYSTEM process writing into user-reachable trees is the root of FILE-2 and PRIV-2 | SYSTEM slot writes with path validation |
| Hostile formats are decoded only in kickoff-parse, which has pipes and nothing else | Without a writable handle the helper cannot overwrite, grow or forge what is committed (R2-5, R2-6) | Handing the helper a staging file descriptor (draft 2) |
| Door and session endpoints | Only admitted peers are told the session endpoint. A specific bind limits candidates to that address (V, iroh-1.3.0 `socket.rs:1922-1956`) | One endpoint filtered after the handshake: candidates register before `after_handshake` runs (V, `connection.rs:359`) |
| One egress guard on the IP transport's send path | iroh sends NAT-traversal probes to candidates the remote announces (V, `remote_state.rs:534, 947`), and offers no send filter | Filtering only the addresses Kickoff passes to `dial` (draft 2) |
| Wire carries UDP tuples; slot and address come from the authenticated link | The wire cannot express ARP, TCP, IPv6 or a spoofed source (V) | Ethernet or IP on the wire |
| Star topology | UE3 clients talk only to the server (V) | Full mesh |
| kickoffd separate from the UI | A webview crash never drops a session (V) | In-process Tauri backend |
| Own transfer protocol: whole-file BLAKE3, resume by offset, zstd-3 | The library is already content-addressed | iroh-blobs 0.x |
| postcard | Compact; iroh tickets use it (V) | JSON, protobuf |
| GitHub Releases plus a static landing page; https invite links | Chat apps turn https links into links and leave `kickoff://` as text; GitHub is independent of the maintainers' own servers | Downloads on a self-hosted server that also runs other services (draft 2) |

### 2.7 Local channels

Every local channel works the same way:

1. **Exclusive endpoint in a private place.** Linux: `$XDG_RUNTIME_DIR/kickoff/` is created with mode 0700 and refused if it already exists with another owner or mode; the socket is created with `bind` (no unlink-and-retry), mode 0600. Windows: the daemon pipe and the service pipe use `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`. The DACL grants clients read and write but not `FILE_CREATE_PIPE_INSTANCE`. A name collision fails closed.
2. **Kernel-authenticated caller.** Linux: `SO_PEERCRED` uid equals ours, and `SO_PEERPIDFD` gives a pidfd for the peer. The peer's `exe` is read through `/proc/<pid>` and must be an installed Kickoff binary; afterwards `pidfd_send_signal(pidfd, 0)` must still succeed, so a recycled PID cannot pass. Windows: `GetNamedPipeClientProcessId`, then the token must have the same user SID and logon session, medium integrity or higher, and no AppContainer; the image path must be under the protected install directory.
3. **Authenticated server.** The client checks the server the same way: the Linux kickoffd listener facade's uid, executable and live pidfd, or kickoff-svc's SYSTEM token and image path. The Linux facade hands an accepted socket, plus a bounded connection lease, to its own hardened child through an unnamed inherited stream pair. That private capability channel accepts only the exact descriptor count and types its protocol requires; it is never reachable through the public endpoint. The worker authenticates the facade and rechecks the client from the transferred socket's kernel credentials before processing its version handshake. The facade never reads client payload, and its lifetime stays pinned while any transferred channel exists.
4. **Role-scoped, versioned commands.** Each role (CLI, UI main window, overlay, gamebox supervisor, service client) has a fixed postcard enum. No command carries a path, URL, shell string or launch command. A version handshake opens every channel; a mismatch closes it before any side effect. Client channels accept no ancillary data: a message carrying `SCM_RIGHTS` or credentials, or truncated control data (`MSG_CTRUNC`), closes the channel after any received descriptors are closed.
5. **Leases are connections.** A Windows LAN lease lives exactly as long as its pipe connection and its bound game process (§3.3).

Same-user malware can still act as the user, which is outside Kickoff's boundary (§6.1). These rules stop other users, other sessions and sandboxed processes, and stop anything from using Kickoff to gain SYSTEM.

**Webview.** It is a client of the UI's Rust layer and is treated as compromised:
- App windows show bundled content only, with CSP `default-src 'self'; script-src 'self'` and no inline script, remote content or iframes.
- Each window has a Tauri capability listing its commands; the overlay can only read status and toggle itself.
- Untrusted strings (peer names, map metadata, catalog entries, importer pages, update notes) are rendered as text only. A lint bans `innerHTML` and its framework equivalents. Map previews arrive as decoded RGBA pixels from `kickoff-parse`, never as image files the webview decodes.
- Joining, approving a map and admitting a bearer-invite guest need a **native** dialog raised by Rust. It renders one immutable approval object (§4.4) with the verified identity fingerprint. A compromised webview can ask, but cannot construct or decide an approval. At most one dialog is open at a time, and at most 6 open per minute.
- The **Epic sign-in window** (Windows, and Linux for players who choose it over the launcher's session, §6.4) is a separate webview with no Tauri capability. Navigation is limited to Epic's sign-in origins, and Rust reads the authorization code from the final redirect. No Kickoff code runs in it.
- Deep links (`kickoff://join/<base32>`, at most 2 KiB, no query, fragment, userinfo or port) are parsed in Rust and never reach a shell or CLI option parser.

## 3. Network design

### 3.1 Game ports and the filter

| Item | Value | Confidence |
|---|---|---|
| Game traffic | UDP, listen server port 7777, set by `PORT=` | (L) RocketPlugin.h:22, RLBot wiki |
| Client source port | ephemeral | (U) |
| Discovery | UE3 beacon defaults: UDP 14001, broadcast, 8-byte nonce; RL's own values sit in encrypted `Coalesced_INT.bin` | (U) |
| Embedded IPs in payloads, max packet size | unknown | (U), M1 |

`GamePorts` is compiled-in data, replaced by measured values in M1. Configuration cannot override it (NET-1). The filter is a second layer: the namespace (Linux) or WFP (Windows) is the boundary.

1. UDP over IPv4 only. ARP is answered locally and never forwarded. IPv6, VLAN tags, IP options and fragments are dropped and counted.
2. Outbound from the local game passes if `src_port` or `dst_port` is in `GamePorts`. It records a flow keyed by (peer identity, generation, 5-tuple), with a 30 s idle timeout and at most 64 per peer.
3. Inbound from a peer passes if `dst_port` is in `GamePorts` or it matches a live flow of the same generation.
4. A compiled denylist always wins: 22, 53, 67, 68, 137, 138, 1900, 5353, 5355, 9002 (BakkesMod RCON), 47984-48010, 49123, 49124, 53317.
5. Broadcast passes only to discovery ports: host to guests, and guest to host only. Budgets are in §6.3.

### 3.2 Linux: the gamebox

**Choice: the game runs in rootless namespaces holding an enumerated list of authorities, and inherits nothing else.** Peers reach only the gamebox network namespace. The game draws into a nested gamescope compositor that runs in a separate sandbox, so the game holds no connection to the host's X11 or Wayland server.

What the game can reach. The list is complete: anything else is absent from its namespaces, not filtered.

| Authority | How it is provided | Bound |
|---|---|---|
| Read the game | the leased copy generation, bind-mounted read-only | — |
| Write its prefix | overlay: lower = the Kickoff prefix base (read-only), upper = a tmpfs discarded at exit | 4 GiB tmpfs, charged to the game cgroup's `memory.max` |
| GPU | the render node of the chosen GPU (`/dev/dri/renderD*`); no KMS card node | the GPU driver remains attack surface (§6.5) |
| Display and input | gamescope's Xwayland socket, alone in a private `/tmp/.X11-unix`. Also gamescope's own Wayland socket, if M0 shows its Vulkan WSI layer needs it | gamescope's server, never the host's |
| Audio | one PipeWire socket with restricted access: playback nodes only (§3.2.3) | — |
| Peers | the `kick0` tap | nft input: UDP from 10.75.0.0/24 to `GamePorts`, plus established flows |
| Internet | pasta | nft output deny set (§3.2.4) |
| Processes | its own pid namespace | cgroup `pids.max` 512 |

Not present: host X11, host Wayland, the session bus, compositor IPC sockets, ssh-agent, home, `/run/user`, host abstract sockets (a separate network namespace has its own abstract namespace) and any descriptor from the host (SI-36).

#### 3.2.1 Why a nested compositor (R2-2)

Draft 2 bind-mounted the host's X11 and Wayland sockets into the gamebox. On the reference machine that hands a compromised game:
- **X11:** the host Xwayland `:0` completes a connection with no authorization cookie and offers XTEST, so the game could type into any X11 window (V, scratch script: raw X11 setup and `QueryExtension`).
- **Wayland:** the host socket offers 71 globals, including `zwp_virtual_keyboard_manager_v1`, `zwlr_virtual_pointer_manager_v1`, `zwlr_data_control_manager_v1` and `ext_data_control_manager_v1` (read the clipboard at any time), `zwlr_screencopy_manager_v1`, `hyprland_toplevel_export_manager_v1`, `zwlr_layer_shell_v1` and `hyprland_global_shortcuts_manager_v1` (V, registry dump).
- **Namespaces do not help:** a pathname socket bind-mounted into `unshare -rn` still connects (V, scratch experiment). Only the mount view decides.
That is keystroke injection into a terminal, clipboard theft from a password manager, and screen capture.

**Design.**
1. **Display sandbox.** kickoff-gamebox starts `gamescope --backend wayland` in its own bwrap: new user, pid, ipc and mount namespaces, a network namespace with no interfaces, no home, the render node, and a private tmpfs `/tmp` and runtime directory. It gets no game command; gamescope runs without a child when none is given (`steamcompmgr.cpp:8516-8545`, V gamescope 3.16.28). It gets no PipeWire socket; gamescope then only warns that screen capture is unavailable (`main.cpp:1100`, V). The SDL backend is never used: it copies the host clipboard into the nested X server (`SDLBackend.cpp:666`, V).
2. **Two independent filters on the host connection.**
   - **Compositor security context.** kickoff-gamebox creates a listener with `wp_security_context_manager_v1` (sandbox engine `dev.kickoff`). Hyprland 0.56.2 hides every global outside a fixed whitelist from clients of such a listener (`ProtocolManager.cpp:348-403`, `Compositor.cpp:262-266`, V source). On the reference machine an existing flatpak security-context socket offers 40 globals: virtual keyboard and pointer, data-control, screencopy, toplevel export, foreign-toplevel, layer shell, input method and global shortcuts are all absent (V, registry dump).
   - **WlFilter**, a long-lived `kickoff-parse` job with no filesystem and no network, sits between gamescope and the security-context connections. It forwards exactly 14 globals: `wl_compositor`, `wl_subcompositor`, `wl_shm`, `wl_seat`, `wl_output`, `xdg_wm_base`, `zwp_linux_dmabuf_v1`, `wp_viewporter`, `wp_presentation`, `wp_single_pixel_buffer_manager_v1`, `zwp_relative_pointer_manager_v1`, `zwp_pointer_constraints_v1`, `wp_fractional_scale_manager_v1` and `wp_color_manager_v1`. The first ten are gamescope's mandatory set (`WaylandBackend.cpp:2005, 2813`, V), and all 14 are in Hyprland's sandboxed set (V).
   - The filter removes the clipboard globals: `wl_data_device_manager` and `zwp_primary_selection_device_manager_v1`. Gamescope forwards the game's X11 clipboard to the host (`steamcompmgr.cpp:5984-5999` calling `WaylandBackend.cpp:1305-1336`, V), and Hyprland 0.56.2 accepts `set_selection` from any client without checking focus or serial (`DataDevice.cpp:248-262`, V). Without the filter, a compromised game could plant text in the host clipboard for the user to paste into a terminal. It also removes `xdg_toplevel_icon_manager_v1` (game-chosen pixels sent to the compositor) and everything else.
   - The filter decodes only message headers and `wl_registry` events and binds; file descriptors pass through untouched. The filter is the primary layer and does not depend on the compositor. The security context is the second layer if the filter is ever bypassed.
   - Gamescope opens more than one host connection (`main.cpp:561` presentation probe, `WaylandBackend.cpp:1989`, V). The filter therefore listens on a socket in gamescope's private runtime directory and pairs each accepted connection with one pre-opened security-context connection (at most 4).
3. **Game sandbox:** `DISPLAY` points at gamescope's Xwayland socket, the only file in its `/tmp/.X11-unix`.

What a compromised game can do to the host display is then what gamescope does for any game: draw one window, receive input while focused, and lock the pointer while focused. Doing more needs a second exploit, of Xwayland or gamescope, which lands in the display sandbox: no home, no network, and a host connection limited to those 14 globals. Compositors without `wp_security_context_v1` keep the filter layer. X11-only desktop sessions are not supported for contained play: gamescope's only nested backend there is SDL.

#### 3.2.2 Launch sequence (each step is a test in M3)

1. kickoff-gamebox creates cgroup `game-<id>` under kickoffd's delegated subtree. It writes `memory.max` 12 GiB, `pids.max` 512 and `cpu.weight` 100. Every later process starts inside it (`clone3` with `CLONE_INTO_CGROUP`).
2. It forks the gamebox init into new user, net, mount, pid and IPC namespaces. The user namespace maps the user's uid to itself.
3. While the child still holds capabilities in its own namespaces, it creates a **non-persistent** tap `kick0` with MAC `02:4b:4f:00:00:<slot>` and `10.75.0.<slot>/24`, and adds `255.255.255.255/32 dev kick0`. Inside the gamebox that route only redirects the game's own broadcasts (Wine reads only `/proc/net/route`, V). It loads the nft tables (§3.2.4) and disables IPv6.
4. The tap fd goes to kickoffd over `SCM_RIGHTS`, where its type is checked (§2.1).
5. kickoff-gamebox starts `pasta` attached to the child's namespaces with every option explicit: `-t none -u none -T none -U none`, `--no-map-gw` (no host-loopback mapping), `--ipv4-only`, and no `--dns-forward`. No pasta default is relied on (L, passt man page; M0 checks each mapping with probes).
6. It starts the display sandbox and WlFilter (§3.2.1), and waits on gamescope's ready pipe (`-R`).
7. The child execs `bwrap` with `--unshare-pid --die-with-parent --new-session --cap-drop ALL` and the view in the table above. bwrap runs `umu-run RocketLeague.exe -noeac <auth args>`. Every descriptor except stdio (`/dev/null`) is closed before exec (`close_range`). The game has no capabilities over its own namespaces, so it cannot change the tap, the routes or nft.
8. Limits inherited by the game: `RLIMIT_CORE` 0, `RLIMIT_FSIZE` 4 GiB, `RLIMIT_NOFILE` 8192, `PR_SET_NO_NEW_PRIVS`.

**Teardown and fail-closed by lifetime (R2-7, NET-12).** `Stop`, game exit, kickoffd death (the supervisor watches its pidfd) or supervisor death (`PR_SET_PDEATHSIG` on the gamebox init) leads to `cgroup.kill` on `game-<id>`, then `rmdir`. That kills the game, its descendants, the display sandbox, WlFilter and pasta in one kernel operation (Linux 5.14 or later). The tap is non-persistent and dies with the namespace. Kickoff leaves no route, firewall rule or device on the host.

#### 3.2.3 Audio

PipeWire's default socket lets a client reach every node, including microphones. Kickoff ships a configuration drop-in, installed by the package with no root at run time. It adds a socket `pipewire-0-kickoff` with access `restricted`; PipeWire supports per-socket access through `module-protocol-native` `sockets` and `module-access` `access.socket` (V, `/usr/share/pipewire/pipewire.conf` on the reference machine, where `pipewire-0-manager` already exists). It also adds a WirePlumber permission manager for that socket that grants permissions only on audio sinks (V that the mechanism exists: WirePlumber 0.5.17 `find-config-access.lua` reads `access.permission-managers` with object rules). The game sees only that socket. (U) M0 must show a capture stream from the probe failing while playback works. If it cannot, the fallback in §3.2.5 applies.

#### 3.2.4 Egress (R2-10)

nft output on the pasta interface drops `0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`, `192.168/16`, `198.18/15`, `224/4`, `240/4` and `255.255.255.255`. It also drops a set that kickoff-gamebox computes from host netlink: every address on every host interface, every directly connected subnet, the default gateway, and the host's public address as last seen by QAD. Those cover LANs with public addresses and services bound to the host's own addresses. The set is recomputed on every `RTM_NEWADDR`, `RTM_DELADDR`, `RTM_NEWROUTE` and `RTM_DELROUTE`. Until the new set is loaded, output is dropped (fail closed).

There is no host DNS forwarder: the reference machine's resolver is `127.0.0.53` (V, `/etc/resolv.conf`), a host service the game should not reach. The gamebox's `resolv.conf` names public resolvers (1.1.1.1, 9.9.9.9), reached through pasta like any internet host. If a network blocks outside DNS, M1 item (c) shows it, and the fallback in §3.2.5 applies.

#### 3.2.5 What M0 and M1 verify

The flatpak portal fact still drives the launch path. Inside the Heroic flatpak, pressure-vessel asks the host's flatpak portal to spawn the game in the host network namespace, so a namespace built around Heroic would not hold. The gamebox therefore runs native `umu-launcher` with the launcher's existing Proton and the Steam runtime in `~/.local/share/umu`, which the flatpak shares with the host (V). The gamebox has no session bus, so a portal escape cannot happen silently.

**M0, containment probes with no game and no account.** Wine probe executables run exactly where the game would. Every item must pass before M1 uses a real account or any custom map:
- (f) display: XTEST, virtual-keyboard and clipboard attempts against canary host windows; a clipboard read and write; a screen-capture attempt; enumeration of host toplevels. No host effect may occur.
- (g) the descriptor inventory of the probe process equals stdio only.
- (h) cgroup accounting: fork, memory and tmpfs-fill probes stop at their limits; `cgroup.kill` leaves no survivor, including a double-forked descendant and pasta.
- (i) pasta: each mapping, the gateway, the host's own addresses (LAN and public), `127.0.0.53` and connected-subnet canaries are unreachable, and an internet host is reachable.
- (j) audio: playback works and capture fails.
- (k) WlFilter: a registry dump through it shows exactly the 14 globals.
- (l) the legendary auth broker against fake expired credentials (§8.1).

**M1, the supervised game session:**
- (a) native umu boots the copy to the main menu, logged in, with GPU acceleration, under gamescope and the filter;
- (b) the game's `/proc/PID/ns/net` equals the gamebox namespace;
- (c) the game boots with internet only through pasta, with public DNS;
- (d) the copy boots without `EasyAntiCheat/` and `Launcher.exe`, read-only, and M1 lists every path it writes;
- (e) the canary probes of SI-14 and SI-35 run beside the real game;
- (m) frame time and input latency with gamescope and the filter, against the same game without them (§7);
- (n) first-match stutter with an ephemeral shader cache, which decides whether a persisted, size-capped cache is worth its cross-session channel.

**If the game cannot run fully contained:** each failing item is held, or replaced by a named degraded mode (audio off; DNS forwarded to one resolver address on port 53; a persistent prefix), decided per item with M0 and M1 data. Host display sockets are never an option. Ban safety does not depend on the gamebox, because the copy works with or without it; containment does.

Requirements: `passt`, `umu-launcher` and `gamescope` (3.16.28 in Arch `extra`, V `pacman -Si`), bubblewrap, unprivileged user namespaces, Landlock ABI 6 or later, a cgroup v2 user delegation with the `cpu`, `memory` and `pids` controllers (V on the reference machine: `user@1000.service` has `Delegate=yes`, and its `cgroup.subtree_control` is `cpu memory pids`), and a Wayland session.

### 3.3 Windows: tap-windows6, WFP and game-instance binding, driven by kickoff-svc

Solo play installs none of this. It is installed, with one UAC prompt, the first time a player hosts or joins.

**Driver.** Unmodified OpenVPN tap-windows6 9.27.0, Microsoft attestation-signed (V), pinned by SHA-256 (`tap0901.sys 581dcaac…d2b1`, `tap0901.cat ee062e5e…05f7`, `OemVista.inf 1327ab3a…2de9`). Whether its installation shows a driver-publisher prompt is (U), checked in W1a.

**Install (elevated, one prompt).**
1. Install to `%ProgramFiles%\Kickoff`. Refuse a pre-existing directory whose DACL grants non-admins write, or that is, or sits under, a reparse point. The service `ImagePath` is quoted and absolute. The installer stub, its helper and kickoff-svc are linked with `/DEPENDENTLOADFLAG:0x800`, so static imports resolve from System32 only (L, Microsoft docs), and they call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` before any dynamic load. A CI import audit fails the build if any of them imports a DLL that is not a KnownDLL or a System32 DLL loaded with that flag. Staging happens in an admin-only directory. Repair and upgrade run the same code (PRIV-3).
2. Stage the driver with `SetupCopyOEMInfW`, which stages only. Create one root device (`SetupDiCreateDeviceInfoW`, `DICD_GENERATE_ID`, `root\tap0901`, `DIF_REGISTERDEVICE`) and install the staged package on that device alone with `DiInstallDevice`. Record the instance ID, `NetCfgInstanceId` and interface LUID in `HKLM\Software\Kickoff` (admin-only).
3. Rename the adapter to `Kickoff`, set metric 1, unbind everything except IPv4, disable NetBIOS and IP forwarding on it, and set MTU 1280. Delete `AllowNonAdmin`, since any integer value enables access (V, `adapter.c:427-443`). Set an admin-only device ACL.
4. Add the persistent WFP objects (below) and, unless players are left to answer a firewall prompt on first host instead, one Windows Firewall rule: allow inbound UDP for `kickoffd.exe` only.
5. Install and start kickoff-svc. Every step writes a ledger entry first; uninstall and an interrupted install both replay the ledger in reverse (PRIV-19).

**Lease contract (R2-3, FILE-21, PRIV-4, NET-3).** The service, not the caller, decides which game a lease serves:
- `LanOpen{slot}` binds the lease to the caller's SID, logon-session LUID and kickoffd process handle (§2.7).
- **Contained mode**: the service starts the game under the contained account (§8.2) and keeps the process handle.
- **Stock mode** (online install, launched by the player's launcher with "Launch without Anti-Cheat"): the service looks for exactly one process system-wide that meets all of these:
  - its image file ID equals the discovered online `RocketLeague.exe`;
  - its token SID and logon session equal the lease's;
  - its command line, read from the process and split with `CommandLineToArgvW`, has exactly one element equal to `-noeac`.
  It opens a `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION` handle and keeps it, so PID reuse cannot alias it. Zero or several matches: refuse.
- For the lifetime of the lease, the service subscribes to process starts (ETW `Microsoft-Windows-Kernel-Process`). Another process with the same image, of any user, in any session, with or without EAC, revokes the permit. Detection is asynchronous: target 50 ms or less, measured in W1a (U).
- The permit dies with the game. The service waits on the process handle, and exit closes the dynamic WFP session and ends the lease (target 100 ms or less). The lease also ends on pipe disconnect, on a session change of the lease's session (logoff, disconnect, console switch away; `SERVICE_CONTROL_SESSIONCHANGE`), and on device drift.
If W1a shows that stock-mode binding cannot be made reliable, stock mode is removed and Windows multiplayer needs contained mode.

**WFP policy (R2-3, NET-11).** One provider and one sublayer, `Kickoff`, with sublayer weight `0xFFFF`. Every filter is conditioned on the Kickoff interface (`IP_LOCAL_INTERFACE`), so physical interfaces keep exactly the policy they had.

| Layers | Filter | Lifetime | Action and weight |
|---|---|---|---|
| `ALE_AUTH_RECV_ACCEPT`, `ALE_AUTH_CONNECT`, `ALE_RESOURCE_ASSIGNMENT`, `ALE_AUTH_LISTEN` (v4 and v6) | all traffic | persistent | hard block (action right cleared), weight 1 |
| `INBOUND_TRANSPORT`, `OUTBOUND_TRANSPORT` (v4 and v6) | anything not UDP to or from 10.75.0.0/24 | persistent | hard block, weight 1 |
| `IPFORWARD_V4`, `IPFORWARD_V6` | source or destination interface is Kickoff | persistent | hard block |
| `ALE_AUTH_RECV_ACCEPT_V4`, `ALE_AUTH_CONNECT_V4`, `ALE_RESOURCE_ASSIGNMENT_V4` | UDP; remote 10.75.0.0/24, or broadcast to a discovery port; app ID = the game image; ALE user ID = the contained account (contained mode) or the lease's SID (stock mode) | the lease's dynamic session | hard permit, weight 15 |

Arbitration: Kickoff's sublayer has the highest weight, and inside it the permit outranks the block. Because the permit is hard, a soft block in a lower sublayer (Windows Firewall's default block for the unidentified network) cannot override it. A hard block from another provider can still veto (L, Microsoft filter-arbitration documentation). The VM suite records the outcome with the firewall's public-profile default, an explicit user block rule for Rocket League, broad UDP allow rules and ICS on the physical adapter. On the Kickoff interface, Kickoff's policy decides. On every other interface, nothing changes.

If the service dies, its dynamic session closes and the permit disappears, leaving the persistent block (fail closed by lifetime). Whether closing the tap handle drops media is (L), checked in the VM.

**Drift during a lease (PRIV-10).** The service subscribes to device-interface changes (`CM_Register_Notification`) and to registry changes on the device's driver key and `AllowNonAdmin` (`RegNotifyChangeKeyValue`). It also re-checks the device ACL and the active driver package every 5 s. Any drift revokes the lease within 5 s.

**Pipe protocol (complete, PRIV-6).** States: `Connected → Hello{version} → Idle → LanOpen{slot} → Leased → Frame* → LanClose | disconnect → Closed`. In contained mode, `Idle` also accepts `LaunchGame{generation: u32, auth: LaunchAuth}`, once per lease; the service builds the image path itself from a fixed root and the generation number, and applies the §6.4 argument allowlist. Any message out of state, any frame longer than 1600 bytes and any unknown tag closes the connection with no side effect. Frames are converted with the shared `vlan` codec on the kickoffd side; the service only moves bytes between the pipe and the tap.

Uninstall reverses the ledger. It removes our device instance, our WFP objects, the firewall rule, the service and the `HKLM` key. It keeps the anti-rollback record (§8.4) unless the player chooses "remove everything". It deletes the driver package only when no other `tap0901` device exists. It asks before deleting copies.

Rejected: Wintun (L3 only; its licence covers its API only, V), ovpn-dco-win (V), our own signed driver (EV certificate and Partner Center).

### 3.4 Transport: iroh 1.3.0

- Pinned `iroh = "=1.3.0"` and `iroh-relay = "=1.3.0"`, vendored with a committed `Cargo.lock` and built `--locked --offline` (PRIV-23). The vendored iroh carries one send-guard patch. Its noq 1.3.0 dependency carries one patch assigning a stable send context to each connection before its driver starts, preserving that context across socket rebinds. A CI check compares each vendor tree to its pinned upstream archive plus the audited patch. The dependency gate also checks these versions as registry packages because cargo deny omits path packages from RustSec and yanked checks.
- **Door endpoint**: the persistent per-device identity. It is relay-only (`clear_ip_transports`, V iroh builder) and accepts only `kickoff/join/1`. It runs only while hosting, or while "friends may join" is on.
- **Session endpoint**: a fresh key for each session.
  - `SessionBind::Direct(addr)` binds to the default-route interface address. With a specific bind, iroh reports only that address plus QAD's public address as candidates (V, `socket.rs:1922-1956`). The endpoint is recreated when the default route changes.
  - `SessionBind::RelayOnly` has no IP transport and runs no QAD probe, so the endpoint owns no UDP socket at all.
  - The host accepts only `kickoff/session/1`, and only from session keys the door admitted (§4.3). Guests' session endpoints accept nothing (NET-4).
- **Address disclosure, stated honestly (R2-9, NET-10).** In a direct session, every admitted peer learns your public and LAN address, and an admitted peer can pass the session endpoint on. Candidates register before the admission hook runs (V, `connection.rs:359`), so whoever learns the endpoint can see them too. Relay-only sessions disclose no address to peers; the relay operator still sees it. Hosting offers two session kinds: **Friends** (bound invites and trusted friends; direct) and **Anyone with the link** (bearer invites; relay-only). These defaults are not final.
- **Before the handshake, on both endpoints:** `Incoming::refuse`, `retry` and `ignore` run before any TLS work (V, `connection.rs:133-219`), with the caps in §6.3. A leaked session endpoint can be flooded; established links are unaffected, and new joins and reconnects may be delayed (§6.5). 0-RTT data is never accepted.
- **After the handshake:** the door needs a `JoinRequest` within 5 s and the session endpoint a `Hello` within 2 s, or the connection closes. An unknown identity on the session endpoint is closed in the admission hook with no further work.
- **Identity key.** Linux: `~/.local/share/kickoff/state/identity` (directory 0700, file 0600, created through `store`). Windows: `%LOCALAPPDATA%\Kickoff\state`, owner-only DACL, DPAPI-wrapped.
  - `kickoff identity reset` creates a new key, and also a **revocation notice**: a `kickoff://revoke/…` link signed by the old key. A friend's Kickoff that opens it deletes every trust entry naming the old key and refuses it from then on. The new key needs a fresh bound invite.
  - A notice signed by a stolen key can only revoke that key. Backups of the Linux key file are the player's responsibility, and a reset is the remedy (PRIV-27).
- **Egress policy** (`net::egress`, the only module that turns data into a destination):
  - Relays come only from the compiled `RelayMap`. A relay URL in a ticket is used only if it equals a map entry; otherwise it is ignored.
  - Direct addresses from tickets are used only if global, or inside a subnet directly connected to this host; loopback, link-local, 100.64/10, 10.75/16 and multicast are never used.
  - Importer and catalog HTTP follows §5.7. Relay credentials stay URL-scoped (V, iroh `actor.rs:1344`).
- **Send guard (R2-10, PRIV-25, NET-15).** iroh chooses some destinations itself. QUIC NAT traversal sends probes to candidate addresses that the remote announces (V, `remote_state.rs:534, 947`), and no application `dial` sees them. iroh 1.3 has no send-path filter. Its custom-transport API is unstable and cannot wrap the IP transport (V, `endpoint.rs:814-827`). The vendored patch therefore calls `SendGuard::admit(context, dst)` in the IP transport's send path (`socket/transports/ip.rs`, `poll_send`) before every packet. The context reaches this hook on ticket sends, NAT probes, path migration and QAD. Outbound peer contexts bind to their expected remote identity before the first send; inbound contexts bind to the verified identity before iroh registers candidate paths. QAD contexts may send only to their original relay-map destination. An unregistered transport refuses every send.
  - A new destination passes only if all of these hold:
    - it is global unicast or inside a directly connected subnet;
    - it is not this host's own address, the default gateway, a configured DNS resolver, loopback, link-local, 100.64/10, 10.75/16, multicast or broadcast;
    - its port is 1024 or higher and not on the §3.1 denylist;
    - the remote has fewer than 8 destinations that are not yet validated, and is under 4 new destinations per second.
  - Probe budgets belong to remote identities across concurrent connections and reconnects. Approved destinations are cached per connection context, so another connection cannot inherit the approval. A connection shutdown removes its approvals; its remote budget remains until expiry, preventing churn from resetting the rate. The hot path costs one cache lookup. Denied packets are dropped and counted. The policy is recomputed on route changes.
  - The guard runs where packets leave, so ticket addresses, NAT-traversal candidates, path migration and any future iroh path source all pass through it.
  - Residual risk: an admitted malicious peer can make your client send a bounded number of encrypted QUIC probes to UDP ports it chooses, on the internet or on your LAN. It cannot choose their content.
- **Rebuttal conceded (NET-15).** Draft 2 said altered ticket addresses "can only break the dial". That was false. Dials have network effects before authentication. The send guard and the destination policy bound those effects, and §4.2 states what a ticket's authenticity rests on.

| Traffic class | Carrier | Why |
|---|---|---|
| LAN game and discovery | QUIC datagrams, `send_datagram` (drop-oldest) | Unreliable and unordered like the game's UDP |
| Control | one bidi stream per link, opened by the guest | Reliable, small, budgeted |
| Map bytes | one bidi stream per request | Reliable, resumable by offset |

**Fragmentation.** `max_datagram_size` is 1162 at connect on a relay path and 1414 after MTU discovery (V, iroh). A LAN datagram that does not fit splits into at most 4 fragments (`frag_id:u16 | idx:u4 | count:u4 | reserved:u8`; reserved must be 0). The receiver checks `count ≤ 4`, `idx < count`, and agreement with the first fragment **before** allocating. It holds at most 8 assemblies per link and 32 overall, keyed by (link generation, `frag_id`). It drops a whole assembly on any conflict, and reassembles within 50 ms or drops.

**Transfer versus play.** The host pauses map transfers while its own game reports `Match`, and otherwise caps them at 80 % of measured throughput. Peers' `Status` reports are informational and never decide scheduling (NET-16).

Measured on the reference machine: direct datagram RTT p50 32-35 µs, p99 99-386 µs; local self-hosted relay p50 95-128 µs; n0 relay-only p50 72.3 ms (V).

## 4. Sessions, invites and admission

### 4.1 Roles

The host runs the Rocket League listen server (Private Match, then Create LAN Match) and the Kickoff session. The roster holds at most 8, the LAN maximum (L). Virtual addresses: `10.75.0.1` for the host, `.2` to `.8` for guests in join order. The host refuses to start if that range overlaps a host network route.

### 4.2 Tickets and invite links

```
Ticket = "kickoff1" + base32(postcard{ v: 1, door: EndpointAddr (relay URL from our map), cap: Cap })   ≤ 2 KiB
Cap    = { session_id: [u8;16], invitee: Option<EndpointId>, nonce: [u8;16], sig: ed25519(door key, fields) }
```
- **Invite links** are `https://not-compromised.github.io/kickoff/join#kickoff1…`. Discord and other chat apps turn https URLs into links but leave `kickoff://` as plain text. The ticket sits in the URL fragment, which browsers never send to the server. The static page's only script hands the fragment to `kickoff://join/…`, or, if Kickoff is not installed, shows the download button and keeps the ticket for after installation. If the page itself were compromised, its script could read a bearer ticket. Bearer admission still needs the host's native approval showing the requester's fingerprint, and bound tickets admit only their invitee.
- **Bound invite** (`invitee` set) for one identity: admitted without a prompt while the session lives.
- **Bearer invite**: single use, valid 15 minutes by the *host's* monotonic clock. The host gets a native prompt showing the requester's verified fingerprint, and is told that the link is transferable (NET-14). Bearer invites belong to "Anyone with the link" sessions, which are relay-only (§3.4).
- **Trusted friends**: persistent identities that may join without a ticket. They are revocable, and a kick overrides them for the session's lifetime.
- **What a ticket's authenticity rests on.** A ticket is only as authentic as the channel that carried it. TLS pins the door identity in the ticket, so a substituted ticket leads to a different host, not to a forged one. The join dialog shows the host's fingerprint, and says whether it matches a trusted friend or is unknown. A guest always treats the host as untrusted (§6.1).

### 4.3 Join and admission

1. The guest dials the host's door (relay-only) on `kickoff/join/1`. It sends `JoinRequest{cap, session_key: EndpointId, name≤32, platform, game_build, kickoff_version}` (≤ 4 KiB, 5 s deadline) over the TLS-authenticated connection.
2. The admission owner decides, possibly through an approval (§4.4). On success it records `{persistent id, session key, slot, generation}` and replies `Admitted{session_addr, slot, generation}`.
3. The guest dials the session endpoint with its session key and sends `Hello{generation}` within 2 s. The host's `after_handshake` hook accepts only session keys with a live admission record.

`connect()` succeeding is not admission: the client treats only `Admitted` and the first `Roster` as admission.

### 4.4 The admission owner and approvals

One module in `session` owns every authorization decision, and every resource carries the generation it was granted under.
- **One live connection per identity.** Each admitted identity has one generation counter. A new session connection from that identity is accepted only through the reconnect path. Accepting it bumps the generation and closes the old one (NET-6).
- **Delivery checks the generation.** Datagrams, control frames, map streams, flows and reassemblies are tagged with their link's generation. Anything whose generation is no longer current is dropped at its next touch (NET-5).
- **Kick** sets the identity to `Revoked` for the session's lifetime. Revocation overrides the trusted-friend list and every outstanding ticket, closes every connection from that identity and bumps the generation. Re-admission needs an explicit host action.
- **Nonces** move atomically `Unused → Pending(conn) → Consumed | Revoked` under the admission lock. A cancelled or timed-out prompt revokes the nonce. A ticket for any other `session_id`, including one from a previous host process, is refused (NET-13).
- **Directional roles.** Guests accept no incoming connections. The host pump has no link-to-link path (§2.4).
- **Approvals (R2-14).** An approval is an immutable object created by the admission owner: `{id: 128-bit random, action: AdmitBearer | InstallMap{map}, session_id, identity, generation, created}`.
  - The native dialog renders that object, and only that object.
  - `Decide{id, allow}` succeeds only while the object is current, and consumes it atomically (`Pending → Decided`).
  - A kick, a reconnect (generation bump), a different map pick, the end of the session or a 60 s timeout invalidates it.
  - At most one approval per action kind is pending. Another bearer join while one is pending is refused at the door. A newer map pick replaces the pending one, and the replaced id stops working.
  - A webview never constructs an id (it receives one in an event) and never decides one.

### 4.5 Wire messages

Unchanged from draft 2. LAN datagram header (6 bytes): `kind:u8 (1=LAN, 2=fragment) | flags:u8 (bit0 broadcast) | src_port:u16 | dst_port:u16`. Slots come from the link and are never read from the packet.

Control (u32 length prefix, ≤ 64 KiB, postcard enum):
- Guest to host: `Hello{generation}`, `Status{game_state, have: Vec<MapId> (≤ 64)}`, `Pong`.
- Host to guest: `Roster{epoch, members ≤ 8}`, `MapPick{bundle}`, `Kick{reason}`, `Ping`, `End`.

No message carries a path, an EAC mode or a launch option. A breaking change bumps the ALPN suffix. An unknown variant closes with error code `VERSION`. The host sends `Ping` every 5 s; a link with no `Pong` for 15 s is closed (PRIV-29).

### 4.6 Reconnect

A guest whose link drops redials its session endpoint with backoff (250 ms doubling to 4 s) for 30 s. The host keeps the slot "reconnecting" for those 30 s, then evicts the guest and bumps the generation. If the host is lost, the session ends.

## 5. Maps

### 5.1 Library and identity

- `MapId` is the BLAKE3 of the exact package bytes. The Epic manifest's per-file digest is **SHA-1** (V), used only to validate copy generations (§5.3).
- Layout under `~/.local/share/kickoff/library` (Windows `%LOCALAPPDATA%\Kickoff\library`): `objects/<blake3>` (mode 0400) and `bundles/<blake3>` (postcard). Both are written only by `store`.
- **Immutable objects.** Every ingest goes through `Staged`: kickoffd copies one snapshot into an unnamed staging file and hashes it as it writes, then commits with a no-replace link. Existing libraries are imported by copying, never hashed in place. Each use (serving, cloning into a copy) re-hashes while reading and refuses on a mismatch (FILE-17).
- Bundle manifest: `{size, blake3, title≤64, author≤64, description≤1024, preview_blake3, source, label}`. It is decoded in `kickoff-parse`. Text fields are text, never paths. **`source` and `label` are informational and authorize nothing** (FILE-19, SI-37).
- The UE3 header (`file_version`, `licensee`) is compatibility metadata, checked by bounded structural validation in `kickoff-parse` to catch wrong-file mistakes. Its result is advisory: it can show a warning, and it never permits anything (FILE-18).

### 5.2 Transfer

- The host serves only the current session map and its preview, one request at a time per peer. A request is `{blake3, offset}`, with `offset ≤ size`. The response is a zstd stream of the remaining bytes.
- The receiver pipes the compressed stream into a `ZstdMap` job in `kickoff-parse` (§5.6). The job decodes from its input pipe to its output pipe. Its limits are a decoder window of at most 8 MiB, a compressed-input cap of `size + size/64 + 64 KiB` (counted by kickoffd as it writes the pipe) and an idle deadline of 30 s.
- kickoffd pumps the output pipe into a `Staged` file with cap `size - offset`, hashing as it writes, and commits only if **its own** hash equals the requested `MapId` (R2-6). The helper never holds a file handle and never reports a hash (R2-5). A resume continues a staging file that this receiver created, whose prefix it hashed itself.
- Disk is reserved before the request (§6.3). A hash mismatch marks that peer as a bad source for the session.

### 5.3 Copy generations (the ban-safety core)

**Rule: the online install, its prefix and the launchers' files are read-only to Kickoff. Every byte Kickoff writes for the game goes into an immutable copy generation that only Kickoff launches, and only with `-noeac`.**

A **generation** is a complete copy of one game build. It is built, validated, then published by one atomic rename, and never changed afterwards except for the map slot and the pinned textures (below).
- **Identity.** A generation is bound to the launcher's manifest for that build, not to a version string. Legendary keeps the Epic manifest beside `installed.json`; Windows Epic keeps one per install; Steam keeps depot manifests. Each manifest is decoded in `kickoff-parse` (`EpicManifest`, `SteamManifest` jobs).
- **Build.** The generation is built fresh, in `copies/<build>-<n>.building/`, from a `ReadOnlyRoot`: never patched incrementally, so no obsolete file survives a refresh.
  - Linux: each file is cloned with `FICLONE`.
  - Windows: each file is hardlinked when the user can create hardlinks to the online files (the same NTFS volume, with write-attribute access; Steam libraries usually grant it, and Program Files usually does not, L). Otherwise each file is copied, and hardlinks are reused from the previous generation for unchanged files.
- **Validation.** Every file is hashed against the manifest's SHA-1; the size must match; and the file list must equal the manifest's minus the EAC exclusion list. A file that changed while it was being cloned fails here, so a copy can never mix two builds.
- **EAC exclusion policy.** The copy omits `EasyAntiCheat/`, `Launcher.exe` and the EAC setup binaries; M1 shows `-noeac` boots without them. If a new build adds a file matching the bootstrap patterns (`*EasyAntiCheat*`, `*EAC*`, `start_protected_game*`) that is not on the compiled list, the build is refused and the UI says Kickoff needs an update. Fail closed.
- **Publication.** `.building` is renamed to `<build>-<n>`, and `current` is replaced by renaming a new symlink over it. Both renames are durable (see Durability below). Startup deletes any `.building` or `.deleting` directory.
- **Leases.** A launch, `set_map` and `reset_map` hold a lease (a shared `flock` on the generation's lease file) for their whole duration. Garbage collection takes the lock exclusively, renames the generation to `.deleting` and deletes it. A leased generation is never refreshed or deleted (FILE-8).
- **Maintenance exclusion.** A refresh runs only while no Kickoff game runs, no launcher process runs and the launcher's lock file is free. It re-reads the installed version at the end and discards the generation if it changed. The UI never offers to launch a generation that is not published.
- **Disk.** Before a refresh, Kickoff reserves the bytes of every file that cannot be reflinked or hardlinked, plus 1 GiB (FILE-16).

**Linux.** Generations live in `~/.local/share/kickoff/copies/`, on the same filesystem as the launcher's install when that is btrfs or XFS. A full reflink clone shares every extent: 41 GB in 20,953 files, no NOCOW files (V on the reference machine, `du`, `find | wc -l`, `lsattr -R`). Validation reads 41 GB once per build; the budget is in §7. The **Kickoff prefix base** is seeded once with the player's input and camera configuration, copied from the default prefix. In the gamebox it is the read-only lower layer of the overlay (§3.2).

**Windows.** Generations live in `%LOCALAPPDATA%\Kickoff\copies\` for same-user modes. In contained mode they live in `%ProgramData%\Kickoff\copies\<user SID>\`, readable by the contained account and writable only by the user. Hardlinked files share content with the online install, so:
- Kickoff opens them only through `ReadOnlyRoot`;
- a launcher update that rewrites one in place changes the generation, so launch re-checks every file's size, last-write time and file ID against the values recorded at validation, and any difference makes the generation stale;
- creating a hardlink changes the online file's link count and change time, never its content or name, and SI-1 states exactly that.
NTFS on fixed local volumes is the only supported filesystem. ReFS, FAT, network and removable volumes are refused (FILE-10).

**Setting the map.**
- The slot is `TAGame/CookedPCConsole/Labs_Utopia_P.upk` ("Utopia Retro", not in online playlists; L).
- `set_map` holds the generation's lease and the per-generation writer lock. It clones or copies the verified object into an unnamed staging file in the copy's `CookedPCConsole`, verifying while copying. It then flushes (`fsync`, or `FlushFileBuffers`) and renames the file over the slot. On Linux the rename is `renameat2` followed by an `fsync` of the directory. On Windows it is `SetFileInformationByHandle(FileRenameInfoEx, POSIX_SEMANTICS | REPLACE_IF_EXISTS)`.
- A rename over a hardlinked slot replaces the copy's directory entry only; the online file keeps its content.
- After any failure, including a sharing violation, `store` re-reads the slot's file ID and hash to learn whether it holds the old or the new content, and never assumes which (FILE-10).
- `reset_map` does the same from the online install's file. Every reachable state is "stock" or "some verified map", neither of which matters for ban safety.

**Durability (FILE-11).** `store` orders operations as: write staging, `fsync` the file, rename, `fsync` the parent. Publishing or deleting a directory is a rename to or from a marker name, followed by an `fsync` of the parent. The claim is narrowed to what is tested: a crash-state model (§9) enumerates every state that POSIX allows after a crash at any point, given the recorded `fsync` barriers, and each state must recover to a valid one. No real power-loss test is claimed.

**Workshop Textures pack.** 14 additive files, 89.6 MB, none in the Epic manifest (V). Their names, sizes and BLAKE3 hashes are a table compiled into Kickoff; peer manifests and catalog entries cannot add names. Missing files are fetched from the pack's original host on first need, verified against the table, and installed into the generation only. The online install is never touched, including when copies of the pack already exist there.

What this removes from draft 1: the `NoEac` gate, the swap journal, restore triggers, the login hook, launcher-manifest restore and recovery's "leave the custom map and tell the user to Verify". Online play needs no Kickoff hook, because nothing Kickoff writes is on its path.

### 5.4 Applying a new build mid-session

Distribute first, then set the map at the next menu state. A same-process reswap under one package name is (U) and may need a game restart (Workshop Map Loader renames maps because fixed-name reloads crashed, V). The UI reports what it did, and never claims a reload it did not see in the log (`Bringing World`).

### 5.5 Map Maker mode

For map authors who build with UDK. Kickoff watches the chosen `.udk` or `.upk` package. It acts after UDK's temp-then-move save (`Log: Moving`, V) and once size and hash have settled, then ingests one snapshot. A mapmaking toolkit may instead call `kickoff library add --receipt <file>`. The receipt is decoded in `kickoff-parse`, and kickoffd compares the receipt's claimed SHA-256 with its own hash of the snapshot. The bundle is labelled **saved**, never "tested": no label variant exists for "tested" until runtime receipts exist. Labels authorize nothing.

### 5.6 kickoff-parse: the hostile-format sandbox

Every format whose bytes come from a peer, a website, the game or a launcher is decoded here and nowhere else:
- `ZstdMap` (stream to pipe), `BundleManifest`, `Ue3Header`, `ZipEntry` (streams one named entry from an archive to the output pipe; never materializes paths), `ImporterPage` (HTML to `{title, author, download_url}`), `Catalog` (signed JSON, §5.7), `Image` (PNG or JPEG to RGBA, at most 1024×1024), `RlReceipt`, `EpicManifest`, `SteamManifest`, `LaunchLog` (long-lived: log in, `GameState` events out) and `WlFilter` (long-lived, §3.2.1).

**The helper holds pipes and nothing else (R2-5).** Input, output and errors are three pipes; `WlFilter` instead gets its two listening and connected sockets. kickoffd counts every byte in each direction against the job's caps, writes all output to `store` itself and kills the helper on any cap or deadline. A compromised helper therefore cannot seek, overwrite a reserved offset, create a sparse file, grow a file past its cap or keep writing after its result is read.

**Linux.**
1. kickoffd spawns the helper with `clone3(CLONE_PIDFD | CLONE_INTO_CGROUP)` into a `parse` cgroup (`memory.max` per job, `pids.max` 1). It uses new user, net, pid, IPC and mount namespaces.
2. The helper's first instructions, before it reads any input byte:
   - `close_range(3, ~0)`, keeping only the allowlisted descriptors, each checked with `fstat` to be a pipe (or a socket for `WlFilter`);
   - a Landlock ruleset that handles every filesystem and network right and grants none, with abstract-socket and signal scoping;
   - `PR_SET_NO_NEW_PRIVS`, `PR_SET_PDEATHSIG(SIGKILL)` and rlimits on AS, CPU, FSIZE 0, NOFILE and CORE 0;
   - a seccomp allowlist: `read`, `write`, `mmap`, `munmap`, `brk`, `futex`, `exit_group`, `clock_gettime`, `sigaltstack` and `rt_sigreturn`, plus `recvmsg`, `sendmsg` and `poll` for `WlFilter` only. No `open`, `socket`, `execve`, `fork` or `ptrace`.
3. kickoffd writes the first input byte only after `/proc/<pid>/status` shows `Seccomp: 2` and `NoNewPrivs: 1`.
4. kickoffd kills the helper through its pidfd at the deadline.

**Windows (exact policy).**
1. kickoffd creates the helper with `CREATE_SUSPENDED` as a **less-privileged AppContainer** (LPAC):
   - `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` with a per-install AppContainer SID and **no** capabilities;
   - `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT`, which is what makes it an LPAC;
   - `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` listing exactly the three pipe handles;
   - `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`;
   - mitigation policies: Win32k system calls disabled, dynamic code prohibited, non-Microsoft-signed image loads blocked except our own signed binary, and strict handle checks.
2. kickoffd assigns it to a Job object, then resumes it. Job limits: `KILL_ON_JOB_CLOSE`, `ACTIVE_PROCESS` 1, `PROCESS_MEMORY`, `JOB_TIME`, all UI restrictions and `DIE_ON_UNHANDLED_EXCEPTION`.
3. kickoffd holds the only job handle, so kickoffd's death kills the helper. Startup has no window in which the helper runs outside the job: suspended, assigned, then resumed.

**Output** of `run` jobs is one postcard value with a size cap. kickoffd validates it as data. Anything that authorizes an action is recomputed by trusted code: hashes by `store`, receipt bindings by kickoffd (SI-37).

The in-process decoders kept are only the small fixed formats on the hot path: the LAN header, control messages and tickets. They live in `wire`, are `#![forbid(unsafe_code)]`, bounded by type and fuzzed. A workspace dependency check keeps `zstd`, `zip`, `html5ever`, `serde_json`, image decoders and the UE3 reader as dependencies of `parse` only.

### 5.7 Map browser, catalog and sources

**The catalog** is a JSON file in the public repository, changed by reviewed pull request. Each release record pins its hash, and catalog updates between releases are signed records with their own sequence and expiry (§8.4). An entry is: `{id, title, author, author_url, page_url, download_url, size, sha256, needs: [textures], preview_url, permission: Granted | LinkOnly}`. Its origins must be on the compiled allowlist.

**Browsing.** Map cards show title, author, a preview and a link to the author's page. Previews are fetched from the author's site when shown and decoded by the `Image` job.

**Playing a map** (2 clicks: the card, then Play):
1. Download from `download_url` on the player's machine, through `net::egress` (HTTPS, exact origin, redirects re-checked, connected address must be global, no cookies or credentials).
2. Check the size and SHA-256 against the catalog. On a mismatch, the author has changed the file since it was catalogued; the UI says so and asks before using it.
3. Extract the package with `ZipEntry`, ingest it, fetch textures if needed, set the map and launch.

Kickoff never mirrors map files. Every download comes from the author's own site, on the player's machine, with attribution on the card. Where an author has not granted permission, the entry is `LinkOnly`: the card opens the author's page in the browser, and the player adds the downloaded file by dropping it on Kickoff. An entry becomes `Granted` only with the author's permission.

Importers (all fetch through `net::egress` and decode in `kickoff-parse`):
- **Paste a URL** from an allowlisted origin (`bakkesplugins.com`, `cdn.bakkesplugins.com`, `lethamyr.com`). Userinfo and non-443 ports are rejected. BakkesPlugins has no public API, and its terms have no scraping clause (V). Lethamyr's `/maps/<id>/download` endpoint is (U); the retained response is a 404 page (V).
- **Drop a file** (`.zip`, `.udk`, `.upk`): read once into `Staged`, then decoded like any download.
- **Steam Workshop**: index a Steam install's `workshop/content/252950/<id>/` and read keyless `GetPublishedFileDetails` metadata (V). Kickoff never runs steamcmd.
- **Existing libraries**: imported by snapshot copy (§5.1).

Every map, whatever its source, is hostile input to the game. The catalog gives integrity and attribution, not a safety review.

## 6. Security model

### 6.1 Principals

| Principal | Trusted for | Kickoff's promise |
|---|---|---|
| The player at the keyboard | what they decide in a native dialog | — |
| Admitted peer (host or guest) | nothing beyond its own slot's game traffic | treated as malicious; it can learn your address in a direct session (§3.4) |
| Outsider, including anyone a peer tells about your session | nothing | cannot exhaust admission reserved for invited friends after the handshake; can delay new joins with a pre-handshake flood (§6.5) |
| Maps, map websites and catalog authors | nothing | maps are hostile input to the game; the catalog gives integrity and attribution only |
| The game process, after loading any map or peer packet | nothing; assumed compromised | Linux: contained by the gamebox. Windows: contained only in contained mode (§8.2) |
| gamescope and its Xwayland | nothing; reachable by the compromised game | contained by the display sandbox, with a 14-global host connection |
| kickoff-parse helpers | nothing; assumed compromised by their input | pipes only; outputs are data, never verdicts |
| Other local users and sessions | nothing | cannot use Kickoff's endpoints, leases or privileges |
| Same-user malware | outside the boundary; it can act as the user | must not gain root or SYSTEM through Kickoff |
| GitHub (repository, Releases, Pages) | availability only | cannot fake an install or update, and cannot freeze updates unnoticed |
| Relay host | availability; sees addresses, identities and timing | — |
| Build dependencies and toolchains | nothing until approved **and** reproduced | §8.4 |
| Kernel, GPU driver, compositor, administrators, Epic and Steam | trusted | out of scope |

### 6.2 Structural rules (one per class of finding)

Each rule makes a class unreachable rather than detecting instances. Classes A to K came from round 1; L to Q came from round 2 (`r2-resolution.md` maps every finding to one).

| Class | Rule |
|---|---|
| A. Ban safety rested on reacting to a modified shared install | **Offline copy generations**: Kickoff writes only into immutable, validated generations that no launcher can start and that lack the EAC bootstrap (§5.3) |
| B. Writes addressed by path; privilege writing into user-reachable trees | **`store` writes through handles it created**: unnamed staging, its own hash, atomic durable commit. No privileged process writes any file a user can reach (§2.3, §3.3) |
| C. Local IPC, pipe and webview without caller authentication | **Authenticated, exclusive, versioned, role-scoped channels** with no ancillary data; leases bound to connections (§2.7) |
| D. Peer reachability decided by port numbers | **Peers land in a namespace that holds only the game** (Linux) or **WFP admits only one service-held game instance of one user** (Windows) (§3.2, §3.3) |
| E. Session authority not bound to identity and generation | **One admission owner.** Every resource carries (identity, generation); revocation dominates trust; roles are directional (§4.4) |
| F. Budgets applied after allocation | **Charge before allocate**, with fixed-capacity queues, tables and pools, on both endpoints and before the handshake (§6.3) |
| G. Bootstrap, update and supply-chain trust | **Download hosts and build inputs are untrusted.** An offline-signed record with root epochs and freshness state admits artifacts by hash, from builds that were approved and reproduced (§8.4) |
| H. Hostile input parsed with ambient authority | **kickoff-parse and the gamebox** (§5.6, §3.2) |
| I. Untrusted data choosing outbound destinations | **One egress policy, enforced where packets leave** (§3.4, §5.7) |
| J. Secrets and metadata leaving through unstructured output | **Typed secrets, schema-built diagnostics, no core dumps** (§6.4) |
| K. Public relay sharing a host and trust with other services | **A relay on its own host**, admitting vouchered identities, with issuer and aggregate caps (§8.5) |
| L. Ambient authority inherited by a sandbox (display sockets, descriptors, handles) | **Authority is enumerated, not inherited.** Every sandboxed or confined process starts from an allowlist of descriptors, handles, mounts and protocol globals; everything else is closed or absent (§2.1, §3.2, §5.6) |
| M. A contained component's statement trusted as a verdict | **Contained components produce data, never verdicts.** Hashes, sizes, bindings and approvals are computed or held by trusted code (§5.2, §5.6, §4.4) |
| N. The game itself attacking its own install, its resources or the desktop | **The game is an attacker.** Linux: copy read-only, online install absent, resources capped, desktop reached only through gamescope. Windows: contained mode, or a disclosed residual (§3.2, §8.2) |
| O. Authority not tied to the lifetime of the thing it authorizes | **Every grant is held through a handle to its subject and dies with it**: cgroup, pidfd, process handle, lease lock (§3.2.2, §3.3, §5.3) |
| P. Destinations chosen inside a dependency | **The egress guard sits on the send path**, below any library logic (§3.4) |
| Q. Agreement or freshness mistaken for trust | **Approval binds the inputs; freshness is persisted state**: provenance approval, root epochs and highest-seen records (§8.4) |

### 6.3 Budgets (charged before allocation)

| Ingress | Budget |
|---|---|
| Door and session endpoint, before the handshake | at most 16 pending `Incoming` per endpoint; `retry` for unvalidated addresses; at most 8 handshakes per second per source address and 64 per second overall; `refuse` when full |
| Door, after the handshake | `JoinRequest` within 5 s; at most 16 connections awaiting a request and 2 per identity. Invalid requests at most 10/min per identity and 60/min overall. Bound-ticket holders and trusted ids use a separate queue that invalid traffic cannot fill |
| Session endpoint, after the handshake | only ids holding an admission pass; one live connection per id; `Hello` within 2 s; idle links closed after 15 s without `Pong` |
| Approvals | one pending per action kind; at most 6 native dialogs per minute |
| Datagrams per link, before reassembly | 3000 pps (burst 1000) and 4 MB/s, charged on attempts. A peer above 10x for 5 s is disconnected |
| Reassembly | 8 per link, 32 total, 4 fragments, 50 ms |
| Control | 64 KiB per message, 32 messages/s, 256 KiB/s; streams 4 bidi, opened at most 4/s |
| Map requests | 1 in flight per peer, 10 per minute |
| Host fan-out | host egress at most 16 MB/s overall, charged per emitted copy; discovery broadcasts 10/s per sender, payload ≤ 1252 bytes |
| Egress guard | at most 8 unvalidated destinations per remote, 4 new per second; 256 unknown connection contexts, 16 reserved for expected or admitted peers, 16 separate QAD contexts |
| Parse jobs | 2 concurrent, queue of 8; per job: memory cgroup or Job limit, CPU time, input and output byte caps counted by kickoffd, deadline |
| Disk | before a transfer, reserve the size plus 64 MiB; before a refresh, reserve the files that cannot be shared plus 1 GiB; keep at least 5 GiB free; library quota 20 GiB with least-recently-used eviction of unpinned objects |
| Game (Linux) | cgroup `memory.max` 12 GiB including the 4 GiB tmpfs prefix; `pids.max` 512; `RLIMIT_FSIZE` 4 GiB. Disk I/O bandwidth is not limited (the `io` controller is not delegated, V) |
| Windows pipe | one lease; frames ≤ 1600 bytes; a 1 s per-message deadline; an idle lease closes after 30 s without frames |

### 6.4 Secrets and diagnostics

- Keys, tickets, exchange codes, Epic refresh tokens and relay vouchers exist only as `secret::Secret<T>`. It implements neither `Debug`, `Display`, `Serialize` nor `Clone`, and it zeroizes on drop; a compile-fail test proves the missing traits. Only the single consumer of each secret can expose it, through a closure.
- `secret::harden_process()` runs before any secret exists in the Linux kickoffd worker: `PR_SET_DUMPABLE 0` and both `RLIMIT_CORE` limits set to 0. Windows excludes Windows Error Reporting for the process and disables the minidump callback. Linux's authentication facade remains inspectable so clients can verify its executable, holds no secret payload, and sets both core limits to 1. Linux rejects that value before invoking a piped core handler, and it is below the minimum ELF core size for a file handler. A clean, disposable startup child must crash without a kernel-reported core dump before the facade opens its endpoint; failed or unavailable verification refuses startup. A limit of 0 alone does **not** suppress piped handlers. The game and launcher helpers require a separately verified suppression policy across exec; M0 crashes a canary probe and checks both the kernel wait status and `coredumpctl`. No core-handler setting on the host is changed. See the [kernel suppression paths](https://code.googlesource.com/linux/torvalds/linux/+/18ded910b589839e38a51623a179837ab4cc3789/fs/coredump.c).
- **Legendary authentication broker (Linux, R2-15).** It runs legendary's `launch Sugar --dry-run` with a fixed argv and a scrubbed environment, only while no launcher process runs and legendary's lock is free. It reads stdout through a pipe straight into a `Secret`, and sends stderr to `/dev/null`, never to a log. Legendary may refresh its stored session first (upstream calls login before the dry-run branch; L for the installed version). That write to legendary's `user.json` is the one launcher-state change Kickoff causes; SI-1 states it and its test bounds it. Kickoff's own Epic sign-in, the alternative to the broker, removes it at the cost of a second login and a second stored refresh token. M0 runs the broker against fake expired credentials before any real account is used.
- The exchange code goes from the broker straight into the game's argv, never to a file. Each launch argument must match an allowlist (`-AUTH_LOGIN=`, `-AUTH_PASSWORD=`, `-AUTH_TYPE=exchangecode`, `-epicapp=Sugar`, `-epicenv=Prod`, `-EpicPortal`, `-epicusername=`, `-epicuserid=`, `-epiclocale=`, `-epicsandboxid=`); anything else refuses the launch. The code is one-time and consumed at login. It is still visible in the game's argv to processes of the same user, which is outside the boundary.
- Diagnostics (`kickoff doctor --export`) are built from an allowlisted schema of counters, states, versions and path types. They never contain raw logs, argv, launcher output, tickets or memory dumps. The export is previewed before it is written. Pattern redaction remains only as a second layer.
- Retention: Kickoff's own logs rotate after 7 days (tested with a controlled clock). Friend records can be listed and deleted in `doctor`.
- Privacy: the door is relay-only. Direct sessions disclose your addresses to admitted peers and to whoever they tell; relay-only sessions disclose them to the relay only (§3.4). Relay-only mode survives reconnects and route changes because the endpoint has no IP transport (tested by packet capture).

### 6.5 Residual risks (stated, not hidden)

- **Windows, unless contained mode is adopted and verified (§8.2).** A map or peer packet that exploits the game runs as the player. It can modify the online install, which risks a ban, and it can read the player's files and launcher tokens. Players see this at install and when a session starts.
- **Linux gamebox.** The game keeps the GPU driver and kernel attack surface. It shares gamescope and Xwayland, which are not hardened servers; a second exploit there reaches a sandbox with no home, no network and a 14-global host connection, which can draw a window, read input while focused, and lock the pointer while focused. pasta, a userspace network stack in the host namespace, parses the gamebox's packets (it is seccomp-confined, L). Disk I/O bandwidth is not limited.
- **Addresses.** In a direct session, admitted peers learn your IP address and can share it.
- **Transport probes.** An admitted peer can make your client send a bounded number of encrypted QUIC probes to UDP ports of its choice (§3.4).
- **Floods.** A pre-handshake flood through a relay, or at a leaked session endpoint, can delay new joins and reconnects. Established links are unaffected.
- **Relay revocation** takes effect by restarting the relay, which briefly drops every relayed connection (§8.5).
- **Same-user malware** can do anything the user can.
- **Lost recovery key**: no in-band recovery; a new root reaches players the way the first install did (§8.4).

### 6.6 Threats → rules → invariants

| Threat | Rule | Invariants |
|---|---|---|
| A modified file reaches an EAC session | A | SI-1, SI-2, SI-3, SI-39 |
| A compromised game modifies the online install or steals launcher credentials | N | SI-34 |
| A compromised game controls the desktop, clipboard or screen | L, N | SI-35 |
| A sandbox inherits authority it was not given | L | SI-36 |
| A write escapes its directory, lands half-done or is forged by a helper | B, M | SI-4, SI-5, SI-6, SI-37 |
| Another local principal drives Kickoff or impersonates a component | C | SI-7 to SI-10, SI-41 |
| A peer reaches a host service, or the wrong game instance | D, O | SI-11 to SI-13, SI-40 |
| The game exhausts resources or outlives its session | N, O | SI-38 |
| A malicious map or format exploits a parser | H | SI-14 to SI-17 |
| An uninvited or kicked peer keeps access | E | SI-18 to SI-22 |
| Floods | F | SI-23 |
| A forged, frozen, rolled-back or unapproved release | G, Q | SI-24 to SI-28 |
| Data or a dependency steers outbound traffic | I, P | SI-29 |
| Secrets or addresses leak | J | SI-30, SI-31 |
| The relay is abused, or becomes a door into other systems | K | SI-32 |

## 7. Performance budget

| Metric | Budget | Measured how |
|---|---|---|
| Added one-way latency, game socket to peer game socket, excluding the network path | p50 ≤ 100 µs, p99 ≤ 500 µs | CI: two in-process nodes over `Mem`, 10k datagrams. Baseline iroh datagram RTT p50 32-35 µs (V) |
| Tap adapter cost (Linux NsTap, Windows WinTap) | ≤ 20 µs per frame each way | netns bench; VM bench |
| Added RTT on a real direct path | ≤ 1 ms p99 above raw UDP | netns with `tc netem delay 30ms` |
| Hot path: codec, filter, generation check | ≤ 2 µs per datagram | criterion |
| Egress guard on an approved destination | ≤ 50 ns per send | criterion, through the patched transport |
| Host CPU in an 8-player session (~1700 pps, U) | ≤ 3 % of one core | 1 h soak |
| kickoffd memory | ≤ 64 MB RSS steady; the §6.3 ceilings hold under flood | soak and flood suite |
| Parse helper | spawn ≤ 10 ms; zstd ≥ 400 MB/s through the pipes into `store` | bench |
| Display path (Linux): gamescope + WlFilter against the same game drawn without them | frame time p99 within 5 %; no added frame of input latency; WlFilter ≤ 50 µs p99 per message | M1 (m), gamescope `--stats-path`, Wayland presentation feedback |
| Copy generation, Linux | build plus validation ≤ 90 s for 41 GB (reflink clone, then SHA-1 over every file on 8 threads) | M5a on the reference machine |
| Copy generation, Windows | hardlink build plus validation ≤ 3 min; full copy shown with progress | W1b |
| Launch re-check of a generation (size, mtime, file ID of 21k files) | ≤ 1 s | M5a, W1b |
| Map transfer | link-limited; BLAKE3 ≥ 1 GB/s | netns, 700 MB file |

## 8. Platform integration

### 8.1 Linux (Heroic, legendary and umu)

- **Discovery** is read-only: Heroic flatpak `…/legendaryConfig/legendary/installed.json`, key `Sugar`; native Heroic and standalone legendary roots (L). The Epic manifest beside it gives the build's file list and SHA-1s.
- **Launch.** Kickoff's Play button:
  1. refuses while a launcher process runs, because two writers of legendary's state are unsafe, and while legendary's lock is held;
  2. refuses while an online Rocket League runs;
  3. reuses or builds the copy generation (§5.3) and takes its lease;
  4. gets launch arguments from the authentication broker (§6.4), or from Kickoff's own Epic sign-in (§2.7);
  5. applies the argument allowlist and starts the gamebox (§3.2).
- **The launcher's own Play path is untouched.** Kickoff installs no hook in any launcher.
- **BakkesMod** is not started in the gamebox. That keeps its RCON port 9002 and its updater out of the namespace.
- **State** comes from the gamebox's pidfd (exit) and from `Launch.log` in the gamebox prefix, read by the supervisor and decoded by a `LaunchLog` job. Markers: `DevNet: Browse:`, `LoadMap:`, `MENU_Main_p`, `Event State = …`, `appRequestExit` (V). The log flushes in 4 KB blocks, so it is good for map and mode but not for timing (V).
- **Overlay**: a Tauri window. On Hyprland, a runtime rule (`float, pin, no_focus, no_initial_focus`) through `hyprctl` keeps it above a fullscreen game (V, app-shell); elsewhere it is an always-on-top window. Toggled by `kickoff --toggle-overlay`. The overlay is a host client, not part of the gamebox.
- **Packaging**: an AUR package `kickoff-bin` (signed release binaries; §8.4) depending on `webkit2gtk-4.1 gtk3 libayatana-appindicator passt umu-launcher bubblewrap gamescope pipewire wireplumber`. It ships the PipeWire and WirePlumber drop-ins and a systemd **user** unit for kickoffd. It ships no setuid binary, file capability, polkit action or system unit. Non-Arch distributions are not decided yet; an AppImage that checks for gamescope, passt and umu and explains what is missing is under consideration (Flatpak cannot run the gamebox's nested namespaces as designed).

### 8.2 Windows (Epic and Steam)

- **Discovery** is read-only: Epic `%ProgramData%\Epic\EpicGamesLauncher\Data\Manifests\*.item`, AppName `Sugar` (V via legendary `egl.py`); Steam: registry, then `libraryfolders.vdf`, then `appmanifest_252950.acf` (L).
- **Launching a copy needs the platform's authentication**, which no launcher gives to a copy:
  - **Epic:** "Sign in with Epic" in Kickoff's isolated sign-in window (§2.7). Kickoff stores the refresh token DPAPI-protected and mints a one-time exchange code per launch, as legendary does. Rocket League is free on Epic, so any Epic account can launch it (L).
  - **Steam:** whether a copy of the Steam build launches (with Steam running, or with Epic authentication) is (U), settled in W1b.
- **Game modes** (which ship is not decided yet; contained mode is recommended once W1 proves it):
  - **Contained (option A, recommended).** The elevated install creates a local standard account `KickoffPlay`. It is hidden from the sign-in screen, has a random password that nobody holds, and is in no group beyond the defaults. Per launch, kickoff-svc logs it on with S4U (no password), sets the token's integrity to **Low** and starts the leased generation's `RocketLeague.exe -noeac <args>` in the player's session and desktop. It keeps the process handle (§3.3). The game then has its own profile, Documents and registry hive, so it shares no configuration or save files with the online game. Low integrity blocks writes to the online install, the launcher's files and the player's registry, even where an ACL grants Users write (mandatory integrity "no write up"). It also blocks window messages, hooks and `SendInput` towards the player's windows (UIPI). The player's own profile, which holds launcher tokens and browser data, is unreadable because it is ACL'd to the player. Still readable: files that any local account may read. Whether Rocket League and Epic's SDK run at Low integrity under a separate account is the main (U), settled by W1.
  - **Same-user copy (option C).** The copy runs as the player. Kickoff causes no ban risk, but a compromised game can do anything the player can, including modifying the online install. The residual is shown at install and per session.
  - **Stock only (option D).** No copy. The player launches the online install from the launcher with "Launch without Anti-Cheat" (§3.3 stock mode). No custom maps on Windows; peer packets remain hostile input to the online game.
- **Installer shape.** Contained mode needs one elevated install, for the app and the account. Same-user and stock modes install per user with no prompt. In every mode, the LAN component (driver, service, firewall rule) installs on first multiplayer use, with its own prompt.
- **Overlay**: `always_on_top`, `focusable(false)`, click-through, with Borderless advised (U).

### 8.3 Builds and dependency gates

- Toolchain pinned in `rust-toolchain.toml` (Rust 1.99.0), with the toolchain manifest hash recorded. cargo-xwin is pinned with an explicit SDK and CRT version and their recorded hashes (L, cargo-xwin docs); the cache is re-verified before each release build.
- Gates on every PR, weekly on `main`, and on the exact release commit (PRIV-23):
  - `cargo deny check advisories sources bans licenses` and `cargo audit`;
  - `cargo vet` against approved audit sets (§8.4);
  - the frontend lockfile through `osv-scanner`;
  - pinned NSIS and WebView2 bootstrapper versions with recorded hashes, and an Authenticode check of the bootstrapper;
  - a watch of tap-windows6 advisories;
  - the vendored iroh and noq diff checks and registry advisory checks (§3.4);
  - the Windows import audit (§3.3).
- **Response deadlines**: critical advisories fixed or mitigated within 7 days, high within 30. Exceptions are dated entries in `advisory-exceptions.toml`, used to generate
  `deny.toml` ignores after both advisory gates validate them; none lasts more than 90 days.
- Third-party notices: MIT and Apache crates, iroh's `LICENSE-BSD3`, and tap-windows6 (GPLv2) shipped byte-identical with COPYING and its source tarball, as a separate program aggregated with Kickoff (GPL-3.0).

### 8.4 Release trust, distribution and updates

**Where players get it.** The public repository is `github.com/not-compromised/kickoff` (GPL-3.0). The link players share is a static GitHub Pages landing page, `https://not-compromised.github.io/kickoff/`. It has one button per platform, pointing at the latest GitHub Release asset, and shows the publisher name and the root fingerprint. It has no cookies, analytics or third-party scripts. Invite links use the same page (§4.2). GitHub is untrusted for integrity: it can withhold, not forge.

**Keys and roots (PRIV-20, R2-12).**
- The *release key* (minisign, on a hardware token) signs release records and catalog records only.
- The *recovery key* (offline, separate custody) signs only roots.
- A root is `{epoch, release_pub, recovery_pub, not_before}`. Root `n+1` must be signed by root `n`'s recovery key, and its epoch must be exactly `n+1`. Clients persist the highest epoch and refuse any older root, so a replayed rotation fails.
- A lost release key is rotated by the recovery key. A lost recovery key has no in-band remedy: a new root reaches players the way the first install did (§6.5).

**Release record** `{root_epoch, version, sequence, issued, expires (30 days), min_safe_version, catalog_sha256, artifacts: [{platform, name, size, sha256}]}`, signed by the release key.

**Freshness (PRIV-21, R2-12).** Clients persist the highest `sequence`, `version`, `root_epoch` and `issued` they have verified.
- A record with a lower sequence or root epoch is refused and flagged.
- A "no update" response, an error or a missing record never refreshes freshness. Only a verified record whose `expires` lies in the future does.
- Past the newest verified record's expiry, the UI shows "updates unavailable since X" persistently.
- If the wall clock is earlier than the highest `issued` seen, the clock is untrusted and the channel shows as stale.
- Below `min_safe_version`, networking is disabled, and solo play continues. Whether a long-stale channel also disables networking is not decided yet.

**Installing updates.** The updater is Tauri with `requireSignedVersion` enabled (default false, V tauri-plugin-updater 2.13.3 `config.rs:116`). It installs only an artifact whose hash is in a verified, unexpired record for this platform.

**Manual installers and anti-rollback (PRIV-7).**
- Each installer embeds its own signed record.
- It refuses to install a version below the highest recorded in `HKLM\Software\Kickoff\AntiRollback` (Windows) or Kickoff's state (Linux), or below the recorded `min_safe_version`. Repair of the same version is allowed.
- It accepts an expired embedded record only when that record's version is at least the highest installed, and then it says the record is expired.
- Uninstall keeps the anti-rollback record unless the player chooses to remove everything.

**First install (PRIV-1).**
- **Windows:** installers are Authenticode-signed. SmartScreen and Smart App Control rely on that signature, and so does trust in the embedded root: it comes from a Microsoft-rooted signature, not from GitHub. Kickoff never tells anyone to click past a SmartScreen or signature warning.
- **Arch:** the AUR `kickoff-bin` PKGBUILD pins artifact SHA-256s. The AUR is independent of GitHub, so a compromised GitHub cannot change those pins. Players never evaluate a PKGBUILD fetched from GitHub; builders build from the signed source tag (PRIV-22).
- **Other Linux:** not decided yet (§8.1).
- The root fingerprint is also published in the README, on the landing page and in the AUR package.

**Builders and provenance (PRIV-8, R2-11).**
- Two isolated builders. Neither holds credentials for other systems, deploy keys or writable mounts. Each fetches the pinned toolchain itself, checks its recorded hash, and builds `--locked --offline` from vendored inputs.
- **Reproduction is necessary, not sufficient.** The signing tool signs a record only when all of these hold:
  1. both builders' unsigned artifacts are byte-identical;
  2. the source commit is a tag signed by the maintainer;
  3. every dependency and toolchain change since the last release has an approval entry: `cargo vet` audits (own or imported from listed audit sets), plus the reviewed vendor diff and the reviewed toolchain and xwin hash changes;
  4. `scripts/check.sh` passed, including the invariant mutants (SI-33), on that exact artifact hash.
  A dependency change that both builders reproduce but nobody approved is refused.

**Upgrades (PRIV-24).** Versions install side by side in `versions\<v>\`. The sequence: quiesce sessions, stop the service, stage and verify the new directory, switch the service's `ImagePath` (one `ChangeServiceConfig` call), start it. If the start fails, switch back and start the old version. The old directory is kept until the new version has completed one start. Local channels and state carry versions; mismatches are refused (§2.7). Interrupting any step leaves the old or the new version working, which the VM suite checks at every step.

**Emergency stop (PRIV-30).** Locally, `kickoff stop --all` ends sessions, kills gameboxes and closes leases. Remotely, a release record that raises `min_safe_version` disables networking on older builds at their next check.

### 8.5 Relay deployment (R2-13)

- Built from `iroh-relay` 1.3.0 as a library with our own `AccessControl` (V: `server.rs:279-305`; `ClientRequest` carries the proven `EndpointId` and the WebSocket request).
- **Vouchers.** A session key is admitted only with a voucher `{session_key, issuer: door EndpointId, audience: relay hostname, not_before, not_after ≤ 12 h, seq}`, signed by the issuer's door key and carried in the per-relay token. The relay checks the audience, so a voucher cannot be replayed at another relay, and checks the validity window.
- **Accounting by issuer.** Every voucher's connections and bytes count against its issuer: at most 4 live vouchered keys per issuer, 8 connections per issuer, and an issuer bandwidth cap. Minting more keys therefore buys nothing.
- **Who may issue** is not decided yet: enrolled identities only (friends of the relay operator), or any Kickoff identity. In the open case, quotas per source address and an aggregate cap bound Sybil identities. The claim is narrowed: an open relay is abuse-limited, not access-controlled.
- **Revocation.** `AccessControl` can deny and observe, but cannot disconnect (V, `server.rs:285-305`; no disconnect method). Revoking an issuer therefore updates the list and restarts the relay. Every client reconnects within seconds, and the revoked issuer and its vouchers are refused. A vendored patch adding per-identity disconnect replaces the restart if M12 shows the blip matters.
- **Before admission.** The relay host's own firewall rate-limits TCP SYNs and concurrent connections per source address and rate-limits the QAD UDP port per source; TLS and HTTP handshakes have deadlines. These limits sit outside `iroh-relay`, whose `accept_conn_limit` is unimplemented (V, `server.rs:486`).
- **Deployment.** A dedicated small host that runs nothing else: not on any private network, no credentials for any other system, an egress firewall denying private, CGNAT and overlay ranges. Non-root, read-only filesystem, no mounts except its TLS key, dropped capabilities, only 443/tcp and the QAD port exposed, metrics off or on localhost (default port 9090, V `defaults.rs:16`). Logs are kept 7 days.
- n0's public relays stay as a fallback ("development and hobby use", V).

## 9. Test strategy

`scripts/check.sh` runs every test that `docs/SECURITY-INVARIANTS.md` names, then runs each row's **mutants**. A mutant is a build or configuration with that row's mitigation removed, and the test must fail against it. A test that passes on a mutant does not count (SI-33).

**CI, no game (a Linux host that allows user namespaces; GitHub runners restrict them, L):**
1. Unit and property tests: codec, filter, tickets, admission and approval state machines, `store` (adversarial filesystem with a fault seam at every syscall, plus the crash-state model), launch-argv builder, secrets (compile-fail).
2. In-process multi-node: admission races driven by barriers, approvals raced against kicks, reconnects and map changes, the 3-node directional test, fragmentation limits, transfer with resume and bad sources, a dishonest `ZstdMap` helper, the latency assertion, and the flood suite including a leaked session endpoint.
3. Linux namespaces, with a nested compositor under test (a headless wlroots compositor with security-context support): two gameboxes with the Wine UDP probe (`udptest.exe`) standing in for the game, plus the **compromised-game probe suite** (SI-34, SI-35, SI-36, SI-38), the pasta and egress matrix, a packet recorder on the session endpoint for the send guard, and kill -9 at every setup step.
4. Fuzz (nightly): LAN codec, control, tickets, pipe frames and command sequences, every `kickoff-parse` job with the sandbox enabled, and WlFilter message streams.
5. Windows VMs (`kickoff-win-a`, `-b`; Secure Boot on):
   - install, repair, upgrade and uninstall, interrupted at every ledger step; a precreated permissive or junction install directory; DLLs planted beside the installer, in the working directory and in `%TEMP%` (every name an ETW image-load trace saw the process try);
   - staging-only driver install next to older, equal and newer OpenVPN adapters;
   - driver drift before and **during** a lease;
   - WFP: the full arbitration matrix of §3.3; the block after a service crash and after reboot; same-image instances, cross-user instances, simultaneous EAC and no-EAC instances, game exit and restart, PID reuse, `-noeac` as a substring;
   - pipe tests from two users, two sessions, low integrity and AppContainer, with a fake server started first, and stateful fuzzing of the pipe protocol;
   - the contained-mode compromised-game probe (W1a);
   - LPAC helper: handle enumeration, named-object access, parent killed at every startup phase.
   The VMs cannot run Rocket League (no GPU).

**Live, with people present** (run by the maintainer, never in CI): a supervised gamebox session on a Linux desktop running the game through Heroic/umu (M1); a stock-map LAN match between two Linux PCs (M4); a Windows PC with a GPU for the contained-account boot, a Steam copy and hardlink timings (W1b); a Windows player with a Linux host, stock map then custom map (M9); a mixed EAC on/off LAN (informational); a Map Maker reswap (M13).

## 10. Milestones (riskiest first; each lands with the invariants it introduces)

| ID | Slice | Proves | Invariants green | Depends on |
|---|---|---|---|---|
| M0 | **Containment probes, no game and no account**: gamebox, display sandbox (gamescope, WlFilter, security context), restricted audio, descriptor inventory, cgroup and teardown, pasta and DNS, and the auth broker against fake credentials. Items (f) to (l) of §3.2.5 | The containment claims, before any real account or custom map | SI-14, SI-34 (Linux), SI-35, SI-36, SI-38 (manual) | `passt`, `umu-launcher` and `gamescope` installed |
| M1 | **Gamebox game spike** (supervised, no peers): spike copy, native umu under gamescope, items (a) to (e), (m) and (n); LAN facts from tap frames; a locally built map in the copy; a same-process reswap | The gamebox and copy thesis, the display cost, every (U) in §3.1 | SI-2 (manual), SI-35 (beside the real game) | M0 |
| W1 | **Windows spike**, beside M1. W1a (VMs): contained account with S4U and Low integrity, compromised-game probe, stock-mode instance binding, WFP arbitration, LPAC helper. W1b (a Windows PC with a GPU): Rocket League boots under the contained token with an Epic exchange code; a Steam copy; hardlink copy timings | Whether contained mode is feasible; whether stock mode can be bound | SI-34 (Windows, VM), SI-40 (VM) | test VMs; W1b needs a Windows tester |
| M2 | Core loop in process: `wire`, `vlan::Mem`, door and session endpoints, admission and approvals, budgets, `ipc` (Linux), `secret` | Wire, admission, generations, budgets, latency | SI-3, SI-7 (Linux), SI-10, SI-18 to SI-23, SI-29 (tickets and guard unit), SI-30, SI-31, SI-33, SI-41 | none (parallel) |
| M5a | **Minimum copy protections**: generations with manifest validation, the EAC exclusion policy, leases, a Kickoff-owned prefix base, fail-closed launch | No experimental copy builder becomes a live launch path | SI-2, SI-39 | M1 |
| M3 | `NsTap` adapter and kickoff-gamebox in CI, Wine probes in two gameboxes, the send-guard packet recorder | Rootless Linux LAN end to end | SI-11 (Linux), SI-12 (Linux), SI-13, SI-14, SI-29 (transport), SI-34 to SI-36, SI-38 in CI | M0, M1, M2, M5a |
| M4 | **Live stock-map LAN match between two Linux PCs** via the CLI | The thesis on Linux | — | M3, M5a, a second player |
| M5 | Full `store`, Landlock, `set_map` and `reset_map`, solo custom map | Ban-safe custom maps (Linux) | SI-1, SI-4, SI-5 | M5a |
| M6a | **Parser confinement on both platforms**, including the dishonest-helper and writable-handle cases and the LPAC policy | No peer-controlled format reaches an unconfined parser | SI-15, SI-37 | M2; W1a for Windows |
| M14 | Map browser: catalog, importers, drop-a-file, textures, Steam Workshop index | Solo custom maps in 2 clicks | SI-29 (importers), SI-17 | M5, M6a |
| M6 | Library, transfer, map pick with approval | Custom maps between peers | SI-16, SI-23 (transfer and disk) | M5, M6a |
| M7 | Windows networking: kickoff-svc, staged driver, WFP, lease contract with instance binding, pipe authentication | Windows LAN without the game | SI-6, SI-7 (Windows), SI-8, SI-11 (Windows), SI-12 (Windows), SI-28, SI-40 | M2, W1a |
| M8 | Windows copy, Epic sign-in and launch in the chosen Windows game mode (§8.2) | Windows custom maps | SI-1, SI-2 (Windows), SI-34 (Windows, if option A) | M7, W1 |
| M9 | Live Windows player with a Linux host: stock map, then custom map | Cross-platform play | — | M4, M7, M8; SI-34 status per the Windows game mode |
| M10 | Tauri UI: capabilities, native approvals, overlay, invites, map browser UI, onboarding | The §1.1 targets | SI-9 | M6, M14 |
| M11a | **Release-trust spikes, early**: bootstrap verifier, both isolated builders reproducing a trivial artifact, provenance approval with `cargo vet`, root rotation and freshness state machine, signing route | That the distribution trust model works before UI completion | SI-24 to SI-27 (spike level) | can start beside M3 |
| M11b | Distribution: landing page, GitHub Releases, AUR, NSIS, updater, `doctor` | Installable from one link | SI-24 to SI-27 | M10, M11a |
| M12 | Relay: vouchers, issuer accounting, revocation, limits before admission, isolated deployment | The project relay | SI-32 | M2 |
| M13 | Map Maker: package watcher and toolkit receipts | Mapmaking flow | (uses SI-15, SI-37) | M6 |
| M15 | Optional: browser feed, host transfer, arm64 | Extras | per feature | M10 |

Gates that override the table:
- **Real peer sessions** (M4, M9, and any hand-delivered alpha) need the compromised-game suite green for that platform: SI-34 to SI-36 and SI-38 on Linux. On Windows, SI-34 in contained mode, or the residual-risk disclosure shipped if same-user or stock mode is chosen (§8.2).
- **No real account and no custom map** before M0 is green.
- **No peer-controlled format** before M6a.
- **No public link** before M11b and a signed Windows installer. A tester can receive an alpha the maintainer hands over directly, subject to the first gate.

## 11. Unverified facts that block milestones

| Fact | Blocks | Settled by |
|---|---|---|
| Native umu runs the copy under gamescope, with legendary-minted arguments passed directly to `RocketLeague.exe` | M1, M3 | M1 (a) |
| gamescope's Wayland backend runs through WlFilter and a security-context socket on Hyprland and other compositors | M1 | M0 (k), M1 (a) |
| The restricted PipeWire socket gives playback and denies capture | M0 | M0 (j) |
| The ephemeral prefix and shader cache cost acceptable first-match stutter | the shader-cache choice (§3.2.5) | M1 (n) |
| The game's network namespace is the gamebox's, not the host's | D on Linux | M1 (b) |
| The game boots with internet only through pasta and public DNS | M3 | M1 (c) |
| The copy boots `-noeac` without `EasyAntiCheat/` and `Launcher.exe`, read-only | the copy (A) | M1 (d) |
| Discovery port, broadcast form, packet sizes, embedded IPs | filter, `GamePorts` | M1 |
| Same-name reswap inside one game process | Map Maker, mid-session map change | M1, the Map Maker live test |
| pasta flags give no inbound forward and no host access | SI-14 | M0 (i), M3 |
| systemd-coredump honours `RLIMIT_CORE 0` for the game | SI-30 | M0 |
| Rocket League and Epic's SDK run at Low integrity under a separate account | contained mode (§8.2) | W1b |
| A Steam copy launches (with Steam running, or with Epic authentication) | Steam players | W1b |
| Hardlink copies work for typical Epic and Steam install locations | §1.1 disk target | W1b |
| The tap driver installs without a publisher prompt | §1.1 prompt target | W1a |
| Hard WFP permit against the firewall's default block, explicit block rules and ICS; media drop on handle close; instance-binding detection latency | M7 | W1a, VM |
| Windows POSIX rename semantics on NTFS for the slot | M8 | VM |
| A signed installer shows no SmartScreen or Smart App Control block on a fresh PC | §1.1 | M11a |
| iroh relay token can be set per URL (vouchers) | M12 | M2 test |
| Package GUID mismatch rejects joins | M6 | the two-PC live match (M4) |
| iroh, ring and blake3 build under pinned cargo-xwin | M7 | first Windows build |

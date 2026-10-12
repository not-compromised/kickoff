Redacted for publication: machine names, paths and addresses replaced with generic terms.

1. **PRIV-1 | critical | First installation bypasses the protected update chain**

   **Scenario:** An attacker compromises the project's download site, replaces the installer and download instructions, and supplies matching checksums plus an attacker-controlled verification key. A friend downloads it and accepts the advertised UAC prompt. The attacker gains administrator execution and can install a SYSTEM service.

   **Why the design does not stop it:** §8.4 distributes the installer, `SHA256SUMS` and its signature together. §11 leaves signing undecided, including “unsigned for friends at first.” §1’s claim that compromising the download host cannot push updates applies only after a trustworthy public key has reached the client.

   **Mitigation:** Define a bootstrap trust channel independent of the download server. Require a known Authenticode publisher for Windows releases and independently distribute the expected publisher/key fingerprint. Never instruct users to bypass signature failures. Distinguish first-install authentication from updater authentication.

   **Automated test:** Replace every download-page asset, checksum, signature and advertised key in a distribution fixture. An independently trusted verifier must reject the installer before execution or elevation.

2. **PRIV-2 | high | Install discovery reintroduces attacker-controlled paths into SYSTEM**

   **Scenario:** A local user changes Steam library metadata, a writable game-library directory, or a directory junction. The service discovers that location, checks its canonical path, then the attacker redirects an ancestor or fixed temporary file before `SlotInstall` writes. SYSTEM writes attacker-selected bytes outside the intended game slot. A protected executable or configuration overwrite can become privilege escalation.

   **Why the design does not stop it:** §2.3 says the service “never opens a path supplied by the user,” but §8.2 discovers paths through registry and launcher metadata. §5.3 specifies `O_NOFOLLOW` and a canonical directory check, then Windows `ReplaceFileW`/`MoveFileEx`. It does not establish Windows protection against ancestor reparse points, hard links, or check-to-use races. `slot_name` is also a string in the supposedly path-free pipe API.

   **Mitigation:** Make slot identifiers an enum. Treat discovered roots and launcher metadata as untrusted. Bind each authorized install to verified directory handles and file identities; reject reparse points throughout privileged traversal; create temporary files exclusively. Keep journals and backups in service-owned storage, indexed by install identity. Prefer writing under the caller’s token wherever elevation is unnecessary.

   **Automated test:** Race junction changes at every filesystem step; plant temporary-file links; forge library metadata and journals. Assert that no file outside the authorized install changes and no unrelated file ACL changes.

3. **PRIV-3 | high | Service and installer executable-loading rules are unspecified**

   **Scenario:** The installer accepts a user-writable destination or reuses an existing directory with permissive ACLs. Malware replaces `kickoff-svc.exe` or plants a DLL searched during elevated installation or service startup. The next installation, upgrade or boot executes it as administrator or SYSTEM.

   **Why the design does not stop it:** §3.3 specifies “NSIS perMachine” and `kickoff-svc install`, but no directory, binary, registry or SCM security descriptors; quoted absolute `ImagePath`; DLL-loading policy; or protected extraction directory. Per-machine installation alone does not establish those properties. Microsoft documents the danger of loading DLLs from attacker-controlled search locations. [DLL security guidance](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security).

   **Mitigation:** Require a protected installation directory with explicit, validated ACLs. Protect the service configuration and privileged state. Use a quoted absolute executable path, safe DLL search settings, absolute helper paths, and protected staging. Apply these checks during repair and upgrade too.

   **Automated test:** Install into precreated permissive and junction-backed directories; plant candidate DLLs in working, download and temporary directories; attempt executable and SCM modification as a standard user. Installation must reject unsafe locations and never load planted code.

4. **PRIV-4 | high | INTERACTIVE authorizes other users and sessions, not Kickoff**

   **Scenario:** Another local account, an RDP user or a fast-user-switching session connects first, calls `LanOpen`, observes game datagrams, injects traffic, or calls `SlotInstall` while another user’s offline game satisfies the gate. Same-user malware can also invoke every permitted command. The attacker gains privileged operations and cross-session interference without using Kickoff’s UI.

   **Why the design does not stop it:** §3.3 says the pipe “admits SYSTEM and INTERACTIVE” and serves one client. There is no caller-to-game-user or logon-session binding. INTERACTIVE is a group, not an application identity; Microsoft recommends logon-SID restrictions for session separation. [Well-known SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids), [pipe access controls](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).

   **Mitigation:** Authenticate each client using its token, bind leases to an authorized SID and logon session, and require the target game to belong to that principal. Define explicit arbitration between sessions. Treat same-user malware as an authorized but hostile client. Specify mandatory integrity policy and AppContainer rejection rather than assuming the DACL answers both.

   **Automated test:** Exercise every command from two users, two sessions of one user, RDP, medium integrity, low integrity and AppContainer tokens. Unauthorized callers must receive no datagrams and cause no privileged changes. Do not assume low-integrity or AppContainer access succeeds; prove rejection under the actual security descriptor.

5. **PRIV-5 | high | A fake named-pipe server can impersonate kickoff-svc**

   **Scenario:** Before service startup, malware creates the expected pipe name. kickoffd connects and sends map bytes and traffic to the fake server, which returns fabricated success or restore results. With an overly broad write ACE, an attacker may also create additional server instances.

   **Why the design does not stop it:** §3.3 specifies the ACL but no first-instance protection or client verification of the server. Microsoft documents that generic pipe write permissions include the right to create pipe instances. [Pipe rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).

   **Mitigation:** Use `FILE_FLAG_FIRST_PIPE_INSTANCE`, fail closed on name collision, grant individual client rights excluding instance creation, and set `PIPE_REJECT_REMOTE_CLIENTS`. Clients must verify the server’s process/token and protected executable identity. Use a suitable client impersonation level. [CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew).

   **Automated test:** Start a fake server before the service and attempt additional instances afterward. Neither client nor service may silently proceed. Test remote UNC access and verify that no attacker server receives game or map data.

6. **PRIV-6 | high | SYSTEM parses attacker-selected messages and bytes despite the isolation claim**

   **Scenario:** Malware connects to the pipe, sends malformed framing, oversized lengths, invalid slots, truncated streams or interleaved commands. Alternatively, it declares a large map and sends bytes indefinitely or extremely slowly. It can exhaust privileged memory/disk, monopolize the single client, or exploit unsafe codec/filesystem code.

   **Why the design does not stop it:** §2.1 says the service “parses no network input,” but §2.3 streams peer-derived map bytes into it. §3.3 defines `SlotInstall` followed by a byte stream without service-specific framing, limits, deadlines or state transitions. §5.2’s daemon transfer caps are not a privileged enforcement boundary. Hashing attacker-chosen bytes against an attacker-chosen hash establishes consistency, not authorization.

   **Mitigation:** Specify a bounded, versioned pipe protocol and explicit state machine. Enforce byte counts, deadlines, disk quotas, concurrency limits and fixed slot/texture authorization inside the service. Stage and verify before replacement. Audit unsafe code and native calls; fuzz complete command sequences, not just isolated messages.

   **Automated test:** Stateful fuzzing must cover command interleaving, disconnects, integer limits, slow streams and excessive bytes. Assert bounded resources, unchanged game files on rejection, and continued restore availability.

7. **PRIV-7 | high | The update manifest can relabel a valid old artifact**

   **Scenario:** A compromised host advertises version `99.0.0` but supplies an older installer and its valid signature. If that signature lacks an authenticated version, the normal “newer version” comparison accepts the manifest while signature verification accepts the old bytes. A user approves an apparent upgrade and receives vulnerable code.

   **Why the design does not stop it:** §6 T9 says “downgrades refused,” but §8.4 only selects Tauri’s static manifest. The locally available Tauri updater 2.13.3 explicitly documents `require_signed_version` as **false by default**, including this attack. Signatures with a signed version already get mismatch checks; legacy signatures without one remain the bypass unless enforcement is enabled. Updater configuration source: tauri-plugin-updater 2.13.3, `src/config.rs:116`.

   **Mitigation:** Require authenticated version metadata from the first release, enable `requireSignedVersion`, disable downgrades, and enforce equivalent checks for manual installers. Bind release identity to platform, channel and artifact. Ensure signing tools actually emit the required metadata.

   **Automated test:** Pair an inflated manifest version with an old signature without version metadata, an old signature with metadata, and another platform’s artifact. All must be rejected before installation.

8. **PRIV-8 | high | Offline signing can authenticate a compromised build**

   **Scenario:** A malicious dependency executes through `build.rs`, a compromised compiler/cache modifies output, or another CI job contaminates release staging. The owner transfers and signs the resulting installer offline. Every client correctly verifies malware, which runs elevated during installation.

   **Why the design does not stop it:** §1 claims “reproducible” from Rust and pinned binaries; §8.3 uses cargo-xwin; §9 permits builds on the maintainer's local CI server. The project standard requires lockfiles and vulnerability scanning, but neither those rules nor offline signing establish artifact provenance, builder isolation or reproducibility.

   **Mitigation:** Define an isolated release builder without credentials for the maintainer's other systems or writable deployment mounts. Pin Rust, LLVM, cargo-xwin, NSIS, frontend tooling and all dependency sources. Use locked/offline builds from authenticated inputs. Record provenance and compare independently rebuilt unsigned artifacts before signing the exact tested release.

   **Automated test:** A deliberately hostile build-script fixture must not read CI secrets, modify other jobs or reach deployment paths. Two clean builders must reproduce the agreed artifact contents; signing must refuse hashes absent from approved provenance.

9. **PRIV-9 | high | DiInstallDriverW contradicts the OpenVPN coexistence promise**

   **Scenario:** A friend has an older OpenVPN TAP adapter. Kickoff calls `DiInstallDriverW` with its newer matching driver. Windows updates the existing adapter too, potentially interrupting a VPN or changing its security-sensitive configuration.

   **Why the design does not stop it:** §3.3 says “Stage the driver with `DiInstallDriverW`” and avoids another API because it “re-drivers a friend’s OpenVPN adapters too.” Microsoft states that `DiInstallDriverW` itself installs on present supported devices when the package ranks better. [API documentation](https://learn.microsoft.com/en-us/windows/win32/api/newdev/nf-newdev-diinstalldriverw).

   **Mitigation:** Use a staging-only operation, then explicitly select the verified package for Kickoff’s recorded device instance. Document any unavoidable shared-driver change as an exception requiring consent. Never use force-install flags indiscriminately.

   **Automated test:** Install alongside older, equal and newer OpenVPN driver/device configurations. Compare package bindings, settings and connectivity before and after. Existing devices must remain unchanged unless an explicitly tested migration was authorized.

10. **PRIV-10 | high | Pinned driver downloads do not prove the active driver is trusted**

   **Scenario:** A machine already contains another higher-ranked `tap0901` package, or an OpenVPN update later rebinds Kickoff’s device or restores `AllowNonAdmin`. Kickoff verifies its bundled files but opens a different active driver or a device now writable by ordinary users. Local processes can sniff or inject traffic.

   **Why the design does not stop it:** §3.3 verifies hashes during installation and deletes `AllowNonAdmin` once. It does not verify the selected package, loaded version, current device ACL or registry state at each use. A `doctor` check is not mandatory admission control.

   **Mitigation:** At startup and every `LanOpen`, verify device identity, active package, expected signer/hash, effective access and absence of `AllowNonAdmin`. Detect device reconfiguration and close on drift. Maintain a supported-driver security policy. State explicitly that an already compromised kernel is outside the recoverable trust boundary.

   **Automated test:** Rebind to an alternate package; reintroduce `AllowNonAdmin` as both 0 and 1; alter device ACLs; simulate an OpenVPN upgrade. Kickoff must refuse use, and an unprivileged process must fail to obtain an injection/sniffing handle.

11. **PRIV-11 | high | The NoEac proof is neither durable nor bound tightly enough**

   **Scenario:** The gate observes an offline process and log, then that process exits or another EAC-enabled process starts during the streamed install. On Linux, a permissive `*wine*` identity check can also select the wrong process. Restoration reacts after a log message or process event, leaving a modified file visible to a protected launch.

   **Why the design does not stop it:** §5.3 constructs `NoEac` from passive observations; §8.1 acknowledges 4 KiB log buffering. No proof lifetime, process-handle binding or exclusion against competing launches is defined. Windows restoration explicitly waits for exit. A Rust proof type cannot freeze external process state.

   **Mitigation:** Bind each proof to install identity, caller, process handle/start identity and a short-lived transaction. Recheck before commit. Define a cooperative launch exclusion protocol and mandatory stock verification before protected launches. Where external launchers cannot be controlled, narrow the safety claim and refuse automatic transitions that depend on an unenforceable guarantee.

   **Automated test:** Kill/restart the game at every transaction boundary; reuse PIDs; supply another user’s log; start an EAC-enabled process while installation is paused. No invalid proof may authorize a commit or clear an unsafe-state indication.

12. **PRIV-12 | high | Recovery can intentionally leave a modified slot without preventing online play**

   **Scenario:** Kickoff crashes while swapped, then the launcher updates its manifest. Recovery refuses to restore the old original and leaves the custom map installed. The user launches online before seeing the repair warning. Disabled login recovery or a failed service start creates similar exposure.

   **Why the design does not stop it:** §1 claims “A crash cannot strand a swapped map.” §5.3 instead says “Otherwise write nothing and tell the user to run launcher Verify.” The supplied prototype reproduces that flagged state. §8.1 makes the online pre-launch stock check an owner decision rather than a required safety mechanism.

   **Mitigation:** Define persistent `Clean`, `Swapped` and `NeedsRepair` states. A failed or unverifiable recovery must remain visibly unsafe and must never be reported as success. Make stock verification mandatory for supported protected launch paths; retain backup/journal state until verified repair. State the limitation for launch paths Kickoff cannot intercept.

   **Automated test:** Crash while swapped, advance the manifest without repairing the slot, and attempt every supported online launch. Each must refuse until repair is verified. Missing manifests, disabled recovery and inaccessible backups must never yield `Clean`.

13. **PRIV-13 | high | The Linux root fallback has no constrained authorization contract**

   **Scenario:** A user-controlled UID, subnet, port list, environment or helper path reaches the elevated setup operation. A broadly matching or cached polkit authorization allows malware to repeat setup with different arguments, create a TAP owned by another principal, or alter firewall/routing policy.

   **Why the design does not stop it:** §3.2 specifies `kickoff-setup-root (pkexec)` but not its installed ownership, exact polkit action, argument schema, subprocess handling or rollback. Refusing euid 0 in kickoffd does not secure this helper. pkexec explicitly does not validate program arguments. [pkexec security notes](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html).

   **Mitigation:** Install a root-owned helper with fixed operations and bounded typed inputs. Derive caller identity from trusted credentials. Use absolute executable paths and argument arrays, or native APIs. Scope authorization to the exact helper, require explicit authentication, and transactionally undo partial setup.

   **Automated test:** Fuzz arguments and environment; supply shell metacharacters, another UID, conflicting interfaces and routes; fail each setup step. Only enumerated Kickoff resources may change, and failed setup must restore the previous configuration.

14. **PRIV-14 | high | Tauri’s webview-to-daemon boundary is undefined**

   **Scenario:** A malicious peer name, map description, importer page or update note reaches an unsafe renderer. Script execution invokes custom commands to join sessions, install maps, export diagnostics or modify the configurable launch command. The daemon’s privileges become available through the UI.

   **Why the design does not stop it:** §2.1 says the UI “talks to kickoffd only,” but specifies no production CSP, custom-command allowlist, origin restrictions or operation authorization. The research spike allows inline scripts. Tauri documents that registered custom app commands are available to all app windows/webviews by default unless restricted. [Capabilities documentation](https://v2.tauri.app/security/capabilities/).

   **Mitigation:** Require bundled content only, strict CSP without unrestricted inline execution, text-only rendering of untrusted fields, narrowly scoped asset access, and explicit command permissions for main versus overlay windows. Keep security-sensitive confirmation and validation in trusted Rust/daemon code. Do not offer a generic IPC proxy or shell-execution command.

   **Automated test:** Render adversarial metadata and update notes containing script, markup and dangerous URLs. Attempt every privileged command from overlay, remote navigation and iframe contexts. Unauthorized calls must fail at the Rust boundary.

15. **PRIV-15 | high | Local daemon IPC lacks authentication and ownership rules**

   **Scenario:** Another user connects to a permissive Unix socket or Windows daemon pipe and issues `join`, `host`, `library add` or `restore`. Alternatively, malware squats the socket before UI startup and supplies fabricated status while collecting tickets and diagnostics.

   **Why the design does not stop it:** §2.1 specifies “IPC (unix socket / pipe)” and starts kickoffd when its socket is missing. No location, directory permissions, peer credentials, server authentication or stale-socket handling is defined.

   **Mitigation:** Use a per-user runtime directory with 0700 permissions and a 0600 socket; verify `SO_PEERCRED` and server identity. Define equivalent SID/logon-session controls on Windows. Bind exclusively, reject foreign existing endpoints, and verify ownership before removing stale files. Explicitly acknowledge that same-UID malware remains a hostile caller.

   **Automated test:** Connect from another UID/SID; precreate sockets and symlinks; forge server replies; race daemon startup. No unauthorized command may succeed, and no unrelated filesystem object may be removed.

16. **PRIV-16 | high | A game-port allowlist does not establish that Rocket League receives traffic**

   **Scenario:** Rocket League stops and another local service binds UDP 7777 or 14001. An admitted peer sends payloads to that port through Kickoff, reaching a loopback-only service. A local process can also generate apparent game traffic that opens reply flows to other ports.

   **Why the design does not stop it:** §3.1 permits traffic by port and records flows based on outgoing tuples. §1 claims peers can reach only Rocket League, but the filter establishes neither socket ownership nor process identity. The denylist covers known services, not arbitrary software.

   **Mitigation:** Narrow the claim to allowed UDP endpoints unless process ownership is enforced. Require a verified active game, close delivery immediately on exit or socket-ownership change, and constrain reply flows to observed game-owned sockets. Use OS isolation/firewall mechanisms where reliable ownership checks are unavailable.

   **Automated test:** Replace the game listener with an unrelated listener on each allowed port; generate outgoing traffic from a non-game process; race game exit and rebinding. Peer payloads must not reach the substitute service.

17. **PRIV-17 | high | “Wine sandboxing” does not establish containment of malicious maps**

   **Scenario:** A compromised host supplies a crafted map that exploits Rocket League’s parser. The game runs with access to the user’s home, launcher credentials or other writable files, allowing account theft and persistence. Windows has no specified containment either.

   **Why the design does not stop it:** §6 T7 acknowledges parser exploitation but lists “Wine sandboxing on Linux” without defining filesystem, process, credential or network isolation. §3.2 explicitly relies on sharing the host network namespace. Hashes and known-source URLs authenticate neither safe content nor author trust.

   **Mitigation:** Describe actual containment and its tested permissions. Treat map execution as running untrusted content. Require explicit per-map approval by default, support host/hash revocation, and isolate the game where practical. Document Windows residual exposure. Do not present Wine itself as a security sandbox.

   **Automated test:** Run a harmless game-context probe that attempts to read credential canaries, write outside approved directories and contact prohibited endpoints. Verify denial in the exact supported launcher environments.

18. **PRIV-18 | high | Public relay exposure is not isolated from the maintainer's other systems and release builder**

   **Scenario:** A relay vulnerability or resource-exhaustion attack compromises or overloads the shared server. If its process can reach local CI artifacts, deployment credentials, private services or shared writable directories, the attacker gains access to the maintainer's other systems or contaminates future releases.

   **Why the design does not stop it:** §3.4 proposes public TCP 443 and UDP 7842 but no process/container isolation or resource budget. The project standard requires localhost-bound ports and Cloudflare exposure; the maintainer's safety rules forbid unspecified wildcard binding. Direct UDP exposure therefore needs a deliberate, documented exception.

   **Mitigation:** Define a dedicated relay deployment and exposure exception. Prefer a separate host or strong isolation from CI and private services. Use a non-root runtime, dropped capabilities, read-only filesystem, restricted mounts, resource limits and filtered ingress. Separate public downloads, relay and CI credentials.

   **Automated test:** Deployment policy checks must reject extra mounts, capabilities and ports. A relay-context probe must fail to read CI/private-data canaries or modify release staging. Flood testing must leave private services healthy.

19. **PRIV-19 | medium | Install, session and uninstall cleanup are not failure-safe**

   **Scenario:** The service is killed, installation fails halfway, or uninstall runs during a loaded game. TAP media, firewall rules, routes or modified slots remain. Uninstall may delete the service and journal before restoration succeeds. A removed preexisting firewall block may never be restored.

   **Why the design does not stop it:** §3.3 relies on “On exit” cleanup and says uninstall removes resources and restores slots without ordering or failure states. `store=active` does not itself prove immediate crash cleanup. The driver, firewall rules and Linux setup also persist intentionally, contradicting §1’s literal “nothing left behind.”

   **Mitigation:** Maintain a durable resource-ownership ledger and transactional cleanup. Restore before deleting recovery machinery; refuse completion when restoration is unverified. Remove only recorded resources, preserve unrelated changes and restore consented firewall edits when appropriate. Separate expected installed residue from session residue.

   **Automated test:** Terminate setup, service, upgrade and uninstall after every step. Read back actual device, address, route, firewall and file state. Test OpenVPN coexistence and loaded-file failures. Report unresolved residue explicitly.

20. **PRIV-20 | medium | An offline update key needs custody, rotation and compromise recovery**

   **Scenario:** The owner signs a mislabeled artifact, loses the only key, or an attacker steals either the current or permanently trusted backup key. Clients accept malicious releases or cannot receive security fixes. Trusting two keys indefinitely increases the usable compromise set.

   **Why the design does not stop it:** §8.4 says the key is offline; §6 T9 says “current plus backup.” There is no signing ceremony, backup custody, revocation, rotation authorization or recovery path.

   **Mitigation:** Define signing approval over exact hashes and provenance, encrypted offline backups, distinct release and recovery roles, and a tested rotation/revocation procedure. Avoid treating a backup key as another unrestricted permanent release key.

   **Automated test:** Exercise current-to-next rotation, rejection after retirement, wrong-role signatures and recovery from a lost release key. Signing must refuse artifacts absent from the approved release record.

21. **PRIV-21 | medium | Freeze attacks silently preserve vulnerable releases**

   **Scenario:** A compromised download server continually serves an old manifest, returns no-update responses or fails requests. Clients stay on a vulnerable version indefinitely, and the attacker exploits it without forging a signature.

   **Why the design does not stop it:** §6 T9 tests tampering and downgrade only. §8.4 has one static endpoint and no authenticated freshness or stale-channel state. Offline signing prevents forgery, not withholding.

   **Mitigation:** Add signed release metadata with sequence numbers and expiry, persisted highest-seen state, independent recovery distribution, and visible stale-check failures. Define whether security-critical minimum versions disable particular operations. Do not promise availability against a withholding server.

   **Automated test:** Serve stale metadata, repeated no-update responses and outages under a controlled clock. The client must detect staleness, preserve highest-seen state and avoid reporting the channel healthy.

22. **PRIV-22 | medium | “pacman owns updates” leaves package authentication unspecified**

   **Scenario:** A friend fetches a modified PKGBUILD or package from the compromised download host. They build/install it through their normal package workflow. The attacker executes build-time user code or root-level package hooks.

   **Why the design does not stop it:** §8.1 disables the Tauri updater and ships a PKGBUILD, but specifies no trusted recipe source, signed package repository, verification key distribution or authenticated source commits. Package management alone is not publisher authentication.

   **Mitigation:** Choose a distribution model explicitly. For binary packages, use signed packages/repository metadata with independently provisioned keys. For PKGBUILDs, authenticate the recipe and pin/verify sources; build unprivileged in a clean environment. Never use `SKIP` for executable inputs.

   **Automated test:** Replace the recipe, package, source archive and repository metadata independently. Each unauthenticated change must fail before executable build hooks or privileged installation.

23. **PRIV-23 | medium | Dependency and toolchain maintenance is incomplete**

   **Scenario:** A newly vulnerable pinned driver, crate or WebView dependency remains deployed because scanning only covers PRs. Alternatively, an unpinned xwin SDK/CRT update changes release inputs despite the same source commit.

   **Why the design does not stop it:** §3.4 pins iroh but calls it `=1.3.x`; §8.3 leaves toolchain inputs unspecified. The project standard covers lockfile scanning, but the design does not map Rust advisories, frontend dependencies, Windows binaries and driver vulnerabilities into one release gate. cargo-xwin defaults SDK and CRT selection to latest. [cargo-xwin configuration](https://github.com/rust-cross/cargo-xwin#customization).

   **Mitigation:** Commit exact lockfiles/toolchain versions; use `--locked`; pin SDK/CRT versions and authenticated digests. Define cargo-audit/cargo-deny or equivalent gates, executable dependency inventory, scheduled scanning, owner response times and expiring exceptions. Revalidate mutable caches.

   **Automated test:** Inject a known advisory, forbidden dependency source and modified cached CRT input. Release checks must fail. Rebuilding an old commit must not resolve newer toolchain inputs.

24. **PRIV-24 | medium | Upgrades have no daemon/service compatibility or transaction boundary**

   **Scenario:** An updater replaces binaries while an older service still owns a TAP handle or active swap journal. A new daemon sends differently interpreted commands; a failed upgrade removes the only working recovery binary.

   **Why the design does not stop it:** §4.3 versions peer ALPNs, but §3.3’s pipe and §2.1’s local IPC have no version handshake. §8.4’s passive installer has no quiescence, journal compatibility or rollback rules.

   **Mitigation:** Version local IPC, service commands and persisted state independently. Quiesce sessions, verify stock/clean state, stop the service, stage and validate replacement, then restart. Reject incompatible combinations. Preserve a tested recovery path through interrupted upgrades.

   **Automated test:** Run every supported old/new UI-daemon-service combination and interrupt upgrade at each step while a journal exists. Incompatible commands must be rejected without side effects; recovery must remain available.

25. **PRIV-25 | medium | Deep links and imported URLs lack a network-destination policy**

   **Scenario:** An attacker sends a ticket whose endpoint contains private/direct addresses or an attacker relay URL. After confirmation, the app probes unintended local destinations or contacts a tracking server. Import redirects can similarly escape the named map-source hosts and fetch internal resources.

   **Why the design does not stop it:** §4.2 says “Parsing is strict” and confirms dialing, but defines no canonical grammar, length limits or endpoint policy. §5.5 constrains initial source URLs without redirect, DNS-resolution, scheme or final-host rules. A typed `EndpointAddr` is not a trust decision.

   **Mitigation:** Specify exact deep-link grammar and byte limits, reject ambiguous encoding and extra components, and keep links out of shell/CLI-option parsing. Constrain relay URLs and importer redirects; reject credentials, unsafe schemes and internal destinations where unnecessary. Show authenticated host identity and contact/privacy consequences before dialing.

   **Automated test:** Fuzz encoded separators, oversized tickets, extra arguments and malformed URLs. Test redirects and DNS answers leading to loopback/private addresses. No unintended fetch, shell action or dial may occur.

26. **PRIV-26 | medium | A shared token embedded in public builds cannot restrict relay use to Kickoff**

   **Scenario:** An attacker downloads Kickoff, extracts its shared token and uses a custom client to relay arbitrary traffic. Rotating the token breaks legitimate old builds while the attacker extracts the replacement.

   **Why the design does not stop it:** §3.4 says `access.shared_token` means “only Kickoff builds use it.” It authenticates possession of a distributed credential, not application identity. `[limits.client.rx]` alone does not establish total connection, egress or aggregate resource limits.

   **Mitigation:** Treat the token as public abuse friction. Use per-identity admission or individually revocable credentials where access restriction matters, plus connection, bandwidth, handshake and aggregate quotas. Define emergency disablement and fallback behavior.

   **Automated test:** A non-Kickoff client possessing an extracted token must still be constrained by quotas. Revoking one identity must leave others working, and many identities must not bypass the aggregate budget.

27. **PRIV-27 | medium | Persistent identity protection is incomplete on Windows and during recovery**

   **Scenario:** Another local user reads an identity from permissive app-data storage or a backup. They impersonate a trusted friend, whose EndpointId is admitted without a new ticket. Copying the same identity to multiple devices also creates simultaneous ownership ambiguity.

   **Why the design does not stop it:** §3.4 specifies mode 0600 “per install,” which does not define a Windows DACL or protection for the parent directory and backups. §4.2 trusts persistent EndpointIds but defines no key-compromise revocation or reset procedure.

   **Mitigation:** Define identity as per-user/per-device; protect parent directories and files with explicit platform ACLs. Consider user-bound Windows encryption. Exclude keys from diagnostics, document backup handling, and provide identity reset plus friend revocation. State that same-user malware can generally act as that user.

   **Automated test:** Other accounts must fail to read the key. Copy/reset/revoke an identity and verify that the old key loses trusted admission and reconnect privileges.

28. **PRIV-28 | medium | Privacy and diagnostic guarantees omit sensitive data and retention**

   **Scenario:** Diagnostic export includes an invite bearer token, endpoint identity, private path, relay credential or authentication value in an unrecognized format. Peer names also inject misleading log lines. Persistent relay logs and friend records reveal social relationships and public IPs.

   **Why the design does not stop it:** §1 says diagnostics “never leak credentials,” but §6 T11 tests a short list of known strings. No collection, retention, export or deletion policy covers tickets, keys, relay tokens, addresses, journals or friend lists. No-pkarr does not prevent relay observation or direct-path address disclosure.

   **Mitigation:** Use structured allowlisted diagnostic fields and prohibit secret collection at the source. Redaction should be a secondary defense. Specify retention, export preview, log escaping and deletion. Explain public/LAN address disclosure before joining; ensure relay-only settings survive reconnect and fallback.

   **Automated test:** Seed all sensitive stores and streams with unique canaries, then exercise every export and failure path. No forbidden canary may appear. Capture relay-only reconnect/fallback traffic and assert no direct candidates or packets. Retention tests must remove expired records.

29. **PRIV-29 | medium | Pre-admission work and privileged recovery lack independent resource budgets**

   **Scenario:** Unauthenticated clients repeatedly initiate QUIC handshakes or join streams before roster admission. An admitted client floods fragmentation or control work. Separately, one pipe client stalls forever, blocking normal networking and restoration.

   **Why the design does not stop it:** §4.3 limits join attempts and deadlines, and §6 T3 limits admitted-peer traffic, but does not define limits before those checks or bound concurrent fragment assemblies. The service admits one client without a lease timeout or independently scheduled recovery path.

   **Mitigation:** Bound pre-auth connections, handshakes, stream allocation, fragment assemblies and pending prompts. Apply quotas before expensive work. Make service recovery independent of a client’s progress, with finite leases and cancellation.

   **Automated test:** Flood pre-auth handshakes, incomplete fragments and slow pipe clients simultaneously. Assert bounded memory/CPU, usable legitimate admission and successful recovery within a stated deadline.

30. **PRIV-30 | medium | Threat boundaries and security invariants are not release requirements**

   **Scenario:** A later implementation adds an importer, overlay command or service operation that bypasses an assumed boundary. Existing codec tests remain green because no single requirement states who may authorize privileged writes, what must remain safe after failure, or which dependencies must fail closed.

   **Why the design does not stop it:** §6 lists threats but omits a complete attacker/trust-boundary model and secure-defaults contract. §9 does not make the project standard’s single `scripts/check.sh`, invariant checks or release-artifact verification explicit. There is no incident-response or local emergency-stop design.

   **Mitigation:** Add a written threat model and `INVARIANTS.md` covering local users, same-user malware, malicious admitted hosts, compromised distribution/build infrastructure and compromised kernels. Require fail-closed verification, authorized fixed writes, recovery availability and privacy defaults. Define bounded security audit events and a local stop operation that closes networking while preserving recovery.

   **Automated test:** Make each invariant traceable to a required check. A release-policy test must reject missing proofs, skipped checks and unsupported privilege/exposure exceptions. Exercise emergency stop during traffic and slot installation; recovery state must survive.

**Claims verified as sound**

- The downloaded driver files match the design’s abbreviated SHA-256 pins; all three full hashes were recomputed locally.
- Deleting `AllowNonAdmin`, rather than setting it to 0, is correct: `adapter.c:427–443` enables access upon any successfully read integer value.
- The supplied swap prototype restores the original in its modeled unchanged-manifest crash cases; rerunning it passed those cases. This does not prove power-loss, Windows or concurrent-launch safety.
- The prototype refuses to restore an old original after a manifest change, then recognizes launcher repair as stock.
- The saved firewall experiment shows a Kickoff drop blocking traffic accepted by another chain, while a Kickoff accept does not override an existing drop. Evidence: recorded firewall results (not published).
- iroh 1.3.0 offers mandatory client authentication and verifies TLS signatures; authenticated EndpointId possession is distinct from authorization to join. Evidence: `iroh-1.3.0/src/tls/verifier.rs` and rustls’s verifier default.
- Tauri’s updater requires artifact signatures; that protects already provisioned clients against arbitrary unsigned replacement, subject to bootstrap, version-binding and signing-custody limitations. [Updater documentation](https://v2.tauri.app/es/plugin/updater/).
- Breaking peer-protocol changes already have ALPN versioning in §4.3. The missing version boundaries are local IPC, privileged commands and persisted state.

**Open questions**

- What exact pipe SDDL, access masks, integrity label, remote-client policy and caller-token checks will be used?
- Which users and simultaneous sessions may control the machine-wide adapter and each game installation?
- Where will service journals/backups live, and which filesystem identities and ACLs authorize a discovered install?
- Which Windows driver staging-only API and explicit device-binding procedure will replace `DiInstallDriverW`?
- Will signed-version enforcement be mandatory from the first release, including manually installed packages?
- How will friends authenticate the first installer independently of the project's download site?
- What exact game filesystem isolation is promised on Linux and Windows?
- Which supported online launch paths can enforce stock verification, and what guarantee remains for uncontrolled launchers?
- Will the public relay share a host, user, writable storage or credentials with local CI and the maintainer's other services?
- Who owns security advisories, key compromise, driver drift and minimum-version decisions?
- The design references track JSON evidence, but those files were absent from the provided research tree. Where is the durable evidence ledger, including driver-signature verification and full source/version provenance?

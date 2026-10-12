Redacted for publication: machine names, paths and addresses replaced with generic terms.

## Section A: resolution of all 71 findings

Verdicts assess the design, not an implementation. No enforcing test suite exists in the reviewed checkout. “RESOLVED” means the proposed mitigation addresses the original attack and the specified test would detect its removal. “PARTIAL” includes incomplete mitigation or a test that leaves the relevant failure undetected.

Section references below point to [draft 2](../design.md). SI references point to [SECURITY-INVARIANTS.md](../SECURITY-INVARIANTS.md).

| Id | Verdict | Section | What is missing |
|---|---|---|---|
| FILE-1 | RESOLVED | §5.3; SI-1, SI-2 | None for the original swap/restore race. Online-tree comparison catches a return to shared-install writes. Compromised-game paths remain, R2-1 and R2-2. |
| FILE-2 | RESOLVED | §3.3, §5.3; SI-4, SI-6 | Removing privileged map writes eliminates the original SYSTEM overwrite. The pipe schema and filesystem suite detect its reintroduction. |
| FILE-3 | PARTIAL | §5.3, §8.2; SI-2 | Copy launches address this, but Windows stock mode uses an externally launched online image. No process-instance binding or corresponding command-line/PID-reuse test is specified for that exception. |
| FILE-4 | RESOLVED | §5.3; SI-1 | Copy-only writes remove dependence on a proof remaining live during a swap. The online-tree test detects shared-install commits. |
| FILE-5 | RESOLVED | §5.1, §5.3; SI-1 | Exact stock identity no longer authorizes online-install writes. SHA-1 is correctly identified. |
| FILE-6 | RESOLVED | §5.3; SI-1 | Restoration cannot overwrite an update because restoration is removed. Copy-refresh coherence is a separate outstanding problem, R2-8. |
| FILE-7 | RESOLVED | §5.3; SI-1 | Missing recovery state cannot strand Kickoff bytes in the online install. Failure-injection plus online-tree comparison detects regression. |
| FILE-8 | PARTIAL | §5.3; SI-3, SI-4 | The writer lock is specified, but SI-3 tests forbidden fields, not concurrent copy refresh, deletion and map replacement. Add generation-bound copy leases and concurrent-operation tests. |
| FILE-9 | RESOLVED | §2.3, §5.3; SI-4 | Exclusive staging and substitution races are explicitly covered. |
| FILE-10 | PARTIAL | §5.3; SI-4 | POSIX rename semantics remain unverified. Specify supported Windows/filesystem combinations, sharing failures, durability and resulting-state checks. The generic suite does not explicitly cover these outcomes. |
| FILE-11 | PARTIAL | §2.3, §5.3, §9; SI-4 | Syscall faults and SIGKILL do not model power-loss persistence. Parent-directory flush ordering and crash-safe directory publication/deletion need explicit requirements and persistence tests. |
| FILE-12 | RESOLVED | §5.3; SI-1, SI-17 | Copy-only textures eliminate online residue. Online-tree comparison and arbitrary-manifest tests cover the original attack. |
| FILE-13 | PARTIAL | §3.2, §6.5; SI-14, SI-16 | Windows approval does not contain exploitation. Linux display sockets provide an indirect host-control path. SI-14 tests direct access only, R2-1 and R2-2. |
| FILE-14 | RESOLVED | §5.7; SI-29 | Exact origins, redirects, resolved/connected addresses and credential exclusion address the original importer SSRF. The connect-recorder test covers their removal. |
| FILE-15 | PARTIAL | §5.6; SI-15 | Windows “less-privileged AppContainer” is not an exact policy; inherited-handle closure and hostile output-handle use are unspecified. Generic open/socket probes do not establish confinement, R2-5. |
| FILE-16 | PARTIAL | §5.2, §5.6, §6.3; SI-15, SI-23 | A compromised Windows helper can bypass logical output caps through its writable file handle. Game/prefix and copy-refresh disk growth are also outside reservations, R2-5 and R2-7. |
| FILE-17 | PARTIAL | §5.1, §5.2; SI-4, SI-5 | The decompressor returns the hash used for commit. A compromised helper can lie. Cache-mutation tests do not cover dishonest helper results or writes after verification, R2-6. |
| FILE-18 | PARTIAL | §5.1; SI-15, SI-17 | The claim is correctly narrowed, but specified fixtures do not test UE3 offset/count arithmetic, supported versions or forged parser results. Texture-path property testing covers only that part. |
| FILE-19 | PARTIAL | §5.5; SI-16 | “Saved” is correct and snapshot binding is specified. SI-16 tests source-label trust, not failed/mismatched receipts, source mutation or incorrect “tested” labels. |
| FILE-20 | PARTIAL | §6.4; SI-30 | Structured diagnostics improve coverage, but exchange codes still enter argv and process memory. Core-dump policy, launcher stderr capture and inherited logging destinations are unspecified, R2-15. |
| FILE-21 | PARTIAL | §2.7, §3.3; SI-7, SI-8 | Authenticate caller-to-game ownership, not just caller identity. The service’s `LanOpen{slot}` contract does not establish its target user, executable or process instance, R2-3. |
| FILE-22 | PARTIAL | §4.5, §8.2; SI-2, SI-3 | The opt-in is removed. Windows stock mode nevertheless depends on observing a command-line switch; the specified argv-builder test does not enforce this externally launched exception. |
| PRIV-1 | RESOLVED | §8.4; SI-24 | Independent expected publisher/root distribution and independently supplied alpha hashes address compromised-download-server bootstrap. The distribution fixture must run a trusted verifier before executing the downloaded installer. |
| PRIV-2 | RESOLVED | §3.3, §5.3; SI-4, SI-6 | Privileged discovered-root writes are removed. Service metadata reads need a narrower invariant, but do not recreate the original write exploit. |
| PRIV-3 | PARTIAL | §3.3; SI-6 | `SetDefaultDllDirectories` executes after initial imports load. Require an import-time dependency/loading audit and DLL planting beside the elevated installer itself, including repair and upgrade. |
| PRIV-4 | PARTIAL | §2.7, §3.3; SI-7, SI-8 | Caller-to-target SID, logon session and process binding remain unspecified. A SYSTEM server cannot interpret “same SID” without an explicit authorized principal, R2-3. |
| PRIV-5 | RESOLVED | §2.7; SI-7 | Exclusive pipe creation, remote rejection, restricted instance rights and server authentication address impersonation. Fake-server tests detect removal. |
| PRIV-6 | PARTIAL | §3.3, §6.3; SI-3, SI-23 | Map streaming is removed, but service-side framing limits and command-state transitions need explicit enforcement. Frame fuzzing and a slow-client test do not cover arbitrary command sequences. |
| PRIV-7 | PARTIAL | §8.4; SI-25 | Updater version binding is addressed. Equivalent anti-rollback checks for manual installer execution, repair and reinstall are not specified or tested. |
| PRIV-8 | PARTIAL | §8.4; SI-26, SI-27 | Two builders reproduce deterministic malicious inputs too. The hostile-build-script fixture tests isolation, not malicious reproduced output or approved provenance, R2-11. |
| PRIV-9 | RESOLVED | §3.3; SI-28 | Staging-only installation and explicit device binding replace the conflicting API. Existing-adapter comparisons detect regression. |
| PRIV-10 | PARTIAL | §3.3; SI-28 | Reverification at `LanOpen` misses drift during a live lease. Subscribe to relevant changes and revoke promptly; mutate driver/ACL/registry state after opening in the VM test. |
| PRIV-11 | RESOLVED | §5.3; SI-1, SI-2 | Copy-only writes remove the old proof-lifetime failure. This does not validate Windows stock-mode process isolation. |
| PRIV-12 | RESOLVED | §5.3; SI-1 | No restore-required state can leave Kickoff modifications online. |
| PRIV-13 | RESOLVED | §3.2, §8.1; SI-13 | Root fallback is removed. Packaging checks and euid refusal detect its reintroduction. |
| PRIV-14 | PARTIAL | §2.7; SI-9, SI-16 | Native approval needs an immutable operation/hash binding. Current tests exercise rendering and command permissions, not approval races or dialog flooding, R2-14. |
| PRIV-15 | RESOLVED | §2.7; SI-7 | Private exclusive endpoints and mutual kernel credential checks address other-user access and endpoint squatting. |
| PRIV-16 | PARTIAL | §3.2, §3.3; SI-11 | Linux isolates host listeners. Windows app-ID filtering identifies a pathname, not the particular launched process, user or launch mode. The other-program test misses same-image substitutes, R2-3. |
| PRIV-17 | PARTIAL | §3.2, §6.5; SI-14, SI-16 | Direct filesystem containment is insufficient with shared display control; Windows execution remains uncontained. |
| PRIV-18 | PARTIAL | §8.5, decision 12; SI-32 | Decision 12 still permits a container on the maintainer's shared server despite the no-shared-host rule. No relay egress policy or canary test for the maintainer's network is specified, R2-13. |
| PRIV-19 | PARTIAL | §3.2, §3.3; SI-12 | Resource ownership by daemon/service does not establish teardown on game death. Interrupted install/uninstall ledger recovery also lacks an explicit test, R2-3 and R2-7. |
| PRIV-20 | PARTIAL | §8.4; SI-26 | Distinct roles help, but root epochs, rotation replay protection, authenticated root fetching, backup custody and lost-key recovery are unspecified, R2-12. |
| PRIV-21 | PARTIAL | §8.4; SI-25 | Specify persisted freshness and stale behavior for outages, repeated “no update” responses and clock rollback. “Refused or flagged” also leaves expired-record installation ambiguous, R2-12. |
| PRIV-22 | PARTIAL | §8.4; SI-24 | Pinned hashes and `validpgpkeys` authenticate sources, not executable PKGBUILD contents. Define recipe authentication before evaluation and the trusted pre-execution verifier. |
| PRIV-23 | PARTIAL | §3.4, §8.3; SI-27 | Rust scanning is specified. Frontend dependencies, NSIS, WebView2, driver advisories, response deadlines and exceptions lack corresponding gates. |
| PRIV-24 | PARTIAL | §2.7, §8.4; SI-10 | Version rejection is sound. A durable multi-binary replacement/rollback transaction and proof that interrupted upgrades leave a working version are not defined. |
| PRIV-25 | PARTIAL | §2.7, §3.4, §5.7; SI-29 | Ticket/importer filtering is specified, but autonomous iroh candidate/path traffic is not covered by the destination guard or recorder fixtures, R2-10. |
| PRIV-26 | PARTIAL | §8.5; SI-32 | Voucher issuer accounting, active revocation, replay/audience scope and pre-authentication relay budgets remain missing, R2-13. |
| PRIV-27 | PARTIAL | §3.4; SI-22 | Local reset cannot revoke trust stored by friends. Define recipient-side revocation/re-pairing and backup behavior; test two devices holding the old trust relationship. |
| PRIV-28 | PARTIAL | §6.4; SI-30 | Diagnostic canaries cover exports. Retention/deletion and relay-only behavior across reconnect, route changes and fallback need separate enforcing tests. |
| PRIV-29 | PARTIAL | §3.4, §6.3; SI-23 | Explicitly bound accepted handshakes and idle authenticated connections until request completion. The pending-`Incoming` cap alone does not specify that lifecycle. |
| PRIV-30 | PARTIAL | §6, §9; SI-33 | Require checks tied to the exact release artifact/platform/configuration, incident ownership and emergency stop. Checking that named tests “ran” does not establish those properties. |
| NET-1 | PARTIAL | §3.1–§3.3; SI-11 | Linux removes shared-host delivery. Windows still permits other instances of the same image; the test excludes different programs only, R2-3. |
| NET-2 | RESOLVED | §3.2; SI-11 | The host-namespace proxy and its reusable sockets disappear. Host-listener canaries detect ordinary isolation regressions. |
| NET-3 | PARTIAL | §2.7, §3.3; SI-7, SI-8 | The lease is connection-bound, but target-user/game binding and session-switch revocation need a concrete service policy, R2-3. |
| NET-4 | RESOLVED | §2.4, §3.4, §4.4; SI-21 | Directional routing is explicit; the three-node test detects fan-out or guest acceptance. |
| NET-5 | RESOLVED | §4.4; SI-18, SI-19 | Revocation dominates trust and tickets; barrier tests cover handshake, reconnect and queued delivery races. |
| NET-6 | RESOLVED | §4.4; SI-18, SI-23 | One live generation and connection-churn tests address resource multiplication per admitted identity. |
| NET-7 | PARTIAL | §3.4, §6.3; SI-23 | Endpoint secrecy fails against malicious admitted peers. Pre-handshake CPU/transport limits and accepted-but-idle connection accounting need explicit policies, R2-9. |
| NET-8 | RESOLVED | §3.4, §6.3; SI-23 | Pre-allocation charging, bounded assemblies, conflict rejection and removal of proxy sockets address the original allocation attack. |
| NET-9 | PARTIAL | §8.5; SI-32 | Enrolled keys replace build-token authentication, but fresh session keys can multiply per-key allowance. Account by voucher issuer and bound work before `AccessControl`, R2-13. |
| NET-10 | PARTIAL | §3.4; SI-31 | An admitted malicious peer can disclose the session endpoint to outsiders. Candidate publication still precedes admission. Test a leaked endpoint explicitly, R2-9. |
| NET-11 | PARTIAL | §3.3; SI-11 | Existing firewall rules are preserved. WFP layers, weights, block/permit arbitration and forwarding/ICS treatment remain unspecified; the current VM test does not cover all of them, R2-3. |
| NET-12 | PARTIAL | §3.2, §3.3; SI-12 | Service death removes its dynamic permit. Game death does not automatically close that service session; namespace/pasta lifetime also needs explicit supervision. |
| NET-13 | RESOLVED | §4.2, §4.4; SI-20 | Atomic nonce transitions, monotonic bearer expiry and session-bound capabilities address the original replay races. |
| NET-14 | RESOLVED | §4.2, §6.4; SI-30 | Bound invites, verified fingerprints and complete-ticket canaries address the stated diagnostic leak and display-name confusion. External clipboard/screenshot exposure remains outside that guarantee. |
| NET-15 | PARTIAL | §3.4; SI-29 | Relay URL filtering addresses the original arbitrary-relay attack. The claim that altered addresses can “only break the dial” ignores pre-authentication network effects and autonomous candidate traffic, R2-10. |
| NET-16 | RESOLVED | §3.4, §6.3; SI-23 | Control/request/open-rate budgets and host-local scheduling address the original bypass. Combined saturation tests detect removal. |
| NET-17 | RESOLVED | §6.3; SI-23 | Per-emitted-copy charging, aggregate egress and bounded discovery payloads address amplification. |
| NET-18 | PARTIAL | §6.3; SI-23 | A reserved queue after authentication cannot reserve handshake capacity. Narrow the availability promise or provide a pre-authentication admission mechanism. |
| NET-19 | RESOLVED | §6.4, §8.5; SI-32 | Listener inventory, private metrics and accurate presence/privacy statements address the original finding. |

## Section B: findings against draft 2

These are design attack scenarios, not demonstrated Rocket League exploits. No game, launcher, Wine, VM, firewall or network configuration was touched.

### R2-1: compromised Windows game can defeat offline-copy ban safety

**Severity: critical**

**Scenario:** A malicious host supplies a map or game datagram that exploits Rocket League. On a supported user-writable Steam/Epic library, the compromised game modifies the online package, launcher configuration or an online-loaded DLL. The user subsequently launches ordinary online play.

**Why draft 2 does not stop it:** §6.1 explicitly assumes the game compromised. On Windows it retains the user’s authority. `store`, `ReadOnlyRoot` and a separate copy constrain Kickoff’s intended writes, not arbitrary code running in Rocket League. Approval of a hash does not establish safe content; stock-map sessions still accept hostile game packets.

**Mitigation:** Put the Windows game under a principal/environment unable to write or control the online installation, launcher state and credentials. Until established, do not claim the standing ban-safety requirement holds for Windows peer sessions.

**Enforcing test:** Run a compromised-game probe under the exact Windows launch token. Attempt online-install/config writes, launcher control and credential access, including a user-owned game library. SI-1 currently exercises Kickoff operations rather than this attacker.

### R2-2: shared display connections bypass Linux file isolation

**Severity: critical**

**Scenario:** After exploiting the game, the attacker uses its authorized connection to the host X server to inject input into an existing host X11 terminal or editor. That host application reads credentials or modifies the online installation outside the gamebox. The game exfiltrates results through its permitted internet access.

**Why draft 2 does not stop it:** §3.2 exposes the host X11 and Wayland sockets. Namespaces and mount restrictions do not constrain actions requested through an authorized display connection. XTEST explicitly supports synthetic keyboard and pointer events. Wayland safety depends on the compositor’s exposed protocols and permission policy, which the design does not establish. [X.Org XTEST documentation](https://www.x.org/releases/X11R7.5/doc/man/man3/XTestFakeKeyEvent.3.html).

**Mitigation:** Use a dedicated nested display server/compositor with restricted host-facing protocols. Exclude host X11, global input, clipboard, capture and desktop-control authority. Broker audio separately if microphone access is unnecessary.

**Enforcing test:** From the compromised-game probe, attempt input injection, clipboard access and capture/control of a canary host application. Assert that no host action occurs. Direct file and D-Bus canaries in SI-14 would pass despite this escape.

### R2-3: the Windows service does not have a complete game-bound authorization contract

**Severity: high**

**Scenario:** Start two instances of the same `RocketLeague.exe` path, with different users or launch modes. One satisfies the observed `-noeac` condition; the other receives permitted traffic. Alternatively, exit the authorized game while kickoffd maintains its lease and continues sending frames.

**Why draft 2 does not stop it:** WFP app ID derives from a filename, not a particular process instance. The complete pipe carries only `LanOpen{slot}`; it supplies no authenticated game-instance binding. Dynamic filters belong to the service session, so game death does not remove them automatically. [Microsoft app-ID API](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0).

The WFP policy also omits exact layers, weights and action rights. A persistent block and dynamic hard permit are not a complete arbitration specification. [Microsoft filter arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration).

**Mitigation:** Define trusted target derivation, SID/logon-session binding, process-handle lifetime and enforceable instance isolation. Specify every WFP layer and forwarding rule. If stock mode cannot isolate the intended instance, remove it.

**Enforcing test:** Same-path instances, cross-user instances, simultaneous EAC/no-EAC instances, game exit/restart, ICS, broad firewall rules and service survival. Require legitimate delivery and zero unauthorized delivery.

### R2-4: the Landlock pathname probe does not prove the claimed boundary

**Severity: high**

**Scenario:** A writable descriptor exists before restriction or crosses from the unrestricted launcher. A compromised component writes through that descriptor after Landlock is installed. Another failure installs an incomplete rights mask that denies creation but permits truncation or other mutations.

**Why draft 2 does not stop it:** §2.1 specifies no descriptor inventory, minimum ABI or complete handled-rights mask. The launcher is deliberately outside the daemon’s Landlock domain. Landlock does not retroactively revoke ordinary access through already-open descriptors. [Kernel documentation](https://cdn.kernel.org/doc/html/latest/userspace-api/landlock.html).

A scratch-only experiment confirmed this on the current machine: a fresh write-open failed with `EACCES`, while an inherited writable descriptor changed the canary from `BEFORE` to `AFTER!`.

**Mitigation:** Close/restrict descriptors before confinement; allowlist received descriptor types and rights. Require sufficient Landlock ABI support and enumerate all mutation rights. Give the launcher a narrow lifecycle with no hostile parser and no unrestricted post-setup broker operations.

**Enforcing test:** Exercise inherited and transferred descriptors, truncation, rename, unlink and directory mutation against canaries. Reject unsupported/incomplete policies. A single root write probe is insufficient.

### R2-5: parser confinement leaves writable-handle authority and startup races unspecified

**Severity: high**

**Scenario:** A compromised parser inherits an unintended descriptor/handle, or uses its intended output handle to overwrite reserved offsets, create a huge sparse file or exceed disk reservations. On Windows it executes before job assignment or continues after the parent dies.

**Why draft 2 does not stop it:** Landlock and AppContainer restrictions do not remove authority already granted by inherited handles. Windows Job memory/CPU limits do not impose a file-size limit. The design does not require suspended creation, job assignment before resume, kill-on-job-close or an exact inherited-handle list.

“Less-privileged AppContainer” must explicitly mean LPAC with specified attributes and capabilities. Regular AppContainers retain access to some system files, registry keys and COM objects. [Microsoft AppContainer/LPAC documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer).

**Mitigation:** Allowlist handles and access masks; use parent-brokered bounded output where necessary. Specify exact LPAC creation and Job settings, fail-closed startup, deadlines and teardown.

**Enforcing test:** Run a deliberately compromised helper, not just bomb fixtures. Enumerate inherited handles, attempt arbitrary offsets/oversized writes and accessible named objects, and kill the parent during every startup phase.

### R2-6: the parser can forge its own integrity result

**Severity: high**

**Scenario:** A hostile zstd stream compromises `kickoff-parse`. The helper writes bytes different from the requested object and returns the requested BLAKE3 value. kickoffd accepts the reported value and commits the object.

**Why draft 2 does not stop it:** §5.2 assigns hash computation to the same hostile parser whose output the hash is supposed to authenticate. “Validates it as data” cannot make a compromised helper’s statement true. Later rehashing may prevent installation, but it does not satisfy SI-4’s prohibition on committing unverified bytes.

**Mitigation:** Terminate the helper and revoke its writable handles before commit. Independently verify final length and hash through a trusted read handle. Treat receipts, parser success and structural-validation results as untrusted assertions where they authorize actions.

**Enforcing test:** Substitute a helper that writes incorrect bytes, reports the expected digest and attempts late writes. Nothing may commit under that digest or reach the game.

### R2-7: compromised-game resources and descendants have no containment budget

**Severity: high**

**Scenario:** A compromised Linux game fills its writable prefix, forks descendants, exhausts memory or leaves a process holding namespace resources after the visible game exits. A read-only copy does not prevent any of these operations.

**Why draft 2 does not stop it:** §6.3 budgets network ingress, parser jobs and library transfers. It gives the game no process, memory, CPU, prefix-disk or I/O limit. `--die-with-parent` is not a complete descendant/resource ownership policy. Pasta and launcher namespace references also need teardown ownership.

**Mitigation:** Define a game process group or delegated cgroup, descendant termination and explicit resource limits. Put persistent writable state under a quota and define safe reset behavior after compromise.

**Enforcing test:** Fork/memory/prefix-write probes and descendants that outlive the game leader. Kill each owner and assert bounded usage, no surviving processes and no surviving peer-facing network.

### R2-8: copy refresh is not a coherent, authenticated game-build transaction

**Severity: high**

**Scenario:** A launcher update changes files while Kickoff individually reflinks/copies them. Metadata identifies build B, but the completed copy contains a mixture of A and B. Windows refresh retains obsolete files not present in the new manifest. Refresh/delete races with a live game or queued map installation.

**Why draft 2 does not stop it:** Reflinking files individually is not a whole-tree snapshot. §5.3 trusts the build label without defining content consistency, deletions or maintenance exclusion. A pre-launch “Heroic is not running” check does not exclude a subsequent launch or another updater. New builds can also change bootstrap and writable-path assumptions.

**Mitigation:** Bind copies to a verified manifest/content identity, not a path component from launcher metadata. Build an immutable generation, validate every file and the EAC/bootstrap exclusion policy, publish atomically, and retain leased generations until unused. Handle obsolete files explicitly.

**Enforcing test:** Change metadata and source bytes at every clone step; introduce bootstrap files, remove files and race refresh with launch/map commit. Only complete validated generations may launch.

### R2-9: session-endpoint secrecy is not an admission boundary

**Severity: high**

**Scenario:** Admit a malicious friend. They send the session endpoint identity/address to an outsider. The outsider completes a rejected session handshake and observes candidates or consumes handshake resources before the admission hook runs.

**Why draft 2 does not stop it:** §3.4 assumes only admitted peers know the endpoint. That assumption conflicts with treating admitted peers as malicious. The retained research already establishes candidate registration before `after_handshake`.

**Mitigation:** Enforce candidate nondisclosure before admission independently of endpoint secrecy. Use relay-only sessions until that is possible, or change the transport registration path. Budget unauthorized session handshakes even when the endpoint is public.

**Enforcing test:** Leak the endpoint from an admitted peer, then inspect rejected connections and flood it using fresh identities. SI-31 must use this reachable-endpoint scenario.

### R2-10: egress restrictions miss transport-generated destinations and public-address LANs

**Severity: high**

**Scenario:** A malicious connected endpoint supplies a new direct candidate through iroh’s path/address machinery rather than the ticket. Separately, a compromised game contacts a host or LAN service on a globally addressed subnet, or the configured DNS forwarder.

**Why draft 2 does not stop it:** `net::egress` is described as the sole destination owner, but iroh performs its own path discovery and connectivity checks. Tests cover tickets and HTTP, not candidate announcements. Gamebox nft rules deny selected private ranges rather than all host/connected destinations. Pasta explicitly maps DNS forwarding to a host resolver. [Pasta documentation](https://passt.top/builds/latest/web/passt.1.html).

**Mitigation:** Apply policy at every actual transport send/connect path. Derive host and connected-subnet exclusions regardless of address classification; explicitly constrain DNS exceptions and all pasta mappings. Recompute policy on route changes.

**Enforcing test:** Malicious transport candidate updates, a globally addressed synthetic LAN, host-public-address services, DNS-forward ports and interface changes. Record actual packets, not only application dial requests.

### R2-11: reproducibility does not make malicious build inputs trustworthy

**Severity: high**

**Scenario:** A malicious vendored dependency or toolchain deterministically inserts installer or service malware. Both builders use the same pinned input and produce identical output. The offline signer approves the matching hashes.

**Why draft 2 does not stop it:** §6.1 trusts dependencies/toolchains “until two builders reproduce.” Reproduction establishes agreement, not benign behavior. The hostile `build.rs` fixture checks access to builder secrets; malware can be embedded without reading any.

**Mitigation:** Separate reproducibility from source/provenance approval. Authenticate and review changed inputs, define trusted toolchain acquisition and bind approval to source, dependencies, build recipe and test evidence. Isolate both builders; the second Linux machine as the second builder must not implicitly expose credentials for the maintainer's other systems.

**Enforcing test:** Supply a reproducible but unapproved modified dependency/toolchain. Signing must refuse it despite identical outputs. Require matching independently recorded provenance and checks for the exact artifact.

### R2-12: release/root metadata lacks complete rollback and freshness rules

**Severity: high**

**Scenario:** Replay an older signed root rotation after a newer one; run an old manual installer; or serve no-update/error responses while the client stops evaluating its last authenticated expiry. An expired signed record remains installable because the policy merely “flags” it.

**Why draft 2 does not stop it:** §8.4 has release sequence/version state but no root epoch or rotation replay protocol. Manual installers do not explicitly honor that state. Expiry, clock rollback, missing metadata and `min_safe_version` enforcement have incomplete behavior.

**Mitigation:** Specify monotonic root epochs and authorized transitions, persistent freshness state, explicit expired-record installation rules and equivalent manual-install checks. Define recovery when a minimum-safe update is withheld.

**Enforcing test:** Replay root transitions, restart with old installers, roll clocks back, withhold metadata and serve repeated no-update responses. Verify stale detection and every required refusal.

### R2-13: relay vouchers and isolation leave delegated abuse paths

**Severity: high**

**Scenario:** One enrolled malicious friend mints many session keys and vouchers, multiplying per-key quotas. A revoked friend continues through an already-open connection or unexpired delegated voucher. An outsider exhausts TLS/HTTP/QAD resources before relay admission. A relay deployed under decision 12 reaches the maintainer's other services.

**Why draft 2 does not stop it:** Voucher issuer, relay audience, delegation ceilings and active revocation are unspecified. The inspected `AccessControl` interface admits connections and reports disconnects; the design supplies no active-revocation mechanism. Connection admission occurs too late to budget all public-listener work. Decision 12 contradicts dedicated-host isolation.

**Mitigation:** Charge delegated identities to their enrolled issuer, scope vouchers, cap issuance and actively disconnect revoked descendants. Bound pre-admission listeners and QAD independently. Remove the shared-server option or define and test its network isolation explicitly.

**Enforcing test:** Many keys from one issuer, issuer revocation with active connections, voucher replay across relays, unauthenticated listener floods and relay-context attempts to reach canaries on the maintainer's other systems.

### R2-14: native approvals need operation binding and abuse limits

**Severity: medium**

**Scenario:** While a native approval for map A is pending, the host sends map B or replaces the session generation. The approval authorizes the current map instead of the displayed hash. A compromised webview repeatedly raises dialogs until the user accepts one.

**Why draft 2 does not stop it:** Native dialogs move rendering into a trusted component, but §2.7 does not define immutable approval objects, single consumption, cancellation on state changes or dialog rate limits. SI-9 tests command access, not approval semantics.

**Mitigation:** Bind approval to action, session, authenticated identity, generation and exact map hash. Consume it once; invalidate on relevant changes. Permit one outstanding prompt and rate-limit requests.

**Enforcing test:** Change maps, reconnect, kick and end sessions while prompts are pending. Old approvals must authorize nothing. A compromised webview must not produce unbounded dialogs.

### R2-15: Legendary dry-run is not established as read-only authentication

**Severity: medium**

**Scenario:** Legendary’s saved session expires. Kickoff invokes the proposed dry-run launch; Legendary refreshes credentials and updates launcher-owned state before reaching its dry-run branch. Concurrent Heroic activity races those changes. Dry-run output also contains authentication arguments.

**Why draft 2 does not stop it:** §8.1 itself acknowledges two writers of Legendary state, contradicting SI-1’s claim that launcher files remain untouched. Current upstream source calls login before the dry-run branch, and refresh updates stored user data. This is evidence requiring verification against the installed version, not proof of that version’s exact behavior. [Legendary CLI source](https://raw.githubusercontent.com/derrod/legendary/master/legendary/cli.py), [Legendary authentication source](https://raw.githubusercontent.com/derrod/legendary/master/legendary/core.py).

**Mitigation:** Define a narrow authentication broker with explicit permitted state changes, serialization and credential handling, or use isolated authentication state. Narrow SI-1 honestly if authenticated token refresh is an intentional exception. Prohibit raw authentication output and dumps.

**Enforcing test:** Fake expired credentials and token refresh against the exact pinned launcher adapter. Observe filesystem changes, concurrent access, stdout/stderr and crash artifacts. This should precede real-account launches.

## Section C: rebuttal verdicts

| Rebuttal | Verdict |
|---|---|
| NET-1: ports 9014–9088 need no denylist | **Holds for the stated rationale.** Remote service ports are not evidence of local listeners, and adding them does not establish process isolation. Retain a measurement-based `GamePorts` policy. The broader finding remains partial because Windows filtering is not instance-bound. |
| NET-4: draft 1 did not forward guest datagrams to other guests | **Substantively holds, with an ambiguity concession.** The round-1 report quoted wording broad enough to invite that reading. Draft 2 clearly distinguishes local-game fan-out from guest delivery and adds the right three-node test. |
| NET-15: unsigned addresses are harmless because TLS pins identity | **Holds only against host impersonation; fails as stated.** TLS pinning does not prevent pre-authentication connections, probing, tracking or denial of service. A separate address signature is not essential if destination policy is complete, but “can only break the dial” is false. Authenticity of the ticket’s delivery channel is also not established merely by verifying its included identity. |

## Section D: milestone-order verdict

**The order front-loads Linux launch compatibility, but it does not yet front-load every fact supporting the security claims.**

Required changes:

1. **Run containment probes before M1 uses a real account or hostile/custom map.** Include display authority, inherited descriptors, descendants, resource budgets, pasta mappings and authentication-state writes. M1 should prove capability boundaries before treating successful game boot as evidence of security.
2. **Make M3 and live M4 depend on the minimum M5 copy/launch protections.** An experimental copy builder must not become the live launch path before copy identity, EAC exclusions, owned-prefix isolation and fail-closed policy exist.
3. **Move a minimal Windows copy/authentication and instance-isolation spike alongside M1.** M7 currently builds privileged networking before M8 determines whether the intended game can launch safely. Windows stock mode needs its own early safety gate.
4. **Make M6 depend on tested parser confinement on both platforms.** The writable-handle and dishonest-helper cases must pass before any peer-controlled format reaches the pipeline.
5. **Split M11.** Bootstrap verification, isolated-builder feasibility, provenance approval and reproducibility should be early spikes. UI completion should not precede discovery that the distribution trust model is unworkable.
6. **Resolve relay vouchers and deployment isolation before accepting M12’s security claim.** Token configuration alone does not prove issuer quotas, active revocation or pre-authentication flood resistance.
7. **Gate real peer sessions on the compromised-game tests.** Hand-delivered alpha builds bypass distribution work, not game-containment or ban-safety requirements.

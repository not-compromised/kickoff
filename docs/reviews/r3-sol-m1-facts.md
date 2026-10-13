Redacted for publication: absolute paths and line links replaced with repo-relative section references.

# Round 3 review: M1 facts (Sol 6.1)

Input: commit `4a3a83f` on `docs/3-m1-facts` ("docs: record M1 real-game facts in the design (#3)"), against `main` and the earlier review records. Resolution: `r3-resolution.md`.

Reviewed commit `4a3a83f` against `main` and the prior review records. Read-only; no files changed.

1. **P2 — §3.1.1: option A does not establish the stated destination boundary.** `docs/design.md §3.1.1`

   Making an honest host advertise kick0 fixes discovery functionality. It does not constrain a malicious host’s `ServerID`. Filtering output on the pasta interface misses joins addressed to the guest’s own loopback, pasta address or kick0 address: those can be delivered locally without traversing pasta. Any reachable UDP listener inside that namespace remains a target. This does not imply access to host-desktop services if the existing namespace and pasta exclusions hold.

   The public-IP leak also remains wherever guest egress permits attacker-chosen UDP destinations. “HTTPS and DNS” must mean explicit protocols and destinations, not merely ports 443 and 53.

   Before recommending A, measure the real guest’s destination handling, accepted `ServerID` syntax and ports, Wine address selection under candidate layouts, and actual LAN-session internet traffic. Require packet-recorded negative tests for public destinations, namespace-local destinations and forbidden services. B can reject this field before game delivery, provided the guest validates independently of the host’s rewrite; other address-bearing game messages still need investigation.

2. **P2 — §3.1.1 and §3.3: the Windows steering boundary is missing.** `docs/design.md §3.1.1, §3.3`

   A relay-only Windows guest accepts a malicious discovery reply naming an attacker’s public server. The game sends its join traffic over a physical interface, whose policy §3.3 deliberately leaves unchanged. Linux gamebox egress narrowing offers no protection there. The attacker learns the guest’s public IP and may steer traffic toward guest-reachable services, subject to the game’s accepted destination syntax and ordinary Windows policy.

   Specify guest-side discovery validation or an equivalent enforced destination restriction for Windows. Gate Windows multiplayer on that protection, including stock mode.

3. **P2 — §3.2.6: parent-death signals and scope stopping do not yet preserve the teardown guarantee.** `docs/design.md §3.2.6`

   Kill the supervisor during startup, before a child arms its parent-death signal. That signal need never arrive. Alternatively, pasta or another forked sibling survives after the watched leader exits. Parent-death settings are cleared across `fork`, and do not retroactively signal an already-dead parent. A scope remains active while any member survives. Ordinary systemd stopping also starts with SIGTERM unless configured otherwise. See the [Linux parent-death contract](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html), [scope lifecycle](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.scope.xml), and [systemd termination procedure](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.kill.xml).

   Specify the surviving owner that triggers whole-cgroup termination, startup death-race handling, immediate kill semantics, and a teardown deadline. Inject SIGKILL at every startup phase, including scope registration and helper forks.

   The composition is viable in principle. Require a final launch barrier proving namespace setup, nft policy, cgroup membership, limits, capability removal, no-new-privileges and descriptor closure before Wine runs. Bubblewrap does not automatically supply arbitrary seccomp or Landlock policy; preserve the separately specified daemon/parser policies. The unresolved tap hand-off is honestly identified and can remain an explicit M3 blocker.

4. **P2 — §8.6: testable settings protections are incorrectly discarded with the account-side residual risk.** `docs/design.md §8.6`

   A stale prefix uploads old settings, or automation observes the expected menu, then confirms after a selection changes. A manual account check after the session cannot prevent either action.

   Epic’s ultimate synchronization behavior can remain a residual risk. Kickoff’s own behavior is testable: settings copied without modification, freshness checks before launch, no settings-editing operation, and automation refusing unknown or stale states. Add an invariant with filesystem fixtures and a fake UI-state/input adapter. Include mutants that alter a copied setting or bypass the confirmation guard. Define what prevents selection changes between observation and confirmation; “reads before every confirm” alone does not close that race.

5. **P2 — SI-2 and SI-30: the new protections lack removal-sensitive test specifications.** `docs/SECURITY-INVARIANTS.md SI-2`, `docs/SECURITY-INVARIANTS.md SI-30`

   Remove SI-2’s runtime command-line check. Its argv property test can still pass because it examines the launcher’s constructed arguments, not arguments changed or dropped downstream. Existing mutants do not exercise that removal. Add a launch-chain stand-in that drops, duplicates or substitutes `-noeac`, plus unreadable-command-line cases; assert timely whole-cgroup termination and failure when the runtime check is disabled.

   SI-30’s game-log canary test is useful, but must actually invoke every supported log-copy/export path and assert a usable sanitized result. Otherwise “no departing copy contains a secret” can pass because no copy occurred. Add redaction-bypass and raw-log-event mutants. The existing dumpability mutant does not prove this new protection.

6. **P2 — §10: the supervised pre-M0 exception lacks a minimum security gate.** `docs/design.md §10`

   The documented session passed direct socket canaries while gamescope still retained host clipboard authority because WlFilter was absent. The new exception permits repeating that configuration with a real account. Supervision cannot revoke clipboard authority, prevent authentication-output leakage or guarantee descendant teardown.

   Keep the no-custom-map gate. For early real-account sessions, enumerate mandatory passing checks for indirect display authority, descriptor inheritance, teardown/resource limits and fake-credential broker handling. Explicitly prohibit peers. Any remaining weakened containment should be a named experimental mode with stated limitations, rather than being covered by unspecified “containment canaries.”

Privacy check: no apparent private machine names, usernames, user-specific home paths or real private addresses in the diff. `192.0.2.2` is a documentation address; `10.75.0.0/24` is the specified virtual LAN.

**Verdict: no P1; six P2 findings listed above.**

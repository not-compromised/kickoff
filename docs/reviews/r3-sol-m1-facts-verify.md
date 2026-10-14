Redacted for publication: absolute paths and line links replaced with repo-relative section references.

# Round 3 verification: M1 facts (Sol 6.1)

Input: `4a3a83f..c982d30` on `docs/3-m1-facts`, verifying the resolution of `r3-sol-m1-facts.md`. Resolution: `r3-resolution.md`, section "Verification round".

Reviewed `4a3a83f..c982d30` read-only. No files changed. These verdicts assess the design and test specifications; no executable mutant results were provided.

- **R3-1 — PARTIAL.** Guest-side validation now addresses public, namespace-local and forbidden destinations independently of option A. Missing: trusted enforcement of the parser result and a removal-sensitive duplicate-key test.
- **R3-2 — PARTIAL.** Shared validation and the Windows multiplayer gate cover stock mode too. The parser trust gap also affects Windows.
- **R3-3 — PARTIAL.** The surviving systemd owner, immediate whole-cgroup termination, startup ordering, deadline and launch barrier address the teardown design. The `cgroup.kill` mutant is still not removal-sensitive.
- **R3-4 — PARTIAL.** Copy integrity, freshness and automation are now invariants. The observation-confirm test contradicts the admitted asynchronous race, and the settings-copy mutant can pass through launch refusal.
- **R3-5 — CLOSED.** The downstream launch-chain stand-in exercises removal of the runtime check, including unreadable command lines. SI-30 now invokes every registered export path and requires useful sanitized output, eliminating the “nothing copied” loophole.
- **R3-6 — CLOSED.** Spike mode now names its weakened containment, prohibits peers/custom maps/distribution, and requires concrete checks before every session.

Remaining and new findings:

1. **P2 — SI-42 delegates security approval to an assumed-compromised parser without specifying trusted enforcement.**  
   `docs/design.md §3.1.1` puts validation in `kickoff-parse`, while `docs/design.md §5.6` requires trusted recomputation of anything authorizing an action. A compromised helper could report a safe `ServerID` while Kickoff delivers the original hostile reply. Specify bounded structured output, trusted enforcement of the expected destination, and trusted reconstruction of the delivered reply, or independent validation of the exact delivered bytes. Add a dishonest-helper test.

2. **P2 — SI-43 requires prevention that its observe-confirm protocol cannot provide.**  
   `docs/design.md §8.6` describes two matching observations and exclusive input, then admits that a game event can change the UI before confirmation. `docs/SECURITY-INVARIANTS.md SI-43` nevertheless requires *no confirm* when selection changes in that window. Inject a dialog immediately after observation two: the described implementation confirms before detecting the mistake. Require atomic expected-state confirmation, or narrow the invariant and test to the prevention actually supplied and explicitly retain the remaining risk.

3. **P2 — Several new mutant specifications can pass with their named protection removed.**

   - **SI-38:** remove direct `cgroup.kill`; the subsequent systemd stop still sends SIGKILL to the whole cgroup. The existing teardown oracle can pass. Test the direct-kill path independently, or define and mutate the combined teardown protection. `docs/design.md §3.2.6`
   - **SI-42:** accepting duplicate keys does not necessarily produce a steered packet. If both parsers select the safe first value, the packet oracle passes. Assert that each invalid reply never reaches the game, independently of destination behavior. `docs/SECURITY-INVARIANTS.md SI-42`
   - **SI-43:** an altered copy can trigger the independent freshness check and cause refusal, which the fixture explicitly permits. Require successful launch with byte-identical settings for stable, valid fixtures, then show that the alteration mutant fails that case. `docs/SECURITY-INVARIANTS.md SI-43`

   SI-2 and SI-30 have appropriate removal-sensitive specifications. SI-36 does too if its mutant disables the complete barrier. SI-38’s binding and SIGTERM mutants need owner-death cases with a surviving, SIGTERM-ignoring helper so redundant fast paths cannot mask removal.

4. **P3 — The supervisor channel contract needs reconciliation.**  
   The new service replaces the inherited socketpair, but `docs/design.md §2.7` recognizes only kickoffd or kickoff-svc as authenticated servers. Explicitly specify reciprocal daemon/supervisor identity checks and update the inherited-descriptor contract. I found no concrete bypass within the stated threat boundary.

The supervisor’s service-to-scope lifetime binding is viable in principle; `BindsTo=` combined with `After=` supplies the intended dependency behavior. [systemd unit documentation](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)

The exact `10.75.0.1:7777` match is consistent with the current contract: the host always occupies `.1`, and game ports are compiled constants. A different address or port should fail closed. Future host transfer or configurable ports must derive the expected tuple from authenticated session state.

Privacy check passed for the complete diff: no apparent machine names, usernames, user-specific home paths or real private addresses. `192.0.2.2` is a documentation address; `10.75.0.0/24` is the specified virtual LAN.

**Final verdict: no P1; three P2 findings and one P3 listed above.**

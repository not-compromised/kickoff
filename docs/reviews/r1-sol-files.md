Redacted for publication: machine names, paths and addresses replaced with generic terms.

1. **FILE-1 | critical | Online launch can reach modified files before restore**

   **Scenario:** Start a valid offline session and swap a map. Kill `kickoffd` with SIGKILL, or start Rocket League through Heroic, Epic or Steam while the swap remains. The online process can access modified files before Kickoff observes it. On Windows, restoration explicitly waits for that process to exit. The failure exposes the owner to the ban risk they prohibit.

   **Design gap:** §5.3 lists reactive triggers, including “any RL process without `-noeac`,” but also says “Never restore over a running game on Windows.” §8.1 keeps online Play hook-free; its pre-launch stock check is merely an owner decision. Neither login recovery nor a cleanup trap covers an online launch later in the same login after SIGKILL.

   **Mitigation:** Use a separate offline installation and prefix whose modified files cannot enter the normal online installation. Otherwise, reliable mediation of **every** online launch must be a release prerequisite. A stock-check shortcut alone does not cover the launcher’s Play button.

   **Automated test:** Against fake launchers, kill every Kickoff component while swapped, then invoke every online entry point. Assert that no online process starts with access to custom slot bytes or session-installed textures.

2. **FILE-2 | critical | A fixed filename does not prevent SYSTEM writes outside the game installation**

   **Scenario:** A local interactive attacker prepares a writable Steam library or discovered installation with a junction in an ancestor, or replaces a checked directory between validation and writing. They invoke `SlotInstall`, causing the SYSTEM service to stage or replace files outside the approved installation. A fixed temporary filename also offers an attack target.

   **Design gap:** §5.3 requires a “real directory under the canonical game root” and `O_NOFOLLOW`; it does not define Windows reparse-point handling, trustworthy root enrollment, ancestor validation or handle-relative operations. §6 T10 equates “service takes no paths” with protection, although paths still enter through installation discovery and filesystem indirection.

   **Mitigation:** Enroll installation roots through an authenticated administrative operation. Bind them to volume and directory identities. Reject reparse points throughout the write ancestry, and perform operations through validated handles without reopening unchecked paths. Keep privileged journal and backup state SYSTEM-owned.

   **Automated test:** Exercise junctions at every ancestor, root substitution, directory replacement during validation, and malicious per-user discovery metadata. Assert that no file outside the enrolled directory identities changes.

3. **FILE-3 | high | `NoEac` evidence is not bound to one authenticated game instance**

   **Scenario:** A stale log is copied or touched after a new process starts. Another process holds the offline lock. A process command line contains `-noeac` inside an argument value rather than as the actual switch. Alternatively, two installations run simultaneously, and evidence from the offline instance authorizes a write to the online instance’s installation. PID reuse can preserve a stale proof.

   **Design gap:** §5.3 requires “A RocketLeague.exe process exists,” a command line that “contains `-noeac`,” and the “newest `Launch.log`.” Matching `*wine*` proves a Wine executable, not the identity of the loaded Windows game. The design does not bind the process, installation, log and lock together. A filesystem timestamp does not establish which process opened a log.

   **Mitigation:** Bind the proof to installation identity, executable identity, user/session, boot identity and process creation identity. Parse an exact command-line switch. Hold a process handle or pidfd. Associate a fresh log stream with that instance and require exclusivity across processes accessing the installation. Bind the lock to the same launch lifecycle.

   **Automated test:** Refuse copied/touched logs, forged process names, substring switches, unrelated lock holders, mismatched installations, simultaneous processes and PID reuse.

4. **FILE-4 | high | The proof can expire during a lengthy swap**

   **Scenario:** Obtain `NoEac`, then stream or copy a large package. The verified process exits while the write proceeds; another game process starts before commit. Kickoff commits using the old proof. An EAC session marker may remain buffered until after exposure.

   **Design gap:** §2.3 passes a `NoEac` value into `swap`; no expiry or revocation behavior is specified. §8.1 acknowledges that logs flush in 4 KB blocks and are “not for timing.” A restore triggered by “Beginning protected session” therefore cannot establish prevention. Restoration also cannot revoke modified data already loaded by the game.

   **Mitigation:** Stage outside the game directory, then perform a serialized commit that revalidates the live instance and launch exclusion. Revoke authorization on process exit, identity change, watcher failure or ambiguous evidence. Treat an EAC marker as an emergency fault, not the safety boundary. Establish that the verified launch mode cannot transition to EAC; otherwise isolate the offline installation.

   **Automated test:** Pause before commit, exit the verified process and start another instance. Delay EAC log flushing. Assert that the commit is refused.

5. **FILE-5 | high | Missing stock manifests have an unsafe fallback**

   **Scenario:** On Windows or Steam, Kickoff cannot obtain the authoritative slot digest. A modified cooked package passes a UE3 header check and is accepted as stock, backed up or later restored. A user’s incomplete Verify action may be mistaken for repair.

   **Design gap:** §5.3 says “Fallback: UE3 header check plus ‘run Verify integrity’.” A header identifies a format, not exact stock bytes. Windows Epic and Steam hash access are explicitly unverified. The claimed SHA-256 availability is also not established by the retained manifest scripts, which compare `f.hash` against SHA-1.

   **Mitigation:** Refuse swaps when the exact installed build’s authoritative file digest is unavailable. Represent digest algorithms explicitly. Verification must finish and be followed by an exact digest comparison before clearing an unsafe state. Do not infer stock identity from package headers.

   **Automated test:** Supply altered packages with valid stock headers, missing manifests, unsupported digest algorithms and incomplete Verify runs. All must remain blocked.

6. **FILE-6 | high | Updates and Verify race with manifest-aware restoration**

   **Scenario:** Restore reads manifest A. Epic or Steam updates the installation to build B, then Kickoff restores A’s saved original. Conversely, Verify repairs a file after Kickoff checks its digest but before Kickoff replaces it. Kickoff overwrites the launcher’s repair.

   **Design gap:** §5.3 says “re-read the current manifest first,” followed by independent file operations. There is no exclusion against patching or Verify, and no stable relationship between manifest publication and installed bytes. The prototype changes the manifest between operations, not during a restore transaction.

   **Mitigation:** Require exclusive installation maintenance access covering manifest selection, digest checks and replacement. If launcher coordination cannot provide that exclusion, refuse maintenance while it is running and use a separate offline installation. Any build change must invalidate pending swaps and restoration decisions.

   **Automated test:** Inject manifest and slot changes between every check and replacement. Assert that restoration never writes build A after build B becomes current and never overwrites a concurrent repair.

7. **FILE-7 | high | Recovery can deliberately leave a custom map without blocking online use**

   **Scenario:** Swap under build A; the manifest advances to B while the custom map remains. Recovery refuses to restore A and tells the user to Verify. The user dismisses the message and launches online. A missing backup, unreadable journal, inaccessible disk or locked Windows slot produces a similar unresolved state.

   **Design gap:** §5.3 says “Otherwise write nothing and tell the user to run launcher Verify.” This avoids one stale write but does not prevent ban exposure. Recovery error handling, persistent quarantine and retry behavior are unspecified. Login and service-start triggers have no specified ordering against launcher startup.

   **Mitigation:** Define durable `unsafe/repair-required` states. They must prevent use of the affected installation until all relevant files are verified. Preserve recovery evidence, retry pending Windows restoration after process exit, and make repair completion machine-verified.

   **Automated test:** Exercise changed manifests, missing backups, malformed journals, permission failures and sharing violations. Restart services and launchers in adversarial order; unresolved states must never authorize online use.

8. **FILE-8 | high | Replacement maps and overlapping leases lack a transaction model**

   **Scenario:** Map A is active. A new journal naming B is persisted, then the process crashes before replacing A. Recovery sees A but recognizes only B as “ours,” so it strands A. Concurrent map picks or an old `SwapLease` destructor can also restore over a newer swap or overwrite its journal.

   **Design gap:** §5.3 permits a swap when “the journal says the bytes are ours,” but journals only one `ours_hash`. §5.4 auto-picks published builds. No per-install serialization, generation identifier or transition state is specified. The prototype restores stock before its next swap, so it does not establish safety for the broader design.

   **Mitigation:** Serialize all swap, restore, texture and maintenance operations per installation. Journal both previous and intended states, preserving the genuine stock backup. Give leases transaction generations so obsolete leases cannot restore newer transactions.

   **Automated test:** Crash throughout A→B replacement and interleave two map picks with old-lease destruction. Recovery must recognize every reachable intermediate state.

9. **FILE-9 | high | Predictable temporary files permit hardlink damage and race attacks**

   **Scenario:** An attacker precreates the swap temporary file as a hardlink to another writable file. Opening it for copying truncates and overwrites that unrelated file. Alternatively, they replace the temporary pathname after its hash is verified but before rename.

   **Design gap:** §5.3 specifies a predictable `.Labs_Utopia_P.kickoff-tmp` and `O_NOFOLLOW`. `O_NOFOLLOW` does not reject hardlinks or prevent pathname substitution after verification. In the retained prototype, I reproduced unrelated-file corruption by hardlinking its equivalent temporary filename; the unrelated file changed from `KEEP` to `MAP`.

   **Mitigation:** Create unique temporary files exclusively with restrictive permissions. Require a regular file with one link, retain its handle, and prevent substitution between verification and commit. Apply the same rules to journal, backup and `.part` staging. Reflink into a newly created file, never reuse an untrusted existing destination.

   **Automated test:** Precreate hardlinks, symlinks and special files at staging names; replace names after hashing. Assert no unrelated inode changes and no unverified inode is committed.

10. **FILE-10 | high | Windows replacement failure can mean partial change**

   **Scenario:** `ReplaceFileW` fails after removing or renaming the old slot. Kickoff treats this as “no change,” leaving a missing slot, displaced original or modified replacement attributes without accurate recovery state.

   **Design gap:** §5.3 explicitly says “treat failure as ‘no change’.” Microsoft documents partial-change outcomes for `ERROR_UNABLE_TO_MOVE_REPLACEMENT` and `ERROR_UNABLE_TO_MOVE_REPLACEMENT_2`. It also states that `REPLACEFILE_WRITE_THROUGH` is unsupported. `MOVEFILE_WRITE_THROUGH` is a different API flag. [Microsoft ReplaceFileW documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew), [MoveFileExW documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).

   **Mitigation:** Specify API-specific flags, flushing and recovery. After every failure, inspect all transaction paths and identities instead of assuming rollback. Preserve the journal until the resulting state is established. Define handling of ACLs, alternate streams and file-sharing locks.

   **Automated test:** Inject each documented partial failure and sharing violation; verify restart recovery for missing, displaced and partially transformed files.

11. **FILE-11 | high | The crash-safety claim exceeds the prototype’s coverage**

   **Scenario:** Power loss occurs during copying, journal publication, restoration or journal deletion. An interrupted write leaves staging debris, or lost directory metadata removes recovery evidence. The design’s advertised invariant is accepted without testing these states.

   **Design gap:** §5.3 claims “crash injection at every step.” `swapproto.py` injects Python exceptions at only three swap checkpoints. It does not kill a process, model power-loss persistence, inject restoration failures, test Windows, or assert its printed results. My interrupted-copy experiment recovered stock but left a `.kickoff-tmp` file in the game directory.

   **Mitigation:** Narrow the claim now. Define durable ordering for backup creation, directory creation, journal publication, replacement and cleanup. Recover abandoned staging files safely. Add failures at individual filesystem operations and explicit invariant assertions.

   **Automated test:** Run subprocess SIGKILL tests at each operation, plus a filesystem persistence model for power loss. Inject ENOSPC/EIO during swap and restore. Assert verified stock or durable quarantine, valid recovery evidence and controlled leftovers.

12. **FILE-12 | high | Texture ownership and cleanup are not crash-safe**

   **Scenario:** Kickoff installs several texture files, then crashes before recording ownership. They persist into later EAC use. Alternatively, Verify restores the slot to stock; recovery drops the shared journal while textures remain. A user replaces a Kickoff-installed texture, and cleanup deletes the replacement.

   **Design gap:** §5.3 promises removal of “only the files it installed,” but its journal schema contains no texture entries or per-file states. “If the slot is stock, drop the journal” is insufficient for additive dependencies. There is no specified hash/identity check before deletion or atomic no-clobber install.

   **Mitigation:** Journal intent before each texture creation, then record completion and file identity/hash. Install without replacing existing names. Remove only unchanged files demonstrably owned by that transaction. Clear the journal only after slot and texture recovery finish. Treat leftover dependencies as an unsafe installation state.

   **Automated test:** Crash before and after every texture write, repair the slot independently, replace a texture externally, and race a preexisting-file creation. Assert no foreign deletion and no untracked installed texture.

13. **FILE-13 | high | Malicious maps run inside an unestablished sandbox**

   **Scenario:** A malicious host sends a correctly hashed package that exploits Rocket League’s UE3 parser. The game runs the payload with the user’s accessible files, launcher credentials and network access. The malicious host chooses both package and digest, so hashing provides no authenticity or safety.

   **Design gap:** §6 T7 relies on “session host and known sources” and “Wine sandboxing on Linux,” then says “None possible” under automated proof. The task explicitly treats hosts as malicious. Wine is not an established containment boundary here; the launcher context says umu escapes into another sandbox and that total network isolation is incompatible with this stack. Windows containment is absent.

   **Mitigation:** Remove the sandbox claim until an explicit containment policy is demonstrated. Use a dedicated offline environment with restricted filesystem, credential and network access on both platforms. Treat parser exploitation as a release risk; source labels and hashes must never imply safety.

   **Automated test:** Launch a harmless probe under the exact proposed game containment policy. Attempts to read launcher secrets, write the online installation or unrelated home files, and reach prohibited services must fail.

14. **FILE-14 | high | Importer redirects can bypass URL restrictions**

   **Scenario:** A user imports an apparently permitted map page. Its download link or redirect targets loopback, a private address, a cloud metadata endpoint or another scheme. Kickoff fetches it using the user’s network access. DNS rebinding can change an allowed hostname’s resolved destination after validation.

   **Design gap:** §5.5 permits a “`cdn.bakkesplugins.com/*.zip` link only,” but does not specify parsed-origin checks, redirect validation, DNS/address restrictions or credential handling. Lethamyr has even fewer constraints. A descriptive User-Agent and user action do not prevent SSRF.

   **Mitigation:** Require HTTPS and exact permitted origins using a URL parser. Reject userinfo and unexpected ports. Validate every redirect and the actual connected address; disallow local, private, link-local and metadata destinations. Disable ambient credentials and cookies. Keep credentials out of cross-origin requests.

   **Automated test:** Use local HTTP fixtures and a controlled resolver for deceptive hostnames, redirects, encoded addresses, IPv6, DNS rebinding and cross-origin transitions. Assert no prohibited connection occurs.

15. **FILE-15 | high | ZIP and HTML imports lack hostile-input boundaries**

   **Scenario:** A download contains `../` entries, absolute Windows paths, symlink entries, case-colliding filenames, many files or enormous expanded data. Extraction writes outside staging or exhausts resources. Hostile HTML supplies unexpected links or active markup that reaches the UI.

   **Design gap:** §6 T5 says “no archive extraction during sessions,” but §5.5 imports ZIP files before sessions. No importer extraction policy or expanded-size budget is defined. “Fixture HTML tests” do not specify security properties.

   **Mitigation:** Prefer reading selected package entries directly into bounded object staging without materializing archive paths. Reject links, special files, absolute/traversing names and ambiguous collisions. Bound archive bytes, expanded bytes, entry count and processing time. Parse HTML without script execution or secondary resource loading, and render metadata as text.

   **Automated test:** Import ZIP-slip, symlink, duplicate-name and bomb fixtures plus hostile HTML. Assert writes remain in private staging, limits stop processing, and markup cannot execute or trigger extra requests.

16. **FILE-16 | high | Transfer limits do not bound decompressor and aggregate resource use**

   **Scenario:** A malicious host sends a zstd frame requiring an excessive window, an endless stream of frames with little output, or stalls transfers indefinitely. Repeated sessions fill disk with completed objects or abandoned parts. Blocking workers and memory are exhausted before the uncompressed-size limit trips.

   **Design gap:** §5.2 caps declared/uncompressed size and checks free space once. It does not bound decoder memory, compressed input, CPU time, idle time, queued work, lifetime cache size or outstanding reservations. `spawn_blocking` does not itself supply those limits.

   **Mitigation:** Bound zstd window size, compressed bytes, frame count, decoder memory and processing time. Limit concurrent/queued work. Reserve aggregate disk space including backup, swap and restore requirements; add persistent cache quotas and safe partial-file cleanup.

   **Automated test:** Feed excessive-window frames, endless empty frames, stalled streams and repeated maximum-size sessions. Assert bounded memory/workers/disk and preserved recovery capacity.

17. **FILE-17 | high | Content-addressed paths do not make stored objects immutable**

   **Scenario:** A package is hashed in an existing library, then edited before copying or serving. Two downloads share `<hash>.part` and corrupt each other’s progress. A completed object or its manifest is subsequently modified; `get()` or the “already holds the hash” shortcut trusts the filename. Inconsistent manifest size or SHA-256 then reaches later decisions.

   **Design gap:** §5.5 says existing libraries are “hashed in place.” §5.2 writes a shared `<hex>.part` and skips existing objects. §5.1 specifies metadata fields but not consistency validation, immutable ingestion, object locking or revalidation.

   **Mitigation:** Import a stable snapshot into private immutable object storage. Validate exact byte count, requested BLAKE3, declared BLAKE3 and SHA-256 before acceptance. Use exclusive per-object transactions and private part files. Bind resumes to a verified local prefix, uncompressed offset and requested object; reject out-of-range offsets.

   **Automated test:** Mutate sources and cached objects, race fetches, corrupt resumed prefixes, and return bytes different from the announced hash. None may become an accepted bundle or reach the game directory.

18. **FILE-18 | medium | `licensee 34` is a forgeable classifier, not a security check**

   **Scenario:** An attacker changes a cooked package’s licensee field to zero, or builds malformed UE3 offsets/counts under an acceptable header. It passes the proposed refusal rule. Conversely, a new legitimate format is mistakenly accepted because it is merely “not 34.”

   **Design gap:** §5.1 states “licensee 34 means stock cooked” and refuses imports with that value. §6 T5 lists this alongside overwrite and malicious-map protections. The attacker controls those header bytes; `deny_unknown_fields` validates JSON shape, not package semantics.

   **Mitigation:** Describe licensee as compatibility metadata only. Define an explicit supported-format policy with bounded structural validation. Keep stock identity dependent on authoritative digests and containment independent of package validation. Pin texture dependencies from application-owned data, not peer-provided declarations.

   **Automated test:** Mutate licensee, file version, magic, offsets and counts; provide inconsistent bundle metadata and arbitrary dependency names. Assert bounded rejection and no expansion of writable paths.

19. **FILE-19 | medium | A save receipt does not prove “the exact bytes you tested”**

   **Scenario:** Publish a newly saved package that has never been reopened or run in Rocket League. Its SHA-256 matches the editor-save receipt, so Map Maker auto-picks it. A mutable package can also change between receipt verification and library ingestion.

   **Design gap:** §1 claim 9 promises “the exact bytes you tested,” while §5.4 requires only the “latest editor-save receipt.” The existing `editor_save.py` explicitly initializes `game_tested=False` and `reopened=False`. A mapmaking toolkit's evidence documentation distinguishes editor, runtime and visual receipts.

   **Mitigation:** Either change the promise to “exact bytes saved,” or require matching runtime-test evidence for the tested claim. Ingest and hash one immutable snapshot. Define receipt schema, workspace/package binding, successful status and evidence requirements; a peer’s `source: Rl` label must not confer trust.

   **Automated test:** Reject mismatched or failed receipts and source mutations. A save-only receipt must never produce a “tested” designation; runtime evidence for another hash must not qualify.

20. **FILE-20 | medium | Credential redaction is asserted without establishing complete coverage**

   **Scenario:** An export includes Legendary’s fresh exchange code, a quoted or differently cased `AUTH_PASSWORD`, a URL-encoded token, a multiline diagnostic or a token split across log chunks. A crash/debug dump bypasses the normal export route. Local logs retain secrets and are later included in diagnostics.

   **Design gap:** §1 promises “Diagnostics never leak credentials”; §6 T11 proposes golden tests for a few known lines. There is no defined export inventory, structured secret handling, chunk-boundary behavior or crash-report policy. No retained redaction implementation or corresponding tests establish the `(V)` claim. The launcher context confirms that fresh exchange codes enter generated launch arguments.

   **Mitigation:** Build diagnostics from an allowlist of structured non-secret fields. Exclude raw command lines, launcher output, generated batch contents and memory dumps. Redact before logging, with defense-in-depth sanitization before export. Explicitly cover exchange-code representations and prohibit raw logs when sanitization cannot be established.

   **Automated test:** Seed synthetic secrets across quoting, casing, encoding, multiline and chunk boundaries. Exercise every log/export/error path and assert none contains a secret or reversible encoding.

21. **FILE-21 | medium | Windows pipe access is broader than the authorized game owner**

   **Scenario:** A different interactive user connects first, installs arbitrary map bytes into a shared installation or monopolizes the service while the legitimate user needs restoration. The service finds an offline process belonging to another user and treats that as sufficient authorization.

   **Design gap:** §3.3 admits “SYSTEM and INTERACTIVE” and serves “one client at a time.” No binding between caller identity, installation owner, game process and transaction is specified. Hashing client-supplied bytes proves integrity, not authorization.

   **Mitigation:** Authorize commands per enrolled user and installation. Derive caller identity from the pipe token and bind the gate to that caller’s game instance. Add upload deadlines and cancellation; restoration must not depend on an occupied client connection.

   **Automated test:** With two simulated user tokens, attempt cross-user installs/restores and stalled uploads. Unauthorized commands must fail and recovery must remain available.

22. **FILE-22 | medium | EAC-on swaps remain offered as a policy choice**

   **Scenario:** The implementation follows §11 and adds an explicit EAC-on opt-in. A friend or owner enables it, bypassing the very invariant the design markets as ban-safe.

   **Design gap:** §11 question 11 asks “refuse … or allow behind an explicit opt-in?” This contradicts §8.2’s mandatory no-EAC requirement and the owner’s standing “never risk a ban” rule.

   **Mitigation:** Remove the option from the design and protocol. Unknown or EAC-on states must be unconditional refusals. Treat peers’ `eac_off` reports as untrusted declarations, never remotely verified safety.

   **Automated test:** Every configuration and IPC combination requesting an EAC-on swap must fail, including forged peer status and unknown launch modes.

**Claims verified as sound, within their demonstrated limits**

- The prototype restores stock after its three injected swap exceptions; I reran those cases successfully in the permitted scratch directory.
- The prototype refuses to restore an old backup when its supplied current manifest digest changes; its update case retained the custom map pending repair.
- POSIX rename preserves old data through an existing file descriptor; both the retained experiment and my restore experiment confirmed this.
- Whole-file verification against the requested BLAKE3 would reject a host serving different bytes under that hash; it establishes byte identity, not map safety.
- Deriving storage names from validated hashes and excluding display names from paths is a sound restriction at the logical naming layer. Filesystem aliases still require protection.
- The existing editor-save receipt records a changed package hash and explicitly does not claim runtime testing; `editor_save.py` supports that narrower provenance claim.

**Open questions**

- Is a dedicated offline installation and prefix acceptable? Without isolation or comprehensive launch mediation, the current shared-install design cannot establish the advertised ban-safety invariant.
- What proves the game process’s launch mode on Windows when `-noeac` is absent? The additional log condition does not resolve the mandatory command-line requirement; absence must currently mean refusal.
- Can Epic and Steam provide exact installed-build digests and exclusion against updates/Verify on every supported platform?
- Where are the track JSON files and primary evidence cited by the design? They were not present in the reviewed tree. The retained Lethamyr response is a 404 page, so it does not verify the stated download endpoint.
- What exact filesystem and network restrictions apply to Rocket League after Heroic/umu launch, and what equivalent containment will exist on Windows?
- Which texture hashes and names are application-pinned, how were they obtained, and what establishes the safety of preexisting texture files during online use?
- Must Map Maker publication mean saved, runtime-tested, or owner-approved? Those need distinct receipt requirements.
- What is the complete credential-bearing diagnostic inventory, including launch failures, service logs and crash reports?

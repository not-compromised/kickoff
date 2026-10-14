# kickoff-game

Install discovery, copy generations and the game launch are not implemented
yet (M5a, M3). What exists is the Linux gamebox spawn path of design §3.2.6,
which runs only Kickoff's own synthetic containment probes (M0).

## The chain

```
kickoff-gamebox (user service; sweeps descriptors first)
 └ systemd-run --user --scope   game scope: BindsTo/After the service,
   │                            KillMode=control-group, KillSignal=SIGKILL,
   │                            MemoryMax=12G, MemorySwapMax=0, TasksMax=512
   └ kickoff-box-link enter     sweep, signal mask reset, PDEATHSIG,
     │                          parent == supervisor, inside the scope
     └ pasta (explicit options) new user, net, mnt, pid, uts, ipc namespaces
       └ kickoff-box-link inner root of pasta's namespaces: IPv6 off, ruleset
         │                      loaded and listed back, rlimits, no_new_privs
         └ bwrap (view of design §3.2's table, less GPU, display, audio, tap)
           └ kickoff-box-link barrier   checks itself, hands over, waits
             └ kickoff-box-probe        the payload; the game in M3
```

The supervisor's request is a closed set of probes (`probe standin`,
`probe inventory [--fault F]`); no path, command or argument comes from
input. The three binaries find each other only as installed siblings.

**Teardown.** Normal stop (SIGTERM to the supervisor, box exit or a refused
barrier) writes `cgroup.kill`, waits for `populated 0` and only then asks the
manager to stop the scope; the supervisor logs the scope's state at that
request. Owner death is the manager's `BindsTo=` with `KillSignal=SIGKILL`.

**Launch barrier.** The barrier link checks namespaces, its cgroup namespace,
rlimits, capability sets, `NoNewPrivs` and its descriptors, writes one byte on
a pipe and closes it. The supervisor then checks the same link through
`/proc/<pid>`, plus the scope name and the nft ruleset (listed through
`nsenter` into bwrap's monitor, which stayed in pasta's user namespace), and
releases it with one byte on a second pipe. The link closes that pipe,
re-checks that only stdio on `/dev/null` is open, and execs the payload.
Any failure kills the cgroup. Each property except the cgroup name and
`NoNewPrivs` has an injectable fault (`--fault`), refused in the SI-36 test.

## Decisions open for review

- **rlimits and no_new_privs are set by the `inner` link through rustix**, not
  by spawning `setpriv` and `prlimit`: same effects, proved at the barrier,
  one exec fewer and no option parsing. Applied after pasta, so pasta keeps
  its own limits.
- **pasta is the box's parent** (`pasta … -- inner`, as the M1 harness ran
  it), not attached to namespaces a link created first. pasta gives its
  command new PID and mount namespaces, so `inner` cannot see its parent;
  pasta is the supervisor's direct child, and its exit at any phase is a
  normal stop. `inner` is init of that PID namespace, so its death kills
  everything below it.
- **The barrier's namespace property is stricter than the design's text**:
  besides differing from the host's, the box's user, mount, PID and IPC
  namespaces must differ from the `inner` link's. pasta already separates
  all five from the host, and its mount namespace is a full copy of the
  host's.
- **The cgroup property is split.** The box has its own cgroup namespace, so
  the barrier link sees `/`; the scope name is checked by the supervisor and
  by `enter` and `inner`.
- **The nft check compares tokens.** nft wraps long element lists by a rule
  of its own; whitespace runs compare equal and every other byte must match.
- **The deny set is computed once per launch** from `getifaddrs` and
  `/proc/net/route`; recomputation on netlink events and the QAD public
  address are not implemented.
- **Absolute tool paths** (`/usr/bin/{systemd-run,systemctl,pasta,bwrap,nft,nsenter}`).
- **The supervisor's run directory** is `box/` (mode 0700, created
  exclusively) inside the service's `RuntimeDirectory=`, so the manager
  removes it whatever way the service ends.
- **The view keeps the M1 harness's choices**: `/sys` read-only, the host's
  `$HOME` path as an empty tmpfs home, a generated `passwd` naming the user
  `player`, no `--disable-userns` (umu's pressure-vessel nests bwrap).
- **Signal mask.** Every link resets it: the supervisor blocks SIGTERM and
  SIGCHLD to read them from a signalfd, and the mask survives exec.

## Tests

`cargo test -p kickoff-gamebox` starts the real supervisor as transient user
services named `kickoff-m0-test-*` and removes them. It needs systemd's user
manager, unprivileged user namespaces, bubblewrap, passt and nft.

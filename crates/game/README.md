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
`probe inventory [--fault F]`, `probe network`, `probe files`, `probe display`); no path, command or argument comes from
input. The three binaries find each other only as installed siblings.

**Teardown.** Normal stop (SIGTERM to the supervisor, box exit or a refused
barrier) writes `cgroup.kill`, waits for `populated 0` and only then asks the
manager to stop the scope; the supervisor logs the scope's state at that
request. Owner death is the manager's `BindsTo=` with `KillSignal=SIGKILL`.

**Waiting.** Every wait of the supervisor (scope registration, the
barrier, helpers, the running box) polls one signalfd, so a stop is seen at
once. Helpers are bounded (5 s) and killed and reaped on a stop, the chain's
end or a timeout; once a stop is pending the barrier is never released.

**Test seams.** Debug builds only: `KICKOFF_TEST_GATE=<phase>` with
`KICKOFF_TEST_GATE_DIR` holds the supervisor or a link at a startup phase,
`KICKOFF_TEST_STALL_HELPER` replaces the outside nft helper by one that
never finishes, and `KICKOFF_TEST_SLOW_REGISTRATION` makes the supervisor
never see its scope registered. Release builds compile none of it.

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
- **The deny set comes from rtnetlink, across every routing table.** One dump
  each of IPv4 addresses and routes: every address and its subnet, every
  non-default route destination in any table (policy tables included), every
  gateway including multipath next hops. A route through a nexthop object
  refuses the launch (its gateway is not in the route). Not covered: the
  host's public address as seen by QAD.
- **Any host network change stops the box (fail closed).** The supervisor
  subscribes to IPv4 address, route and rule notifications before it reads
  the view; any notification, or a lost one, stops the box with "the host
  network changed". Recomputing and reloading the deny set live is a later
  chunk; until then a long session on a host whose routes change (a VPN
  reconnecting) ends.
- **Startup probes (requirement 6) cover the gateway mapping only.** Before
  the ruleset loads, `inner` connects to pasta's gateway on a port the
  supervisor listens on at the host's loopback; a connection refuses the
  launch, and the supervisor confirms at the barrier that it accepted
  nothing. Not yet probed: pasta's `-T`/`-U` `auto` forwarding (explicitly
  off) and bwrap not being setuid.
- **The SI-14 oracle is a UDP send.** The ruleset drops, so a TCP connect to
  a forbidden destination hangs; a dropped UDP send fails at once with
  EPERM. Each forbidden destination must give exactly EPERM, and a DNS
  exchange with a public resolver is the positive control (the test needs
  internet access). The host's own addresses are tested, but no synthetic
  LAN with public addresses and no route change yet.
- **The prefix's writable layer is a sized tmpfs.** bwrap's `--tmp-overlay`
  writes into its unsized root tmpfs, so the setup link (root of pasta's user
  and mount namespaces) mounts a tmpfs of the request's size on the run
  directory's `prefix-rw`, invisible to the host, and bwrap overlays the
  prefix base with it. Both barrier sides check the overlay's size (statvfs
  reports the upper layer). Game launches get 4 GiB; the `limits` probe gets
  16 MiB, 64 tasks and 64 MiB and really fills, forks and allocates.
- **OOMPolicy.** Game scopes use `OOMPolicy=stop` (an out-of-memory kill ends
  the box); the `limits` probe's scope uses `continue`, so the probe sees its
  allocating child killed.
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

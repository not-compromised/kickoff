//! kickoff-gamebox: creates the game scope, starts the chain inside it,
//! holds the launch barrier and owns teardown (design §2.1, §3.2.6).

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use rustix::fs::{Mode, OFlags};

use super::Refused;
use super::barrier::{Check, Fault, NAMESPACES, Proc, Sides, identity};
use super::events::{Events, Halt, POLL, Wake, after};
use super::gate;
use super::install::{LINK, PROBE, require_unprivileged, sibling};
use super::link::{READY, RELEASE, RULESET, SETUP_NS};
use super::net::{self, PASTA, same_ruleset};
use super::netlink::{self, HostWatch};
use super::scope::{self, Limits, Owner, REGISTRATION_DEADLINE, Scope, TEARDOWN_DEADLINE};
use super::startup::Canaries;
use super::view::{BWRAP, View, in_box};

const NSENTER: &str = "/usr/bin/nsenter";
/// From the scope's registration to the barrier link's ready byte.
const BARRIER_DEADLINE: Duration = Duration::from_secs(30);
/// Any one helper the supervisor waits on (the outside nft listing).
const HELPER_LIMIT: Duration = Duration::from_secs(5);

/// What the supervisor was asked to run. Until kickoffd's channel exists
/// (design §2.7) the only requests are Kickoff's own containment probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Request {
    /// The scope alone with a stand-in that ignores SIGTERM and has a
    /// double-forked descendant: each teardown path is tested without the
    /// box's own fast paths (design §3.2.6, SI-38).
    StandIn,
    /// The whole chain with a probe as payload, optionally with one setup
    /// fault the launch must refuse.
    Probe(Payload, Fault),
}

/// The probe payloads; see the probe binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Payload {
    /// Holds only if stdio is all it has (SI-36).
    Inventory,
    /// Tries the host and private destinations, the internet and changes
    /// to its network; exits 0 only if the box allows exactly the internet
    /// (SI-14).
    Network,
    /// Tries to change the game copy and to find launcher state (SI-34).
    Files,
    /// Looks for host display and bus sockets (SI-35, direct half).
    Display,
    /// Sends to the test fixtures' globally addressed LANs (SI-14).
    Lans,
    /// Fills the prefix, forks and allocates until the box's small probe
    /// limits stop it (SI-38).
    Limits,
}

impl Payload {
    fn limits(self) -> Limits {
        match self {
            Payload::Limits => Limits::PROBE,
            _ => Limits::GAME,
        }
    }
}

impl Request {
    fn parse(args: &[OsString]) -> Result<Request, Refused> {
        let args: Vec<&str> = args
            .iter()
            .map(|a| a.to_str().ok_or(Refused::Malformed))
            .collect::<Result<_, _>>()?;
        let payload = |name: &str| match name {
            "inventory" => Ok(Payload::Inventory),
            "network" => Ok(Payload::Network),
            "files" => Ok(Payload::Files),
            "display" => Ok(Payload::Display),
            "lans" => Ok(Payload::Lans),
            "limits" => Ok(Payload::Limits),
            _ => Err(Refused::Malformed),
        };
        match args.as_slice() {
            ["probe", "standin"] => Ok(Request::StandIn),
            ["probe", name] => Ok(Request::Probe(payload(name)?, Fault::None)),
            ["probe", name, "--fault", fault] => {
                Ok(Request::Probe(payload(name)?, Fault::parse(fault)?))
            }
            _ => Err(Refused::Malformed),
        }
    }
}

enum End {
    Exited(ExitStatus),
    Stopped,
}

pub fn supervisor_main() -> ExitCode {
    if let Err(error) = super::core::enter() {
        report(&format!("refused: {error}"));
        return ExitCode::from(error.code());
    }
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&args) {
        Ok(End::Exited(status)) => {
            report(&format!("box exited: {status}"));
            ExitCode::SUCCESS
        }
        Ok(End::Stopped) => {
            report("box stopped");
            ExitCode::SUCCESS
        }
        Err(refused) => {
            report(&format!("refused: {refused}"));
            ExitCode::from(refused.code())
        }
    }
}

/// One line to stdout, which the service manager sends to the journal.
fn report(line: &str) {
    let _ = writeln!(std::io::stdout(), "{line}");
}

fn run(args: &[OsString]) -> Result<End, Refused> {
    // Nothing the service was started with reaches the chain (design §2.7).
    if !cfg!(feature = "mutant-si36-no-fd-sweep") {
        kickoff_local::fds::close_descriptors_above_stdio()?;
    }
    let request = Request::parse(args)?;
    let owner = Owner::current()?;
    let link = sibling(LINK)?;
    let probe = sibling(PROBE)?;

    let mut events = Events::new()?;

    let name = owner.scope_name();
    let limits = match request {
        Request::StandIn => Limits::GAME,
        Request::Probe(payload, _) => payload.limits(),
    };
    let prefix = limits.prefix.to_string();
    let sides = Sides::requested();
    let mut chain = scope::create_command();
    chain
        .args(scope::create_args(&owner, &name, limits))
        .arg(&link)
        .arg("enter")
        .arg(std::process::id().to_string())
        .arg(&name)
        .arg("--");
    let boxed = match request {
        Request::StandIn => {
            chain.arg(&probe).arg("hold");
            None
        }
        Request::Probe(payload, fault) => {
            require_unprivileged(Path::new(BWRAP))?;
            let run = RunDir::create()?;
            let host = host_namespaces()?;
            gate::hold("host-view");
            // Watching starts before the view is read, so a change between
            // the two is seen.
            let watch = HostWatch::open()?;
            let network = netlink::host_view()?;
            events.watch(watch);
            let ruleset = net::ruleset(&net::deny_set(&network));
            std::fs::write(run.0.join(RULESET), &ruleset)?;
            let ready = open_pipe(&run.0.join(READY), OFlags::RDONLY | OFlags::NONBLOCK)?;
            let release = open_pipe(&run.0.join(RELEASE), OFlags::RDWR)?;
            let release_id = identity(&run.0.join(RELEASE))?;
            // The startup probe's target: the gateway must not lead here.
            let canaries = Canaries::open()?;
            let canary_port = canaries.tcp_port()?.to_string();
            let udp_port = canaries.udp_port()?.to_string();
            let witness = witness_dir();
            let view = View {
                witness: witness.as_deref(),
                run: &run.0,
                link: &link,
                probe: &probe,
                home: &home()?,
                uid: rustix::process::getuid().as_raw(),
                gid: rustix::process::getgid().as_raw(),
            };
            chain
                .arg(PASTA)
                .args(net::pasta_args(fault, &canaries)?)
                .arg(&link)
                .args(["inner", &name])
                .arg(&run.0)
                .args([fault.name(), &canary_port, &udp_port, &prefix, "--", BWRAP])
                .args(view.bwrap_args(fault))
                .arg(in_box(LINK))
                .args(["barrier", fault.name(), sides.name(), &prefix])
                .args(&host)
                .args(NAMESPACES.iter().map(|ns| format!("{SETUP_NS}{ns}")))
                .arg("--")
                .arg(in_box(PROBE));
            match payload {
                Payload::Inventory => chain.arg("inventory"),
                Payload::Files => chain.arg("files"),
                Payload::Display => chain.arg("display"),
                Payload::Network => chain.arg("network").args(
                    net::host_addresses(&network)
                        .iter()
                        .map(Ipv4Addr::to_string),
                ),
                Payload::Lans => chain.arg("lans"),
                Payload::Limits => chain.arg("limits"),
            };
            Some(Boxed {
                _run: run,
                canaries,
                ready,
                release: Some(release),
                release_id,
                host,
                ruleset,
                link_id: identity(&link)?,
                prefix: limits.prefix,
                sides,
            })
        }
    };
    gate::hold("before-registration");
    let mut chain = chain
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let scope = match register(&mut events, &name, &mut chain) {
        Ok(scope) => scope,
        Err(halt) => {
            // The chain's first process is ours to end; anything that
            // registered unseen is ended by the manager's stop, and by the
            // binding once this process exits.
            if matches!(chain.try_wait(), Ok(None)) {
                let _ = chain.kill();
            }
            let _ = chain.wait();
            let stopped = scope::stop_named(&name);
            let end = conclude(early(halt));
            stopped?;
            return end;
        }
    };
    gate::hold("scope-registered");
    // `boxed` holds the run directory the box's mounts come from until the
    // scope is empty.
    let mut boxed = boxed;
    let halt = match boxed.as_mut() {
        Some(boxed) => match boxed.barrier(&mut events, &mut chain, &scope, &name) {
            Ok(()) => {
                report("barrier: released");
                events.until_end(&mut chain)
            }
            Err(halt) => early(halt),
        },
        None => events.until_end(&mut chain),
    };
    let torn = teardown(&scope, &mut chain);
    drop(boxed);
    let end = conclude(halt);
    torn?;
    end
}

/// Waits until the chain is inside the scope, still answering a stop and
/// the chain's end.
fn register(events: &mut Events, name: &str, chain: &mut Child) -> Result<Scope, Halt> {
    let deadline = after(REGISTRATION_DEADLINE);
    loop {
        if !gate::slow_registration()
            && let Some(scope) = Scope::try_open(name, chain.id())?
        {
            return Ok(scope);
        }
        if cfg!(feature = "mutant-si38-registration-deaf") {
            std::thread::sleep(POLL);
        } else if events.wait(None, after(POLL).min(deadline))? == Wake::Child
            && let Some(status) = chain.try_wait()?
        {
            return Err(Halt::Ended(status));
        }
        if Instant::now() >= deadline {
            return Err(Refused::Scope.into());
        }
    }
}

/// Before the barrier is released, the chain ending is a refusal: some
/// link refused, and its exit status says which check.
fn early(halt: Halt) -> Halt {
    match halt {
        Halt::Ended(status) => Halt::Refused(Refused::BoxEnded(status.code().unwrap_or(-1))),
        other => other,
    }
}

fn conclude(halt: Halt) -> Result<End, Refused> {
    match halt {
        Halt::Stop => Ok(End::Stopped),
        Halt::Ended(status) => Ok(End::Exited(status)),
        Halt::HostChanged => Err(Refused::HostChanged),
        Halt::Refused(refused) => Err(refused),
    }
}

/// The supervisor's half of a launch through the whole chain.
struct Boxed {
    /// Bytes of the prefix's writable layer.
    prefix: u64,
    sides: Sides,
    /// Held, not read: the box's mounts come from it until teardown.
    _run: RunDir,
    canaries: Canaries,
    ready: OwnedFd,
    release: Option<OwnedFd>,
    release_id: (u64, u64),
    host: Vec<String>,
    ruleset: String,
    link_id: (u64, u64),
}

impl Boxed {
    /// Waits for the barrier link's ready byte, checks it from outside and
    /// releases it, unless a stop arrived first.
    fn barrier(
        &mut self,
        events: &mut Events,
        chain: &mut Child,
        scope: &Scope,
        name: &str,
    ) -> Result<(), Halt> {
        if cfg!(feature = "mutant-si36-barrier-skip") {
            let release = self.release.take().ok_or(Refused::Malformed)?;
            std::fs::File::from(release).write_all(b"G")?;
            return Ok(());
        }
        let deadline = after(BARRIER_DEADLINE);
        let mut file = std::fs::File::from(self.ready.try_clone()?);
        let mut byte = [0u8; 1];
        loop {
            match events.wait(Some(self.ready.as_fd()), deadline)? {
                Wake::Extra => break,
                Wake::Child => {
                    if let Some(status) = chain.try_wait()? {
                        return Err(Halt::Ended(status));
                    }
                }
                Wake::Timeout => return Err(Refused::Barrier(Check::Descriptors).into()),
            }
        }
        match file.read(&mut byte)? {
            1 if byte == *b"C" => {
                file.read_exact(&mut byte)?;
                if byte != *b"R" {
                    return Err(Refused::CoreDumps.into());
                }
                report("core probe: suppressed");
            }
            // The link closed its end without the byte: it refused, and its
            // exit status says which check.
            0 => return Err(Halt::Ended(ended(events, chain)?)),
            _ => return Err(Refused::Barrier(Check::Descriptors).into()),
        }
        // The link closes its end after the byte; wait for that close, so
        // the inventory below sees only the release pipe.
        let deadline = after(TEARDOWN_DEADLINE);
        loop {
            match file.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => return Err(Refused::Barrier(Check::Descriptors).into()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            if events.wait(Some(self.ready.as_fd()), deadline)? == Wake::Timeout {
                return Err(Refused::Barrier(Check::Descriptors).into());
            }
        }
        gate::hold("barrier");
        self.canaries.held()?;
        if self.sides.outside() {
            self.check_from_outside(events, chain, scope, name)?;
        }
        events.pending()?;
        let release = self.release.take().ok_or(Refused::Malformed)?;
        std::fs::File::from(release).write_all(b"G")?;
        Ok(())
    }

    fn check_from_outside(
        &self,
        events: &mut Events,
        chain: &mut Child,
        scope: &Scope,
        name: &str,
    ) -> Result<(), Halt> {
        // Each process is pinned once; every later read goes through it.
        let procs: Vec<Proc> = scope
            .procs()?
            .into_iter()
            .filter_map(|pid| Proc::pid(pid).ok())
            .collect();
        let bwrap = identity(Path::new(BWRAP))?;
        let mut links = procs
            .iter()
            .filter(|p| p.exe().is_ok_and(|e| e == self.link_id));
        let (Some(link), None) = (links.next(), links.next()) else {
            return Err(Refused::Barrier(Check::Cgroup).into());
        };
        let suffix = format!("/{name}.scope");

        // bwrap's monitor is the setup link after its exec: it stayed in
        // pasta's namespaces, whose user namespace owns the box's network.
        let net = link.namespace("net")?;
        let user = link.namespace("user")?;
        let mut monitors = procs.iter().filter(|p| {
            p.exe().is_ok_and(|e| e == bwrap)
                && p.namespace("net").is_ok_and(|n| n == net)
                && p.namespace("user").is_ok_and(|u| u != user)
        });
        let (Some(monitor), None) = (monitors.next(), monitors.next()) else {
            return Err(Refused::Barrier(Check::Namespaces).into());
        };
        let setup: Vec<String> = NAMESPACES
            .iter()
            .map(|ns| monitor.namespace(ns))
            .collect::<Result<_, _>>()?;
        link.namespaces_separate(&self.host, &setup)?;
        link.cgroup_is(|path| path.ends_with(&suffix))?;
        link.rlimits()?;
        link.privileges()?;
        link.prefix_size(self.prefix)?;
        link.descriptors(&link.descriptor_numbers()?, &[self.release_id])?;

        let mut list = if gate::stall_helper() {
            let mut stalled = Command::new("/usr/bin/sleep");
            stalled
                .arg("3600")
                .stdin(Stdio::null())
                .stderr(Stdio::null());
            stalled
        } else {
            // nsenter enters the monitor's namespaces through descriptors
            // pinned here, handed over as its stdin and stderr, never by PID.
            let mut list = Command::new(NSENTER);
            list.args([
                "--user=/proc/self/fd/0",
                "--net=/proc/self/fd/2",
                "--preserve-credentials",
                "--",
                net::nft_binary(),
                "list",
                "ruleset",
            ])
            .stdin(Stdio::from(monitor.namespace_fd("user")?))
            .stderr(Stdio::from(monitor.namespace_fd("net")?));
            list
        };
        list.env_clear();
        gate::mark("helper");
        let (status, out) = if cfg!(feature = "mutant-si38-helper-unbounded") {
            let out = list.output()?;
            (out.status, out.stdout)
        } else {
            events.helper(chain, &mut list, HELPER_LIMIT)?
        };
        let listed = String::from_utf8(out).map_err(|_| Refused::Barrier(Check::Nft))?;
        if !status.success() || !same_ruleset(&listed, &self.ruleset) {
            return Err(Refused::Barrier(Check::Nft).into());
        }
        link.still_running()?;
        monitor.still_running()?;
        Ok(())
    }
}

/// The supervisor's private directory for one box, inside the service's
/// runtime directory, which the manager removes when the service stops.
struct RunDir(PathBuf);

impl RunDir {
    fn create() -> Result<RunDir, Refused> {
        let base =
            PathBuf::from(std::env::var_os("RUNTIME_DIRECTORY").ok_or(Refused::NotAService)?);
        let meta = std::fs::symlink_metadata(&base)?;
        if !base.is_absolute()
            || !meta.is_dir()
            || meta.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(Refused::NotAService);
        }
        let dir = base.join("box");
        // Private by its own mode, whatever the runtime directory's; one left
        // by an earlier box refuses the launch.
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let run = RunDir(dir);
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let home = home()?;
        let home = home.to_str().ok_or(Refused::Malformed)?;
        let files = [
            (
                "resolv.conf",
                "nameserver 1.1.1.1\nnameserver 9.9.9.9\noptions edns0\n".to_owned(),
            ),
            (
                "hosts",
                "127.0.0.1 localhost\n127.0.1.1 kickoff\n".to_owned(),
            ),
            (
                "passwd",
                format!(
                    "root:x:0:0::/root:/bin/sh\nplayer:x:{uid}:{gid}::{home}:/bin/sh\nnobody:x:65534:65534::/:/usr/bin/nologin\n"
                ),
            ),
            (
                "group",
                format!("root:x:0:\nplayer:x:{gid}:\nnobody:x:65534:\n"),
            ),
        ];
        for (name, text) in files {
            std::fs::write(run.0.join(name), text)?;
        }
        for dir in ["game", "prefix", "prefix-rw"] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(run.0.join(dir))?;
        }
        // Stands in for the game copy's files until copy generations exist.
        std::fs::write(run.0.join("game").join("canary"), b"copy\n")?;
        for pipe in [READY, RELEASE] {
            rustix::fs::mknodat(
                rustix::fs::CWD,
                run.0.join(pipe),
                rustix::fs::FileType::Fifo,
                Mode::RUSR | Mode::WUSR,
                0,
            )?;
        }
        Ok(run)
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The chain's exit status once it ends, within the teardown deadline.
fn ended(events: &mut Events, chain: &mut Child) -> Result<ExitStatus, Halt> {
    let deadline = after(TEARDOWN_DEADLINE);
    loop {
        if let Some(status) = chain.try_wait()? {
            return Ok(status);
        }
        if events.wait(None, deadline)? == Wake::Timeout {
            return Err(Refused::BoxEnded(-1).into());
        }
    }
}

/// Debug builds: a test's payload-entry witness directory.
fn witness_dir() -> Option<PathBuf> {
    if !cfg!(debug_assertions) {
        return None;
    }
    let dir = PathBuf::from(std::env::var_os("KICKOFF_TEST_WITNESS_DIR")?);
    dir.is_absolute().then_some(dir)
}

fn home() -> Result<PathBuf, Refused> {
    let home = PathBuf::from(std::env::var_os("HOME").ok_or(Refused::Malformed)?);
    if !home.is_absolute() {
        return Err(Refused::Malformed);
    }
    Ok(home)
}

fn host_namespaces() -> Result<Vec<String>, Refused> {
    let me = Proc::this();
    NAMESPACES.iter().map(|ns| me.namespace(ns)).collect()
}

fn open_pipe(path: &Path, flags: OFlags) -> Result<OwnedFd, Refused> {
    Ok(rustix::fs::open(
        path,
        flags | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// The normal stop: the direct kill first, then the manager is asked to
/// stop a scope that is already empty (design §3.2.6, SI-38).
fn teardown(scope: &Scope, chain: &mut Child) -> Result<(), Refused> {
    if !cfg!(feature = "mutant-si38-no-direct-kill") {
        scope.kill()?;
        scope.wait_empty(TEARDOWN_DEADLINE)?;
    }
    report(&format!(
        "teardown: stop request with the scope populated={}",
        u8::from(scope.populated()?)
    ));
    scope.stop()?;
    scope.wait_empty(TEARDOWN_DEADLINE)?;
    // Everything in the scope is dead, the chain's first process included.
    let deadline = after(TEARDOWN_DEADLINE);
    while chain.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            return Err(Refused::Teardown);
        }
        std::thread::sleep(POLL);
    }
    Ok(())
}

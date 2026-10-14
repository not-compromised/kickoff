//! kickoff-gamebox: creates the game scope, starts the chain inside it,
//! holds the launch barrier and owns teardown (design §2.1, §3.2.6).

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::SignalFd;
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{Mode, OFlags};

use super::Refused;
use super::barrier::{Check, Fault, NAMESPACES, Proc, identity};
use super::install::{LINK, PROBE, sibling};
use super::link::{READY, RELEASE, RULESET, SETUP_NS};
use super::net::{self, PASTA, same_ruleset};
use super::scope::{self, Owner, Scope, TEARDOWN_DEADLINE};
use super::view::{BWRAP, View, in_box};

const NSENTER: &str = "/usr/bin/nsenter";
/// From the scope's registration to the barrier link's ready byte.
const BARRIER_DEADLINE: Duration = Duration::from_secs(30);

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

    // Stop arrives as SIGTERM from the manager, and box exit as SIGCHLD;
    // both are read from one descriptor instead of a handler.
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGTERM);
    mask.add(Signal::SIGCHLD);
    mask.thread_block()?;
    let signals = SignalFd::new(&mask)?;

    let name = owner.scope_name();
    let mut chain = scope::create_command();
    chain
        .args(scope::create_args(&owner, &name))
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
            let run = RunDir::create()?;
            let host = host_namespaces()?;
            let ruleset = net::ruleset(&net::deny_set()?);
            std::fs::write(run.0.join(RULESET), &ruleset)?;
            let ready = open_pipe(&run.0.join(READY), OFlags::RDONLY | OFlags::NONBLOCK)?;
            let release = open_pipe(&run.0.join(RELEASE), OFlags::RDWR)?;
            let release_id = identity(&run.0.join(RELEASE))?;
            // The startup probe's target: the gateway must not lead here.
            let canary = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            canary.set_nonblocking(true)?;
            let canary_port = canary.local_addr()?.port().to_string();
            let view = View {
                run: &run.0,
                link: &link,
                probe: &probe,
                home: &home()?,
                uid: rustix::process::getuid().as_raw(),
                gid: rustix::process::getgid().as_raw(),
            };
            chain
                .arg(PASTA)
                .args(net::pasta_args(fault))
                .arg(&link)
                .args(["inner", &name])
                .arg(&run.0)
                .args([fault.name(), &canary_port, "--", BWRAP])
                .args(view.bwrap_args(fault))
                .arg(in_box(LINK))
                .args(["barrier", fault.name()])
                .args(&host)
                .args(NAMESPACES.iter().map(|ns| format!("{SETUP_NS}{ns}")))
                .arg("--")
                .arg(in_box(PROBE));
            match payload {
                Payload::Inventory => chain.arg("inventory"),
                Payload::Files => chain.arg("files"),
                Payload::Display => chain.arg("display"),
                Payload::Network => chain
                    .arg("network")
                    .args(net::host_addresses()?.iter().map(Ipv4Addr::to_string)),
            };
            Some(Boxed {
                _run: run,
                canary,
                ready,
                release: Some(release),
                release_id,
                host,
                ruleset,
                link_id: identity(&link)?,
            })
        }
    };
    let mut child = chain
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let scope = match Scope::registered(&name, child.id()) {
        Ok(scope) => scope,
        Err(refused) => {
            // Not registered means nothing past systemd-run started; if it
            // registered unseen, the binding ends it when this process exits.
            let _ = child.kill();
            let _ = child.wait();
            return Err(refused);
        }
    };
    // `boxed` holds the run directory the box's mounts come from until the
    // scope is empty.
    let mut boxed = boxed;
    let end = match boxed.as_mut() {
        Some(boxed) => match boxed.barrier(&signals, &mut child, &scope, &name) {
            Ok(None) => {
                report("barrier: released");
                wait(&signals, &mut child)
            }
            Ok(Some(end)) => Ok(end),
            Err(refused) => Err(refused),
        },
        None => wait(&signals, &mut child),
    };
    let torn = teardown(&scope, &mut child);
    drop(boxed);
    let end = end?;
    torn?;
    Ok(end)
}

/// The supervisor's half of a launch through the whole chain.
struct Boxed {
    /// Held, not read: the box's mounts come from it until teardown.
    _run: RunDir,
    canary: TcpListener,
    ready: OwnedFd,
    release: Option<OwnedFd>,
    release_id: (u64, u64),
    host: Vec<String>,
    ruleset: String,
    link_id: (u64, u64),
}

impl Boxed {
    /// Waits for the barrier link's ready byte, checks it from outside and
    /// releases it. `Some` if the request ended first.
    fn barrier(
        &mut self,
        signals: &SignalFd,
        child: &mut Child,
        scope: &Scope,
        name: &str,
    ) -> Result<Option<End>, Refused> {
        if cfg!(feature = "mutant-si36-barrier-skip") {
            let release = self.release.take().ok_or(Refused::Malformed)?;
            std::fs::File::from(release).write_all(b"G")?;
            return Ok(None);
        }
        let started = Instant::now();
        loop {
            let left = BARRIER_DEADLINE
                .checked_sub(started.elapsed())
                .ok_or(Refused::Barrier(Check::Descriptors))?;
            let mut fds = [
                PollFd::new(signals, PollFlags::IN),
                PollFd::new(&self.ready, PollFlags::IN),
            ];
            rustix::event::poll(&mut fds, Some(&timespec(left)))?;
            let [signal, ready] = fds;
            if signal.revents().contains(PollFlags::IN) {
                match next_signal(signals, child)? {
                    Some(End::Exited(status)) => {
                        return Err(Refused::BoxEnded(status.code().unwrap_or(-1)));
                    }
                    Some(End::Stopped) => return Ok(Some(End::Stopped)),
                    None => {}
                }
            }
            if !ready.revents().is_empty() {
                break;
            }
        }
        let mut byte = [0u8; 1];
        let mut file = std::fs::File::from(self.ready.try_clone()?);
        match file.read(&mut byte)? {
            1 if byte == *b"R" => {}
            // The link closed its end without the byte: it refused, and its
            // exit status says which check.
            0 => return Err(ended(child)),
            _ => return Err(Refused::Barrier(Check::Descriptors)),
        }
        // The link closes its end after the byte; wait for that close, so
        // the inventory below sees only the release pipe.
        let started = Instant::now();
        loop {
            match file.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => return Err(Refused::Barrier(Check::Descriptors)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            if started.elapsed() > TEARDOWN_DEADLINE {
                return Err(Refused::Barrier(Check::Descriptors));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        self.check_from_outside(scope, name)?;
        let release = self.release.take().ok_or(Refused::Malformed)?;
        std::fs::File::from(release).write_all(b"G")?;
        Ok(None)
    }

    fn check_from_outside(&self, scope: &Scope, name: &str) -> Result<(), Refused> {
        let procs = scope.procs()?;
        let links: Vec<i32> = procs
            .iter()
            .copied()
            .filter(|pid| exe_is(*pid, self.link_id))
            .collect();
        let [pid] = links.as_slice() else {
            return Err(Refused::Barrier(Check::Cgroup));
        };
        let link = Proc::pid(*pid);
        let suffix = format!("/{name}.scope");

        // bwrap's monitor is the setup link after its exec: it stayed in
        // pasta's namespaces, whose user namespace owns the box's network.
        let bwrap = identity(Path::new(BWRAP))?;
        let net = link.namespace("net")?;
        let user = link.namespace("user")?;
        let monitors: Vec<i32> = procs
            .iter()
            .copied()
            .filter(|pid| {
                let p = Proc::pid(*pid);
                exe_is(*pid, bwrap)
                    && p.namespace("net").is_ok_and(|n| n == net)
                    && p.namespace("user").is_ok_and(|u| u != user)
            })
            .collect();
        let [monitor] = monitors.as_slice() else {
            return Err(Refused::Barrier(Check::Namespaces));
        };
        let setup = Proc::pid(*monitor);
        let setup: Vec<String> = NAMESPACES
            .iter()
            .map(|ns| setup.namespace(ns))
            .collect::<Result<_, _>>()?;
        link.namespaces_separate(&self.host, &setup)?;
        link.cgroup_is(|path| path.ends_with(&suffix))?;
        link.rlimits()?;
        link.privileges()?;
        link.descriptors(&link.descriptor_numbers()?, &[self.release_id])?;
        if !cfg!(feature = "mutant-si14-no-startup-probe") {
            match self.canary.accept() {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                _ => return Err(Refused::PastaMapsHost),
            }
        }

        let out = Command::new(NSENTER)
            .arg(format!("--target={monitor}"))
            .args(["--user", "--net", "--preserve-credentials", "--"])
            .args([net::NFT, "list", "ruleset"])
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        let listed = String::from_utf8(out.stdout).map_err(|_| Refused::Barrier(Check::Nft))?;
        if !out.status.success() || !same_ruleset(&listed, &self.ruleset) {
            return Err(Refused::Barrier(Check::Nft));
        }
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
        for dir in ["game", "prefix"] {
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
fn ended(child: &mut Child) -> Refused {
    let started = Instant::now();
    while started.elapsed() < TEARDOWN_DEADLINE {
        match child.try_wait() {
            Ok(Some(status)) => return Refused::BoxEnded(status.code().unwrap_or(-1)),
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => return error.into(),
        }
    }
    Refused::BoxEnded(-1)
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

fn exe_is(pid: i32, id: (u64, u64)) -> bool {
    identity(Path::new(&format!("/proc/{pid}/exe"))).is_ok_and(|e| e == id)
}

fn open_pipe(path: &Path, flags: OFlags) -> Result<OwnedFd, Refused> {
    Ok(rustix::fs::open(
        path,
        flags | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

fn timespec(d: Duration) -> Timespec {
    Timespec {
        tv_sec: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(d.subsec_nanos()),
    }
}

fn next_signal(signals: &SignalFd, child: &mut Child) -> Result<Option<End>, Refused> {
    let Some(info) = signals.read_signal()? else {
        return Ok(None);
    };
    let signal = i32::try_from(info.ssi_signo)
        .ok()
        .and_then(|n| Signal::try_from(n).ok());
    match signal {
        Some(Signal::SIGTERM) => Ok(Some(End::Stopped)),
        Some(Signal::SIGCHLD) => Ok(child.try_wait()?.map(End::Exited)),
        _ => Ok(None),
    }
}

fn wait(signals: &SignalFd, child: &mut Child) -> Result<End, Refused> {
    loop {
        if let Some(end) = next_signal(signals, child)? {
            return Ok(end);
        }
    }
}

/// The normal stop: the direct kill first, then the manager is asked to
/// stop a scope that is already empty (design §3.2.6, SI-38).
fn teardown(scope: &Scope, child: &mut Child) -> Result<(), Refused> {
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
    child.wait()?;
    Ok(())
}

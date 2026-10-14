//! The trusted links of the chain (design §3.2.6). Each sweeps its
//! descriptors and arms its parent-death signal before it does anything
//! else, then execs the next link:
//!
//! - `enter`, first inside the scope: checks its parent is the supervisor
//!   and that it is in the scope, then execs pasta.
//! - `inner`, pasta's command, root of the box's user and network
//!   namespaces: turns IPv6 off, loads and verifies the ruleset, sets the
//!   rlimits, then execs bwrap holding the two barrier pipes.
//! - `barrier`, inside bwrap: the last link, which execs the payload only
//!   after its own checks and the supervisor's release.

use std::convert::Infallible;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use rustix::fs::{Mode, OFlags};
use rustix::process::{Resource, Rlimit};

use super::Refused;
use super::barrier::{Check, FSIZE, Fault, NAMESPACES, NOFILE, Proc, Sides, identity};
use super::gate;
use super::install::require_null_stdio;
use super::net::{GATEWAY, NFT, same_ruleset};

/// The barrier pipes' numbers from `inner` through bwrap to `barrier`.
pub(super) const READY_FD: i32 = 3;
pub(super) const RELEASE_FD: i32 = 4;
pub(super) const RULESET: &str = "ruleset.nft";
/// Stands in the barrier link's arguments for the setup link's namespace
/// of that name, which only the setup link can read.
pub(super) const SETUP_NS: &str = "@setup-ns:";
pub(super) const READY: &str = "ready";
pub(super) const RELEASE: &str = "release";
/// How long the startup probe waits for a connection pasta should refuse.
const PROBE_TIMEOUT: Duration = Duration::from_millis(300);
/// How long the barrier link waits for the supervisor's release.
const RELEASE_DEADLINE: Duration = Duration::from_secs(30);

pub fn link_main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&args) {
        Ok(never) => match never {},
        Err(refused) => ExitCode::from(refused.code()),
    }
}

fn run(args: &[OsString]) -> Result<Infallible, Refused> {
    let (stage, rest) = args.split_first().ok_or(Refused::Malformed)?;
    let split = rest
        .iter()
        .position(|a| a == "--")
        .ok_or(Refused::Malformed)?;
    let (own, next) = rest.split_at(split);
    let next = next.get(1..).ok_or(Refused::Malformed)?;
    let own: Vec<&str> = own
        .iter()
        .map(|a| a.to_str().ok_or(Refused::Malformed))
        .collect::<Result<_, _>>()?;
    match (stage.to_str(), own.as_slice()) {
        (Some("enter"), [parent, scope]) => enter(parent, scope, next),
        (Some("inner"), [scope, run, fault, port, udp, prefix]) => {
            let port = port.parse().map_err(|_| Refused::Malformed)?;
            let udp = udp.parse().map_err(|_| Refused::Malformed)?;
            let prefix = prefix.parse().map_err(|_| Refused::Malformed)?;
            let setup = Setup {
                run: Path::new(run),
                fault: Fault::parse(fault)?,
                canary: port,
                udp_canary: udp,
                prefix,
            };
            inner(scope, &setup, next)
        }
        (Some("barrier"), [fault, sides, prefix, ns @ ..])
            if ns.len() == NAMESPACES.len().saturating_mul(2) =>
        {
            let (host, setup) = ns.split_at(NAMESPACES.len());
            let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
            let expect = Expect {
                fault: Fault::parse(fault)?,
                sides: Sides::parse(sides)?,
                prefix: prefix.parse().map_err(|_| Refused::Malformed)?,
                host: own(host),
                setup: own(setup),
            };
            barrier(&expect, next)
        }
        _ => Err(Refused::Malformed),
    }
}

fn enter(parent: &str, scope: &str, next: &[OsString]) -> Result<Infallible, Refused> {
    sweep(&[])?;
    gate::hold("enter-before-pdeathsig");
    arm_parent_death()?;
    // Parent-death signals never fire for a parent that is already dead.
    let parent: i32 = parent.parse().map_err(|_| Refused::Malformed)?;
    let current = rustix::process::getppid().map(rustix::process::Pid::as_raw_pid);
    if current != Some(parent) {
        return Err(Refused::ParentGone);
    }
    require_scope(scope)?;
    gate::hold("enter-after-pdeathsig");
    exec(next)
}

/// pasta runs its command as init of new PID and mount namespaces, so this
/// link cannot see its parent. pasta is the supervisor's direct child, and
/// the supervisor tears the scope down when it exits at any phase; this
/// link's own death kills everything in its PID namespace.
/// What the setup link builds the box's network and prefix from.
struct Setup<'a> {
    run: &'a Path,
    fault: Fault,
    /// The supervisor's loopback ports the startup probes must not reach.
    canary: u16,
    udp_canary: u16,
    /// Bytes of the prefix's writable layer.
    prefix: u64,
}

fn inner(scope: &str, setup: &Setup<'_>, next: &[OsString]) -> Result<Infallible, Refused> {
    let Setup {
        run,
        fault,
        canary,
        udp_canary,
        prefix,
    } = *setup;
    sweep(&[])?;
    gate::hold("inner-before-pdeathsig");
    arm_parent_death()?;
    gate::hold("inner-after-pdeathsig");
    // The first descriptors opened after the sweep: READY_FD and RELEASE_FD.
    let ready = open_pipe(&run.join(READY), OFlags::WRONLY)?;
    let release = open_pipe(&run.join(RELEASE), OFlags::RDONLY)?;
    if ready.as_raw_fd() != READY_FD || release.as_raw_fd() != RELEASE_FD {
        return Err(Refused::Malformed);
    }
    if rustix::process::getppid().is_some() || rustix::process::getuid().as_raw() != 0 {
        return Err(Refused::NetworkSetup);
    }
    require_scope(scope)?;
    startup_probes(canary, udp_canary)?;
    for path in [
        "/proc/sys/net/ipv6/conf/all/disable_ipv6",
        "/proc/sys/net/ipv6/conf/default/disable_ipv6",
    ] {
        std::fs::write(path, b"1")?;
        if std::fs::read_to_string(path)?.trim() != "1" {
            return Err(Refused::NetworkSetup);
        }
    }
    let ruleset = std::fs::read_to_string(run.join(RULESET))?;
    nft(&["-f", "-"], Some(&ruleset))?;
    if !same_ruleset(&nft(&["list", "ruleset"], None)?, &ruleset) {
        return Err(Refused::Barrier(Check::Nft));
    }
    gate::hold("inner-after-nft");
    if fault == Fault::Nft {
        nft(
            &["add", "rule", "inet", "gamebox", "output", "accept"],
            None,
        )?;
    }
    let core = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    rustix::process::setrlimit(Resource::Core, core)?;
    let fsize = Rlimit {
        current: Some(FSIZE),
        maximum: Some(FSIZE),
    };
    rustix::process::setrlimit(Resource::Fsize, fsize)?;
    if fault != Fault::Rlimits {
        let nofile = Rlimit {
            current: Some(NOFILE),
            maximum: Some(NOFILE),
        };
        rustix::process::setrlimit(Resource::Nofile, nofile)?;
    }
    if fault == Fault::Cgroup {
        leave_the_scope()?;
    }
    sized_prefix(run, prefix, fault)?;
    rustix::thread::set_no_new_privs(true)?;
    for pipe in [&ready, &release] {
        rustix::io::fcntl_setfd(pipe, rustix::io::FdFlags::empty())?;
    }
    let me = Proc::this();
    let next = next
        .iter()
        .map(
            |arg| match arg.to_str().and_then(|a| a.strip_prefix(SETUP_NS)) {
                Some(ns) if NAMESPACES.contains(&ns) => me.namespace(ns).map(OsString::from),
                _ => Ok(arg.clone()),
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    exec(&next)
}

/// Startup probes (design §3.2.6 requirement 6), before the ruleset could
/// hide the answer. The supervisor listens on the host's loopback: neither
/// pasta's gateway nor the box's own loopback may lead there. The UDP
/// datagram is checked on arrival by the supervisor.
fn startup_probes(tcp: u16, udp: u16) -> Result<(), Refused> {
    if cfg!(feature = "mutant-si14-no-startup-probe") {
        return Ok(());
    }
    if TcpStream::connect_timeout(&SocketAddr::from((GATEWAY, tcp)), PROBE_TIMEOUT).is_ok() {
        return Err(Refused::PastaMapsHost);
    }
    let loopback = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, tcp));
    if TcpStream::connect_timeout(&loopback, PROBE_TIMEOUT).is_ok() {
        return Err(Refused::PastaForwards);
    }
    let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let _ = socket.send_to(b"kickoff probe", (std::net::Ipv4Addr::LOCALHOST, udp));
    Ok(())
}

/// The cgroup fault: this link (and so the box) moves into a child cgroup of
/// the scope. Still killed with the scope, but no longer in it directly.
fn leave_the_scope() -> Result<(), Refused> {
    let text = std::fs::read_to_string("/proc/self/cgroup")?;
    let path = text
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or(Refused::WrongScope)?;
    let child = Path::new("/sys/fs/cgroup")
        .join(path.trim_start_matches('/'))
        .join("moved");
    std::fs::create_dir(&child)?;
    std::fs::write(child.join("cgroup.procs"), b"0")?;
    Ok(())
}

/// The prefix's writable layer is a tmpfs of `bytes`, mounted on the
/// supervisor's `prefix-rw` in pasta's mount namespace, which the host never
/// sees (a namespace an unprivileged user creates gets no propagation back).
/// RLIMIT_FSIZE bounds one file; this bounds them all.
fn sized_prefix(run: &Path, bytes: u64, fault: Fault) -> Result<(), Refused> {
    let rw = run.join("prefix-rw");
    if fault != Fault::PrefixUnsized && !cfg!(feature = "mutant-si38-prefix-unsized") {
        let data = std::ffi::CString::new(format!("size={bytes},mode=0700"))
            .map_err(|_| Refused::Malformed)?;
        rustix::mount::mount(
            "tmpfs",
            &rw,
            "tmpfs",
            rustix::mount::MountFlags::NOSUID | rustix::mount::MountFlags::NODEV,
            data.as_c_str(),
        )?;
    }
    for dir in ["upper", "work"] {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(rw.join(dir))?;
    }
    Ok(())
}

/// The last link. bwrap's `--die-with-parent` and PID namespace cover its
/// parent; it checks itself, hands over to the supervisor's outside check
/// and execs the payload only on the release byte.
/// What the barrier link checks itself against.
struct Expect {
    fault: Fault,
    sides: Sides,
    /// Bytes of the prefix's writable layer.
    prefix: u64,
    /// The host's and the setup link's namespaces.
    host: Vec<String>,
    setup: Vec<String>,
}

fn barrier(expect: &Expect, next: &[OsString]) -> Result<Infallible, Refused> {
    if cfg!(feature = "mutant-si36-barrier-skip") {
        return exec(next);
    }
    sweep(&[READY_FD, RELEASE_FD])?;
    let me = Proc::this();
    let ready_path = format!("/proc/self/fd/{READY_FD}");
    let release_path = format!("/proc/self/fd/{RELEASE_FD}");
    if expect.sides.inside() {
        me.namespaces_separate(&expect.host, &expect.setup)?;
        // The box has its own cgroup namespace; the supervisor checks the name.
        me.cgroup_is(|path| path == "/")?;
        me.rlimits()?;
        me.privileges()?;
        me.prefix_size(expect.prefix)?;
        let pipes = [
            identity(Path::new(&ready_path))?,
            identity(Path::new(&release_path))?,
        ];
        me.descriptors(&kickoff_local::fds::open_descriptors()?, &pipes)?;
    }
    let mut ready = std::fs::File::from(open_pipe(Path::new(&ready_path), OFlags::WRONLY)?);
    let release = open_pipe(Path::new(&release_path), OFlags::RDONLY)?;
    nix::unistd::close(READY_FD)?;
    if expect.fault != Fault::Descriptors {
        nix::unistd::close(RELEASE_FD)?;
    }
    ready.write_all(b"R")?;
    drop(ready);
    await_release(release)?;
    if expect.sides.inside() {
        me.descriptors(&kickoff_local::fds::open_descriptors()?, &[])?;
    }
    exec(next)
}

fn await_release(release: OwnedFd) -> Result<(), Refused> {
    use rustix::event::{PollFd, PollFlags, Timespec};
    let timeout = Timespec {
        tv_sec: i64::try_from(RELEASE_DEADLINE.as_secs()).map_err(|_| Refused::Malformed)?,
        tv_nsec: 0,
    };
    let mut fds = [PollFd::new(&release, PollFlags::IN)];
    if rustix::event::poll(&mut fds, Some(&timeout))? == 0 {
        return Err(Refused::ParentGone);
    }
    let mut byte = [0u8; 1];
    let read = std::fs::File::from(release).read(&mut byte)?;
    if read != 1 || byte != *b"G" {
        return Err(Refused::ParentGone);
    }
    Ok(())
}

/// Every link's first step. The signal mask is reset too: the supervisor
/// blocks SIGTERM and SIGCHLD to read them from a descriptor, the mask
/// survives exec, and pasta with SIGCHLD blocked never sees its command end.
fn sweep(keep: &[i32]) -> Result<(), Refused> {
    nix::sys::signal::SigSet::empty().thread_set_mask()?;
    kickoff_local::fds::close_descriptors_above_stdio_except(keep)?;
    require_null_stdio()
}

fn arm_parent_death() -> Result<(), Refused> {
    Ok(rustix::process::set_parent_process_death_signal(Some(
        rustix::process::Signal::KILL,
    ))?)
}

fn require_scope(scope: &str) -> Result<(), Refused> {
    let suffix = format!("/{scope}.scope");
    Proc::this()
        .cgroup_is(|path| path.ends_with(&suffix))
        .map_err(|_| Refused::WrongScope)
}

fn open_pipe(path: &Path, access: OFlags) -> Result<OwnedFd, Refused> {
    Ok(rustix::fs::open(
        path,
        access | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

fn nft(args: &[&str], input: Option<&str>) -> Result<String, Refused> {
    let mut child = Command::new(NFT)
        .args(args)
        .env_clear()
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(text.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(Refused::NetworkSetup);
    }
    String::from_utf8(out.stdout).map_err(|_| Refused::NetworkSetup)
}

fn exec(next: &[OsString]) -> Result<Infallible, Refused> {
    let (program, args) = next.split_first().ok_or(Refused::Malformed)?;
    Err(Command::new(program).args(args).exec().into())
}

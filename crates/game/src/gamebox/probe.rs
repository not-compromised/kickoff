//! The synthetic payload that stands in for the game: a fixed set of
//! behaviours, chosen by name, that test what the box allows.

use std::convert::Infallible;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use nix::sys::signal::{SigSet, Signal};

use super::Refused;
use super::view::WITNESS;

pub fn probe_main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("core-canary") {
        return super::core::canary(std::env::args().nth(2).as_deref());
    }
    // The payload-entry witness: present only where a test bound one.
    let _ = std::fs::write(format!("{WITNESS}/entered"), b"");
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("network") => return network(args.get(1..).unwrap_or_default()),
        Some("files") => return files(),
        Some("display") => return display(),
        Some("lans") => return lans(),
        Some("limits") => return limits(),
        Some("eat") => return eat(),
        _ => {}
    }
    let arg = args.first();
    let result = match arg.map(String::as_str) {
        Some("hold") => hold().map(|never| match never {}),
        Some("inventory") => inventory().map(|never| match never {}),
        Some("hold-mid") => hold_mid(),
        Some("hold-leaf") => sleep_ignoring_sigterm().map(|never| match never {}),
        _ => Err(Refused::Malformed),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(refused) => ExitCode::from(refused.code()),
    }
}

/// Private, special and host destinations the ruleset must drop. A UDP
/// send that the output chain drops fails at once with EPERM, so the answer
/// needs no timeout and no listener; any other outcome means the datagram
/// left the box toward that destination.
const FORBIDDEN: [([u8; 4], u16); 9] = [
    ([192, 0, 2, 1], 9),
    ([10, 0, 0, 1], 9),
    ([100, 64, 0, 1], 9),
    ([169, 254, 169, 254], 80),
    ([172, 16, 0, 1], 9),
    ([192, 168, 0, 1], 9),
    ([198, 18, 0, 1], 9),
    ([224, 0, 0, 251], 5353),
    ([240, 0, 0, 1], 9),
];
const RESOLVERS: [[u8; 4]; 2] = [[1, 1, 1, 1], [9, 9, 9, 9]];

/// SI-14 from inside the box. Exit 0 only if every forbidden destination
/// (the fixed list, then each host address given as an argument) is
/// dropped, a public resolver answers, and the box cannot change its
/// link, routes or ruleset. Otherwise 20 plus the destination's index, 40
/// for no internet, 41 to 43 for a change not refused with EPERM, or 44 if
/// a control failed.
fn network(hosts: &[String]) -> ExitCode {
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    let mut forbidden: Vec<SocketAddr> = FORBIDDEN
        .iter()
        .map(|(a, port)| SocketAddr::from((Ipv4Addr::from(*a), *port)))
        .collect();
    for host in hosts {
        match host.parse::<Ipv4Addr>() {
            Ok(addr) => forbidden.push(SocketAddr::from((addr, 9))),
            Err(_) => return ExitCode::from(Refused::Malformed.code()),
        }
    }
    for (index, dest) in forbidden.iter().enumerate() {
        let dropped = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .and_then(|socket| socket.send_to(b"kickoff probe", dest))
            .is_err_and(|e| e.raw_os_error() == Some(nix::errno::Errno::EPERM as i32));
        if !dropped {
            return ExitCode::from(u8::try_from(index).map_or(39, |i| i.saturating_add(20)));
        }
    }
    if !RESOLVERS.iter().any(|r| resolves(Ipv4Addr::from(*r))) {
        return ExitCode::from(40);
    }
    let refused = network_changes();
    for (code, refused) in (41u8..).zip(refused) {
        if !refused {
            return ExitCode::from(code);
        }
    }
    ExitCode::SUCCESS
}

/// Asks the kernel directly, over netlink, to take the loopback down, add a
/// route and add an nft table, and requires each to be refused with EPERM
/// (the box has no capability over its network namespace). Then two
/// controls: a netlink dump works from here, and a request the kernel does
/// not know is refused with something other than EPERM, so EPERM is the
/// answer to these requests and not to every request.
fn network_changes() -> [bool; 4] {
    use super::netlink::{answer, host_view, request};
    const REQUEST_ACK: u16 = 0x1 | 0x4;
    const CREATE_EXCL: u16 = 0x400 | 0x200;
    let eperm = nix::errno::Errno::EPERM as i32;
    let mut link_down = vec![0u8, 0, 0, 0];
    link_down.extend_from_slice(&1i32.to_ne_bytes()); // lo
    link_down.extend_from_slice(&0u32.to_ne_bytes()); // flags
    link_down.extend_from_slice(&1u32.to_ne_bytes()); // change IFF_UP
    let mut route_add = vec![2u8, 24, 0, 0, 254, 4, 253, 1];
    route_add.extend_from_slice(&0u32.to_ne_bytes());
    route_add.extend_from_slice(&8u16.to_ne_bytes());
    route_add.extend_from_slice(&1u16.to_ne_bytes()); // RTA_DST
    route_add.extend_from_slice(&[203, 0, 113, 0]);
    route_add.extend_from_slice(&8u16.to_ne_bytes());
    route_add.extend_from_slice(&4u16.to_ne_bytes()); // RTA_OIF
    route_add.extend_from_slice(&1u32.to_ne_bytes());
    let nft_table = [1u8, 0, 0, 0]; // nfgenmsg: NFPROTO_INET
    let netfilter = Some(rustix::net::netlink::NETFILTER);
    let refused = |protocol, kind, flags, body: &[u8]| {
        request(kind, flags, body)
            .and_then(|m| answer(protocol, &m))
            .is_ok_and(|errno| errno == eperm)
    };
    let controls = host_view().is_ok_and(|v| !v.routes.is_empty())
        && request(0x7ff0, REQUEST_ACK, &[0; 16])
            .and_then(|m| answer(None, &m))
            .is_ok_and(|errno| errno != 0 && errno != eperm);
    [
        refused(None, 16, REQUEST_ACK, &link_down),
        refused(None, 24, REQUEST_ACK | CREATE_EXCL, &route_add),
        refused(netfilter, 10 << 8, REQUEST_ACK, &nft_table),
        controls,
    ]
}

/// One DNS query for the root's NS records gets an answer with its id.
fn resolves(resolver: std::net::Ipv4Addr) -> bool {
    let query = [
        0x4b, 0x4f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x01,
    ];
    let Ok(socket) = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)) else {
        return false;
    };
    if socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .is_err()
        || socket.connect((resolver, 53)).is_err()
    {
        return false;
    }
    let mut reply = [0u8; 512];
    (0..3).any(|_| {
        socket.send(&query).is_ok()
            && socket
                .recv(&mut reply)
                .is_ok_and(|n| n >= 2 && reply.get(..2) == Some(&query[..2]))
    })
}

/// Globally addressed LANs the SI-14 tests put on the supervisor's host,
/// one per kind of route: a connected subnet and a gateway route in the
/// main table, and a subnet in a policy table. Exit 0 only if each is
/// dropped (EPERM) while a public destination is not; otherwise 70 plus
/// the index, or 73 if the public destination was dropped too.
fn lans() -> ExitCode {
    use std::net::{Ipv4Addr, UdpSocket};
    let send = |addr: [u8; 4]| {
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .and_then(|socket| socket.send_to(b"kickoff probe", (Ipv4Addr::from(addr), 9)))
    };
    let lans = [[203, 0, 113, 7], [192, 88, 99, 7], [198, 51, 100, 7]];
    for (code, lan) in (70u8..).zip(lans) {
        let dropped =
            send(lan).is_err_and(|e| e.raw_os_error() == Some(nix::errno::Errno::EPERM as i32));
        if !dropped {
            return ExitCode::from(code);
        }
    }
    if send([1, 1, 1, 1]).is_err() {
        return ExitCode::from(73);
    }
    ExitCode::SUCCESS
}

/// SI-38's limits, enforced rather than configured, under the probe's
/// small limits (16 MiB prefix, 64 tasks, 64 MiB): filling the prefix in
/// 1 MiB files stops with ENOSPC within its size; forking stops with EAGAIN
/// below the task limit; and a child that keeps allocating is killed by the
/// kernel. Every loop is bounded, so a missing limit fails the probe instead
/// of loading the machine. Exit 0, or 80 to 82 for the failed check.
fn limits() -> ExitCode {
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;
    let chunk = vec![0x4bu8; 1 << 20];
    let mut written = 0u64;
    let mut stopped = false;
    for n in 0..64 {
        let file = std::fs::File::create(format!("/kickoff/prefix/fill-{n}"));
        let result = file.and_then(|mut f| f.write_all(&chunk).and_then(|()| f.sync_all()));
        match result {
            Ok(()) => written = written.saturating_add(1 << 20),
            Err(e) => {
                stopped = e.raw_os_error() == Some(nix::errno::Errno::ENOSPC as i32);
                break;
            }
        }
    }
    if !stopped || written > 16 << 20 {
        return ExitCode::from(80);
    }

    let mut children = Vec::new();
    let mut refused = false;
    for _ in 0..80 {
        match respawn("hold-leaf") {
            Ok(child) => children.push(child),
            Err(Refused::Io(std::io::ErrorKind::WouldBlock)) => {
                refused = true;
                break;
            }
            Err(_) => break,
        }
    }
    let forked = children.len();
    for mut child in children {
        let _ = child.kill();
        let _ = child.wait();
    }
    if !refused || forked >= 64 {
        return ExitCode::from(81);
    }

    let killed = respawn("eat")
        .and_then(|mut child| Ok(child.wait()?))
        .is_ok_and(|status| status.signal() == Some(9));
    if !killed {
        return ExitCode::from(82);
    }
    ExitCode::SUCCESS
}

/// Allocates and touches up to 256 MiB, 1 MiB at a time; returns only if
/// nothing stopped it.
fn eat() -> ExitCode {
    // Select the deliberate allocator as the OOM victim instead of pasta.
    if std::fs::write("/proc/self/oom_score_adj", b"1000").is_err() {
        return ExitCode::from(82);
    }
    let mut held: Vec<Vec<u8>> = Vec::new();
    for _ in 0..256 {
        held.push(std::hint::black_box(vec![0x4b; 1 << 20]));
    }
    ExitCode::from(u8::try_from(held.len() % 2).unwrap_or(0))
}

/// SI-34 from inside the box. Exit 0 only if every write, truncate, rename,
/// delete and create in the game copy fails, the copy is readable, the
/// prefix is writable, and no launcher or Kickoff state of the host is
/// visible. Otherwise 60 plus the failed check's index.
fn files() -> ExitCode {
    use std::fs::OpenOptions;
    let canary = "/kickoff/game/canary";
    let home = std::env::var("HOME").unwrap_or_default();
    let refused: [bool; 5] = [
        OpenOptions::new().append(true).open(canary).is_err(),
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(canary)
            .is_err(),
        std::fs::rename(canary, "/kickoff/game/renamed").is_err(),
        std::fs::remove_file(canary).is_err(),
        std::fs::write("/kickoff/game/created", b"x").is_err(),
    ];
    let controls = [
        std::fs::read(canary).is_ok_and(|b| !b.is_empty()),
        std::fs::write("/kickoff/prefix/written", b"x").is_ok(),
    ];
    let absent = [
        ".config/legendary",
        ".config/heroic",
        ".var/app",
        ".local/share/kickoff",
        ".ssh",
    ]
    .map(|p| {
        std::fs::symlink_metadata(std::path::Path::new(&home).join(p))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    });
    first_failure(60, refused.iter().chain(&controls).chain(&absent))
}

/// The direct half of SI-35 from inside the box: no host X11, Wayland or
/// bus socket exists in its view, and the host's abstract X11 sockets are
/// unreachable (the box has its own network namespace, so its own abstract
/// namespace). Paths are only looked at, never connected to. Exit 0, or 50
/// plus the failed check's index.
fn display() -> ExitCode {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
    let empty_or_absent = |dir: &str| match std::fs::read_dir(dir) {
        Ok(mut entries) => entries.next().is_none(),
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    };
    let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
    let abstract_unreachable = (0..10).all(|n| {
        SocketAddr::from_abstract_name(format!("/tmp/.X11-unix/X{n}"))
            .and_then(|addr| UnixStream::connect_addr(&addr))
            .is_err()
    });
    // Positive control: the same connect reaches a listener of the box's own.
    let control = SocketAddr::from_abstract_name("kickoff-probe-control")
        .and_then(|addr| UnixListener::bind_addr(&addr).map(|l| (l, addr)))
        .and_then(|(listener, addr)| UnixStream::connect_addr(&addr).map(|s| (listener, s)))
        .is_ok();
    let checks = [
        empty_or_absent("/tmp/.X11-unix"),
        empty_or_absent(&runtime),
        std::fs::symlink_metadata("/run/dbus/system_bus_socket").is_err(),
        abstract_unreachable,
        control,
    ];
    first_failure(50, checks.iter())
}

fn first_failure<'a>(base: u8, checks: impl Iterator<Item = &'a bool>) -> ExitCode {
    for (offset, ok) in (0u8..).zip(checks) {
        if !*ok {
            return ExitCode::from(base.saturating_add(offset));
        }
    }
    ExitCode::SUCCESS
}

/// The game's descriptor inventory (SI-36): first it writes to every
/// descriptor above stdio, as a compromised game would; then it holds only
/// if stdio is all it has. A leaked descriptor exits with
/// [`Refused::Leaked`].
fn inventory() -> Result<Infallible, Refused> {
    use std::os::unix::fs::MetadataExt;
    let open = kickoff_local::fds::open_descriptors()?;
    for fd in open.iter().filter(|fd| **fd > 2) {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .append(true)
            .open(format!("/proc/self/fd/{fd}"))
        {
            let _ = std::io::Write::write_all(&mut file, b"written from inside the box\n");
        }
    }
    let null = std::fs::metadata("/dev/null")?;
    let clean = open == [0, 1, 2]
        && open.iter().all(|fd| {
            std::fs::metadata(format!("/proc/self/fd/{fd}"))
                .is_ok_and(|m| (m.dev(), m.ino()) == (null.dev(), null.ino()))
        });
    if !clean {
        return Err(Refused::Leaked);
    }
    sleep_ignoring_sigterm()
}

/// A leader that ignores SIGTERM, with a double-forked descendant in its own
/// session that also ignores it and arms no parent-death signal: only the
/// cgroup kill, or a SIGKILL from the manager, ends both.
fn hold() -> Result<Infallible, Refused> {
    let status = respawn("hold-mid")?.wait()?;
    if !status.success() {
        return Err(Refused::Io(std::io::ErrorKind::Other));
    }
    sleep_ignoring_sigterm()
}

fn hold_mid() -> Result<(), Refused> {
    rustix::process::setsid()?;
    respawn("hold-leaf")?;
    Ok(())
}

fn respawn(stage: &str) -> Result<std::process::Child, Refused> {
    Ok(Command::new("/proc/self/exe")
        .arg(stage)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

/// Holds forever; the process name `holding` tells an observer that the
/// probe's own checks are done and its descriptors are settled.
fn sleep_ignoring_sigterm() -> Result<Infallible, Refused> {
    let mut term = SigSet::empty();
    term.add(Signal::SIGTERM);
    term.thread_block()?;
    rustix::thread::set_name(c"holding")?;
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

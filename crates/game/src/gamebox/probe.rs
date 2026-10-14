//! The synthetic payload that stands in for the game: a fixed set of
//! behaviours, chosen by name, that test what the box allows.

use std::convert::Infallible;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use nix::sys::signal::{SigSet, Signal};

use super::Refused;

pub fn probe_main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("network") {
        return network(args.get(1..).unwrap_or_default());
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
/// for no internet, or 41 to 43 for a change that went through.
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
    let changes: [&[&str]; 3] = [
        &["/usr/bin/ip", "link", "set", "lo", "down"],
        &["/usr/bin/ip", "route", "add", "203.0.113.0/24", "dev", "lo"],
        &["/usr/bin/nft", "flush", "ruleset"],
    ];
    for (code, change) in (41u8..).zip(changes) {
        let Some((program, args)) = change.split_first() else {
            continue;
        };
        let applied = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if applied {
            return ExitCode::from(code);
        }
    }
    ExitCode::SUCCESS
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

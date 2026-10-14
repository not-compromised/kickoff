//! The synthetic payload that stands in for the game: a fixed set of
//! behaviours, chosen by name, that test what the box allows.

use std::convert::Infallible;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use nix::sys::signal::{SigSet, Signal};

use super::Refused;

pub fn probe_main() -> ExitCode {
    let arg = std::env::args().nth(1);
    let result = match arg.as_deref() {
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

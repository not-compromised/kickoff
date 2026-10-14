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
        Some("hold-mid") => hold_mid(),
        Some("hold-leaf") => sleep_ignoring_sigterm().map(|never| match never {}),
        _ => Err(Refused::Malformed),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(refused) => ExitCode::from(refused.code()),
    }
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

fn sleep_ignoring_sigterm() -> Result<Infallible, Refused> {
    let mut term = SigSet::empty();
    term.add(Signal::SIGTERM);
    term.thread_block()?;
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

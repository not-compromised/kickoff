//! kickoff-gamebox: creates the game scope, starts the chain inside it and
//! owns its teardown (design §2.1, §3.2.6).

use std::ffi::OsString;
use std::io::Write;
use std::process::{Child, ExitCode, ExitStatus, Stdio};

use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::SignalFd;

use super::Refused;
use super::install::{LINK, PROBE, sibling};
use super::scope::{self, Owner, Scope, TEARDOWN_DEADLINE};

/// What the supervisor was asked to run. Until kickoffd's channel exists
/// (design §2.7) the only requests are Kickoff's own containment probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Request {
    /// The scope alone with a stand-in that ignores SIGTERM and has a
    /// double-forked descendant: each teardown path is tested without the
    /// box's own fast paths (design §3.2.6, SI-38).
    StandIn,
}

impl Request {
    fn parse(args: &[OsString]) -> Result<Request, Refused> {
        match args {
            [probe, kind] if probe == "probe" && kind == "standin" => Ok(Request::StandIn),
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
    kickoff_local::fds::close_descriptors_above_stdio()?;
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
    match request {
        Request::StandIn => chain.arg(&probe).arg("hold"),
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
    let end = wait(&signals, &mut child);
    let torn = teardown(&scope, &mut child);
    let end = end?;
    torn?;
    Ok(end)
}

fn wait(signals: &SignalFd, child: &mut Child) -> Result<End, Refused> {
    loop {
        let Some(info) = signals.read_signal()? else {
            continue;
        };
        let signal = i32::try_from(info.ssi_signo)
            .ok()
            .and_then(|n| Signal::try_from(n).ok());
        match signal {
            Some(Signal::SIGTERM) => return Ok(End::Stopped),
            Some(Signal::SIGCHLD) => {
                if let Some(status) = child.try_wait()? {
                    return Ok(End::Exited(status));
                }
            }
            _ => {}
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

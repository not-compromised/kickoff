//! The trusted links of the chain. Each sweeps its descriptors, arms its
//! parent-death signal and checks that its parent is still the one it
//! expects before it execs the next link (design §3.2.6).

use std::convert::Infallible;
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

use super::Refused;
use super::install::require_null_stdio;

pub fn link_main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&args) {
        Ok(never) => match never {},
        Err(refused) => ExitCode::from(refused.code()),
    }
}

fn run(args: &[OsString]) -> Result<Infallible, Refused> {
    kickoff_local::fds::close_descriptors_above_stdio()?;
    require_null_stdio()?;
    match args {
        [stage, parent, scope, dashes, next @ ..] if stage == "enter" && dashes == "--" => {
            arm_parent_death(parent)?;
            require_scope(scope.to_str().ok_or(Refused::Malformed)?)?;
            exec(next)
        }
        _ => Err(Refused::Malformed),
    }
}

/// Parent-death signals are a fast path only: they never fire for a parent
/// that is already dead, so the parent is checked after arming.
fn arm_parent_death(parent: &OsString) -> Result<(), Refused> {
    let parent: i32 = parent
        .to_str()
        .and_then(|p| p.parse().ok())
        .ok_or(Refused::Malformed)?;
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))?;
    let current = rustix::process::getppid().map(rustix::process::Pid::as_raw_pid);
    if current != Some(parent) {
        return Err(Refused::ParentGone);
    }
    Ok(())
}

fn require_scope(scope: &str) -> Result<(), Refused> {
    let text = std::fs::read_to_string("/proc/self/cgroup")?;
    let suffix = format!("/{scope}.scope");
    let mut paths = text.lines().filter_map(|l| l.strip_prefix("0::"));
    match (paths.next(), paths.next()) {
        (Some(path), None) if path.ends_with(&suffix) => Ok(()),
        _ => Err(Refused::WrongScope),
    }
}

fn exec(next: &[OsString]) -> Result<Infallible, Refused> {
    let (program, args) = next.split_first().ok_or(Refused::Malformed)?;
    Err(Command::new(program).args(args).exec().into())
}

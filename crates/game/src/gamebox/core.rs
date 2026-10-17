//! Core suppression that survives exec. Inspectable links keep dumpable=1;
//! an inherited hard limit prevents the payload from lifting suppression.

use super::Refused;
use rustix::process::{Resource, Rlimit};
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

const SCRATCH: &str = "/tmp/kickoff-core-probe";
const READY: &str = "/tmp/kickoff-core-probe/ready";

fn select(pattern: Option<&[u8]>, hard: Option<u64>) -> Result<u64, Refused> {
    if cfg!(feature = "mutant-si30-game-handler-unchecked") {
        return Ok(hard.map_or(1, |h| h.min(1)));
    }
    match pattern.and_then(|p| p.first()) {
        None | Some(b'@') => Err(Refused::CoreDumps),
        Some(b'|') if hard == Some(0) => Err(Refused::CoreDumps),
        _ => Ok(hard.map_or(1, |h| h.min(1))),
    }
}

/// First application action in each trusted entry point. No host setting changes.
pub(super) fn enter() -> Result<(), Refused> {
    let limit = select(
        std::fs::read("/proc/sys/kernel/core_pattern")
            .ok()
            .as_deref(),
        rustix::process::getrlimit(Resource::Core).maximum,
    )?;
    rustix::process::setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(limit),
            maximum: Some(limit),
        },
    )?;
    Ok(())
}

pub(super) fn limit() -> Result<u64, Refused> {
    let limits = rustix::process::getrlimit(Resource::Core);
    match (limits.current, limits.maximum) {
        (Some(a), Some(b)) if a == b && a <= 1 => Ok(a),
        _ => Err(Refused::CoreDumps),
    }
}

/// Runs after bwrap exec, before the launch barrier releases any payload.
pub(super) fn verify() -> Result<(), Refused> {
    let expected = limit()?;
    std::fs::DirBuilder::new().mode(0o700).create(SCRATCH)?;
    let result = (|| {
        let mut probe = kickoff_local::spawn::spawn_clean(
            Path::new("/kickoff/bin/kickoff-box-probe"),
            &["core-canary".into(), expected.to_string().into()],
            &[],
            None,
            true,
        )?;
        let started = Instant::now();
        let status = loop {
            if let Some(status) = probe.try_exit()? {
                break status;
            }
            if started.elapsed() >= Duration::from_secs(3) {
                return Err(Refused::CoreDumps);
            }
            std::thread::sleep(super::events::POLL);
        };
        if status.terminating_signal() != Some(6)
            || status.as_raw() & 0x80 != 0
            || std::fs::read(READY)? != b"checked-before-abort"
        {
            return Err(Refused::CoreDumps);
        }
        std::fs::remove_file(READY)?;
        if std::fs::read_dir(SCRATCH)?.next().is_some() {
            return Err(Refused::CoreDumps);
        }
        #[cfg(debug_assertions)]
        if Path::new(super::view::WITNESS).is_dir() {
            std::fs::write(
                Path::new(super::view::WITNESS).join("core-verified"),
                b"SIGABRT-no-core",
            )?;
        }
        Ok(())
    })();
    // A failed crash leaves only a private, disposable probe directory in
    // the box's tmpfs; the entire scope is torn down on refusal.
    if result.is_ok() {
        std::fs::remove_dir(SCRATCH)?;
    }
    result
}

/// Deliberately does not repair inherited state: that is what this exec tests.
pub(super) fn canary(expected: Option<&str>) -> ExitCode {
    let expected = match expected {
        Some("0") => 0,
        Some("1") => 1,
        _ => return ExitCode::FAILURE,
    };
    let canary = format!("synthetic-core-secret-{}", std::process::id()).into_bytes();
    let valid = (|| -> Result<(), Refused> {
        std::env::set_current_dir(SCRATCH)?;
        if limit()? != expected
            || rustix::process::dumpable_behavior()? != rustix::process::DumpableBehavior::Dumpable
            || std::env::vars_os().next().is_some()
            || std::env::current_dir()? != Path::new(SCRATCH)
        {
            return Err(Refused::CoreDumps);
        }
        super::install::require_null_stdio()?;
        if kickoff_local::fds::open_descriptors()?
            .iter()
            .any(|fd| *fd > 2)
        {
            return Err(Refused::CoreDumps);
        }
        rustix::thread::set_name(c"kickoff-core")?;
        std::hint::black_box(&canary);
        std::fs::write(READY, b"checked-before-abort")?;
        #[cfg(debug_assertions)]
        if Path::new(super::view::WITNESS).is_dir() {
            std::fs::write(
                Path::new(super::view::WITNESS).join("core-canary"),
                b"checked-before-abort",
            )?;
        }
        Ok(())
    })();
    if valid.is_err() || cfg!(feature = "mutant-si30-core-canary-no-crash") {
        return ExitCode::FAILURE;
    }
    std::hint::black_box(&canary);
    std::process::abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn si_30_exec_core_policy_refuses_unsupported_handlers_before_crashing() {
        for (pattern, hard, expected) in [
            (None, None, Err(Refused::CoreDumps)),
            (Some(&b""[..]), None, Err(Refused::CoreDumps)),
            (Some(&b"@handler"[..]), None, Err(Refused::CoreDumps)),
            (Some(&b"|handler"[..]), Some(0), Err(Refused::CoreDumps)),
            (Some(&b"|handler"[..]), None, Ok(1)),
            (Some(&b"core"[..]), Some(0), Ok(0)),
            (Some(&b"/var/core"[..]), None, Ok(1)),
        ] {
            assert_eq!(select(pattern, hard), expected);
        }
    }
}

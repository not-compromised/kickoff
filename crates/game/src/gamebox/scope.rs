//! The game scope (design §3.2.6): a transient systemd user scope that is
//! the box's cgroup, bound to the supervisor's service so the user manager
//! ends it however the supervisor dies.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::process::Command;
use std::time::{Duration, Instant};

use rustix::fs::{Mode, OFlags};

use super::Refused;

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// Design §3.2.6: on either teardown path the cgroup is empty within 2 s.
pub(super) const TEARDOWN_DEADLINE: Duration = Duration::from_secs(2);
pub(super) const REGISTRATION_DEADLINE: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(5);

/// Limits of design §3.2.2 step 1, carried by the scope.
const LIMITS: [&str; 4] = [
    "MemoryMax=12G",
    "MemorySwapMax=0",
    "TasksMax=512",
    "CPUWeight=100",
];

/// The supervisor's own service unit, read from the kernel's view of its
/// cgroup rather than from anything it was told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Owner(String);

impl Owner {
    pub(super) fn current() -> Result<Owner, Refused> {
        let text = std::fs::read_to_string("/proc/self/cgroup")?;
        Owner::from_cgroup(&text, rustix::process::geteuid().as_raw())
    }

    fn from_cgroup(text: &str, uid: u32) -> Result<Owner, Refused> {
        let mut lines = text.lines().filter_map(|l| l.strip_prefix("0::"));
        let (Some(path), None) = (lines.next(), lines.next()) else {
            return Err(Refused::NotAService);
        };
        let manager = format!("user@{uid}.service");
        let below: Vec<&str> = path
            .split('/')
            .skip_while(|p| *p != manager)
            .skip(1)
            .collect();
        let (unit, slices) = below.split_last().ok_or(Refused::NotAService)?;
        let valid = unit.strip_suffix(".service").is_some_and(|stem| {
            !stem.is_empty()
                && stem
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:@".contains(&b))
        });
        if !valid || slices.iter().any(|p| !p.ends_with(".slice")) {
            return Err(Refused::NotAService);
        }
        Ok(Owner((*unit).to_owned()))
    }

    /// The one name a box of this supervisor gets. A scope left over from a
    /// failed teardown keeps the name taken, so the next launch refuses.
    pub(super) fn scope_name(&self) -> String {
        let stem = self.0.strip_suffix(".service").unwrap_or(&self.0);
        format!("{stem}-game")
    }
}

/// `systemd-run` arguments that create the scope, ending in `--`: the
/// command after them runs inside the scope once it is registered.
pub(super) fn create_args(owner: &Owner, scope: &str) -> Vec<OsString> {
    let mut args: Vec<String> = vec![
        "--user".into(),
        "--scope".into(),
        "--quiet".into(),
        "--collect".into(),
        format!("--unit={scope}"),
    ];
    if !cfg!(feature = "mutant-si38-no-bindsto") {
        args.extend([
            format!("--property=BindsTo={}", owner.0),
            format!("--property=After={}", owner.0),
        ]);
    }
    args.push("--property=KillMode=control-group".into());
    if !cfg!(feature = "mutant-si38-sigterm-stop") {
        args.push("--property=KillSignal=SIGKILL".into());
    }
    args.push("--property=SendSIGKILL=yes".into());
    if !cfg!(feature = "mutant-si38-no-limits") {
        args.extend(LIMITS.iter().map(|l| format!("--property={l}")));
    }
    args.push("--".into());
    args.into_iter().map(OsString::from).collect()
}

pub(super) fn create_command() -> Command {
    Command::new(SYSTEMD_RUN)
}

/// A registered game scope, held by its cgroup directory.
pub(super) struct Scope {
    name: String,
    dir: OwnedFd,
}

impl Scope {
    /// Opens `name`'s cgroup once `launcher` (the `systemd-run` child) is in
    /// it; `None` until then. `systemd-run --scope` moves itself in before it
    /// execs the first link, so nothing runs outside it.
    pub(super) fn try_open(name: &str, launcher: u32) -> Result<Option<Scope>, Refused> {
        let uid = rustix::process::geteuid().as_raw();
        let suffix = format!("/{name}.scope");
        let text = std::fs::read_to_string(format!("/proc/{launcher}/cgroup"))?;
        let Some(path) = text
            .lines()
            .filter_map(|l| l.strip_prefix("0::"))
            .find(|p| p.ends_with(&suffix))
        else {
            return Ok(None);
        };
        if !path.contains(&format!("/user@{uid}.service/")) || path.contains("/../") {
            return Err(Refused::Scope);
        }
        let dir = rustix::fs::open(
            format!("/sys/fs/cgroup{path}"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Some(Scope {
            name: name.to_owned(),
            dir,
        }))
    }

    /// Kills every process in the scope in one kernel operation.
    pub(super) fn kill(&self) -> Result<(), Refused> {
        let file = rustix::fs::openat(
            &self.dir,
            "cgroup.kill",
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        );
        match file {
            Ok(file) => Ok(std::fs::File::from(file).write_all(b"1")?),
            // A removed cgroup was empty: the kernel refuses rmdir otherwise.
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::NODEV) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn populated(&self) -> Result<bool, Refused> {
        let file = rustix::fs::openat(
            &self.dir,
            "cgroup.events",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let file = match file {
            Ok(file) => file,
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::NODEV) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let mut text = String::new();
        std::fs::File::from(file)
            .take(4096)
            .read_to_string(&mut text)?;
        match text.lines().find_map(|l| l.strip_prefix("populated ")) {
            Some("0") => Ok(false),
            Some("1") => Ok(true),
            _ => Err(Refused::Scope),
        }
    }

    /// Every process in the scope now.
    pub(super) fn procs(&self) -> Result<Vec<i32>, Refused> {
        let file = rustix::fs::openat(
            &self.dir,
            "cgroup.procs",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let mut text = String::new();
        std::fs::File::from(file).read_to_string(&mut text)?;
        text.lines()
            .map(|l| l.parse().map_err(|_| Refused::Scope))
            .collect()
    }

    pub(super) fn wait_empty(&self, deadline: Duration) -> Result<(), Refused> {
        let started = Instant::now();
        while self.populated()? {
            if started.elapsed() > deadline {
                return Err(Refused::Teardown);
            }
            std::thread::sleep(POLL);
        }
        Ok(())
    }

    /// Asks the manager to stop the scope. After a direct kill it is empty
    /// and may already be collected, which systemctl reports as not loaded.
    pub(super) fn stop(&self) -> Result<(), Refused> {
        stop_named(&self.name)
    }
}

/// The manager's stop of a scope by name, within the teardown deadline; for
/// a scope that may have registered unseen, too. Its `KillSignal=SIGKILL`
/// ends whatever is in it.
pub(super) fn stop_named(name: &str) -> Result<(), Refused> {
    let status = super::events::bounded(
        Command::new(SYSTEMCTL)
            .args(["--user", "stop", "--"])
            .arg(format!("{name}.scope")),
        TEARDOWN_DEADLINE,
    )?;
    match status.code() {
        Some(0 | 5) => Ok(()),
        _ => Err(Refused::Scope),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_is_the_service_cgroup_under_this_users_manager() {
        let ok =
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/kickoff-gamebox.service\n";
        let owner = Owner::from_cgroup(ok, 1000).unwrap();
        assert_eq!(owner.scope_name(), "kickoff-gamebox-game");
        for bad in [
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope\n",
            "0::/user.slice/user-1000.slice/user@1001.service/app.slice/x.service\n",
            "0::/system.slice/x.service\n",
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.service/sub\n",
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/x y.service\n",
            "",
        ] {
            assert_eq!(
                Owner::from_cgroup(bad, 1000),
                Err(Refused::NotAService),
                "{bad}"
            );
        }
    }
}

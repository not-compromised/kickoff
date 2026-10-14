//! The final launch barrier (design §3.2.6). The last trusted link checks
//! itself from inside the box and the supervisor checks it from outside
//! through `/proc/<pid>`; the payload execs only after both agree.

use std::fmt;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{AtFlags, Mode, OFlags};

use super::Refused;

/// One barrier property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Namespaces,
    Nft,
    Cgroup,
    Rlimits,
    Capabilities,
    NoNewPrivs,
    Descriptors,
    PrefixSize,
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Check::Namespaces => "namespaces",
            Check::Nft => "nft ruleset",
            Check::Cgroup => "cgroup",
            Check::Rlimits => "rlimits",
            Check::Capabilities => "capability sets",
            Check::NoNewPrivs => "no_new_privs",
            Check::Descriptors => "descriptor inventory",
            Check::PrefixSize => "prefix size",
        })
    }
}

/// A setup fault the launch must refuse: each leaves exactly one barrier
/// property or startup-probe fact wrong. Kickoff's own probes inject them
/// to prove the refusal (SI-36, SI-14); `None` is every real launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fault {
    None,
    /// The box shares the setup link's IPC namespace.
    Namespaces,
    /// A rule is added after the ruleset was verified at load.
    Nft,
    /// The descriptor limit is left at the host's.
    Rlimits,
    /// The box runs as root of its user namespace with every capability.
    Capabilities,
    /// The barrier link keeps one of its pipe descriptors.
    Descriptors,
    /// pasta keeps its default mapping of the gateway to the host's
    /// loopback, which the setup link's startup probe must notice.
    PastaMapsHost,
    /// The prefix's writable layer is left unsized.
    PrefixUnsized,
    /// The setup link moves into a child cgroup of the scope, so the barrier
    /// link is not directly in the game scope.
    Cgroup,
    /// The box shares the setup link's cgroup namespace and sees the host's
    /// cgroup path.
    CgroupNamespace,
    /// pasta forwards the box's loopback ports to the host's (`-T`, `-U`).
    PastaForwardsLoopback,
    /// pasta forwards a host port into the box (`-t`, `-u`).
    PastaForwardsInbound,
}

impl Fault {
    pub(super) const ALL: [(&'static str, Fault); 12] = [
        ("none", Fault::None),
        ("namespaces", Fault::Namespaces),
        ("nft", Fault::Nft),
        ("rlimits", Fault::Rlimits),
        ("capabilities", Fault::Capabilities),
        ("descriptors", Fault::Descriptors),
        ("pasta-maps-host", Fault::PastaMapsHost),
        ("prefix-unsized", Fault::PrefixUnsized),
        ("cgroup", Fault::Cgroup),
        ("cgroup-namespace", Fault::CgroupNamespace),
        ("pasta-forwards-loopback", Fault::PastaForwardsLoopback),
        ("pasta-forwards-inbound", Fault::PastaForwardsInbound),
    ];

    pub(super) fn parse(name: &str) -> Result<Fault, Refused> {
        Fault::ALL
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, f)| *f)
            .ok_or(Refused::Malformed)
    }

    pub(super) fn name(self) -> &'static str {
        Fault::ALL
            .iter()
            .find(|(_, f)| *f == self)
            .map_or("none", |(n, _)| n)
    }
}

/// Which sides of the barrier check. Every launch checks both; debug builds
/// let a test disable one (`KICKOFF_TEST_BARRIER=inside|outside` keeps
/// only that side), to show each side refuses alone (SI-36).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Sides {
    Both,
    Inside,
    Outside,
}

impl Sides {
    pub(super) fn requested() -> Sides {
        if !cfg!(debug_assertions) {
            return Sides::Both;
        }
        match std::env::var("KICKOFF_TEST_BARRIER").as_deref() {
            Ok("inside") => Sides::Inside,
            Ok("outside") => Sides::Outside,
            _ => Sides::Both,
        }
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Sides::Both => "both",
            Sides::Inside => "inside",
            Sides::Outside => "outside",
        }
    }

    /// Release builds accept only both sides.
    pub(super) fn parse(name: &str) -> Result<Sides, Refused> {
        match name {
            "both" => Ok(Sides::Both),
            "inside" if cfg!(debug_assertions) => Ok(Sides::Inside),
            "outside" if cfg!(debug_assertions) => Ok(Sides::Outside),
            _ => Err(Refused::Malformed),
        }
    }

    pub(super) fn inside(self) -> bool {
        self != Sides::Outside && !cfg!(feature = "mutant-si36-inside-barrier-skip")
    }

    pub(super) fn outside(self) -> bool {
        self != Sides::Inside && !cfg!(feature = "mutant-si36-outside-barrier-skip")
    }
}

/// The prefix as the box sees it.
pub(super) const PREFIX: &str = "/kickoff/prefix";

/// The namespaces the box must not share with the host, in argv order.
pub(super) const NAMESPACES: [&str; 5] = ["user", "net", "mnt", "pid", "ipc"];

pub(super) const RLIMITS: [(&str, &str); 3] = [
    ("Max core file size", "0"),
    ("Max file size", "4294967296"),
    ("Max open files", "8192"),
];
pub(super) const FSIZE: u64 = 4 << 30;
pub(super) const NOFILE: u64 = 8192;

/// A process's `/proc` directory. Another process is pinned: its
/// directory is opened once and every read goes through that descriptor,
/// with a pidfd to confirm it still runs, so a recycled PID can never mix
/// two processes' answers.
pub(super) struct Proc(Base);

enum Base {
    This,
    Pinned {
        dir: OwnedFd,
        pidfd: OwnedFd,
    },
    #[cfg(test)]
    Fixture(std::path::PathBuf),
}

impl Proc {
    pub(super) fn this() -> Proc {
        Proc(Base::This)
    }

    pub(super) fn pid(pid: i32) -> Result<Proc, Refused> {
        let dir = rustix::fs::open(
            format!("/proc/{pid}"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let raw = rustix::process::Pid::from_raw(pid).ok_or(Refused::Malformed)?;
        let pidfd = rustix::process::pidfd_open(raw, rustix::process::PidfdFlags::empty())?;
        let proc = Proc(Base::Pinned { dir, pidfd });
        // If the directory's process died before the pidfd was taken, its
        // entries are gone and this fails.
        proc.read("stat")?;
        proc.still_running()?;
        Ok(proc)
    }

    /// A directory standing in for `/proc/<pid>`, for the checks' tests.
    #[cfg(test)]
    pub(super) fn fixture(dir: &Path) -> Proc {
        Proc(Base::Fixture(dir.to_owned()))
    }

    /// The pinned process has not exited (a pidfd turns readable when it
    /// does). Checks end with this, so every answer came from a live process.
    pub(super) fn still_running(&self) -> Result<(), Refused> {
        if let Base::Pinned { pidfd, .. } = &self.0 {
            let mut fds = [PollFd::new(pidfd, PollFlags::IN)];
            if rustix::event::poll(
                &mut fds,
                Some(&Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            )? != 0
            {
                return Err(Refused::Barrier(Check::Cgroup));
            }
        }
        Ok(())
    }

    fn open(&self, name: &str) -> Result<OwnedFd, Refused> {
        let flags = OFlags::RDONLY | OFlags::CLOEXEC;
        Ok(match &self.0 {
            Base::This => rustix::fs::open(format!("/proc/self/{name}"), flags, Mode::empty())?,
            Base::Pinned { dir, .. } => rustix::fs::openat(dir, name, flags, Mode::empty())?,
            #[cfg(test)]
            Base::Fixture(dir) => rustix::fs::open(dir.join(name), flags, Mode::empty())?,
        })
    }

    fn stat(&self, name: &str) -> Result<rustix::fs::Stat, Refused> {
        Ok(match &self.0 {
            Base::This => rustix::fs::stat(format!("/proc/self/{name}"))?,
            Base::Pinned { dir, .. } => rustix::fs::statat(dir, name, AtFlags::empty())?,
            #[cfg(test)]
            Base::Fixture(dir) => rustix::fs::stat(dir.join(name))?,
        })
    }

    fn read(&self, name: &str) -> Result<String, Refused> {
        let mut text = String::new();
        std::fs::File::from(self.open(name)?)
            .take(1 << 16)
            .read_to_string(&mut text)?;
        Ok(text)
    }

    pub(super) fn namespace(&self, ns: &str) -> Result<String, Refused> {
        let name = format!("ns/{ns}");
        let link = match &self.0 {
            Base::This => rustix::fs::readlink(format!("/proc/self/{name}"), Vec::new())?,
            Base::Pinned { dir, .. } => rustix::fs::readlinkat(dir, name, Vec::new())?,
            #[cfg(test)]
            Base::Fixture(dir) => rustix::fs::readlink(dir.join(name), Vec::new())?,
        };
        link.into_string().map_err(|_| Refused::Malformed)
    }

    /// A descriptor for one of the process's namespaces, for `setns`.
    pub(super) fn namespace_fd(&self, ns: &str) -> Result<OwnedFd, Refused> {
        self.open(&format!("ns/{ns}"))
    }

    /// The prefix's writable layer holds exactly `bytes` (an overlay reports
    /// its upper layer's size).
    pub(super) fn prefix_size(&self, bytes: u64) -> Result<(), Refused> {
        let stat = match &self.0 {
            Base::This => rustix::fs::statvfs(PREFIX)?,
            Base::Pinned { dir, .. } => {
                let path = format!("root{PREFIX}");
                let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
                rustix::fs::fstatvfs(rustix::fs::openat(dir, path, flags, Mode::empty())?)?
            }
            #[cfg(test)]
            Base::Fixture(dir) => rustix::fs::statvfs(dir.join("prefix"))?,
        };
        if stat.f_blocks.checked_mul(stat.f_frsize) != Some(bytes) {
            return Err(Refused::Barrier(Check::PrefixSize));
        }
        Ok(())
    }

    /// Device and inode of the process's executable.
    pub(super) fn exe(&self) -> Result<(u64, u64), Refused> {
        let stat = self.stat("exe")?;
        Ok((stat.st_dev, stat.st_ino))
    }

    /// Each of [`NAMESPACES`] differs from the host's, and every one but
    /// the network namespace differs from the setup link's too: pasta gives
    /// the setup link new namespaces, but its mount namespace is a copy of
    /// the host's and its user namespace owns the box's network.
    pub(super) fn namespaces_separate(
        &self,
        host: &[String],
        setup: &[String],
    ) -> Result<(), Refused> {
        if host.len() != NAMESPACES.len() || setup.len() != NAMESPACES.len() {
            return Err(Refused::Malformed);
        }
        for ((ns, host), setup) in NAMESPACES.iter().zip(host).zip(setup) {
            let own = self.namespace(ns)?;
            if own == *host || (*ns != "net" && own == *setup) {
                return Err(Refused::Barrier(Check::Namespaces));
            }
        }
        Ok(())
    }

    /// The process's cgroup path, as the reader's cgroup namespace shows it.
    pub(super) fn cgroup_is(&self, accept: impl Fn(&str) -> bool) -> Result<(), Refused> {
        let text = self.read("cgroup")?;
        let mut paths = text.lines().filter_map(|l| l.strip_prefix("0::"));
        match (paths.next(), paths.next()) {
            (Some(path), None) if accept(path) => Ok(()),
            _ => Err(Refused::Barrier(Check::Cgroup)),
        }
    }

    /// Soft and hard limits both at the values of design §3.2.2 step 8.
    pub(super) fn rlimits(&self) -> Result<(), Refused> {
        let text = self.read("limits")?;
        for (name, value) in RLIMITS {
            let ok = text.lines().any(|line| {
                line.strip_prefix(name).is_some_and(|rest| {
                    let mut words = rest.split_whitespace();
                    words.next() == Some(value) && words.next() == Some(value)
                })
            });
            if !ok {
                return Err(Refused::Barrier(Check::Rlimits));
            }
        }
        Ok(())
    }

    /// Every capability set empty, and `NoNewPrivs` 1.
    pub(super) fn privileges(&self) -> Result<(), Refused> {
        let text = self.read("status")?;
        let field = |name: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(name))
                .map(str::trim)
        };
        for set in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
            let empty = field(set).is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b == b'0'));
            if !empty {
                return Err(Refused::Barrier(Check::Capabilities));
            }
        }
        if !cfg!(feature = "mutant-si36-nnp-unchecked") && field("NoNewPrivs:") != Some("1") {
            return Err(Refused::Barrier(Check::NoNewPrivs));
        }
        Ok(())
    }

    /// Descriptors 0 to 2 are `/dev/null`, and every other one is a FIFO in
    /// `pipes` (by device and inode); nothing else is open.
    pub(super) fn descriptors(&self, numbers: &[i32], pipes: &[(u64, u64)]) -> Result<(), Refused> {
        let null = std::fs::metadata("/dev/null")?;
        let bad = Refused::Barrier(Check::Descriptors);
        if numbers.len() != pipes.len().saturating_add(3) {
            return Err(bad);
        }
        for fd in numbers {
            let stat = self.stat(&format!("fd/{fd}"))?;
            let id = (stat.st_dev, stat.st_ino);
            let fifo =
                rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Fifo;
            let ok = match fd {
                0..=2 => id == (null.dev(), null.ino()),
                _ => fifo && pipes.contains(&id),
            };
            if !ok {
                return Err(bad);
            }
        }
        Ok(())
    }

    /// Descriptor numbers of another process, through the same strict
    /// listing as the sweep.
    pub(super) fn descriptor_numbers(&self) -> Result<Vec<i32>, Refused> {
        let dir = self.open("fd")?;
        let mut numbers = kickoff_local::fds::descriptors_in(dir)?;
        numbers.sort_unstable();
        Ok(numbers)
    }
}

/// Device and inode of a file, as the barrier compares descriptors.
pub(super) fn identity(path: &Path) -> Result<(u64, u64), Refused> {
    let meta = std::fs::metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(no_new_privs: &str, effective: &str) -> String {
        format!(
            "Name:\tprobe\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n\
             CapEff:\t{effective}\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n\
             NoNewPrivs:\t{no_new_privs}\n"
        )
    }

    #[test]
    fn si_36_barrier_refuses_a_payload_without_no_new_privs() {
        // bwrap sets no_new_privs unconditionally and it cannot be cleared,
        // so no setup can fault it: the check is shown on a status file.
        let dir = std::env::temp_dir().join(format!("kickoff-nnp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cases = [
            ("1", "0000000000000000", Ok(())),
            (
                "0",
                "0000000000000000",
                Err(Refused::Barrier(Check::NoNewPrivs)),
            ),
            (
                "1",
                "0000000000200000",
                Err(Refused::Barrier(Check::Capabilities)),
            ),
        ];
        for (nnp, eff, want) in cases {
            std::fs::write(dir.join("status"), status(nnp, eff)).unwrap();
            assert_eq!(
                Proc::fixture(&dir).privileges(),
                want,
                "NoNewPrivs {nnp}, CapEff {eff}"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

//! The final launch barrier (design §3.2.6). The last trusted link checks
//! itself from inside the box and the supervisor checks it from outside
//! through `/proc/<pid>`; the payload execs only after both agree.

use std::fmt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

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
        })
    }
}

/// A setup fault the barrier must catch: each leaves exactly one barrier
/// property wrong. Kickoff's own probes inject them to prove the barrier
/// refuses (SI-36); `None` is every real launch.
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
}

impl Fault {
    pub(super) const ALL: [(&'static str, Fault); 6] = [
        ("none", Fault::None),
        ("namespaces", Fault::Namespaces),
        ("nft", Fault::Nft),
        ("rlimits", Fault::Rlimits),
        ("capabilities", Fault::Capabilities),
        ("descriptors", Fault::Descriptors),
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

/// The namespaces the box must not share with the host, in argv order.
pub(super) const NAMESPACES: [&str; 5] = ["user", "net", "mnt", "pid", "ipc"];

pub(super) const RLIMITS: [(&str, &str); 3] = [
    ("Max core file size", "0"),
    ("Max file size", "4294967296"),
    ("Max open files", "8192"),
];
pub(super) const FSIZE: u64 = 4 << 30;
pub(super) const NOFILE: u64 = 8192;

/// A process's `/proc` directory: `/proc/self` or `/proc/<pid>`.
pub(super) struct Proc(pub PathBuf);

impl Proc {
    pub(super) fn this() -> Proc {
        Proc(PathBuf::from("/proc/self"))
    }

    pub(super) fn pid(pid: i32) -> Proc {
        Proc(PathBuf::from(format!("/proc/{pid}")))
    }

    fn read(&self, name: &str) -> Result<String, Refused> {
        Ok(std::fs::read_to_string(self.0.join(name))?)
    }

    pub(super) fn namespace(&self, ns: &str) -> Result<String, Refused> {
        let link = std::fs::read_link(self.0.join("ns").join(ns))?;
        link.into_os_string()
            .into_string()
            .map_err(|_| Refused::Malformed)
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
        if field("NoNewPrivs:") != Some("1") {
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
            let meta = std::fs::metadata(self.0.join("fd").join(fd.to_string()))?;
            let id = (meta.dev(), meta.ino());
            let ok = match fd {
                0..=2 => id == (null.dev(), null.ino()),
                _ => meta.file_type().is_fifo() && pipes.contains(&id),
            };
            if !ok {
                return Err(bad);
            }
        }
        Ok(())
    }

    /// Descriptor numbers of another process.
    pub(super) fn descriptor_numbers(&self) -> Result<Vec<i32>, Refused> {
        let mut numbers = Vec::new();
        for entry in std::fs::read_dir(self.0.join("fd"))? {
            let name = entry?.file_name();
            numbers.push(
                name.to_str()
                    .and_then(|n| n.parse().ok())
                    .ok_or(Refused::Malformed)?,
            );
        }
        numbers.sort_unstable();
        Ok(numbers)
    }
}

/// Device and inode of a file, as the barrier compares descriptors.
pub(super) fn identity(path: &Path) -> Result<(u64, u64), Refused> {
    let meta = std::fs::metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

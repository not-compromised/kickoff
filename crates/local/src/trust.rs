use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use std::os::fd::OwnedFd;

use nix::sys::socket::getsockopt;
use nix::sys::socket::sockopt::PeerPidfd;
use rustix::event::{PollFd, PollFlags, Timespec};
use tokio::net::UnixStream;

use crate::{Error, PeerCred};

const SERVER_BINARY: &str = "kickoffd";
const CLIENT_BINARIES: &[&str] = &["kickoff", "kickoff-ui"];

/// Who may sit at the other end of a channel: one uid, and a process whose
/// executable is one of a fixed set of files. Both come from the kernel
/// (`SO_PEERCRED`, `SO_PEERPIDFD` and `/proc/<pid>/exe`), never from anything
/// the peer sends.
#[derive(Debug, Clone)]
pub struct Trust {
    uid: u32,
    exes: Vec<FileId>,
}

/// Compared by inode rather than by path, so a hard link, a bind mount or a
/// renamed directory neither fools nor breaks the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
}

impl FileId {
    fn of(path: &Path) -> std::io::Result<FileId> {
        let meta = std::fs::metadata(path)?;
        Ok(FileId {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
}

impl Trust {
    /// What a client accepts as its server: our uid running the installed
    /// `kickoffd` next to the client's own executable.
    pub fn kickoffd() -> Result<Trust, Error> {
        Trust::installed(&[SERVER_BINARY])
    }

    /// What kickoffd accepts as callers: our uid running the installed CLI or
    /// UI next to the daemon's own executable.
    pub fn clients() -> Result<Trust, Error> {
        Trust::installed(CLIENT_BINARIES)
    }

    /// Our uid running one of `exes`. Every file must exist now.
    pub fn same_user(exes: &[&Path]) -> Result<Trust, Error> {
        Trust::for_uid(rustix::process::geteuid().as_raw(), exes)
    }

    /// Another uid running one of `exes`. Exists for tests that need a
    /// server or client which considers the caller a different user.
    pub fn for_uid(uid: u32, exes: &[&Path]) -> Result<Trust, Error> {
        let exes = exes
            .iter()
            .map(|p| FileId::of(p))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Trust { uid, exes })
    }

    /// Binaries that are not installed are left out; if none is, every peer
    /// is refused.
    fn installed(names: &[&str]) -> Result<Trust, Error> {
        let me = std::env::current_exe()?;
        let dir = me.parent().ok_or(Error::PeerRejected)?;
        let exes = names
            .iter()
            .map(|name| dir.join(name))
            .filter_map(|path: PathBuf| FileId::of(&path).ok())
            .collect();
        Ok(Trust {
            uid: rustix::process::geteuid().as_raw(),
            exes,
        })
    }

    /// The uid check comes first and alone decides for other users; the
    /// executable check narrows our own uid to Kickoff's binaries. A peer
    /// whose pid we cannot see (another pid namespace) is refused.
    ///
    /// The executable is read through `/proc/<pid>`, and a pid can be reused
    /// once its process is gone. So the process itself is pinned first with
    /// `SO_PEERPIDFD`, taken from the socket like the credentials, and the
    /// answer counts only if that process is still running after the read:
    /// if it is, the pid cannot have been recycled in between.
    pub fn check(&self, socket: &UnixStream) -> Result<PeerCred, Error> {
        self.pin(socket).map(|(peer, _)| peer)
    }

    pub fn pin(&self, socket: &UnixStream) -> Result<(PeerCred, Option<OwnedFd>), Error> {
        let cred = socket.peer_cred()?;
        if !cfg!(feature = "mutant-si7-no-uid-check") && cred.uid() != self.uid {
            return Err(Error::PeerRejected);
        }
        let pid = cred
            .pid()
            .filter(|pid| *pid > 0)
            .ok_or(Error::PeerRejected)?;
        let pinned = if cfg!(feature = "mutant-si7-pid-not-pidfd") {
            None
        } else {
            // Kernels before 6.5 have no SO_PEERPIDFD: every peer is refused.
            Some(getsockopt(socket, PeerPidfd).map_err(|_| Error::PeerRejected)?)
        };
        let exe = FileId::of(&proc_exe(pid)).map_err(|_| Error::PeerRejected)?;
        if !cfg!(feature = "mutant-si7-no-exe-check") && !self.exes.contains(&exe) {
            return Err(Error::PeerRejected);
        }
        if let Some(pidfd) = &pinned
            && !still_running(pidfd)
        {
            return Err(Error::PeerRejected);
        }
        Ok((
            PeerCred {
                uid: cred.uid(),
                pid,
            },
            pinned,
        ))
    }
}

/// A pidfd polls readable once its process has exited, zombie or reaped, so
/// "not readable" means the pid still names that process. (The design names
/// `pidfd_send_signal(pidfd, 0)`; rustix cannot express signal 0 without
/// `unsafe`, and this answers the same question, refusing zombies as well.)
fn still_running(pidfd: &OwnedFd) -> bool {
    let mut fds = [PollFd::new(pidfd, PollFlags::IN)];
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    matches!(rustix::event::poll(&mut fds, Some(&now)), Ok(0))
}

fn proc_exe(pid: i32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/exe"))
}

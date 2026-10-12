use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use tokio::net::unix::UCred;

use crate::{IpcError, PeerCred};

const SERVER_BINARY: &str = "kickoffd";
const CLIENT_BINARIES: &[&str] = &["kickoff", "kickoff-ui"];

/// Who may sit at the other end of a channel: one uid, and a process whose
/// executable is one of a fixed set of files. Both come from the kernel
/// (`SO_PEERCRED` and `/proc/<pid>/exe`), never from anything the peer sends.
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
    pub fn kickoffd() -> Result<Trust, IpcError> {
        Trust::installed(&[SERVER_BINARY])
    }

    /// What kickoffd accepts as callers: our uid running the installed CLI or
    /// UI next to the daemon's own executable.
    pub fn clients() -> Result<Trust, IpcError> {
        Trust::installed(CLIENT_BINARIES)
    }

    /// Our uid running one of `exes`. Every file must exist now.
    pub fn same_user(exes: &[&Path]) -> Result<Trust, IpcError> {
        Trust::for_uid(super::euid(), exes)
    }

    /// Another uid running one of `exes`. Exists for tests that need a
    /// server or client which considers the caller a different user.
    pub fn for_uid(uid: u32, exes: &[&Path]) -> Result<Trust, IpcError> {
        let exes = exes
            .iter()
            .map(|p| FileId::of(p))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Trust { uid, exes })
    }

    /// Binaries that are not installed are left out; if none is, every peer
    /// is refused.
    fn installed(names: &[&str]) -> Result<Trust, IpcError> {
        let me = std::env::current_exe()?;
        let dir = me.parent().ok_or(IpcError::PeerRejected)?;
        let exes = names
            .iter()
            .map(|name| dir.join(name))
            .filter_map(|path: PathBuf| FileId::of(&path).ok())
            .collect();
        Ok(Trust {
            uid: super::euid(),
            exes,
        })
    }

    /// The uid check comes first and alone decides for other users; the
    /// executable check narrows our own uid to Kickoff's binaries. A peer
    /// whose pid we cannot see (another pid namespace) is refused.
    ///
    /// Residual: the pid is read when the peer connected. If that process
    /// has exited and the pid was reused by one of our own Kickoff binaries,
    /// the check passes; only a same-uid process can arrange that, and
    /// same-user malware is outside Kickoff's boundary (§6.1).
    pub(super) fn check(&self, cred: UCred) -> Result<PeerCred, IpcError> {
        if !cfg!(feature = "mutant-si7-no-uid-check") && cred.uid() != self.uid {
            return Err(IpcError::PeerRejected);
        }
        let pid = cred
            .pid()
            .filter(|pid| *pid > 0)
            .ok_or(IpcError::PeerRejected)?;
        let exe = FileId::of(&proc_exe(pid)).map_err(|_| IpcError::PeerRejected)?;
        if !cfg!(feature = "mutant-si7-no-exe-check") && !self.exes.contains(&exe) {
            return Err(IpcError::PeerRejected);
        }
        Ok(PeerCred {
            uid: cred.uid(),
            pid,
        })
    }
}

fn proc_exe(pid: i32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/exe"))
}

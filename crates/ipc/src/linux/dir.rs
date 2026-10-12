use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::IpcError;

const DIR_NAME: &str = "kickoff";
const SOCKET_NAME: &str = "kickoffd.sock";

/// `$XDG_RUNTIME_DIR/kickoff`: a directory only this user can enter, so
/// nobody else can create, replace or reach the socket inside it.
#[derive(Debug)]
pub struct RuntimeDir {
    socket: PathBuf,
    uid: u32,
}

impl RuntimeDir {
    pub fn open() -> Result<RuntimeDir, IpcError> {
        let base = std::env::var_os("XDG_RUNTIME_DIR").ok_or(IpcError::UnsafeDir)?;
        RuntimeDir::open_in(Path::new(&base))
    }

    /// `base` stands in for `$XDG_RUNTIME_DIR` and must be an absolute,
    /// non-symlink directory owned by us that no one else can access. The
    /// `kickoff` directory inside it is created mode 0700, or, if it already
    /// exists, accepted only as a real directory owned by us with mode 0700.
    pub fn open_in(base: &Path) -> Result<RuntimeDir, IpcError> {
        if !base.is_absolute() {
            return Err(IpcError::UnsafeDir);
        }
        let uid = super::euid();
        let base_fd = open_dir(rustix::fs::CWD, base)?;
        let base_mode = owned_dir_mode(&base_fd, uid)?;
        if !cfg!(feature = "mutant-si7-base-unchecked") && base_mode & 0o077 != 0 {
            return Err(IpcError::UnsafeDir);
        }

        let created = match rustix::fs::mkdirat(&base_fd, DIR_NAME, Mode::RWXU) {
            Ok(()) => true,
            Err(Errno::EXIST) => false,
            Err(e) => return Err(std::io::Error::from(e).into()),
        };
        let fd = open_dir(&base_fd, DIR_NAME)?;
        if created {
            // The umask can only have narrowed 0700; restore it exactly.
            rustix::fs::fchmod(&fd, Mode::RWXU).map_err(std::io::Error::from)?;
        }
        if owned_dir_mode(&fd, uid)? != 0o700 && !cfg!(feature = "mutant-si7-dir-mode-unchecked") {
            return Err(IpcError::UnsafeDir);
        }
        Ok(RuntimeDir {
            socket: base.join(DIR_NAME).join(SOCKET_NAME),
            uid,
        })
    }

    /// kickoffd's socket. The only place its name is built.
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub(super) fn uid(&self) -> u32 {
        self.uid
    }
}

/// Never follows a symlink in the last component: a planted link is refused,
/// not resolved.
fn open_dir<Fd: AsFd>(at: Fd, path: impl rustix::path::Arg) -> Result<OwnedFd, IpcError> {
    rustix::fs::openat(
        at,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| IpcError::UnsafeDir)
}

/// The permission bits of a directory we own, read from the open handle so
/// the answer is about the directory we will use, not whatever the name
/// points at a moment later.
fn owned_dir_mode(fd: &OwnedFd, uid: u32) -> Result<u32, IpcError> {
    let stat = rustix::fs::fstat(fd).map_err(std::io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory || stat.st_uid != uid {
        return Err(IpcError::UnsafeDir);
    }
    Ok(stat.st_mode & 0o7777)
}

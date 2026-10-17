//! Kernel-authenticated local transports shared by IPC and secret transmission,
//! and the descriptor sweep shared by every process that drops inherited authority.
#[cfg(target_os = "linux")]
pub mod fds;
#[cfg(target_os = "linux")]
pub mod spawn;
#[cfg(target_os = "linux")]
mod stream;
#[cfg(target_os = "linux")]
mod trust;

#[cfg(target_os = "linux")]
pub use stream::{AncillaryRefused, DataOnly, InstalledPeer, PeerKind};
#[cfg(target_os = "linux")]
pub use trust::Trust;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub pid: i32,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("peer is not an installed Kickoff binary of this user")]
    PeerRejected,
    #[error("ancillary data on a local channel")]
    Ancillary,
    #[error("local i/o error: {0:?}")]
    Io(std::io::ErrorKind),
}
#[cfg(target_os = "linux")]
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        if error.get_ref().is_some_and(|e| e.is::<AncillaryRefused>()) {
            Self::Ancillary
        } else {
            Self::Io(error.kind())
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/support/exec.rs"]
mod test_exec;

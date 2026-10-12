//! Local channels between Kickoff's own processes (design §2.7). Every
//! channel is an exclusive endpoint in a private place, authenticates the
//! caller and the server through the kernel, opens with a version handshake,
//! and carries one role's fixed command enum. Linux lands in M2, Windows pipes
//! in M7.
//!
//! ```text
//! client                                   kickoffd
//! connect ── check server uid + exe ──►    accept ── slot ── check caller uid + exe
//!         ── Hello{version, role} ──►              ── version and role served?
//!         ◄── Welcome{version} ──
//! call    ── role command ──►              recv ── budget ── decode for role only
//!         ◄── reply ──                     reply ── allowed for role?
//! ```

mod codec;
mod command;
mod frame;
#[cfg(target_os = "linux")]
mod linux;

use std::time::Duration;

pub use command::{
    ApprovalId, CliCommand, InviteFor, OverlayCommand, Refusal, Reply, Request, TicketText,
    UiCommand,
};
#[cfg(target_os = "linux")]
pub use linux::{
    Channel, Client, Facade, RuntimeDir, Server, Trust, Worker, connect,
    run_core_probe_if_requested,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IpcError {
    #[error("not supported on this platform yet")]
    Unsupported,
    #[error("kernel core-dump suppression probe failed")]
    Hardening,
    #[error("runtime directory is missing or has the wrong owner, type or mode")]
    UnsafeDir,
    #[error("endpoint name taken by a live endpoint or by something that is not our socket")]
    Squatted,
    #[error("peer is not an installed Kickoff binary of this user")]
    PeerRejected,
    #[error("version mismatch")]
    Version,
    #[error("role not served on this channel")]
    Role,
    #[error("malformed or unknown message")]
    Malformed,
    #[error("frame longer than {max} bytes")]
    TooLarge { max: usize },
    #[error("over budget")]
    OverBudget,
    #[error("deadline passed")]
    Timeout,
    #[error("channel closed")]
    Closed,
    #[error("reply without a pending request")]
    Unrequested,
    #[error("descriptors, credentials or other control data on a local channel")]
    Ancillary,
    #[error("i/o error: {0:?}")]
    Io(std::io::ErrorKind),
}

/// Bumped on any change to a role's command enum; a mismatch closes the
/// channel before any side effect (SI-10).
pub const PROTOCOL_VERSION: u16 = 3;

/// Each role has its own fixed command enum, and none carries a path, URL,
/// shell string, launch command or EAC mode (SI-3). Only `Cli`, `UiMain` and
/// `Overlay` are served on kickoffd's socket; the gamebox launcher uses a
/// socketpair and the service client a Windows pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelRole {
    Cli,
    UiMain,
    Overlay,
    Gamebox,
    ServiceClient,
}

pub use kickoff_local::PeerCred;

/// Client-side role markers: a `Client<Cli>` can only send `CliCommand`s.
/// Only the built-in markers can implement `Role`.
///
/// ```compile_fail,E0277
/// use kickoff_ipc::{ChannelRole, UiCommand, role::Role};
/// struct ExternalRole;
/// impl Role for ExternalRole {
///     const ROLE: ChannelRole = ChannelRole::Overlay;
///     type Command = UiCommand;
/// }
/// ```
///
/// External clients cannot supply their own seal either.
///
/// ```compile_fail,E0405
/// use kickoff_ipc::{ChannelRole, UiCommand, role};
/// struct ExternalRole;
/// impl role::Sealed for ExternalRole {}
/// impl role::Role for ExternalRole {
///     const ROLE: ChannelRole = ChannelRole::Overlay;
///     type Command = UiCommand;
/// }
/// ```
pub mod role {
    use crate::command::{CliCommand, OverlayCommand, UiCommand};
    use crate::{ChannelRole, command};

    pub trait Role: sealed::Sealed + Send + 'static {
        const ROLE: ChannelRole;
        type Command: Into<command::Op> + Send;
    }

    pub struct Cli;
    pub struct UiMain;
    pub struct Overlay;

    impl Role for Cli {
        const ROLE: ChannelRole = ChannelRole::Cli;
        type Command = CliCommand;
    }

    impl Role for UiMain {
        const ROLE: ChannelRole = ChannelRole::UiMain;
        type Command = UiCommand;
    }

    impl Role for Overlay {
        const ROLE: ChannelRole = ChannelRole::Overlay;
        type Command = OverlayCommand;
    }

    mod sealed {
        pub trait Sealed {}
        impl Sealed for super::Cli {}
        impl Sealed for super::UiMain {}
        impl Sealed for super::Overlay {}
    }
}

// Per-connection budgets (§6.3 "charge before allocate"). A request is at most
// a tag, a ticket and its length; a reply is at most a full diagnostics report.
pub const MAX_REQUEST_FRAME: usize = 4096;
pub const MAX_REPLY_FRAME: usize = 8192;
/// Concurrent channels per server; the slot is taken before a byte is read.
pub const MAX_CHANNELS: usize = 16;
/// Requests per second per channel, also the burst.
pub const REQUEST_RATE: u32 = 32;
/// Once a frame's first byte arrives, the rest must follow within this; an
/// idle channel may wait for its next first byte indefinitely.
pub const FRAME_DEADLINE: Duration = Duration::from_secs(1);
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(1);
pub const WRITE_DEADLINE: Duration = Duration::from_secs(1);

/// What a server refused, for the diagnostics counters `ipc.peers_rejected`
/// and `ipc.frames_refused`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpcHealth {
    /// Callers refused by the kernel-credential check.
    pub peers_rejected: u64,
    /// Failed handshakes, oversize frames, and unknown or out-of-role
    /// commands.
    pub frames_refused: u64,
}

impl From<std::io::Error> for IpcError {
    fn from(e: std::io::Error) -> Self {
        #[cfg(target_os = "linux")]
        if e.get_ref()
            .is_some_and(|inner| inner.is::<linux::AncillaryRefused>())
        {
            return IpcError::Ancillary;
        }
        match e.kind() {
            std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset => IpcError::Closed,
            kind => IpcError::Io(kind),
        }
    }
}

#[cfg(target_os = "linux")]
impl From<kickoff_local::Error> for IpcError {
    fn from(error: kickoff_local::Error) -> Self {
        match error {
            kickoff_local::Error::PeerRejected => Self::PeerRejected,
            kickoff_local::Error::Ancillary => Self::Ancillary,
            kickoff_local::Error::Io(kind) => std::io::Error::from(kind).into(),
        }
    }
}

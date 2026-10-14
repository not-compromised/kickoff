use std::io;

use super::barrier::Check;

/// Why a gamebox process refused or failed. Every trusted link exits with
/// [`Refused::code`], so the supervisor sees which check stopped a launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("malformed arguments")]
    Malformed,
    #[error("not the main process of a systemd user service")]
    NotAService,
    #[error("a Kickoff binary is missing beside this one")]
    Install,
    #[error("stdio is not /dev/null")]
    Stdio,
    #[error("the expected parent died before its death signal was armed")]
    ParentGone,
    #[error("not inside the expected game scope")]
    WrongScope,
    #[error("the game scope was not registered")]
    Scope,
    #[error("the game scope did not empty within the teardown deadline")]
    Teardown,
    #[error("the host network could not be read")]
    Network,
    #[error("the box's network setup failed")]
    NetworkSetup,
    #[error("launch barrier: {0}")]
    Barrier(Check),
    #[error("the box ended before the launch barrier, status {0}")]
    BoxEnded(i32),
    #[error("the probe holds a descriptor beyond stdio")]
    Leaked,
    #[error("pasta maps the gateway to the host")]
    PastaMapsHost,
    #[error("a helper failed or did not finish in time")]
    HelperFailed,
    #[error("the host network changed")]
    HostChanged,
    #[error("i/o error: {0:?}")]
    Io(io::ErrorKind),
}

impl Refused {
    /// The exit status a link uses for this refusal. Distinct from the
    /// probe's own statuses (below 64) and from bwrap's and pasta's 1.
    pub fn code(self) -> u8 {
        match self {
            Refused::Malformed => 64,
            Refused::NotAService => 65,
            Refused::Install => 66,
            Refused::Stdio => 67,
            Refused::ParentGone => 68,
            Refused::WrongScope => 69,
            Refused::Scope => 70,
            Refused::Teardown => 71,
            Refused::Io(_) => 72,
            Refused::Network => 73,
            Refused::Leaked => 76,
            Refused::PastaMapsHost => 77,
            Refused::HelperFailed => 78,
            Refused::HostChanged => 79,
            Refused::NetworkSetup => 74,
            Refused::BoxEnded(_) => 75,
            Refused::Barrier(check) => match check {
                Check::Namespaces => 80,
                Check::Nft => 81,
                Check::Cgroup => 82,
                Check::Rlimits => 83,
                Check::Capabilities => 84,
                Check::NoNewPrivs => 85,
                Check::Descriptors => 86,
            },
        }
    }
}

impl From<io::Error> for Refused {
    fn from(error: io::Error) -> Self {
        Refused::Io(error.kind())
    }
}

impl From<rustix::io::Errno> for Refused {
    fn from(error: rustix::io::Errno) -> Self {
        Refused::Io(io::Error::from(error).kind())
    }
}

impl From<nix::errno::Errno> for Refused {
    fn from(error: nix::errno::Errno) -> Self {
        Refused::Io(io::Error::from(error).kind())
    }
}

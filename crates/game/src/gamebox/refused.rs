use std::io;

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

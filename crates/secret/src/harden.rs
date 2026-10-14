//! Process hardening that keeps secrets out of crash dumps and out of other
//! processes' reach (design §6.4, SI-30).

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HardenError {
    /// `RLIMIT_CORE` could not be set to 0.
    CoreLimit,
    /// `PR_SET_DUMPABLE` could not be cleared.
    Dumpable,
    /// No hardening exists for this platform yet (Windows lands in M7).
    Unsupported,
}

impl fmt::Display for HardenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HardenError::CoreLimit => "could not disable core dumps",
            HardenError::Dumpable => "could not mark the process not dumpable",
            HardenError::Unsupported => "process hardening is not supported on this platform",
        })
    }
}

impl std::error::Error for HardenError {}

/// Call first in `main`, before any secret exists. Afterwards the kernel
/// writes no core dump for this process, whatever the core pattern, and no
/// other process of the same user can read its memory (`/proc/<pid>/mem`,
/// `ptrace`) without `CAP_SYS_PTRACE`; its `/proc/<pid>` files become
/// root-owned.
///
/// Both settings are inherited by threads and forks; an `execve` resets
/// "dumpable", so a helper that runs another program must harden itself.
pub fn harden_process() -> Result<(), HardenError> {
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{DumpableBehavior, Resource, Rlimit};
        // The hard limit too, so nothing later in the process can raise it.
        let none = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        rustix::process::setrlimit(Resource::Core, none).map_err(|_| HardenError::CoreLimit)?;
        // Not dumpable also stops a core-pattern pipe handler from being
        // run at all, which RLIMIT_CORE alone does not.
        if !cfg!(feature = "mutant-si30-dumpable") {
            rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)
                .map_err(|_| HardenError::Dumpable)?;
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(HardenError::Unsupported)
    }
}

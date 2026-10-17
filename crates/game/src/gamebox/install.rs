use std::path::{Path, PathBuf};

use super::Refused;

pub(super) const LINK: &str = "kickoff-box-link";
pub(super) const PROBE: &str = "kickoff-box-probe";

/// A Kickoff binary installed beside the running one.
pub(super) fn sibling(name: &str) -> Result<PathBuf, Refused> {
    let exe = std::env::current_exe()?;
    let path = exe.parent().ok_or(Refused::Install)?.join(name);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => Ok(path),
        _ => Err(Refused::Install),
    }
}

/// Stdio of every trusted link is `/dev/null` (design §2.7): nothing the
/// chain was started with may reach the box through descriptors 0 to 2.
pub(super) fn require_null_stdio() -> Result<(), Refused> {
    use std::os::unix::fs::MetadataExt;
    let null = std::fs::metadata(Path::new("/dev/null"))?;
    for stat in [
        rustix::fs::fstat(std::io::stdin()),
        rustix::fs::fstat(std::io::stdout()),
        rustix::fs::fstat(std::io::stderr()),
    ] {
        let stat = stat?;
        if stat.st_dev != null.dev() || stat.st_ino != null.ino() {
            return Err(Refused::Stdio);
        }
    }
    Ok(())
}

/// A tool that builds the box must run unprivileged: a setuid or setgid
/// bwrap builds it with real privileges, outside the user-namespace model
/// the barrier assumes (design §3.2.6 requirement 6).
pub(super) fn require_unprivileged(path: &Path) -> Result<(), Refused> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o6000 != 0 && !cfg!(feature = "mutant-si36-setuid-bwrap-allowed") {
        return Err(Refused::SetuidTool);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn si_36_launch_refuses_a_setuid_or_setgid_bwrap() {
        let file = std::env::temp_dir().join(format!("kickoff-bwrap-{}", std::process::id()));
        std::fs::write(&file, b"").unwrap();
        for (mode, want) in [
            (0o755, Ok(())),
            (0o4755, Err(Refused::SetuidTool)),
            (0o2755, Err(Refused::SetuidTool)),
        ] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(require_unprivileged(&file), want, "mode {mode:o}");
        }
        std::fs::remove_file(&file).unwrap();
    }
}

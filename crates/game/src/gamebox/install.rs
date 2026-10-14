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

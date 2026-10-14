//! Test-only hold points (debug builds only; release builds compile them
//! to nothing). With `KICKOFF_TEST_GATE=<phase>` and `KICKOFF_TEST_GATE_DIR`
//! in its environment, a process reaching `<phase>` writes
//! `<dir>/<phase>` and waits until `<dir>/<phase>.go` exists, so a test can
//! kill the supervisor or a link at an exact startup phase (SI-38).

#[cfg(debug_assertions)]
use std::path::PathBuf;

#[cfg(debug_assertions)]
fn armed(phase: &str) -> Option<PathBuf> {
    let wanted = std::env::var("KICKOFF_TEST_GATE").ok()?;
    let dir = PathBuf::from(std::env::var_os("KICKOFF_TEST_GATE_DIR")?);
    (wanted == phase && dir.is_absolute()).then_some(dir)
}

/// Marks `phase` reached, without holding.
pub(super) fn mark(phase: &str) {
    #[cfg(debug_assertions)]
    if let Some(dir) = armed(phase) {
        let _ = std::fs::write(dir.join(phase), b"");
    }
    #[cfg(not(debug_assertions))]
    let _ = phase;
}

/// Marks `phase` reached and holds until the test releases it.
pub(super) fn hold(phase: &str) {
    #[cfg(debug_assertions)]
    if let Some(dir) = armed(phase) {
        let _ = std::fs::write(dir.join(phase), b"");
        let go = dir.join(format!("{phase}.go"));
        while !go.exists() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = phase;
}

/// A helper that never finishes, in place of the real one, so a test can
/// stop the supervisor while it waits on a stalled helper (debug builds).
pub(super) fn stall_helper() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var_os("KICKOFF_TEST_STALL_HELPER").is_some()
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// Scope registration that never completes, so a test can stop the
/// supervisor while it waits for registration (debug builds).
pub(super) fn slow_registration() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var_os("KICKOFF_TEST_SLOW_REGISTRATION").is_some()
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

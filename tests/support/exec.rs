//! Copies a test executable without this process ever holding the copy open
//! for writing. A copy written in-process leaves a writable descriptor that
//! every concurrent fork in the test binary inherits until its child execs,
//! and executing the copy in that window fails with ETXTBSY ("Text file
//! busy"). `cp` writes the copy in its own process instead, so once it has
//! exited no writer of the copy remains anywhere.
#![allow(dead_code, clippy::unwrap_used)]

use std::path::Path;

pub fn copy_executable(from: impl AsRef<Path>, to: impl AsRef<Path>) {
    let (from, to) = (from.as_ref(), to.as_ref());
    let status = std::process::Command::new("cp")
        .arg("--")
        .arg(from)
        .arg(to)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "cp {} {} failed: {status}",
        from.display(),
        to.display()
    );
}

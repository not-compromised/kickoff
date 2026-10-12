//! Placeholder binary; nothing is wired until the core loop works in process.

#![allow(clippy::print_stderr)]

use std::process::ExitCode;

fn main() -> ExitCode {
    // First, before any secret exists: no core dump, and no other process of
    // this user can read our memory (SI-30). A daemon that cannot harden
    // itself does not start.
    if let Err(e) = kickoff_secret::harden_process() {
        eprintln!("kickoffd: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("kickoffd: not implemented yet");
    ExitCode::FAILURE
}

//! Placeholder binary; nothing is wired until the core loop works in process.

#![allow(clippy::print_stderr)]

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("kickoffd: not implemented yet");
    ExitCode::FAILURE
}

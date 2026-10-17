//! SI-30: exec must preserve a core policy effective for piped handlers.
#![allow(clippy::unwrap_used, clippy::panic)]
mod support;
use std::os::unix::fs::DirBuilderExt;
use support::{Options, Supervisor};
struct Witness(std::path::PathBuf);
impl Drop for Witness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn si_30_game_exec_keeps_the_verified_core_policy() {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let witness = Witness(
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("core-witness-{}", std::process::id())),
    );
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&witness.0)
        .unwrap();
    let supervisor = Supervisor::start_with(
        Options {
            properties: vec!["LimitCORE=infinity".to_owned()],
            env: vec![("KICKOFF_TEST_WITNESS_DIR", witness.0.display().to_string())],
            ..Options::default()
        },
        &["probe", "inventory"],
    );
    let probes = supervisor.wait_procs("kickoff-box-probe", 1);
    for pid in probes {
        let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
        let core = limits
            .lines()
            .find_map(|line| line.strip_prefix("Max core file size"))
            .unwrap();
        let values: Vec<_> = core.split_whitespace().take(2).collect();
        assert_eq!(
            values,
            ["1", "1"],
            "exec restored the ineffective zero core policy"
        );
    }
    assert!(
        supervisor.report().contains("core probe: suppressed"),
        "{}",
        supervisor.report()
    );
    assert_eq!(
        std::fs::read(witness.0.join("core-canary"))
            .expect("startup skipped the genuine exec canary"),
        b"checked-before-abort"
    );
    assert_eq!(
        std::fs::read(witness.0.join("core-verified"))
            .expect("startup skipped crash-status verification"),
        b"SIGABRT-no-core"
    );
    // Kernel wait status is checked synchronously by the barrier. Journal
    // inspection is a secondary, bounded check; recording can be delayed.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let journal = std::process::Command::new("/usr/bin/coredumpctl")
        .env("LC_ALL", "C")
        .args([
            "--no-pager",
            "--json=short",
            "--since",
            &format!("@{since}"),
            "list",
            "COREDUMP_COMM=kickoff-core",
        ])
        .output()
        .unwrap();
    assert_eq!(
        journal.status.code(),
        Some(1),
        "a core was recorded: {:?}",
        journal
    );
    assert!(journal.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&journal.stderr).trim(),
        "No coredumps found.",
        "core journal evidence was unavailable: {:?}",
        journal
    );
}

#[test]
fn si_30_piped_handler_with_inherited_zero_refuses_before_starting_a_scope() {
    if !std::fs::read("/proc/sys/kernel/core_pattern")
        .unwrap()
        .starts_with(b"|")
    {
        return;
    }
    let supervisor = Supervisor::start_with(
        Options {
            properties: vec!["LimitCORE=0".to_owned()],
            ..Options::default()
        },
        &["probe", "inventory"],
    );
    supervisor.wait_exit();
    assert!(supervisor.scope_absent());
    assert!(
        supervisor
            .report()
            .contains("core dump suppression could not be verified"),
        "{}",
        supervisor.report()
    );
}

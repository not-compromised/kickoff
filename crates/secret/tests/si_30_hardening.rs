//! SI-30: after `harden_process`, a secret reaches neither a core dump nor
//! another process of the same user reading `/proc/<pid>/mem`. Needs no
//! root: the reader is the child's own parent, the strongest same-user
//! reader there is without `CAP_SYS_PTRACE` (Yama's default scope allows a
//! parent and nobody else), and the kernel itself reports whether a core was
//! dumped in the child's wait status.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing
)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};

use kickoff_secret::Secret;

const CHILD_ENV: &str = "KSEC_CANARY_CHILD";

/// Runs only as a child of the test below: holds a fresh canary secret,
/// reports where it lives, and then exits or crashes as told.
#[test]
fn canary_child() {
    let Ok(mode) = std::env::var(CHILD_ENV) else {
        return;
    };
    if mode == "hardened" {
        kickoff_secret::harden_process().unwrap();
    }
    let mut seed = [0u8; 16];
    getrandom::fill(&mut seed).unwrap();
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    let canary = Secret::new(format!("kickoff-canary-{hex}"));
    canary.expose(|c| {
        println!(
            "KSEC {} {} {} {c}",
            std::process::id(),
            c.as_ptr().addr(),
            c.len()
        );
    });
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    if line.trim() == "crash" {
        std::process::abort();
    }
    drop(canary);
}

/// A child holding a canary. Dropping it kills the child with SIGKILL, which
/// never dumps core, so a failing assertion leaves no dump behind either.
struct CanaryChild {
    child: Child,
    stdin: ChildStdin,
    pid: u32,
    addr: u64,
    canary: String,
}

impl CanaryChild {
    fn spawn(mode: &str, cwd: &Path) -> CanaryChild {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "canary_child", "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, mode)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let report = stdout
            .lines()
            .map_while(Result::ok)
            .find_map(|l| l.split_once("KSEC ").map(|(_, r)| r.to_owned()))
            .expect("the canary child did not report");
        let parts: Vec<&str> = report.split(' ').collect();
        let [pid, addr, len, canary] = parts.as_slice() else {
            panic!("bad report: {report}");
        };
        assert_eq!(len.parse::<usize>().unwrap(), canary.len());
        CanaryChild {
            child,
            stdin,
            pid: pid.parse().unwrap(),
            addr: addr.parse().unwrap(),
            canary: (*canary).to_owned(),
        }
    }

    /// What this process, the child's parent and of the same user, can read
    /// at the canary's address.
    fn read_canary(&self) -> std::io::Result<Vec<u8>> {
        let mem = std::fs::File::open(format!("/proc/{}/mem", self.pid))?;
        let mut buf = vec![0u8; self.canary.len()];
        mem.read_exact_at(&mut buf, self.addr)?;
        Ok(buf)
    }

    fn core_limit(&self) -> String {
        let limits = std::fs::read_to_string(format!("/proc/{}/limits", self.pid)).unwrap();
        let line = limits
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .unwrap();
        line.split_whitespace()
            .skip(4)
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl Drop for CanaryChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        let path = PathBuf::from(format!("/tmp/ksec-crash-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn si_30_hardened_process_leaks_no_secret_to_a_core_dump_or_proc_mem() {
    let cwd = TempDir::new();

    // Control: unhardened, the same child's canary is readable here, so the
    // reader works and only hardening can stop it below.
    let plain = CanaryChild::spawn("plain", &cwd.0);
    let seen = plain
        .read_canary()
        .expect("control: a parent must read its unhardened child (Yama ptrace_scope 0 or 1)");
    assert_eq!(seen, plain.canary.as_bytes());
    drop(plain);

    let mut hardened = CanaryChild::spawn("hardened", &cwd.0);
    let refused = hardened
        .read_canary()
        .expect_err("another process of this user read the hardened child's memory");
    assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(
        hardened.core_limit(),
        "0 0",
        "RLIMIT_CORE must be 0, hard too"
    );

    writeln!(hardened.stdin, "crash").unwrap();
    let status = hardened.child.wait().unwrap();
    assert_eq!(status.signal(), Some(6), "the child must die of SIGABRT");
    // The kernel sets this bit whenever it wrote a core, to a file or to a
    // core-pattern pipe such as systemd-coredump; a non-dumpable process
    // never reaches either.
    assert!(!status.core_dumped(), "a core was dumped");
    let left: Vec<_> = std::fs::read_dir(&cwd.0).unwrap().collect();
    assert!(
        left.is_empty(),
        "files left in the crash directory: {left:?}"
    );
}

//! Runs the real supervisor as a transient systemd user service, the way the
//! user manager runs `kickoff-gamebox.service`, and cleans up every unit it
//! started. Every unit is named `kickoff-m0-test-*`.

#![allow(dead_code, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU32 = AtomicU32::new(0);

pub const DEADLINE: Duration = Duration::from_secs(2);

pub struct Supervisor {
    pub unit: String,
    out: PathBuf,
}

fn systemctl(args: &[&str]) -> std::process::Output {
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

impl Supervisor {
    pub fn start(args: &[&str]) -> Supervisor {
        Supervisor::start_with(&[], args)
    }

    /// `properties` are extra unit properties, such as an `OpenFile=` leak.
    pub fn start_with(properties: &[String], args: &[&str]) -> Supervisor {
        let unit = format!(
            "kickoff-m0-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{unit}.out"));
        let _ = std::fs::remove_file(&out);
        let status = Command::new("systemd-run")
            .args(["--user", "--quiet", "--collect"])
            .arg(format!("--unit={unit}"))
            .arg("--property=KillMode=control-group")
            .arg(format!("--property=RuntimeDirectory={unit}"))
            .args(properties.iter().map(|p| format!("--property={p}")))
            .arg(format!("--property=StandardOutput=file:{}", out.display()))
            .arg(format!("--property=StandardError=file:{}", out.display()))
            .arg("--")
            .arg(env!("CARGO_BIN_EXE_kickoff-gamebox"))
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "systemd-run failed for {unit}");
        Supervisor { unit, out }
    }

    pub fn scope_unit(&self) -> String {
        format!("{}-game.scope", self.unit)
    }

    /// The scope's cgroup directory, once registered.
    pub fn scope_dir(&self) -> PathBuf {
        let started = Instant::now();
        loop {
            let out = systemctl(&["show", "--value", "-p", "ControlGroup", &self.scope_unit()]);
            let path = String::from_utf8(out.stdout).unwrap();
            let path = path.trim();
            if !path.is_empty() {
                return PathBuf::from(format!("/sys/fs/cgroup{path}"));
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "scope never registered; supervisor said: {}",
                self.report()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Waits until the scope holds at least `count` processes running `exe`
    /// that finished their own checks and hold (process name `holding`).
    pub fn wait_procs(&self, exe: &str, count: usize) -> Vec<i32> {
        let dir = self.scope_dir();
        let started = Instant::now();
        loop {
            let procs: Vec<i32> = std::fs::read_to_string(dir.join("cgroup.procs"))
                .unwrap_or_default()
                .lines()
                .filter_map(|l| l.parse().ok())
                .filter(|pid| {
                    std::fs::read_link(format!("/proc/{pid}/exe"))
                        .is_ok_and(|p| p.file_name().is_some_and(|n| n == exe))
                        && std::fs::read_to_string(format!("/proc/{pid}/comm"))
                            .is_ok_and(|c| c.trim() == "holding")
                })
                .collect();
            if procs.len() >= count {
                return procs;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the box never reached {count} {exe} processes; supervisor said: {}",
                self.report()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Sends `signal` to the supervisor process without asking the manager
    /// to stop its unit (a unit stop would also stop the bound scope).
    pub fn signal(&self, signal: &str) {
        let out = systemctl(&["kill", "--signal", signal, &self.unit]);
        assert!(out.status.success(), "systemctl kill failed");
    }

    pub fn wait_exit(&self) {
        assert!(
            self.exited_within(Duration::from_secs(10)),
            "the supervisor did not exit: {}",
            self.report()
        );
    }

    pub fn exited_within(&self, deadline: Duration) -> bool {
        within(deadline, || {
            !systemctl(&["is-active", "--quiet", &self.unit])
                .status
                .success()
        })
    }

    pub fn main_pid(&self) -> i32 {
        let out = systemctl(&["show", "--value", "-p", "MainPID", &self.unit]);
        String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    pub fn report(&self) -> String {
        std::fs::read_to_string(&self.out).unwrap_or_default()
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        for unit in [self.scope_unit(), format!("{}.service", self.unit)] {
            systemctl(&["kill", "--signal", "SIGKILL", &unit]);
            systemctl(&["stop", &unit]);
            systemctl(&["reset-failed", &unit]);
        }
        let _ = std::fs::remove_file(&self.out);
    }
}

/// Device and inode of what `/proc/<pid>/fd/<n>` refers to, for every open
/// descriptor of `pid`.
pub fn descriptors(pid: i32) -> Vec<(i32, (u64, u64))> {
    use std::os::unix::fs::MetadataExt;
    let mut fds: Vec<_> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .map(|e| {
            let n: i32 = e.unwrap().file_name().to_str().unwrap().parse().unwrap();
            let meta = std::fs::metadata(format!("/proc/{pid}/fd/{n}")).unwrap();
            (n, (meta.dev(), meta.ino()))
        })
        .collect();
    fds.sort();
    fds
}

pub fn identity(path: &std::path::Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).unwrap();
    (meta.dev(), meta.ino())
}

/// A process that exists and is not a zombie.
pub fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(") ")
            .is_some_and(|(_, rest)| !rest.starts_with('Z') && !rest.starts_with('X'))
    })
}

/// Polls until `done` holds or the deadline passes; returns whether it held.
pub fn within(deadline: Duration, mut done: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    loop {
        if done() {
            return true;
        }
        if started.elapsed() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

//! The installed executable's two modes use the same seam as the IPC tests,
//! and what it holds after startup is only what it opened itself (SI-36).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout
)]
#[path = "../../../tests/support/exec.rs"]
mod exec;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CANARY: &str = "leak-canary";
/// Where a launcher leaks the canary in kickoffd: a fresh number, since
/// dup2 onto the same number would keep close-on-exec.
const LEAKED_FD: i32 = 200;
const RUNTIME_HELPER: &str = "KICKOFFD_TEST_RUNTIME";
const RUNTIME_LINE: &str = "KICKOFFD-RUNTIME ";

/// A daemon and the client it trusts, installed side by side in a private
/// `$XDG_RUNTIME_DIR` stand-in that is removed on drop.
struct Install {
    base: PathBuf,
    daemon: PathBuf,
    client: PathBuf,
    dir: kickoff_ipc::RuntimeDir,
}

impl Install {
    fn new(name: &str) -> Install {
        use std::os::unix::fs::PermissionsExt;
        let base =
            std::env::temp_dir().join(format!("kickoff-startup-{name}-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let installed = base.join("install");
        std::fs::create_dir(&installed).unwrap();
        let daemon = installed.join("kickoffd");
        let client = installed.join("kickoff");
        exec::copy_executable(env!("CARGO_BIN_EXE_kickoffd"), &daemon);
        exec::copy_executable(std::env::current_exe().unwrap(), &client);
        let dir = kickoff_ipc::RuntimeDir::open_in(&base).unwrap();
        Install {
            base,
            daemon,
            client,
            dir,
        }
    }

    /// Waits for the socket, then has the installed client complete calls,
    /// which proves the facade has handed off to a serving worker.
    fn serve_one_client(&self, daemon: &mut Daemon) {
        let deadline = Instant::now().checked_add(Duration::from_secs(3)).unwrap();
        while !self.dir.socket_path().exists() {
            assert!(
                Instant::now() < deadline,
                "daemon did not create the real IPC socket"
            );
            assert!(!daemon.exited(), "daemon startup failed");
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = Command::new(&self.client)
            .args([
                "--exact",
                "client_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KIPC_STARTUP_CLIENT", &self.base)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "installed daemon refused the authenticated client: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!daemon.exited(), "daemon exited after serving");
    }
}

impl Drop for Install {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// A launched daemon, killed and reaped on drop unless already reaped.
struct Daemon(Option<rustix::process::Pid>);

impl Daemon {
    fn pid(&self) -> String {
        self.0.unwrap().as_raw_nonzero().to_string()
    }

    fn exited(&mut self) -> bool {
        let Some(pid) = self.0 else {
            return true;
        };
        let status =
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap();
        if status.is_some() {
            self.0 = None;
        }
        status.is_some()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(pid) = self.0.take() {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
            let _ = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty());
        }
    }
}

#[derive(Clone, Copy)]
enum Launch {
    /// stdio on `/dev/null`.
    NullStdio,
    /// stdio closed, as some launchers start a daemon.
    ClosedStdio,
}

/// Starts the installed daemon as a launcher would, through posix_spawn so
/// the test decides exactly which descriptors it inherits: stdio as
/// `launch` says, `leak` without close-on-exec at [`LEAKED_FD`], nothing else.
fn launch(install: &Install, launch: Launch, leak: Option<&std::fs::File>) -> Daemon {
    use nix::spawn::{PosixSpawnAttr, PosixSpawnFileActions, posix_spawn};
    let program = CString::new(install.daemon.as_os_str().as_bytes()).unwrap();
    let mut env: Vec<CString> = std::env::vars_os()
        .filter(|(key, _)| key != "XDG_RUNTIME_DIR")
        .map(|(key, value)| {
            CString::new([key.as_bytes(), b"=", value.as_bytes()].concat()).unwrap()
        })
        .collect();
    env.push(
        CString::new([b"XDG_RUNTIME_DIR=", install.base.as_os_str().as_bytes()].concat()).unwrap(),
    );
    let null = std::fs::File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    let mut actions = PosixSpawnFileActions::init().unwrap();
    for target in 0..3 {
        match launch {
            Launch::NullStdio => actions.add_dup2(null.as_raw_fd(), target).unwrap(),
            Launch::ClosedStdio => actions.add_close(target).unwrap(),
        }
    }
    if let Some(leak) = leak {
        assert_ne!(leak.as_raw_fd(), LEAKED_FD);
        actions.add_dup2(leak.as_raw_fd(), LEAKED_FD).unwrap();
    }
    let attr = PosixSpawnAttr::init().unwrap();
    let pid = posix_spawn(
        program.as_c_str(),
        &actions,
        &attr,
        std::slice::from_ref(&program),
        &env,
    )
    .unwrap();
    Daemon(Some(rustix::process::Pid::from_raw(pid.as_raw()).unwrap()))
}

#[test]
fn client_helper() {
    let Some(base) = std::env::var_os("KIPC_STARTUP_CLIENT") else {
        return;
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let dir = kickoff_ipc::RuntimeDir::open_in(std::path::Path::new(&base)).unwrap();
        let mut client = kickoff_ipc::connect::<kickoff_ipc::role::Cli>(
            &dir,
            &kickoff_ipc::Trust::kickoffd().unwrap(),
        )
        .await
        .unwrap();
        assert!(matches!(
            client.call(kickoff_ipc::CliCommand::Status).await,
            Ok(kickoff_ipc::Reply::Refused(kickoff_ipc::Refusal::Failed))
        ));
        let identity =
            kickoff_secret::key::IdentityKey::new(iroh_base::SecretKey::from_bytes(&[7; 32]));
        let mut invites = kickoff_wire::Invites::new(&identity).unwrap();
        let ticket = kickoff_secret::Secret::new(kickoff_wire::Ticket {
            door: iroh_base::EndpointAddr::new(identity.public())
                .with_relay_url("https://relay.example./".parse().unwrap()),
            cap: invites.issue(&identity, None, Instant::now()).unwrap(),
        });
        let text =
            kickoff_ipc::TicketText::new(kickoff_wire::encode_ticket(&ticket).unwrap()).unwrap();
        assert!(
            matches!(
                client.call(kickoff_ipc::CliCommand::Join(text)).await,
                Ok(kickoff_ipc::Reply::Refused(kickoff_ipc::Refusal::Failed))
            ),
            "the installed facade/worker must receive a genuine protected ticket command"
        );
    });
}

#[test]
fn si_7_installed_daemon_modes_authenticate_with_hardening() {
    let install = Install::new("modes");
    let mut daemon = launch(&install, Launch::NullStdio, None);
    install.serve_one_client(&mut daemon);
    // Worker mode alone, without an inherited facade pair, must fail closed.
    assert!(
        !Command::new(&install.daemon)
            .arg("--ipc-worker")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn si_36_kickoffd_closes_a_descriptor_its_launcher_leaked() {
    let install = Install::new("leak");
    let canary = install.base.join(CANARY);
    std::fs::write(&canary, b"").unwrap();
    let leaked = std::fs::File::options().append(true).open(&canary).unwrap();
    let mut daemon = launch(&install, Launch::NullStdio, Some(&leaked));
    drop(leaked);
    install.serve_one_client(&mut daemon);
    let held = write_through(&daemon.pid(), &canary);
    assert_eq!(
        (held, std::fs::read(&canary).unwrap()),
        (0, Vec::new()),
        "kickoffd kept a writable descriptor its launcher leaked"
    );
}

#[test]
fn si_36_kickoffd_descriptor_table_equals_its_allowlist() {
    let install = Install::new("inventory");
    let canary = install.base.join(CANARY);
    std::fs::write(&canary, b"").unwrap();
    let leaked = std::fs::File::options().append(true).open(&canary).unwrap();
    let mut daemon = launch(&install, Launch::ClosedStdio, Some(&leaked));
    drop(leaked);
    install.serve_one_client(&mut daemon);
    // Closed stdio comes back as /dev/null, so no later open can take 0-2.
    // Above it: the runtime, the listener and the worker's control pair.
    let mut expected = runtime_descriptors();
    expected.push(format!(
        "unix listener {}",
        install.dir.socket_path().display()
    ));
    expected.push("unix stream connected".to_owned());
    expected.sort();
    let expected = (vec!["/dev/null".to_owned(); 3], expected);
    // The client's connection lease closes after the client exits.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let table = descriptors(&daemon.pid());
        let actual = table.as_ref().map(split_stdio);
        if actual.as_ref().is_ok_and(|actual| *actual == expected) {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "kickoffd's descriptors are not its allowlist\n  expected {expected:?}\n  actual   {table:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// What kickoffd's runtime opens, measured in a fresh process with the same
/// tokio build and settings, so the allowlist follows tokio's features.
fn runtime_descriptors() -> Vec<String> {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "runtime_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(RUNTIME_HELPER, "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    // libtest prints `test runtime_helper ... ` on the first line's start.
    let kinds: Vec<String> = stdout
        .lines()
        .filter_map(|line| Some(line.split_once(RUNTIME_LINE)?.1.to_owned()))
        .collect();
    assert!(!kinds.is_empty(), "the runtime helper reported nothing");
    kinds
}

#[test]
fn runtime_helper() {
    if std::env::var_os(RUNTIME_HELPER).is_none() {
        return;
    }
    let before = descriptors("self").unwrap();
    // As kickoffd builds it.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut opened: Vec<String> = descriptors("self").unwrap().into_values().collect();
    drop(runtime);
    for kind in before.values() {
        if let Some(i) = opened.iter().position(|k| k == kind) {
            opened.remove(i);
        }
    }
    for kind in opened {
        println!("{RUNTIME_LINE}{kind}");
    }
    std::io::stdout().flush().unwrap();
}

/// stdio by number, then everything above it sorted.
fn split_stdio(table: &BTreeMap<i32, String>) -> (Vec<String>, Vec<String>) {
    let stdio = (0..3)
        .map(|fd| {
            table
                .get(&fd)
                .cloned()
                .unwrap_or_else(|| "closed".to_owned())
        })
        .collect();
    let mut rest: Vec<String> = table
        .iter()
        .filter(|(fd, _)| **fd >= 3)
        .map(|(_, kind)| kind.clone())
        .collect();
    rest.sort();
    (stdio, rest)
}

/// What each descriptor of `pid` is: Unix sockets by their kernel entry,
/// anonymous inodes by kind, `/dev/null` by inode, anything else by path.
fn descriptors(pid: &str) -> std::io::Result<BTreeMap<i32, String>> {
    let null = std::fs::metadata("/dev/null")?;
    let unix = unix_sockets(pid)?;
    let mut table = BTreeMap::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        let path = entry?.path();
        let fd: i32 = path
            .file_name()
            .and_then(|name| name.to_str()?.parse().ok())
            .ok_or(std::io::ErrorKind::InvalidData)?;
        let target = std::fs::read_link(&path)?;
        let target = target.to_string_lossy();
        let kind = if let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
        {
            unix.get(inode)
                .cloned()
                .unwrap_or_else(|| "socket, not unix".to_owned())
        } else if target.starts_with("anon_inode:") {
            target.into_owned()
        } else {
            let meta = std::fs::metadata(&path)?;
            if (meta.dev(), meta.ino()) == (null.dev(), null.ino()) {
                "/dev/null".to_owned()
            } else {
                format!("file {target}")
            }
        };
        table.insert(fd, kind);
    }
    Ok(table)
}

/// `/proc/<pid>/net/unix` by inode: listeners with their path, others by
/// type and state.
fn unix_sockets(pid: &str) -> std::io::Result<BTreeMap<String, String>> {
    const ACCEPTCON: u32 = 0x1_0000;
    let text = std::fs::read_to_string(format!("/proc/{pid}/net/unix"))?;
    let mut sockets = BTreeMap::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [_, _, _, flags, kind, state, inode, rest @ ..] = fields.as_slice() else {
            continue;
        };
        let flags = u32::from_str_radix(flags, 16).unwrap_or(0);
        let path = rest.first().copied().unwrap_or("");
        let described = match (*kind, *state) {
            _ if flags & ACCEPTCON != 0 => format!("unix listener {path}"),
            ("0001", "03") if path.is_empty() => "unix stream connected".to_owned(),
            _ => format!("unix type {kind} state {state} {path}"),
        };
        sockets.insert((*inode).to_owned(), described);
    }
    Ok(sockets)
}

/// The SI-36 test hook: writes through every descriptor of `pid` that names
/// `canary`, and returns how many there were.
fn write_through(pid: &str, canary: &Path) -> usize {
    let canary = std::fs::metadata(canary).unwrap();
    let mut held: usize = 0;
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd")).unwrap() {
        let path = entry.unwrap().path();
        if let Ok(target) = std::fs::metadata(&path)
            && (target.dev(), target.ino()) == (canary.dev(), canary.ino())
        {
            let mut file = std::fs::File::options().append(true).open(&path).unwrap();
            file.write_all(b"leaked").unwrap();
            held = held.saturating_add(1);
        }
    }
    held
}

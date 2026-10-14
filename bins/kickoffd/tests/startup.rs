//! The installed executable's two modes use the same seam as the IPC tests,
//! and what it holds after startup is only what it opened itself (SI-36).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::arithmetic_side_effects
)]
#[path = "../../../tests/support/exec.rs"]
mod exec;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CANARY: &str = "leak-canary";
/// Where a launcher leaks the canaries in kickoffd: fresh numbers, since
/// dup2 onto the same number would keep close-on-exec.
const LEAKED_FD: i32 = 200;
const LEAKED_SOCKET: i32 = 201;
const LEAKED_EVENTFD: i32 = 202;
const LEAKED_EPOLL: i32 = 203;
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
/// `launch` says, each leak without close-on-exec at its number, nothing else.
fn launch(install: &Install, launch: Launch, leaks: &[(BorrowedFd<'_>, i32)]) -> Daemon {
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
    for (leak, number) in leaks {
        assert_ne!(leak.as_raw_fd(), *number);
        actions.add_dup2(leak.as_raw_fd(), *number).unwrap();
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
    let mut daemon = launch(&install, Launch::NullStdio, &[]);
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
    let mut daemon = launch(&install, Launch::NullStdio, &[(leaked.as_fd(), LEAKED_FD)]);
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
    let canaries = Canaries::new(&install);
    let mut daemon = launch(&install, Launch::ClosedStdio, &canaries.leaks());
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
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "kickoffd's descriptors are not its allowlist\n  expected {expected:?}\n  actual   {table:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    canaries.assert_absent_from(&daemon.pid());
    assert_own_descriptors(&daemon.pid(), &install.daemon);
}

/// One leaked descriptor of each kind kickoffd holds above stdio, so a
/// leaked one kept in place of its own still shows: kind strings and counts
/// cannot tell an inherited socket, eventfd or epoll from kickoffd's own.
struct Canaries {
    file: std::fs::File,
    /// Leaked; its peer stays in this process.
    socket: std::os::unix::net::UnixStream,
    peer: std::os::unix::net::UnixStream,
    eventfd: OwnedFd,
    /// Watches `peer`, which kickoffd never holds.
    epoll: OwnedFd,
}

impl Canaries {
    fn new(install: &Install) -> Canaries {
        use rustix::event::{EventfdFlags, epoll, eventfd};
        let path = install.base.join(CANARY);
        std::fs::write(&path, b"").unwrap();
        let file = std::fs::File::options().append(true).open(&path).unwrap();
        let (socket, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let eventfd = eventfd(0, EventfdFlags::CLOEXEC).unwrap();
        let epoll = epoll::create(epoll::CreateFlags::CLOEXEC).unwrap();
        epoll::add(
            &epoll,
            &peer,
            epoll::EventData::new_u64(0),
            epoll::EventFlags::IN,
        )
        .unwrap();
        Canaries {
            file,
            socket,
            peer,
            eventfd,
            epoll,
        }
    }

    fn leaks(&self) -> [(BorrowedFd<'_>, i32); 4] {
        [
            (self.file.as_fd(), LEAKED_FD),
            (self.socket.as_fd(), LEAKED_SOCKET),
            (self.eventfd.as_fd(), LEAKED_EVENTFD),
            (self.epoll.as_fd(), LEAKED_EPOLL),
        ]
    }

    /// No descriptor of `pid` is one of these, by socket inode or eventfd id;
    /// a kept canary epoll fails [`assert_own_descriptors`].
    fn assert_absent_from(&self, pid: &str) {
        let sockets = [inode(&self.socket), inode(&self.peer)];
        let eventfd = fdinfo_field("self", self.eventfd.as_raw_fd(), "eventfd-id:");
        for (fd, target) in links(pid) {
            assert!(
                !sockets
                    .iter()
                    .any(|ino| target == format!("socket:[{ino}]")),
                "kickoffd holds the leaked socket at {fd}"
            );
            if target == "anon_inode:[eventfd]" {
                assert_ne!(
                    fdinfo_field(pid, fd, "eventfd-id:"),
                    eventfd,
                    "kickoffd holds the leaked eventfd at {fd}"
                );
            }
        }
    }
}

/// Each anonymous descriptor of kickoffd is its own. Every epoll entry names
/// a descriptor kickoffd holds at that number with that inode, and every
/// eventfd is one an epoll watches. Each connected socket pairs with one
/// that neither kickoffd nor its launcher (this process) holds: the worker's
/// end, whose own table is unreadable because the worker is nondumpable.
/// kickoffd's only child is that worker.
fn assert_own_descriptors(pid: &str, daemon: &Path) {
    let table = links(pid);
    let mut watched = Vec::new();
    for (fd, target) in &table {
        if target != "anon_inode:[eventpoll]" {
            continue;
        }
        for (tfd, ino) in epoll_entries(pid, *fd) {
            let held = std::fs::metadata(format!("/proc/{pid}/fd/{tfd}")).map(|m| m.ino());
            assert_eq!(
                held.ok(),
                Some(ino),
                "kickoffd's epoll {fd} watches {tfd}, which is not kickoffd's descriptor"
            );
            watched.push(tfd);
        }
    }
    let ours = links("self");
    let mut paired = 0;
    for (fd, target) in &table {
        if target == "anon_inode:[eventfd]" {
            assert!(
                watched.contains(fd),
                "kickoffd's eventfd {fd} is not one its runtime watches"
            );
        }
        let Some(ino) = socket_inode(target) else {
            continue;
        };
        let Some(peer) = unix_peer(ino) else {
            continue;
        };
        assert_eq!(unix_peer(peer), Some(ino), "socket {fd} is not paired");
        let peer = format!("socket:[{peer}]");
        assert!(
            !table.values().chain(ours.values()).any(|t| *t == peer),
            "kickoffd's socket {fd} is connected to kickoffd or its launcher"
        );
        paired += 1;
    }
    assert_eq!(paired, 1, "kickoffd's control socket was not found paired");
    let children = children(pid);
    assert_eq!(children.len(), 1, "kickoffd's children: {children:?}");
    let mut worker = daemon.as_os_str().as_bytes().to_vec();
    worker.extend_from_slice(b"\0--ipc-worker\0");
    assert_eq!(
        std::fs::read(format!("/proc/{}/cmdline", children[0])).unwrap(),
        worker,
        "kickoffd's child is not its worker"
    );
}

/// Link targets of `pid`'s descriptors.
fn links(pid: &str) -> BTreeMap<i32, String> {
    let mut table = BTreeMap::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd")).unwrap() {
        let path = entry.unwrap().path();
        let Ok(target) = std::fs::read_link(&path) else {
            // Closed while listed.
            continue;
        };
        let fd = path.file_name().unwrap().to_str().unwrap().parse().unwrap();
        table.insert(fd, target.to_string_lossy().into_owned());
    }
    table
}

fn inode(socket: &std::os::unix::net::UnixStream) -> u64 {
    rustix::fs::fstat(socket).unwrap().st_ino
}

fn socket_inode(target: &str) -> Option<u32> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn fdinfo_field(pid: &str, fd: i32, field: &str) -> String {
    let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")).unwrap();
    let value = info
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .unwrap_or_else(|| panic!("no {field} in fdinfo {fd} of {pid}: {info}"));
    value.trim().to_owned()
}

/// (target number, target inode) of each entry of epoll `fd` in `pid`.
fn epoll_entries(pid: &str, fd: i32) -> Vec<(i32, u64)> {
    let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")).unwrap();
    info.lines()
        .filter_map(|line| line.strip_prefix("tfd:"))
        .map(|entry| {
            let mut words = entry.split_whitespace();
            let tfd = words.next().unwrap().parse().unwrap();
            let ino = words.find_map(|word| word.strip_prefix("ino:")).unwrap();
            (tfd, u64::from_str_radix(ino, 16).unwrap())
        })
        .collect()
}

/// Live processes whose parent is `pid`.
fn children(pid: &str) -> Vec<String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap() {
        let name = entry.unwrap().file_name();
        let Some(child) = name
            .to_str()
            .filter(|n| n.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{child}/stat")) else {
            continue;
        };
        let mut fields = stat.rsplit_once(')').unwrap().1.split_whitespace();
        let state = fields.next();
        if fields.next() == Some(pid) && state != Some("Z") {
            found.push(child.to_owned());
        }
    }
    found
}

/// The peer inode of Unix socket `inode`, or `None` if it has none, from
/// NETLINK_SOCK_DIAG (unix_diag_req with UDIAG_SHOW_PEER).
fn unix_peer(inode: u32) -> Option<u32> {
    use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketType, netlink};
    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const NLM_F_REQUEST: u16 = 1;
    const NLMSG_ERROR: u16 = 2;
    const UDIAG_SHOW_PEER: u32 = 4;
    const UNIX_DIAG_PEER: u16 = 2;
    let diag = rustix::net::socket(
        AddressFamily::NETLINK,
        SocketType::DGRAM,
        Some(netlink::SOCK_DIAG),
    )
    .unwrap();
    let mut request = Vec::new();
    request.extend(40u32.to_ne_bytes());
    request.extend(SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    request.extend(NLM_F_REQUEST.to_ne_bytes());
    request.extend([0; 8]);
    request.extend([1, 0, 0, 0]); // AF_UNIX, protocol, padding
    request.extend(u32::MAX.to_ne_bytes()); // every state
    request.extend(inode.to_ne_bytes());
    request.extend(UDIAG_SHOW_PEER.to_ne_bytes());
    request.extend([0xff; 8]); // no cookie
    rustix::net::send(&diag, &request, SendFlags::empty()).unwrap();
    let mut reply = vec![0u8; 8192];
    let (len, _) = rustix::net::recv(&diag, &mut reply[..], RecvFlags::empty()).unwrap();
    let reply = &reply[..len];
    let u16_at = |at: usize| u16::from_ne_bytes(reply[at..at + 2].try_into().unwrap());
    let u32_at = |at: usize| u32::from_ne_bytes(reply[at..at + 4].try_into().unwrap());
    assert_ne!(u16_at(4), NLMSG_ERROR, "sock_diag refused socket {inode}");
    assert_eq!(u32_at(20), inode, "sock_diag answered for another socket");
    // nlmsghdr (16) and unix_diag_msg (16), then 4-aligned attributes.
    let mut at = 32;
    while at + 8 <= reply.len() {
        let attr_len = usize::from(u16_at(at));
        if u16_at(at + 2) == UNIX_DIAG_PEER {
            return Some(u32_at(at + 4));
        }
        assert!(attr_len >= 4, "malformed sock_diag attribute");
        at += attr_len.next_multiple_of(4);
    }
    None
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

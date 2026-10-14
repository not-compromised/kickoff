//! Actual subprocess handoff, hostile control capabilities, and lifetime.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout
)]
mod common;
use common::*;
use kickoff_ipc::role::Cli;
use kickoff_ipc::{
    CliCommand, Facade, IpcError, Reply, Request, Trust, Worker, WorkerLaunch, connect,
};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const MODE: &str = "KIPC_FACADE_MODE";
const BASE: &str = "KIPC_FACADE_BASE";
/// Simulates the reset of "dumpable" that a credential change performs:
/// `before-accept` or `after-accept`.
const REDUMP: &str = "KIPC_FACADE_REDUMP";
const CANARY: &str = "leak-canary";

fn command(mode: &str) -> Command {
    let mut command = Command::new(me());
    command
        .args([
            "--exact",
            "process_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, mode);
    command
}

fn launch(mode: &str) -> WorkerLaunch {
    let mut worker = WorkerLaunch::new(me());
    worker
        .args([
            "--exact",
            "process_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, mode);
    worker
}

fn emit(message: &str) {
    println!("KIPC {message}");
    std::io::stdout().flush().unwrap();
}

#[test]
fn process_helper() {
    kickoff_ipc::run_core_probe_if_requested().unwrap();
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    if let Some(next) = launcher_target(&mode) {
        // A launcher that leaks a descriptor or imposes a zero hard core
        // limit hands both to the facade across exec.
        let _leaked = if mode == "leaky-launcher" {
            // Writable, as SI-36's inheritance test requires.
            let base = std::env::var_os(BASE).unwrap();
            let leaked = std::fs::File::options()
                .append(true)
                .open(std::path::Path::new(&base).join(CANARY))
                .unwrap();
            rustix::io::fcntl_setfd(&leaked, rustix::io::FdFlags::empty()).unwrap();
            Some(leaked)
        } else {
            let zero = rustix::process::Rlimit {
                current: Some(0),
                maximum: Some(0),
            };
            rustix::process::setrlimit(rustix::process::Resource::Core, zero).unwrap();
            None
        };
        let error = command(next).exec();
        panic!("exec failed: {error}");
    }
    if mode == "probe-direct" || mode == "probe-direct-leak" {
        probe_directly(mode == "probe-direct-leak");
        return;
    }
    if mode == "early-core-policy" {
        let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
        assert_eq!(limit.current, Some(1));
        assert_eq!(limit.maximum, Some(1));
        emit("early-policy");
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        match mode.as_str() {
            "facade" | "rogue-client-policy" => {
                let base = std::env::var_os(BASE).unwrap();
                let dir = kickoff_ipc::RuntimeDir::open_in(std::path::Path::new(&base)).unwrap();
                let clients = if mode == "rogue-client-policy" {
                    Trust::same_user(&[&other_exe()]).unwrap()
                } else {
                    trust_me()
                };
                let worker_command = launch("worker");
                let facade = Facade::spawn(&dir, clients, worker_command).await.unwrap();
                let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
                assert_eq!(limit.current, Some(1));
                assert_eq!(limit.maximum, Some(1));
                assert_eq!(
                    rustix::process::dumpable_behavior().unwrap(),
                    rustix::process::DumpableBehavior::Dumpable
                );
                emit("ready");
                let _ = facade.run().await;
            }
            "worker" => {
                let base = std::env::var_os(BASE).map(std::path::PathBuf::from);
                if let Some(base) = &base {
                    std::fs::write(base.join("worker.pid"), std::process::id().to_string())
                        .unwrap();
                    write_through_leaked_canary(base);
                }
                kickoff_secret::harden_process().unwrap();
                assert_eq!(
                    rustix::process::dumpable_behavior().unwrap(),
                    rustix::process::DumpableBehavior::NotDumpable
                );
                let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
                assert_eq!(limit.current, Some(0));
                assert_eq!(limit.maximum, Some(0));
                let mut worker = Worker::inherit(trust_me(), trust_me()).await.unwrap();
                let redump = std::env::var(REDUMP).unwrap_or_default();
                if redump == "before-accept" {
                    make_dumpable();
                }
                let record = move |error: IpcError| {
                    if let Some(base) = &base {
                        std::fs::write(base.join("worker.result"), format!("{error:?}")).unwrap();
                    }
                };
                loop {
                    let mut channel = match worker.accept().await {
                        Ok(channel) => channel,
                        Err(error) => {
                            record(error);
                            break;
                        }
                    };
                    let redump = redump.clone();
                    let record = record.clone();
                    tokio::spawn(async move {
                        if redump == "after-accept" {
                            make_dumpable();
                        }
                        loop {
                            let request = match channel.recv().await {
                                Ok(request) => request,
                                Err(error) => {
                                    record(error);
                                    break;
                                }
                            };
                            let reply = match request {
                                Request::Cli(CliCommand::Join(ticket)) => Reply::Invite(ticket),
                                _ => Reply::Done,
                            };
                            if channel.reply(reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
            "receiver" | "rogue-receiver" | "rogue-worker" | "bad-ready-version" => {
                let facade = if mode == "rogue-receiver" {
                    Trust::same_user(&[&other_exe()]).unwrap()
                } else {
                    trust_me()
                };
                if mode == "rogue-worker" || mode == "bad-ready-version" {
                    std::io::stdin()
                        .as_fd()
                        .try_clone_to_owned()
                        .map(|fd| {
                            let mut socket = std::os::unix::net::UnixStream::from(fd);
                            let version = if mode == "bad-ready-version" {
                                kickoff_ipc::PROTOCOL_VERSION.checked_add(1).unwrap()
                            } else {
                                kickoff_ipc::PROTOCOL_VERSION
                            };
                            let [high, low] = version.to_be_bytes();
                            socket.write_all(&[high, low, 1]).unwrap();
                            std::thread::sleep(Duration::from_millis(300));
                        })
                        .unwrap();
                    return;
                }
                match Worker::inherit(facade, trust_me()).await {
                    Ok(mut worker) => {
                        emit("accepted");
                        let _ = worker.accept().await;
                    }
                    Err(_) => emit("rejected"),
                }
            }
            "racing-facade" => {
                let base = std::path::PathBuf::from(std::env::var_os(BASE).unwrap());
                let dir = kickoff_ipc::RuntimeDir::open_in(&base).unwrap();
                let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let racer = {
                    let stop = std::sync::Arc::clone(&stop);
                    let socket = dir.socket_path().to_path_buf();
                    let canary = base.join(CANARY);
                    std::thread::spawn(move || race_descriptors(&socket, &canary, &stop))
                };
                let facade = Facade::spawn(&dir, trust_me(), launch("worker")).await;
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                let opened = racer.join().unwrap();
                facade.unwrap();
                emit(&format!("raced {opened}"));
            }
            "facade-zero-core" => {
                let base = std::env::var_os(BASE).unwrap();
                let dir = kickoff_ipc::RuntimeDir::open_in(std::path::Path::new(&base)).unwrap();
                let worker = launch("worker");
                match Facade::spawn(&dir, trust_me(), worker).await {
                    Ok(_facade) => {
                        let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
                        assert_eq!((limit.current, limit.maximum), (Some(0), Some(0)));
                        emit("ready-zero");
                    }
                    Err(IpcError::CoreDumpsEnabled) => emit("refused-core-dumps"),
                    Err(error) => emit(&format!("error {error:?}")),
                }
            }
            "not-parent" => {
                // This pair was created by this child, rather than inherited
                // from its parent. Matching uid and executable alone is not
                // sufficient to bind a worker to the facade's lifecycle.
                let (_tx, rx) = std::os::unix::net::UnixStream::pair().unwrap();
                let result = Worker::from_control(rx.into(), trust_me(), trust_me()).await;
                emit(if result.is_err() {
                    "rejected"
                } else {
                    "accepted"
                });
            }
            _ => panic!("unknown test mode"),
        }
    });
}

/// The SI-36 test hook: writes through every inherited descriptor that names
/// the launcher's canary. A worker that received none leaves it empty.
fn write_through_leaked_canary(base: &std::path::Path) {
    use std::os::unix::fs::MetadataExt;
    let Ok(canary) = std::fs::metadata(base.join(CANARY)) else {
        return;
    };
    let fds: Vec<_> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    for fd in fds {
        if let Ok(target) = std::fs::metadata(&fd)
            && (target.dev(), target.ino()) == (canary.dev(), canary.ino())
        {
            let mut file = std::fs::File::options().append(true).open(&fd).unwrap();
            file.write_all(b"leaked").unwrap();
        }
    }
}

/// Opens descriptors to the canary without close-on-exec, as fast as it can,
/// from when the listener exists (the probe is done) until `stop`. Returns
/// how many it opened.
fn race_descriptors(
    socket: &std::path::Path,
    canary: &std::path::Path,
    stop: &std::sync::atomic::AtomicBool,
) -> usize {
    use std::sync::atomic::Ordering;
    while !socket.exists() {
        if stop.load(Ordering::Relaxed) {
            return 0;
        }
        std::hint::spin_loop();
    }
    let mut held = std::collections::VecDeque::new();
    let mut opened: usize = 0;
    while !stop.load(Ordering::Relaxed) {
        let file = std::fs::File::options().append(true).open(canary).unwrap();
        rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty()).unwrap();
        held.push_back(file);
        if held.len() > 64 {
            held.pop_front();
        }
        opened = opened.saturating_add(1);
    }
    opened
}

/// What a uid, gid, fsuid or capability change does to a hardened process
/// when `fs.suid_dumpable` is 1 or 2.
fn make_dumpable() {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::Dumpable).unwrap();
}

fn launcher_target(mode: &str) -> Option<&'static str> {
    match mode {
        "leaky-launcher" => Some("facade"),
        "zero-core-launcher" => Some("facade-zero-core"),
        _ => None,
    }
}

/// Runs the installed probe as the facade does, except that one descriptor
/// may be left open. Everything else this helper inherited, including
/// whatever the test runner leaked, is closed in the probe.
fn probe_directly(leak: bool) {
    use nix::spawn::{PosixSpawnAttr, PosixSpawnFileActions, posix_spawn};
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::DirBuilderExt;
    let scratch = std::path::Path::new(&std::env::var_os(BASE).unwrap()).join("probe-scratch");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&scratch)
        .unwrap();
    let null = std::fs::File::open("/dev/null").unwrap();
    let kept = std::fs::File::open("/dev/null").unwrap();
    let mut actions = PosixSpawnFileActions::init().unwrap();
    for target in 0..3 {
        actions.add_dup2(null.as_raw_fd(), target).unwrap();
    }
    if leak {
        // dup2 onto itself would keep close-on-exec; a fresh number clears it.
        actions.add_dup2(kept.as_raw_fd(), 200).unwrap();
    }
    let open: Vec<i32> = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect();
    for fd in open.into_iter().filter(|fd| *fd >= 3 && *fd != 200) {
        actions.add_close(fd).unwrap();
    }
    let program = CString::new(me().as_os_str().as_bytes()).unwrap();
    let argv = [
        program.clone(),
        c"--exact".to_owned(),
        c"process_helper".to_owned(),
        c"--nocapture".to_owned(),
        c"--test-threads=1".to_owned(),
    ];
    let mut marker = b"KICKOFF_IPC_CORE_PROBE=".to_vec();
    marker.extend_from_slice(scratch.as_os_str().as_bytes());
    let envp = [CString::new(marker).unwrap()];
    let attr = PosixSpawnAttr::init().unwrap();
    let pid = posix_spawn(program.as_c_str(), &actions, &attr, &argv, &envp).unwrap();
    let pid = rustix::process::Pid::from_raw(pid.as_raw()).unwrap();
    let (_, status) = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())
        .unwrap()
        .unwrap();
    drop((null, kept));
    let dumped = status.as_raw() & 0x80 != 0;
    emit(match (status.terminating_signal(), status.exit_status()) {
        (Some(6), _) if !dumped => "crashed",
        (None, Some(code)) if code != 0 => "refused",
        _ => "other",
    });
}

struct Running {
    child: Child,
    output: BufReader<std::process::ChildStdout>,
    worker: Option<OwnedFd>,
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(worker) = &self.worker {
            let _ = rustix::process::pidfd_send_signal(worker, rustix::process::Signal::KILL);
        }
    }
}
impl Running {
    fn line(&mut self) -> String {
        loop {
            let mut line = String::new();
            assert_ne!(
                self.output.read_line(&mut line).unwrap(),
                0,
                "helper exited before report"
            );
            if let Some((_, report)) = line.split_once("KIPC ") {
                return report.trim().to_owned();
            }
        }
    }
}
fn helper(base: &TempBase, mode: &str) -> Running {
    helper_with(base, mode, &[])
}

fn helper_with(base: &TempBase, mode: &str, envs: &[(&str, &str)]) -> Running {
    let mut child = command(mode)
        .env(BASE, base.path())
        .envs(envs.iter().copied())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let output = BufReader::new(child.stdout.take().unwrap());
    Running {
        child,
        output,
        worker: None,
    }
}

fn facade(base: &TempBase, mode: &str) -> Running {
    facade_with(base, mode, &[])
}

fn facade_with(base: &TempBase, mode: &str, envs: &[(&str, &str)]) -> Running {
    let mut running = helper_with(base, mode, envs);
    assert_eq!(running.line(), "ready");
    let pid = std::fs::read_to_string(base.path().join("worker.pid"))
        .unwrap()
        .parse::<i32>()
        .unwrap();
    running.worker = Some(
        rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(pid).unwrap(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap(),
    );
    running
}

#[tokio::test]
async fn si_7_transferred_socket_keeps_listener_creator_identity() {
    if !installed_fixture("si_7_transferred_socket_keeps_listener_creator_identity") {
        return;
    }
    let base = TempBase::new();
    let dir = base.dir();
    let running = facade(&base, "facade");
    let mut client = connect::<Cli>(&dir, &trust_me()).await.unwrap();
    assert_eq!(
        client.server().pid,
        i32::try_from(running.child.id()).unwrap()
    );
    let reply = client
        .call(CliCommand::Join(canary_ticket("kickoff1RANDOMCANARY123")))
        .await
        .unwrap();
    let Reply::Invite(ticket) = reply else {
        panic!("ticket did not reach worker");
    };
    assert!(ticket.secret().ct_eq(b"kickoff1RANDOMCANARY123"));
}

#[tokio::test]
async fn si_30_facade_and_worker_keep_core_hard_limits() {
    let base = TempBase::new();
    let dir = base.dir();
    let _running = facade(&base, "facade");
    let mut client = connect::<Cli>(&dir, &trust_me()).await.unwrap();
    assert!(matches!(
        client.call(CliCommand::Status).await,
        Ok(Reply::Done)
    ));
    // Both subprocesses assert their current AND hard core limits. The
    // worker also asserts NotDumpable, while the facade stays Dumpable.
}

#[tokio::test]
async fn si_7_facade_refuses_rogue_clients_before_worker_payload() {
    let base = TempBase::new();
    let dir = base.dir();
    let _running = facade(&base, "rogue-client-policy");
    let got = connect::<Cli>(&dir, &trust_me()).await;
    assert_eq!(got.err(), Some(IpcError::Closed));
}

#[tokio::test]
async fn si_7_facade_death_closes_transferred_channels() {
    let base = TempBase::new();
    let dir = base.dir();
    let mut running = facade(&base, "facade");
    let mut client = connect::<Cli>(&dir, &trust_me()).await.unwrap();
    assert!(matches!(
        client.call(CliCommand::Status).await,
        Ok(Reply::Done)
    ));
    running.child.kill().unwrap();
    running.child.wait().unwrap();
    // Waiting for EOF proves closure rather than merely failing a future
    // authentication check. A late Status must not reach an orphan worker.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let result =
        tokio::time::timeout(Duration::from_secs(2), client.call(CliCommand::Status)).await;
    assert!(
        result.is_ok_and(|result| result.is_err()),
        "orphan worker still serves an established connection"
    );
}

fn receiver(mode: &str, fd: OwnedFd) -> Running {
    let mut child = command(mode)
        .stdin(Stdio::from(fd))
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let output = BufReader::new(child.stdout.take().unwrap());
    Running {
        child,
        output,
        worker: None,
    }
}

#[test]
fn si_7_worker_refuses_rogue_facade_executable() {
    let (_tx, rx) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut running = receiver("rogue-receiver", rx.into());
    assert_eq!(running.line(), "rejected");
}

#[test]
fn si_7_worker_refuses_control_not_created_by_parent() {
    let mut child = command("not-parent")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let output = BufReader::new(child.stdout.take().unwrap());
    let mut running = Running {
        child,
        output,
        worker: None,
    };
    assert_eq!(running.line(), "rejected");
}

#[test]
fn si_7_worker_refuses_datagram_control_capability() {
    let (_tx, rx) = rustix::net::socketpair(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::DGRAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    let mut running = receiver("receiver", rx);
    assert_eq!(running.line(), "rejected");
}

#[test]
fn si_7_worker_refuses_named_control_capability() {
    let base = TempBase::new();
    let path = base.path().join("control");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let tx = std::os::unix::net::UnixStream::connect(&path).unwrap();
    let (rx, _) = listener.accept().unwrap();
    let mut running = receiver("receiver", rx.into());
    assert_eq!(running.line(), "rejected");
    drop(tx);
}

fn send_control(tx: &std::os::unix::net::UnixStream, fds: &[std::os::fd::BorrowedFd<'_>]) {
    let mut space = [std::mem::MaybeUninit::uninit(); 256];
    let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() {
        assert!(ancillary.push(rustix::net::SendAncillaryMessage::ScmRights(fds)));
    }
    rustix::net::sendmsg(
        tx,
        &[std::io::IoSlice::new(&[
            kickoff_ipc::PROTOCOL_VERSION.to_be_bytes()[0],
            kickoff_ipc::PROTOCOL_VERSION.to_be_bytes()[1],
            2,
        ])],
        &mut ancillary,
        rustix::net::SendFlags::NOSIGNAL,
    )
    .unwrap();
}

#[test]
fn si_7_worker_closes_wrong_descriptor_count_and_type() {
    for count in [0usize, 1, 2, 3, 32] {
        let (tx, rx) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut running = receiver("receiver", rx.into());
        assert_eq!(running.line(), "accepted");
        let (pipe_r, pipe_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let fds = vec![pipe_w.as_fd(); count];
        send_control(&tx, &fds);
        drop(fds);
        drop(pipe_w);
        assert!(running.child.wait().unwrap().success());
        rustix::io::ioctl_fionbio(&pipe_r, true).unwrap();
        assert_eq!(
            rustix::io::read(&pipe_r, &mut [0u8; 1]).unwrap(),
            0,
            "received descriptor leaked at count {count}"
        );
    }
}

#[tokio::test]
async fn si_7_transferred_client_still_refuses_ancillary() {
    let base = TempBase::new();
    let dir = base.dir();
    let _running = facade(&base, "facade");
    let mut stream = tokio::net::UnixStream::connect(dir.socket_path())
        .await
        .unwrap();
    let (pipe_r, pipe_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let mut space = [std::mem::MaybeUninit::uninit(); 64];
    let mut control = rustix::net::SendAncillaryBuffer::new(&mut space);
    let fds = [pipe_w.as_fd()];
    assert!(control.push(rustix::net::SendAncillaryMessage::ScmRights(&fds)));
    rustix::net::sendmsg(
        &stream,
        &[std::io::IoSlice::new(&hello(
            kickoff_ipc::PROTOCOL_VERSION,
            1,
        ))],
        &mut control,
        rustix::net::SendFlags::NOSIGNAL,
    )
    .unwrap();
    drop(pipe_w);
    assert!(closed_within(&mut stream, Duration::from_secs(2)).await);
    rustix::io::ioctl_fionbio(&pipe_r, true).unwrap();
    assert_eq!(rustix::io::read(&pipe_r, &mut [0u8; 1]).unwrap(), 0);
}

#[tokio::test]
async fn si_23_facade_bounds_outstanding_channels() {
    let base = TempBase::new();
    let dir = base.dir();
    let _running = facade(&base, "facade");
    let mut clients = Vec::new();
    for _ in 0..kickoff_ipc::MAX_CHANNELS {
        clients.push(connect::<Cli>(&dir, &trust_me()).await.unwrap());
    }
    let trust = trust_me();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), connect::<Cli>(&dir, &trust))
            .await
            .is_err()
    );
    drop(clients.pop());
    let mut client = connect::<Cli>(&dir, &trust).await.unwrap();
    assert!(matches!(
        client.call(CliCommand::Status).await,
        Ok(Reply::Done)
    ));
}

#[tokio::test]
async fn si_7_worker_refuses_extra_control_descriptor() {
    let base = TempBase::new();
    let dir = base.dir();
    let listener = std::os::unix::net::UnixListener::bind(dir.socket_path()).unwrap();
    let (tx, rx) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut running = receiver("receiver", rx.into());
    assert_eq!(running.line(), "accepted");
    let trust = trust_me();
    let client = tokio::spawn(async move { connect::<Cli>(&dir, &trust).await });
    let socket = tokio::task::spawn_blocking(move || listener.accept().unwrap().0)
        .await
        .unwrap();
    let (_lease_tx, lease_rx) = std::os::unix::net::UnixStream::pair().unwrap();
    let (pipe_r, pipe_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    send_control(&tx, &[pipe_w.as_fd(), socket.as_fd(), lease_rx.as_fd()]);
    drop(socket);
    drop(lease_rx);
    drop(pipe_w);
    let result = tokio::time::timeout(Duration::from_secs(2), client)
        .await
        .unwrap()
        .unwrap();
    assert!(
        result.is_err(),
        "worker accepted three descriptors instead of exactly two"
    );
    assert!(running.child.wait().unwrap().success());
    rustix::io::ioctl_fionbio(&pipe_r, true).unwrap();
    assert_eq!(rustix::io::read(&pipe_r, &mut [0u8; 1]).unwrap(), 0);
}

#[tokio::test]
async fn si_7_facade_refuses_substituted_worker_executable() {
    let base = TempBase::new();
    let dir = base.dir();
    let rogue = base.path().join("rogue-worker");
    std::fs::copy(me(), &rogue).unwrap();
    let mut worker = WorkerLaunch::new(rogue);
    worker
        .args([
            "--exact",
            "process_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, "rogue-worker");
    assert!(
        matches!(
            Facade::spawn(&dir, trust_me(), worker).await,
            Err(IpcError::PeerRejected)
        ),
        "facade launched a worker from another executable inode"
    );
}

#[test]
fn bad_probe_helper() {
    if std::env::var_os("KICKOFF_IPC_CORE_PROBE").is_some() {
        return;
    }
    process_helper();
}

#[tokio::test]
async fn si_30_facade_requires_kernel_crash_probe() {
    let base = TempBase::new();
    let dir = base.dir();
    let mut worker = WorkerLaunch::new(me());
    worker
        .args([
            "--exact",
            "bad_probe_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, "worker");
    assert!(
        matches!(
            Facade::spawn(&dir, trust_me(), worker).await,
            Err(IpcError::Hardening)
        ),
        "an executable that did not crash was accepted as kernel suppression proof"
    );
}

#[tokio::test]
async fn si_30_facade_crash_suppression_is_verified_before_listening() {
    let base = TempBase::new();
    let dir = base.dir();
    let _running = facade(&base, "facade");
    let mut client = connect::<Cli>(&dir, &trust_me()).await.unwrap();
    assert!(matches!(
        client.call(CliCommand::Status).await,
        Ok(Reply::Done)
    ));
    assert!(std::fs::read_dir(base.kickoff()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".core-probe-")
    }));
}

#[test]
fn hanging_probe_helper() {
    if std::env::var_os("KICKOFF_IPC_CORE_PROBE").is_some() {
        std::thread::sleep(Duration::from_secs(30));
        return;
    }
    process_helper();
}

#[tokio::test]
async fn si_30_facade_core_probe_timeout_reaps_child_and_scratch() {
    let base = TempBase::new();
    let dir = base.dir();
    let mut worker = WorkerLaunch::new(me());
    worker
        .args([
            "--exact",
            "hanging_probe_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, "worker");
    assert!(matches!(
        Facade::spawn(&dir, trust_me(), worker).await,
        Err(IpcError::Timeout)
    ));
    assert!(!dir.socket_path().exists());
    assert!(std::fs::read_dir(base.kickoff()).unwrap().next().is_none());
}

#[test]
fn si_30_facade_crash_probe_refuses_inherited_capabilities() {
    let base = TempBase::new();
    // Control: the same direct launch without the extra descriptor crashes,
    // so the refusal below is the descriptor check and nothing else.
    let mut clean = helper(&base, "probe-direct");
    assert_eq!(clean.line(), "crashed");
    assert!(clean.child.wait().unwrap().success());
    std::fs::remove_dir(base.path().join("probe-scratch")).unwrap();
    let mut leaky = helper(&base, "probe-direct-leak");
    assert_eq!(
        leaky.line(),
        "refused",
        "the probe crashed while holding an inherited descriptor"
    );
    assert!(leaky.child.wait().unwrap().success());
}

#[tokio::test]
async fn si_30_facade_probe_closes_descriptors_inherited_from_its_launcher() {
    // Desktop launchers and CI runners pass descriptors without
    // close-on-exec. They must neither reach the crash probe nor stop
    // Kickoff from starting.
    let base = TempBase::new();
    let dir = base.dir();
    std::fs::write(base.path().join(CANARY), b"").unwrap();
    let _running = facade(&base, "leaky-launcher");
    let mut client = connect::<Cli>(&dir, &trust_me()).await.unwrap();
    assert!(matches!(
        client.call(CliCommand::Status).await,
        Ok(Reply::Done)
    ));
}

#[tokio::test]
async fn si_36_worker_never_holds_a_descriptor_leaked_to_its_launcher() {
    let base = TempBase::new();
    let dir = base.dir();
    let canary = base.path().join(CANARY);
    std::fs::write(&canary, b"").unwrap();
    let _running = facade(&base, "leaky-launcher");
    let mut client = connect::<Cli>(&dir, &trust_me()).await.unwrap();
    assert!(matches!(
        client.call(CliCommand::Status).await,
        Ok(Reply::Done)
    ));
    assert_eq!(
        std::fs::read(&canary).unwrap(),
        b"",
        "the secret-holding worker held a descriptor its launcher leaked"
    );
}

/// The worker records its refusal as it closes the client, so the client
/// may see the close first.
async fn worker_result(base: &TempBase) -> String {
    let path = base.path().join("worker.result");
    for _ in 0..200 {
        if let Ok(result) = std::fs::read_to_string(&path) {
            return result;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the worker recorded no refusal");
}

#[test]
fn si_36_worker_never_holds_a_descriptor_opened_while_it_is_spawned() {
    // Another thread of the facade opens inheritable descriptors while the
    // worker is being spawned; a parent-side close list built beforehand
    // misses them.
    let mut raced: usize = 0;
    for _ in 0..10 {
        let base = TempBase::new();
        let _dir = base.dir();
        let canary = base.path().join(CANARY);
        std::fs::write(&canary, b"").unwrap();
        let mut running = helper(&base, "racing-facade");
        let line = running.line();
        let opened: usize = line.strip_prefix("raced ").unwrap().parse().unwrap();
        raced = raced.saturating_add(opened);
        assert_eq!(
            std::fs::read(&canary).unwrap(),
            b"",
            "the worker held a descriptor opened during its spawn"
        );
    }
    assert!(raced > 0, "the racer never ran during a worker spawn");
}

#[tokio::test]
async fn si_30_worker_refuses_clients_once_dumpable_again() {
    let base = TempBase::new();
    let dir = base.dir();
    let _running = facade_with(&base, "facade", &[(REDUMP, "before-accept")]);
    assert!(
        connect::<Cli>(&dir, &trust_me()).await.is_err(),
        "a worker that became dumpable read a client's bytes"
    );
    assert_eq!(worker_result(&base).await, "Hardening");
}

#[tokio::test]
async fn si_30_worker_channel_refuses_requests_once_dumpable_again() {
    let base = TempBase::new();
    let dir = base.dir();
    let _running = facade_with(&base, "facade", &[(REDUMP, "after-accept")]);
    let mut client = connect::<Cli>(&dir, &trust_me()).await.unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        client.call(CliCommand::Join(canary_ticket("kickoff1REDUMPCANARY456"))),
    )
    .await
    .unwrap();
    assert!(
        result.is_err(),
        "a worker that became dumpable received a ticket"
    );
    assert_eq!(worker_result(&base).await, "Hardening");
}

#[test]
fn si_30_facade_follows_a_zero_hard_core_limit() {
    // A hard limit of 0 cannot be raised to the pipe sentinel 1. It still
    // stops file dumps, so the facade starts; a `|` program or `@` socket
    // handler ignores it, so startup is refused by name before any probe.
    let base = TempBase::new();
    let _dir = base.dir();
    let pattern = std::fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap();
    let expected = if pattern.starts_with('|') || pattern.starts_with('@') {
        "refused-core-dumps"
    } else {
        "ready-zero"
    };
    let mut running = helper(&base, "zero-core-launcher");
    assert_eq!(running.line(), expected);
    assert!(std::fs::read_dir(base.kickoff()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".core-probe-")
    }));
}

#[test]
fn dumping_probe_helper() {
    if std::env::var_os("KICKOFF_IPC_CORE_PROBE").is_some() {
        // What a relative file core_pattern leaves in the probe's cwd.
        let scratch = std::env::var_os("KICKOFF_IPC_CORE_PROBE").unwrap();
        std::fs::write(std::path::Path::new(&scratch).join("core"), b"").unwrap();
        std::process::abort();
    }
    process_helper();
}

#[tokio::test]
async fn si_30_facade_refuses_by_name_when_the_probe_leaves_a_core() {
    let base = TempBase::new();
    let dir = base.dir();
    let mut worker = WorkerLaunch::new(me());
    worker
        .args([
            "--exact",
            "dumping_probe_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, "worker");
    assert_eq!(
        Facade::spawn(&dir, trust_me(), worker).await.err(),
        Some(IpcError::CoreDumpsEnabled),
        "a crash that left a core file was not refused as kept crash dumps"
    );
    assert!(!dir.socket_path().exists());
    assert!(std::fs::read_dir(base.kickoff()).unwrap().next().is_none());
}

#[tokio::test]
async fn si_10_control_ready_version_refused_before_serving() {
    let base = TempBase::new();
    let dir = base.dir();
    let worker = launch("bad-ready-version");
    assert!(matches!(
        Facade::spawn(&dir, trust_me(), worker).await,
        Err(IpcError::Version)
    ));
    assert!(!dir.socket_path().exists());
}

#[tokio::test]
async fn si_10_control_version_refused_before_descriptor_use() {
    let base = TempBase::new();
    let dir = base.dir();
    let listener = std::os::unix::net::UnixListener::bind(dir.socket_path()).unwrap();
    let (tx, rx) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut running = receiver("receiver", rx.into());
    assert_eq!(running.line(), "accepted");
    let trust = trust_me();
    let client = tokio::spawn(async move { connect::<Cli>(&dir, &trust).await });
    let socket = tokio::task::spawn_blocking(move || listener.accept().unwrap().0)
        .await
        .unwrap();
    let (_lease_tx, lease_rx) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut space = [std::mem::MaybeUninit::uninit(); 256];
    let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut space);
    let fds = [socket.as_fd(), lease_rx.as_fd()];
    assert!(ancillary.push(rustix::net::SendAncillaryMessage::ScmRights(&fds)));
    let [high, low] = kickoff_ipc::PROTOCOL_VERSION
        .checked_add(1)
        .unwrap()
        .to_be_bytes();
    rustix::net::sendmsg(
        &tx,
        &[std::io::IoSlice::new(&[high, low, 2])],
        &mut ancillary,
        rustix::net::SendFlags::NOSIGNAL,
    )
    .unwrap();
    drop(socket);
    drop(lease_rx);
    let result = tokio::time::timeout(Duration::from_secs(2), client)
        .await
        .unwrap()
        .unwrap();
    assert!(
        result.is_err(),
        "wrong-version control transferred a usable client stream"
    );
    assert!(running.child.wait().unwrap().success());
}

#[test]
fn si_30_facade_policy_precedes_arguments_runtime_and_trust() {
    let result = command("early-core-policy").output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("KIPC early-policy"));
}

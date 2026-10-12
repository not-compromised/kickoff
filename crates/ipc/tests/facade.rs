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
use kickoff_ipc::{CliCommand, Facade, IpcError, Reply, Request, Trust, Worker, connect};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const MODE: &str = "KIPC_FACADE_MODE";
const BASE: &str = "KIPC_FACADE_BASE";

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
                let mut worker_command = command("worker");
                worker_command.stdout(Stdio::null()).stderr(Stdio::null());
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
                if let Some(base) = std::env::var_os(BASE) {
                    std::fs::write(
                        std::path::Path::new(&base).join("worker.pid"),
                        std::process::id().to_string(),
                    )
                    .unwrap();
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
                while let Ok(mut channel) = worker.accept().await {
                    tokio::spawn(async move {
                        while let Ok(request) = channel.recv().await {
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
            "probe-fd-leak" => {
                let base = std::env::var_os(BASE).unwrap();
                let dir = kickoff_ipc::RuntimeDir::open_in(std::path::Path::new(&base)).unwrap();
                let file = std::fs::File::open("/dev/null").unwrap();
                rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty()).unwrap();
                let mut worker = command("worker");
                worker.stdout(Stdio::null()).stderr(Stdio::null());
                let result = Facade::spawn(&dir, trust_me(), worker).await;
                assert!(
                    matches!(result, Err(IpcError::Hardening)),
                    "probe inherited an unlisted descriptor"
                );
                emit("fd-refused");
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
fn facade(base: &TempBase, mode: &str) -> Running {
    let mut child = command(mode)
        .env(BASE, base.path())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let output = BufReader::new(child.stdout.take().unwrap());
    let mut running = Running {
        child,
        output,
        worker: None,
    };
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
    let mut worker = Command::new(rogue);
    worker
        .args([
            "--exact",
            "process_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, "rogue-worker")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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
    let mut worker = Command::new(me());
    worker
        .args([
            "--exact",
            "bad_probe_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, "worker")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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
    let mut worker = Command::new(me());
    worker
        .args([
            "--exact",
            "hanging_probe_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE, "worker")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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
    let _dir = base.dir();
    let mut child = command("probe-fd-leak")
        .env(BASE, base.path())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let output = BufReader::new(child.stdout.take().unwrap());
    let mut running = Running {
        child,
        output,
        worker: None,
    };
    assert_eq!(running.line(), "fd-refused");
    assert!(running.child.wait().unwrap().success());
}

#[tokio::test]
async fn si_10_control_ready_version_refused_before_serving() {
    let base = TempBase::new();
    let dir = base.dir();
    let mut worker = command("bad-ready-version");
    worker.stdout(Stdio::null()).stderr(Stdio::null());
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

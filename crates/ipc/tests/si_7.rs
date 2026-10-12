//! SI-7 (Linux): the endpoint is created exclusively in a place only its user
//! can write, a caller is accepted only after kernel credentials (same uid,
//! a Kickoff executable) check out, and the client checks its server the
//! same way. Every refusal leaves no side effect.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

mod common;

use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use kickoff_ipc::role::Cli;
use kickoff_ipc::{CliCommand, IpcError, Reply, RuntimeDir, Server, Trust, connect};
use tokio::io::AsyncReadExt;

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn si_7_runtime_dir_created_private_and_reused() {
    let base = TempBase::new();
    let dir = RuntimeDir::open_in(base.path()).unwrap();
    assert_eq!(mode(&base.kickoff()), 0o700);
    assert_eq!(dir.socket_path().parent().unwrap(), base.kickoff());
    RuntimeDir::open_in(base.path()).unwrap();
    assert_eq!(mode(&base.kickoff()), 0o700);
}

#[test]
fn si_7_runtime_dir_with_wrong_mode_type_or_link_refused() {
    let base = TempBase::new();
    std::fs::create_dir(base.kickoff()).unwrap();
    chmod(&base.kickoff(), 0o755);
    assert_eq!(
        RuntimeDir::open_in(base.path()).unwrap_err(),
        IpcError::UnsafeDir
    );
    assert_eq!(mode(&base.kickoff()), 0o755, "refusal must not touch it");

    let base = TempBase::new();
    let elsewhere = TempBase::new();
    std::os::unix::fs::symlink(elsewhere.path(), base.kickoff()).unwrap();
    assert_eq!(
        RuntimeDir::open_in(base.path()).unwrap_err(),
        IpcError::UnsafeDir
    );
    assert!(!elsewhere.kickoff().exists());

    let base = TempBase::new();
    std::fs::write(base.kickoff(), b"squatter").unwrap();
    assert_eq!(
        RuntimeDir::open_in(base.path()).unwrap_err(),
        IpcError::UnsafeDir
    );
    assert_eq!(std::fs::read(base.kickoff()).unwrap(), b"squatter");
}

#[test]
fn si_7_runtime_base_must_be_private_absolute_and_real() {
    let base = TempBase::new();
    chmod(base.path(), 0o755);
    assert_eq!(
        RuntimeDir::open_in(base.path()).unwrap_err(),
        IpcError::UnsafeDir
    );
    assert!(
        !base.kickoff().exists(),
        "nothing created under a public base"
    );

    assert_eq!(
        RuntimeDir::open_in(Path::new("relative/run")).unwrap_err(),
        IpcError::UnsafeDir
    );

    let real = TempBase::new();
    let link = TempBase::new();
    let link_path = link.path().join("run");
    std::os::unix::fs::symlink(real.path(), &link_path).unwrap();
    assert_eq!(
        RuntimeDir::open_in(&link_path).unwrap_err(),
        IpcError::UnsafeDir
    );
}

#[tokio::test]
async fn si_7_socket_created_0600_and_removed_on_drop() {
    let base = TempBase::new();
    let dir = base.dir();
    let server = Server::bind(&dir, trust_me()).unwrap();
    let meta = std::fs::symlink_metadata(dir.socket_path()).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.mode() & 0o7777, 0o600);
    drop(server);
    assert!(!dir.socket_path().exists());
}

#[tokio::test]
async fn si_7_squatted_socket_name_refused_without_touching_it() {
    // A file.
    let base = TempBase::new();
    let dir = base.dir();
    std::fs::write(dir.socket_path(), b"squatter").unwrap();
    assert_eq!(
        Server::bind(&dir, trust_me()).err(),
        Some(IpcError::Squatted)
    );
    assert_eq!(std::fs::read(dir.socket_path()).unwrap(), b"squatter");

    // A symlink to where a squatter wants the socket to go.
    let base = TempBase::new();
    let dir = base.dir();
    let target = base.path().join("target");
    std::os::unix::fs::symlink(&target, dir.socket_path()).unwrap();
    assert_eq!(
        Server::bind(&dir, trust_me()).err(),
        Some(IpcError::Squatted)
    );
    assert!(!target.exists());

    // A live server (a fake started first).
    let base = TempBase::new();
    let dir = base.dir();
    let fake = std::os::unix::net::UnixListener::bind(dir.socket_path()).unwrap();
    assert_eq!(
        Server::bind(&dir, trust_me()).err(),
        Some(IpcError::Squatted)
    );
    // The probe connection is the only trace; the fake still listens.
    fake.set_nonblocking(true).unwrap();
    std::os::unix::net::UnixStream::connect(dir.socket_path()).unwrap();
}

#[tokio::test]
async fn dead_socket_of_ours_is_reclaimed() {
    let base = TempBase::new();
    let dir = base.dir();
    drop(std::os::unix::net::UnixListener::bind(dir.socket_path()).unwrap());
    assert!(
        dir.socket_path().exists(),
        "a killed daemon leaves its socket"
    );
    let server = Arc::new(Server::bind(&dir, trust_me()).unwrap());
    let (_task, _seen) = serve(server);
    let mut client = connect::<Cli>(&dir, &trust_me()).await.unwrap();
    assert!(matches!(
        client.call(CliCommand::Status).await.unwrap(),
        Reply::Done
    ));
}

/// The server believes its user is another uid, so this process is, to it,
/// a caller from a second uid. Only the uid check can refuse it: the exe
/// is trusted.
#[tokio::test]
async fn si_7_caller_with_another_uid_refused() {
    let base = TempBase::new();
    let dir = base.dir();
    let as_other_user = Trust::for_uid(euid().wrapping_add(1), &[&me()]).unwrap();
    let server = Arc::new(Server::bind(&dir, as_other_user).unwrap());
    let (_task, mut seen) = serve(Arc::clone(&server));

    let got = connect::<Cli>(&dir, &trust_me()).await;
    assert_eq!(got.err(), Some(IpcError::Closed));
    assert_eq!(server.health().peers_rejected, 1);
    assert_eq!(server.health().frames_refused, 0, "hello never read");
    assert!(seen.try_recv().is_err());
}

#[tokio::test]
async fn si_7_caller_running_another_executable_refused() {
    let base = TempBase::new();
    let dir = base.dir();
    let only_other = Trust::same_user(&[&other_exe()]).unwrap();
    let server = Arc::new(Server::bind(&dir, only_other).unwrap());
    let (_task, mut seen) = serve(Arc::clone(&server));

    let got = connect::<Cli>(&dir, &trust_me()).await;
    assert_eq!(got.err(), Some(IpcError::Closed));
    assert_eq!(server.health().peers_rejected, 1);
    assert!(seen.try_recv().is_err());
}

/// A fake server (this binary, so same uid) started before the real one: a
/// client that does not trust it as kickoffd sends it nothing at all.
#[tokio::test]
async fn si_7_client_refuses_fake_server_before_sending() {
    for trust in [
        Trust::same_user(&[&other_exe()]).unwrap(),
        Trust::for_uid(euid().wrapping_add(1), &[&me()]).unwrap(),
    ] {
        let base = TempBase::new();
        let dir = base.dir();
        let fake = tokio::net::UnixListener::bind(dir.socket_path()).unwrap();
        let recorder = tokio::spawn(async move {
            let (mut stream, _) = fake.accept().await.unwrap();
            let mut got = Vec::new();
            stream.read_to_end(&mut got).await.unwrap();
            got
        });
        assert_eq!(
            connect::<Cli>(&dir, &trust).await.err(),
            Some(IpcError::PeerRejected)
        );
        assert!(recorder.await.unwrap().is_empty(), "fake server got bytes");
    }
}

#[tokio::test]
async fn si_7_client_refuses_a_socket_name_that_is_not_a_socket() {
    let base = TempBase::new();
    let dir = base.dir();
    std::fs::write(dir.socket_path(), b"squatter").unwrap();
    assert_eq!(
        connect::<Cli>(&dir, &trust_me()).await.err(),
        Some(IpcError::Squatted)
    );
}

const HELPER_ENV: &str = "KIPC_OTHER_UID_SOCKET";

/// Runs only inside `si_7_second_uid_refused`, as a subordinate uid: connect
/// to the socket, send a valid hello, and report what came back.
#[test]
fn other_uid_helper() {
    let Some(path) = std::env::var_os(HELPER_ENV) else {
        return;
    };
    let report = match std::os::unix::net::UnixStream::connect(&path) {
        Err(e) => format!("connect-error:{:?}", e.kind()),
        Ok(mut stream) => {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let _ = stream.write_all(&hello(kickoff_ipc::PROTOCOL_VERSION, CLI));
            let mut got = Vec::new();
            match stream.read_to_end(&mut got) {
                Ok(_) => format!("closed-after:{}", got.len()),
                Err(e) => format!("read-error:{:?}:{}", e.kind(), got.len()),
            }
        }
    };
    println!("KIPC {report}");
}

/// Runs `other_uid_helper` from a copy of this binary as the first
/// subordinate uid (`unshare --map-auto`, newuidmap and /etc/subuid; no
/// root), and returns its report.
async fn as_second_uid(helper: &Path, socket: &Path) -> String {
    let helper = helper.to_path_buf();
    let socket = socket.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let out = std::process::Command::new("unshare")
            .args(["--map-auto", "--setuid", "0", "--setgid", "0"])
            .arg(&helper)
            .args([
                "--exact",
                "other_uid_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(HELPER_ENV, &socket)
            .output()
            .expect("unshare must run");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        stdout
            .lines()
            .find_map(|l| l.split_once("KIPC ").map(|(_, r)| r.trim().to_owned()))
            .unwrap_or_else(|| {
                panic!(
                    "the second-uid helper did not run; this test needs util-linux \
                     unshare, newuidmap and a /etc/subuid entry for this user. \
                     stdout: {stdout} stderr: {}",
                    String::from_utf8_lossy(&out.stderr)
                )
            })
    })
    .await
    .unwrap()
}

/// A real second uid. With the directory as Kickoff creates it, the kernel
/// refuses the connect outright. With the directory and socket opened up on
/// purpose, the connect succeeds and the `SO_PEERCRED` check alone must
/// refuse it: the helper's executable is trusted, so only the uid differs.
#[tokio::test(flavor = "multi_thread")]
async fn si_7_second_uid_refused() {
    let base = TempBase::new();
    let dir = base.dir();

    let shared = TempBase::new();
    chmod(shared.path(), 0o755);
    let helper = shared.path().join("helper");
    std::fs::copy(me(), &helper).unwrap();
    chmod(&helper, 0o755);

    let server =
        Arc::new(Server::bind(&dir, Trust::same_user(&[&me(), &helper]).unwrap()).unwrap());
    let (_task, mut seen) = serve(Arc::clone(&server));

    let report = as_second_uid(&helper, dir.socket_path()).await;
    assert_eq!(report, "connect-error:PermissionDenied");
    assert_eq!(server.health().peers_rejected, 0);

    chmod(base.path(), 0o711);
    chmod(&base.kickoff(), 0o711);
    chmod(dir.socket_path(), 0o666);
    let report = as_second_uid(&helper, dir.socket_path()).await;
    // Closed unread, so the kernel may report a reset instead of EOF.
    assert!(
        matches!(
            report.as_str(),
            "closed-after:0" | "read-error:ConnectionReset:0"
        ),
        "another uid got a reply: {report}"
    );
    assert_eq!(server.health().peers_rejected, 1);
    assert_eq!(server.health().frames_refused, 0, "hello never read");
    assert!(seen.try_recv().is_err());

    // The same helper as our own uid is admitted, so the refusal above was
    // the uid and nothing else.
    let mut ok = std::process::Command::new(&helper);
    ok.args(["--exact", "other_uid_helper", "--nocapture"])
        .env(HELPER_ENV, dir.socket_path());
    let out = tokio::task::spawn_blocking(move || ok.output().unwrap())
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("KIPC read-error:WouldBlock:7")
            || String::from_utf8_lossy(&out.stdout).contains("KIPC read-error:TimedOut:7"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Sends `bytes` with one descriptor attached as `SCM_RIGHTS`.
fn send_with_fd(stream: &tokio::net::UnixStream, bytes: &[u8], fd: std::os::fd::BorrowedFd<'_>) {
    let mut space = [std::mem::MaybeUninit::uninit(); 64];
    let mut control = rustix::net::SendAncillaryBuffer::new(&mut space);
    let fds = [fd];
    assert!(control.push(rustix::net::SendAncillaryMessage::ScmRights(&fds)));
    let sent = rustix::net::sendmsg(
        stream,
        &[std::io::IoSlice::new(bytes)],
        &mut control,
        rustix::net::SendFlags::empty(),
    )
    .unwrap();
    assert_eq!(sent, bytes.len());
}

/// A trusted caller attaches a descriptor, once to its hello and once to a
/// command after a clean hello. Either way the channel closes, the daemon
/// sees nothing, and the descriptor is closed: once the caller drops its own
/// copy, the pipe has no writer left anywhere.
#[tokio::test]
async fn si_7_descriptors_from_a_caller_close_the_channel_and_are_closed() {
    for after_hello in [false, true] {
        let base = TempBase::new();
        let dir = base.dir();
        let server = Arc::new(Server::bind(&dir, trust_me()).unwrap());
        let (_task, mut seen) = serve(Arc::clone(&server));
        let (mut stream, bytes) = if after_hello {
            (raw_channel(&dir, CLI).await, frame(&[1]))
        } else {
            (
                tokio::net::UnixStream::connect(dir.socket_path())
                    .await
                    .unwrap(),
                hello(kickoff_ipc::PROTOCOL_VERSION, CLI),
            )
        };
        let (pipe_r, pipe_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        send_with_fd(&stream, &bytes, std::os::fd::AsFd::as_fd(&pipe_w));
        drop(pipe_w);

        assert!(
            closed_within(&mut stream, Duration::from_secs(2)).await,
            "after_hello={after_hello}: the channel must close, unanswered"
        );
        assert!(seen.try_recv().is_err(), "the daemon saw a request");
        assert_eq!(server.health().frames_refused, 1);
        rustix::io::ioctl_fionbio(&pipe_r, true).unwrap();
        let mut sink = [0u8; 1];
        assert_eq!(
            rustix::io::read(&pipe_r, &mut sink).unwrap(),
            0,
            "a copy of the descriptor is still open"
        );
    }
}

const RECYCLE_ENV: &str = "KIPC_RECYCLE_BASE";
const ROLE_ENV: &str = "KIPC_RECYCLE_ROLE";
const SOCKET_ENV: &str = "KIPC_RECYCLE_SOCKET";

fn run_role(exe: &Path, role: &str, socket: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["--exact", "pid_recycle_role", "--test-threads=1"])
        .env(ROLE_ENV, role)
        .env(SOCKET_ENV, socket)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cmd
}

/// The processes `pid_recycle_helper` starts. `connect`: an untrusted
/// executable connects, hands the connection to a `hold` child, and exits.
/// `hold`: speaks on the inherited connection. `sleep`: a trusted executable
/// that only exists to occupy the recycled pid.
#[test]
fn pid_recycle_role() {
    let (Some(role), Some(socket)) = (std::env::var(ROLE_ENV).ok(), std::env::var_os(SOCKET_ENV))
    else {
        return;
    };
    match role.as_str() {
        "connect" => {
            let stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
            // Not waited for: this process must exit while the child lives
            // on with the connection; the namespace's init reaps it.
            #[allow(clippy::zombie_processes)]
            let _holder = run_role(&me(), "hold", Path::new(&socket))
                .stdin(std::os::fd::OwnedFd::from(stream))
                .spawn()
                .unwrap();
        }
        "hold" => {
            let fd = std::os::fd::AsFd::as_fd(&std::io::stdin())
                .try_clone_to_owned()
                .unwrap();
            let mut stream = std::os::unix::net::UnixStream::from(fd);
            let _ = stream.write_all(&hello(kickoff_ipc::PROTOCOL_VERSION, CLI));
            let _ = stream.write_all(&frame(&[1]));
            let mut sink = Vec::new();
            let _ = stream.read_to_end(&mut sink);
        }
        "sleep" => {
            let mut sink = Vec::new();
            let _ = std::io::stdin().read_to_end(&mut sink);
        }
        _ => {}
    }
}

/// Runs only inside `si_7_recycled_pid_refused`, as pid 1 of a fresh pid
/// namespace where it may choose the next pid (`ns_last_pid`).
#[test]
fn pid_recycle_helper() {
    let Some(base) = std::env::var_os(RECYCLE_ENV) else {
        return;
    };
    let base = Path::new(&base).to_path_buf();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let report = rt.block_on(async move {
        let dir = RuntimeDir::open_in(&base).unwrap();
        let server = Server::bind(&dir, trust_me()).unwrap();

        // Control: a live trusted caller is admitted here, so SO_PEERPIDFD
        // works in this namespace and a refusal below is the recycle.
        let trust = trust_me();
        let (client, accepted) = tokio::join!(connect::<Cli>(&dir, &trust), server.accept());
        let control = client.is_ok() && accepted.is_ok();
        drop((client, accepted));

        // An untrusted executable: a copy of this binary, another inode.
        let untrusted = base.join("untrusted");
        std::fs::copy(me(), &untrusted).unwrap();
        let mut connector = run_role(&untrusted, "connect", dir.socket_path())
            .spawn()
            .unwrap();
        let old_pid = connector.id();
        assert!(connector.wait().unwrap().success());

        // The connection now lives in the `hold` child; its connecting pid
        // is free. Hand it to a trusted process.
        std::fs::write(
            "/proc/sys/kernel/ns_last_pid",
            old_pid.checked_sub(1).unwrap().to_string(),
        )
        .unwrap();
        let mut squatter = run_role(&me(), "sleep", dir.socket_path())
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let recycled = squatter.id() == old_pid;

        let admitted = tokio::time::timeout(Duration::from_secs(2), server.accept())
            .await
            .is_ok_and(|r| r.is_ok());
        let _ = squatter.kill();
        let _ = squatter.wait();
        format!(
            "control={control} recycled={recycled} admitted={admitted} rejected={}",
            server.health().peers_rejected
        )
    });
    println!("KIPC {report}");
}

/// The caller connects and exits, and its pid is reused by a process
/// running a trusted Kickoff executable before the server looks. Reading
/// `/proc/<pid>/exe` alone would admit it; the pidfd taken from the socket
/// still names the exited caller, so the check refuses. Runs in a user and
/// pid namespace (`unshare --map-root-user`; no root, no subordinate ids),
/// the only place an unprivileged process can choose the next pid.
#[tokio::test(flavor = "multi_thread")]
async fn si_7_recycled_pid_refused() {
    let base = TempBase::new();
    let path = base.path().to_path_buf();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--mount-proc",
            ])
            .arg(me())
            .args([
                "--exact",
                "pid_recycle_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(RECYCLE_ENV, &path)
            .output()
            .expect("unshare must run")
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let report = stdout
        .lines()
        .find_map(|l| l.split_once("KIPC ").map(|(_, r)| r.trim().to_owned()))
        .unwrap_or_else(|| {
            panic!(
                "the pid-recycle helper did not run; this test needs util-linux \
                 unshare and unprivileged user namespaces. stdout: {stdout} \
                 stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
    assert_eq!(
        report, "control=true recycled=true admitted=false rejected=1",
        "a caller whose pid was recycled by a trusted binary was admitted"
    );
}

const HARDENED_SERVER_ENV: &str = "KIPC_HARDENED_SERVER_BASE";

#[test]
fn hardened_server_helper() {
    let Some(base) = std::env::var_os(HARDENED_SERVER_ENV) else {
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let dir = RuntimeDir::open_in(Path::new(&base)).unwrap();
        let mut worker = std::process::Command::new(me());
        worker.args([
            "--exact",
            "hardened_worker_helper",
            "--nocapture",
            "--test-threads=1",
        ]);
        worker
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let facade = kickoff_ipc::Facade::spawn(&dir, trust_me(), worker)
            .await
            .unwrap();
        println!("KIPC hardened-ready");
        std::io::stdout().flush().unwrap();
        let _ = facade.run().await;
    });
}

#[test]
fn hardened_worker_helper() {
    kickoff_ipc::run_core_probe_if_requested().unwrap();
    if std::env::var_os(HARDENED_SERVER_ENV).is_none() {
        return;
    }
    kickoff_secret::harden_process().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut worker = kickoff_ipc::Worker::inherit(trust_me(), trust_me())
            .await
            .unwrap();
        while let Ok(mut channel) = worker.accept().await {
            tokio::spawn(async move {
                while let Ok(request) = channel.recv().await {
                    let reply = match request {
                        kickoff_ipc::Request::Cli(CliCommand::Join(ticket)) => {
                            Reply::Invite(ticket)
                        }
                        _ => Reply::Done,
                    };
                    if channel.reply(reply).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
}

/// Real daemon hardening and client authentication must hold together.
#[tokio::test]
async fn si_7_hardened_server_remains_authenticatable() {
    use std::io::{BufRead, BufReader};
    let base = TempBase::new();
    let dir = base.dir();
    let mut child = std::process::Command::new(me())
        .args([
            "--exact",
            "hardened_server_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HARDENED_SERVER_ENV, base.path())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut ready = false;
    for _ in 0..10 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        if line.contains("KIPC hardened-ready") {
            ready = true;
            break;
        }
    }
    let result = if ready {
        match connect::<Cli>(&dir, &trust_me()).await {
            Ok(mut client) => client.call(CliCommand::Status).await,
            Err(error) => Err(error),
        }
    } else {
        Err(IpcError::Closed)
    };
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        ready,
        "the real hardened server did not reach its accept loop"
    );
    assert!(
        matches!(result, Ok(Reply::Done)),
        "hardened server refused: {result:?}"
    );
}

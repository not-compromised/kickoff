#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

#[path = "../../../../tests/support/exec.rs"]
mod exec;
pub use exec::copy_executable;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use kickoff_ipc::{Channel, Reply, Request, RuntimeDir, Server, TicketText, Trust};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

/// A private stand-in for `$XDG_RUNTIME_DIR`, removed on drop.
pub struct TempBase {
    path: PathBuf,
}

impl TempBase {
    pub fn new() -> TempBase {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!("/tmp/kipc-{}-{n}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        TempBase { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn kickoff(&self) -> PathBuf {
        self.path.join("kickoff")
    }

    pub fn dir(&self) -> RuntimeDir {
        RuntimeDir::open_in(&self.path).unwrap()
    }
}

impl Drop for TempBase {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(self.kickoff(), std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub fn me() -> PathBuf {
    std::env::current_exe().unwrap()
}

pub fn euid() -> u32 {
    // /proc/self is owned by the process's euid while it is dumpable.
    std::fs::metadata("/proc/self").unwrap().uid()
}

/// This test binary is both the "installed kickoffd" and its "clients".
pub fn trust_me() -> Trust {
    Trust::same_user(&[&me()]).unwrap()
}

/// Some executable that is not this test binary.
pub fn other_exe() -> PathBuf {
    ["/usr/bin/env", "/bin/sh", "/usr/bin/true"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .unwrap()
}

pub fn canary_ticket(canary: &str) -> TicketText {
    TicketText::new(kickoff_wire::TicketTextValue::protect(canary.to_owned())).unwrap()
}

/// What the stand-in daemon saw: the Debug form of each request, which is
/// redacted for tickets.
pub type Seen = mpsc::UnboundedReceiver<String>;

/// Runs a stand-in daemon that answers every request with `Done`, except
/// `Invite`, which it answers with an invite ticket.
pub fn serve(server: Arc<Server>) -> (tokio::task::JoinHandle<()>, Seen) {
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let Ok(channel) = server.accept().await else {
                return;
            };
            tokio::spawn(answer(channel, tx.clone()));
        }
    });
    (task, rx)
}

async fn answer(mut channel: Channel, tx: mpsc::UnboundedSender<String>) {
    while let Ok(request) = channel.recv().await {
        let _ = tx.send(format!("{request:?}"));
        let reply = match request {
            Request::Cli(kickoff_ipc::CliCommand::Invite(_))
            | Request::UiMain(kickoff_ipc::UiCommand::Invite(_)) => {
                Reply::Invite(canary_ticket("kickoff1INVITE"))
            }
            _ => Reply::Done,
        };
        if channel.reply(reply).await.is_err() {
            return;
        }
    }
}

/// A frame as the wire carries it: a big-endian u32 length, then the bytes.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

/// The frozen hello layout: magic, version, role tag.
pub fn hello(version: u16, role_tag: u8) -> Vec<u8> {
    let [v0, v1] = version.to_be_bytes();
    frame(&[b'K', b'O', v0, v1, role_tag])
}

pub const CLI: u8 = 1;
pub const UI_MAIN: u8 = 2;
pub const OVERLAY: u8 = 3;
pub const GAMEBOX: u8 = 4;

/// Reads one frame, or `None` if the other end closed first.
pub async fn read_frame(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await.ok()?;
    Some(body)
}

/// Connects without any of the client's checks and completes the hello.
pub async fn raw_channel(dir: &RuntimeDir, role_tag: u8) -> UnixStream {
    let mut stream = UnixStream::connect(dir.socket_path()).await.unwrap();
    stream
        .write_all(&hello(kickoff_ipc::PROTOCOL_VERSION, role_tag))
        .await
        .unwrap();
    let welcome = read_frame(&mut stream).await.unwrap();
    assert_eq!(welcome[2], 0, "welcome must accept");
    stream
}

/// True if the other end closed (EOF or reset) within `wait`.
pub async fn closed_within(stream: &mut UnixStream, wait: Duration) -> bool {
    let mut byte = [0u8; 1];
    matches!(
        tokio::time::timeout(wait, stream.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    )
}

/// Runs the same regression from a private installation. Both transport ends
/// execute the installed helper, so canonical kernel authentication is real.
pub fn installed_fixture(test: &str) -> bool {
    if std::env::var("KIPC_INSTALLED_TEST").ok().as_deref() == Some(test) {
        return true;
    }
    let base = TempBase::new();
    let client = base.path().join("kickoff");
    copy_executable(me(), &client);
    std::fs::hard_link(&client, base.path().join("kickoffd")).unwrap();
    let output = std::process::Command::new(client)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env("KIPC_INSTALLED_TEST", test)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "installed regression {test}: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

/// A real second installed process; its checks use the production kernel path.
pub struct InstalledDaemon {
    child: std::process::Child,
    transcript: PathBuf,
    _stdout: std::process::ChildStdout,
}

impl InstalledDaemon {
    pub fn start(base: &TempBase, mode: &str) -> Self {
        use std::io::BufRead;
        let transcript = base.path().join("seen");
        let mut child = std::process::Command::new(me())
            .args([
                "--exact",
                "common::installed_daemon_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KIPC_DAEMON_BASE", base.path())
            .env("KIPC_DAEMON_MODE", mode)
            .env("KIPC_DAEMON_TRANSCRIPT", &transcript)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut reader = std::io::BufReader::new(stdout);
        let mut lines = (&mut reader).lines();
        assert!(
            lines.any(|line| line.unwrap().contains("KIPC_READY")),
            "daemon did not bind"
        );
        Self {
            child,
            transcript,
            _stdout: reader.into_inner(),
        }
    }

    pub async fn finish(mut self) -> Vec<String> {
        let status = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(status.success(), "installed daemon failed");
        std::fs::read_to_string(&self.transcript)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Drop for InstalledDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn installed_daemon_helper() {
    let Some(base) = std::env::var_os("KIPC_DAEMON_BASE") else {
        return;
    };
    let mode = std::env::var("KIPC_DAEMON_MODE").unwrap();
    let dir = RuntimeDir::open_in(Path::new(&base)).unwrap();
    let server = Server::bind(&dir, trust_me()).unwrap();
    println!("KIPC_READY");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    let channel_sizes: &[usize] = if mode == "roles" { &[2, 2, 1] } else { &[1] };
    let mut seen = Vec::new();
    for &count in channel_sizes {
        let mut channel = server.accept().await.unwrap();
        for _ in 0..count {
            let request = channel.recv().await.unwrap();
            seen.push(format!("{request:?}"));
            let reply = match (&*mode, request) {
                ("join", Request::Cli(kickoff_ipc::CliCommand::Join(t))) => {
                    assert!(t.secret().ct_eq(b"kickoff1CANARYQ7XZ3T2WVB"));
                    Reply::Done
                }
                ("invite", Request::UiMain(kickoff_ipc::UiCommand::Invite(_))) => {
                    Reply::Invite(canary_ticket("kickoff1CANARYQ7XZ3T2WVB"))
                }
                ("roles", Request::Cli(kickoff_ipc::CliCommand::Invite(_))) => {
                    Reply::Invite(canary_ticket("kickoff1INVITE"))
                }
                ("roles", _) => Reply::Done,
                _ => panic!("unexpected installed daemon request"),
            };
            channel.reply(reply).await.unwrap();
        }
    }
    std::fs::write(
        std::env::var_os("KIPC_DAEMON_TRANSCRIPT").unwrap(),
        seen.join("\n"),
    )
    .unwrap();
}

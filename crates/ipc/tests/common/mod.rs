#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use kickoff_ipc::{Channel, Reply, Request, RuntimeDir, Server, TicketText, Trust};
use kickoff_secret::Secret;
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
    TicketText::new(Secret::new(canary.to_owned())).unwrap()
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

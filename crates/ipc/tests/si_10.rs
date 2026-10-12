//! SI-10: a channel carries a version, and a mismatch is refused before any
//! side effect, on either end.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use kickoff_ipc::role::Cli;
use kickoff_ipc::{IpcError, PROTOCOL_VERSION, Server, connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const LEAVE: u8 = 8;

/// An old or new client sends its hello and, without waiting, a command. The
/// server answers `Version` and closes; the command never reaches the daemon.
#[tokio::test]
async fn si_10_version_mismatch_refused_before_any_command() {
    let base = TempBase::new();
    let dir = base.dir();
    let server = Arc::new(Server::bind(&dir, trust_me()).unwrap());
    let (_task, mut seen) = serve(Arc::clone(&server));

    for other in [
        PROTOCOL_VERSION.wrapping_add(1),
        PROTOCOL_VERSION.wrapping_sub(1),
    ] {
        let mut stream = UnixStream::connect(dir.socket_path()).await.unwrap();
        let mut bytes = hello(other, CLI);
        bytes.extend_from_slice(&frame(&[LEAVE]));
        stream.write_all(&bytes).await.unwrap();
        let welcome = read_frame(&mut stream).await.unwrap();
        let [v0, v1] = PROTOCOL_VERSION.to_be_bytes();
        assert_eq!(welcome, [v0, v1, 1], "welcome must say Version");
        assert!(closed_within(&mut stream, Duration::from_secs(2)).await);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        seen.try_recv().is_err(),
        "a command crossed a version mismatch"
    );
    assert_eq!(server.health().frames_refused, 2);
}

#[tokio::test]
async fn si_10_roles_not_served_here_refused() {
    let base = TempBase::new();
    let dir = base.dir();
    let server = Arc::new(Server::bind(&dir, trust_me()).unwrap());
    let (_task, mut seen) = serve(server);

    for role in [GAMEBOX, 5, 0, 99] {
        let mut stream = UnixStream::connect(dir.socket_path()).await.unwrap();
        let mut bytes = hello(PROTOCOL_VERSION, role);
        bytes.extend_from_slice(&frame(&[LEAVE]));
        stream.write_all(&bytes).await.unwrap();
        let welcome = read_frame(&mut stream).await.unwrap();
        assert_eq!(welcome[2], 2, "welcome must say Role");
        assert!(closed_within(&mut stream, Duration::from_secs(2)).await);
    }
    assert!(seen.try_recv().is_err());
}

#[tokio::test]
async fn garbage_or_oversize_hello_closes_without_welcome() {
    let base = TempBase::new();
    let dir = base.dir();
    let server = Arc::new(Server::bind(&dir, trust_me()).unwrap());
    let (_task, _seen) = serve(Arc::clone(&server));

    for bytes in [
        frame(b"GET / HTTP/1.1"),
        u32::MAX.to_be_bytes().to_vec(),
        frame(&[b'K', b'O', 0]),
    ] {
        let mut stream = UnixStream::connect(dir.socket_path()).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut got)).await;
        // A well-formed frame of the wrong shape gets a Version welcome; an
        // oversize one gets nothing at all.
        assert!(got.is_empty() || got[6] == 1, "{got:?}");
    }
}

/// A server speaking another version: the client stops after its hello and
/// reports `Version`.
#[tokio::test]
async fn si_10_client_refuses_server_of_other_version() {
    let base = TempBase::new();
    let dir = base.dir();
    let fake = tokio::net::UnixListener::bind(dir.socket_path()).unwrap();
    let recorder = tokio::spawn(async move {
        let (mut stream, _) = fake.accept().await.unwrap();
        let hello = read_frame(&mut stream).await.unwrap();
        let [v0, v1] = PROTOCOL_VERSION.wrapping_add(1).to_be_bytes();
        stream.write_all(&frame(&[v0, v1, 0])).await.unwrap();
        let mut after = Vec::new();
        stream.read_to_end(&mut after).await.unwrap();
        (hello, after)
    });
    assert_eq!(
        connect::<Cli>(&dir, &trust_me()).await.err(),
        Some(IpcError::Version)
    );
    let (hello, after) = recorder.await.unwrap();
    assert_eq!(&hello[..2], b"KO");
    assert!(after.is_empty(), "client sent a command after a mismatch");
}

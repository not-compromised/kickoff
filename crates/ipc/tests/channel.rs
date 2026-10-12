//! Role scoping and per-connection budgets on a real socket.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use kickoff_ipc::role::{Cli, Overlay, UiMain};
use kickoff_ipc::{
    ApprovalId, CliCommand, FRAME_DEADLINE, InviteFor, IpcError, MAX_CHANNELS, MAX_REQUEST_FRAME,
    OverlayCommand, REQUEST_RATE, Refusal, Reply, Request, Server, UiCommand, connect,
};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

const STATUS: u8 = 1;
const KICK: u8 = 5;
const RETIRED_APPROVE: u8 = 6;
const PICK_MAP: u8 = 7;
const DECIDE: u8 = 11;
const DONE: [u8; 1] = [1];
const REFUSED_UNKNOWN: [u8; 2] = [2, 1];

fn decide(allow: bool) -> Vec<u8> {
    let mut out = vec![DECIDE];
    out.extend_from_slice(&[9; 16]);
    out.push(u8::from(allow));
    out
}

fn with_32(tag: u8) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(
        iroh_base::SecretKey::from_bytes(&[3; 32])
            .public()
            .as_bytes(),
    );
    out
}

async fn started() -> (TempBase, kickoff_ipc::RuntimeDir, Arc<Server>, Seen) {
    let base = TempBase::new();
    let dir = base.dir();
    let server = Arc::new(Server::bind(&dir, trust_me()).unwrap());
    let (_task, seen) = serve(Arc::clone(&server));
    (base, dir, server, seen)
}

#[tokio::test]
async fn each_role_calls_its_own_commands() {
    let (_base, dir, _server, mut seen) = started().await;
    let mut cli = connect::<Cli>(&dir, &trust_me()).await.unwrap();
    assert!(matches!(
        cli.call(CliCommand::Status).await.unwrap(),
        Reply::Done
    ));
    assert!(matches!(
        cli.call(CliCommand::Invite(InviteFor::Bearer))
            .await
            .unwrap(),
        Reply::Invite(_)
    ));
    let mut ui = connect::<UiMain>(&dir, &trust_me()).await.unwrap();
    let id = iroh_base::SecretKey::from_bytes(&[4; 32]).public();
    assert!(matches!(
        ui.call(UiCommand::Kick(id)).await.unwrap(),
        Reply::Done
    ));
    let approval = ApprovalId::from_bytes([7; 16]);
    assert!(matches!(
        ui.call(UiCommand::Decide {
            approval,
            allow: true
        })
        .await
        .unwrap(),
        Reply::Done
    ));
    let mut overlay = connect::<Overlay>(&dir, &trust_me()).await.unwrap();
    assert!(matches!(
        overlay.call(OverlayCommand::Status).await.unwrap(),
        Reply::Done
    ));
    let mut got = Vec::new();
    while let Ok(s) = seen.try_recv() {
        got.push(s);
    }
    assert_eq!(got.len(), 5, "{got:?}");
    assert!(got[2].starts_with("UiMain(Kick("));
    assert_eq!(
        got[3],
        format!("UiMain(Decide {{ approval: {approval:?}, allow: true }})")
    );
    assert_eq!(got[4], "Overlay(Status)");
}

/// A command another role owns is as unknown as a tag nobody defined: it is
/// refused on the socket and never reaches the daemon.
#[tokio::test]
async fn commands_outside_the_role_and_unknown_tags_refused() {
    let (_base, dir, server, mut seen) = started().await;
    let cases: [(u8, Vec<Vec<u8>>); 3] = [
        (
            OVERLAY,
            vec![
                with_32(KICK),
                decide(true),
                decide(false),
                with_32(RETIRED_APPROVE),
                vec![8],
                vec![2],
                vec![0xee],
            ],
        ),
        (
            CLI,
            vec![
                with_32(KICK),
                decide(true),
                with_32(RETIRED_APPROVE),
                with_32(PICK_MAP),
                vec![0],
            ],
        ),
        (
            UI_MAIN,
            vec![
                vec![10],
                vec![0xff],
                vec![STATUS, 0],
                with_32(RETIRED_APPROVE),
            ],
        ),
    ];
    let mut refused = 0;
    for (role, frames) in cases {
        let mut stream = raw_channel(&dir, role).await;
        for body in frames {
            stream.write_all(&frame(&body)).await.unwrap();
            assert_eq!(read_frame(&mut stream).await.unwrap(), REFUSED_UNKNOWN);
            refused += 1;
        }
        // The channel survives a refusal and still serves its own commands.
        stream.write_all(&frame(&[STATUS])).await.unwrap();
        assert_eq!(read_frame(&mut stream).await.unwrap(), DONE);
    }
    let mut got = Vec::new();
    while let Ok(s) = seen.try_recv() {
        got.push(s);
    }
    assert_eq!(got.len(), 3, "only the three Status calls: {got:?}");
    assert_eq!(server.health().frames_refused, refused);
}

#[tokio::test]
async fn overlay_never_receives_a_ticket() {
    let base = TempBase::new();
    let dir = base.dir();
    let server = Arc::new(Server::bind(&dir, trust_me()).unwrap());
    let daemon_server = Arc::clone(&server);
    let daemon = tokio::spawn(async move {
        let mut channel = daemon_server.accept().await.unwrap();
        let _ = channel.recv().await.unwrap();
        channel
            .reply(Reply::Invite(canary_ticket("kickoff1OVERLAY")))
            .await
    });
    let mut overlay = connect::<Overlay>(&dir, &trust_me()).await.unwrap();
    let reply = overlay.call(OverlayCommand::Status).await.unwrap();
    assert!(matches!(reply, Reply::Refused(Refusal::Failed)));
    assert_eq!(daemon.await.unwrap().err(), Some(IpcError::Role));
}

#[tokio::test]
async fn reply_without_request_and_unanswered_request() {
    let base = TempBase::new();
    let dir = base.dir();
    let server = Arc::new(Server::bind(&dir, trust_me()).unwrap());
    let daemon_server = Arc::clone(&server);
    let daemon = tokio::spawn(async move {
        let mut channel = daemon_server.accept().await.unwrap();
        assert_eq!(
            channel.reply(Reply::Done).await.err(),
            Some(IpcError::Unrequested)
        );
        let first = channel.recv().await.unwrap();
        // Not answered: the next recv answers it Refused(Failed) first.
        let second = channel.recv().await.unwrap();
        channel.reply(Reply::Done).await.unwrap();
        matches!(first, Request::Cli(CliCommand::Status))
            && matches!(second, Request::Cli(CliCommand::Leave))
    });
    let mut cli = connect::<Cli>(&dir, &trust_me()).await.unwrap();
    assert!(matches!(
        cli.call(CliCommand::Status).await.unwrap(),
        Reply::Refused(Refusal::Failed)
    ));
    assert!(matches!(
        cli.call(CliCommand::Leave).await.unwrap(),
        Reply::Done
    ));
    assert!(daemon.await.unwrap());
}

/// SI-23 on the socket: the length is checked from the header alone, so an
/// oversize frame closes the channel without its body ever being awaited or
/// allocated.
#[tokio::test]
async fn si_23_oversize_frame_closes_channel_before_body() {
    let (_base, dir, server, mut seen) = started().await;
    for len in [u32::MAX, u32::try_from(MAX_REQUEST_FRAME + 1).unwrap()] {
        let mut stream = raw_channel(&dir, CLI).await;
        let started = Instant::now();
        // Header only; the body never comes.
        stream.write_all(&len.to_be_bytes()).await.unwrap();
        assert!(closed_within(&mut stream, FRAME_DEADLINE / 2).await);
        assert!(started.elapsed() < FRAME_DEADLINE / 2);
    }
    assert_eq!(server.health().frames_refused, 2);
    assert!(seen.try_recv().is_err());
}

#[tokio::test]
async fn si_23_stalled_frame_closes_channel() {
    let (_base, dir, _server, mut seen) = started().await;
    let mut stream = raw_channel(&dir, CLI).await;
    stream.write_all(&[0, 0, 0, 10, STATUS]).await.unwrap();
    assert!(closed_within(&mut stream, FRAME_DEADLINE * 3).await);
    assert!(seen.try_recv().is_err());
}

#[tokio::test]
async fn si_23_request_rate_budget_closes_channel() {
    let (_base, dir, _server, _seen) = started().await;
    let mut stream = raw_channel(&dir, CLI).await;
    let burst: Vec<u8> = (0..=REQUEST_RATE).flat_map(|_| frame(&[STATUS])).collect();
    stream.write_all(&burst).await.unwrap();
    let mut answered = 0;
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(reply) = read_frame(&mut stream).await {
            assert_eq!(reply, DONE);
            answered += 1;
        }
    })
    .await;
    assert!(closed.is_ok(), "a channel over its rate stayed open");
    assert_eq!(answered, REQUEST_RATE);
}

/// At most `MAX_CHANNELS` channels exist; the next caller waits unaccepted
/// until one closes.
#[tokio::test]
async fn si_23_channel_slots_are_bounded() {
    let (_base, dir, _server, _seen) = started().await;
    let mut open = Vec::new();
    for _ in 0..MAX_CHANNELS {
        open.push(raw_channel(&dir, CLI).await);
    }
    let mut extra = UnixStream::connect(dir.socket_path()).await.unwrap();
    extra
        .write_all(&hello(kickoff_ipc::PROTOCOL_VERSION, CLI))
        .await
        .unwrap();
    let waited = tokio::time::timeout(Duration::from_millis(300), read_frame(&mut extra)).await;
    assert!(waited.is_err(), "a channel beyond the limit was served");
    drop(open.pop());
    let welcome = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut extra))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(welcome[2], 0);
}

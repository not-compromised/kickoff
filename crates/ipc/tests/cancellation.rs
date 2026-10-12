//! Request/reply association when a caller drops a real pending exchange.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use common::{TempBase, trust_me};
use kickoff_ipc::role::Cli;
use kickoff_ipc::{CliCommand, IpcError, Refusal, Reply, Request, Server, connect};

#[tokio::test]
async fn cancelled_client_call_cannot_shift_replies() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let base = TempBase::new();
        let dir = base.dir();
        let server = Arc::new(Server::bind(&dir, trust_me()).unwrap());
        let trust = trust_me();
        let (client, channel) = tokio::join!(connect::<Cli>(&dir, &trust), server.accept());
        let mut client = client.unwrap();
        let mut channel = channel.unwrap();
        let mut first = Box::pin(client.call(CliCommand::Status));
        tokio::select! {
            result = &mut first => panic!("Status completed before its held reply: {result:?}"),
            request = channel.recv() => assert!(matches!(request.unwrap(), Request::Cli(CliCommand::Status))),
        }
        poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        }).await;
        drop(first);

        channel.reply(Reply::Done).await.unwrap();
        let result = client.call(CliCommand::Leave).await;
        if !matches!(result, Err(IpcError::Closed)) {
            // On the broken client the genuine Leave is dispatched, refused,
            // and queued behind the Status reply returned by the Leave call.
            assert!(matches!(channel.recv().await.unwrap(), Request::Cli(CliCommand::Leave)));
            channel.reply(Reply::Refused(Refusal::NotHost)).await.unwrap();
        }
        assert!(matches!(result, Err(IpcError::Closed)), "Leave returned the held Status reply: {result:?}");
    }).await.expect("held-reply regression must finish");
}

#[tokio::test]
async fn completed_held_client_call_keeps_reply_association() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let base = TempBase::new();
        let dir = base.dir();
        let server = Server::bind(&dir, trust_me()).unwrap();
        let trust = trust_me();
        let (client, channel) = tokio::join!(connect::<Cli>(&dir, &trust), server.accept());
        let mut client = client.unwrap();
        let mut channel = channel.unwrap();
        let mut first = Box::pin(client.call(CliCommand::Status));
        tokio::select! {
            result = &mut first => panic!("Status completed before its held reply: {result:?}"),
            request = channel.recv() => assert!(matches!(request.unwrap(), Request::Cli(CliCommand::Status))),
        }
        poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        }).await;
        channel.reply(Reply::Done).await.unwrap();
        assert!(matches!(first.await.unwrap(), Reply::Done));
        let (result, ()) = tokio::join!(client.call(CliCommand::Leave), async {
            assert!(matches!(channel.recv().await.unwrap(), Request::Cli(CliCommand::Leave)));
            channel.reply(Reply::Refused(Refusal::NotHost)).await.unwrap();
        });
        assert!(matches!(result.unwrap(), Reply::Refused(Refusal::NotHost)));
    }).await.expect("completed exchange must finish");
}

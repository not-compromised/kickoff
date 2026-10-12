use std::future::{Future, poll_fn};
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::CliCommand;

// The duplicate is test-only observation/pressure on the real socket. The
// channel still authenticates, handshakes, reads and writes through DataOnly.
async fn authenticated_pair() -> (Channel, UnixStream, OwnedFd) {
    let (sender, mut peer) = UnixStream::pair().unwrap();
    rustix::net::sockopt::set_socket_send_buffer_size(&sender, 4096).unwrap();
    let observer = rustix::io::dup(&sender).unwrap();
    let executable = std::env::current_exe().unwrap();
    let trust = Trust::same_user(&[&executable]).unwrap();
    let slot = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
    let (channel, ()) = tokio::join!(
        admit_stream(&trust, Arc::default(), sender, slot, None),
        async {
            write_frame(
                &mut peer,
                &codec::encode_hello(crate::PROTOCOL_VERSION, ChannelRole::Cli),
            )
            .await
            .unwrap();
            let welcome = read_frame(&mut peer, codec::WELCOME_LEN).await.unwrap();
            codec::decode_welcome(&welcome).unwrap();
        }
    );
    (channel.unwrap(), peer, observer)
}

async fn pending(future: Pin<&mut impl Future>) {
    let mut future = future;
    poll_fn(|cx| {
        assert!(
            future.as_mut().poll(cx).is_pending(),
            "real socket operation must be pending"
        );
        Poll::Ready(())
    })
    .await;
}

async fn request_status(channel: &mut Channel, peer: &mut UnixStream) {
    write_frame(peer, &[0]).await.unwrap();
    assert!(matches!(
        channel.recv().await.unwrap(),
        Request::Cli(CliCommand::Status)
    ));
}

fn fill_output(socket: &OwnedFd) -> usize {
    let bytes = [0xa5; 4096];
    let mut written = 0usize;
    loop {
        match rustix::net::send(
            socket,
            &bytes,
            rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
        ) {
            Ok(n) => {
                assert!(n > 0);
                written = written.checked_add(n).unwrap();
                assert!(written <= 1024 * 1024, "fixture output must be bounded");
            }
            Err(rustix::io::Errno::WOULDBLOCK) => {
                assert!(
                    written > 0,
                    "socket pressure must contain real queued bytes"
                );
                return written;
            }
            Err(error) => panic!("socket pressure failed: {error}"),
        }
    }
}

async fn drain_pressure(peer: &mut UnixStream, written: usize) {
    let mut bytes = vec![0; written];
    peer.read_exact(&mut bytes).await.unwrap();
    assert!(bytes.iter().all(|byte| *byte == 0xa5));
}

#[tokio::test]
async fn cancelled_blocked_server_reply_closes_channel() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (mut channel, mut peer, socket) = authenticated_pair().await;
        request_status(&mut channel, &mut peer).await;
        let written = fill_output(&socket);
        let mut reply = Box::pin(channel.reply(Reply::Done));
        pending(reply.as_mut()).await;
        drop(reply);
        drain_pressure(&mut peer, written).await;
        write_frame(&mut peer, &[4]).await.unwrap();
        assert_eq!(
            channel.recv().await.err(),
            Some(IpcError::Closed),
            "cancelled blocked reply accepted another request"
        );
        assert_eq!(
            channel.reply(Reply::Done).await.err(),
            Some(IpcError::Closed)
        );
    })
    .await
    .expect("blocked reply regression must finish");
}

#[tokio::test]
async fn completed_blocked_server_reply_keeps_channel_usable() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (mut channel, mut peer, socket) = authenticated_pair().await;
        request_status(&mut channel, &mut peer).await;
        let written = fill_output(&socket);
        let mut reply = Box::pin(channel.reply(Reply::Done));
        pending(reply.as_mut()).await;
        let (sent, ()) = tokio::join!(reply, drain_pressure(&mut peer, written));
        sent.unwrap();
        assert_eq!(
            &*read_frame(&mut peer, MAX_REPLY_FRAME).await.unwrap(),
            &[0]
        );
        request_status(&mut channel, &mut peer).await;
        channel
            .reply(Reply::Refused(Refusal::NotHost))
            .await
            .unwrap();
        assert_eq!(
            &*read_frame(&mut peer, MAX_REPLY_FRAME).await.unwrap(),
            &[1, 2]
        );
    })
    .await
    .expect("resumed blocked reply must finish");
}

async fn consumed_partial_header(
    channel: &mut Channel,
    peer: &mut UnixStream,
    socket: &OwnedFd,
    cancel: bool,
) {
    peer.write_all(&[0]).await.unwrap();
    assert_eq!(rustix::io::ioctl_fionread(socket).unwrap(), 1);
    let mut recv = Box::pin(channel.recv());
    poll_fn(|cx| {
        assert!(recv.as_mut().poll(cx).is_pending());
        if rustix::io::ioctl_fionread(socket).unwrap() == 0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    if cancel {
        drop(recv);
    } else {
        peer.write_all(&[0, 0, 1, 0]).await.unwrap();
        assert!(matches!(
            recv.await.unwrap(),
            Request::Cli(CliCommand::Status)
        ));
    }
}

#[tokio::test]
async fn cancelled_partial_server_receive_closes_channel() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (mut channel, mut peer, socket) = authenticated_pair().await;
        consumed_partial_header(&mut channel, &mut peer, &socket, true).await;
        write_frame(&mut peer, &[0]).await.unwrap();
        assert_eq!(
            channel.recv().await.err(),
            Some(IpcError::Closed),
            "cancelled partial header was reused as a new frame"
        );
        assert_eq!(
            channel.reply(Reply::Done).await.err(),
            Some(IpcError::Closed)
        );
    })
    .await
    .expect("partial receive regression must finish");
}

#[tokio::test]
async fn completed_partial_server_receive_keeps_channel_usable() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (mut channel, mut peer, socket) = authenticated_pair().await;
        consumed_partial_header(&mut channel, &mut peer, &socket, false).await;
        channel.reply(Reply::Done).await.unwrap();
        assert_eq!(
            &*read_frame(&mut peer, MAX_REPLY_FRAME).await.unwrap(),
            &[0]
        );
        request_status(&mut channel, &mut peer).await;
        channel.reply(Reply::Done).await.unwrap();
        assert_eq!(
            &*read_frame(&mut peer, MAX_REPLY_FRAME).await.unwrap(),
            &[0]
        );
    })
    .await
    .expect("completed partial receive must finish");
}

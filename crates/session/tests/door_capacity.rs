//! Priority admission remains available while outsiders refuse reply credit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::Ipv4Addr;
use std::time::Duration;

use common::*;
use kickoff_net::JOIN_ALPN;
use kickoff_wire::{JoinReply, LEN_PREFIX_LEN, WireMessage};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_23_zero_credit_replies_preserve_priority_capacity() {
    let host = loopback_host().await;
    let invalid = host.bound(iroh::SecretKey::generate().public());
    let mut held = Vec::new();
    for n in 1..=16u8 {
        let raw = raw_endpoint_with_window(Ipv4Addr::new(127, 0, 4, n), 0).await;
        let conn = raw
            .connect(host.identity.door.addr(), JOIN_ALPN)
            .await
            .unwrap();
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(&kickoff_wire::encode_framed(&raw_request(&invalid, raw.id())).unwrap())
            .await
            .unwrap();
        send.finish().unwrap();
        held.push((raw, conn, send, recv));
    }
    // Extra general requests close rather than waiting outside the door's
    // event loop. Eight of the sixteen reply places remain reserved.
    tokio::time::timeout(Duration::from_secs(1), async {
        while held
            .iter()
            .filter(|(_, conn, _, _)| conn.close_reason().is_some())
            .count()
            < 8
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("general requests occupied the reserved priority capacity");
    assert!(
        held.iter()
            .any(|(_, conn, _, _)| conn.close_reason().is_none()),
        "the fixture did not retain any blocked replies"
    );

    let friend = raw_endpoint_with_window(Ipv4Addr::new(127, 0, 4, 100), 512 * 1024).await;
    let ticket = host.bound(friend.id());
    let priority = async {
        let conn = friend
            .connect(host.identity.door.addr(), JOIN_ALPN)
            .await
            .unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&kickoff_wire::encode_framed(&raw_request(&ticket, friend.id())).unwrap())
            .await
            .unwrap();
        send.finish().unwrap();
        let mut prefix = [0u8; LEN_PREFIX_LEN];
        recv.read_exact(&mut prefix).await.unwrap();
        let len = kickoff_wire::frame_len::<JoinReply>(prefix).unwrap();
        assert!(len <= JoinReply::MAX_LEN);
        let mut body = vec![0; len];
        recv.read_exact(&mut body).await.unwrap();
        let reply = kickoff_wire::decode::<JoinReply>(&body).unwrap();
        assert!(
            matches!(reply, JoinReply::Admitted(_)),
            "a priority identity was not admitted: {reply:?}"
        );
        conn.close(iroh::endpoint::VarInt::from_u32(0), b"");
    };
    tokio::time::timeout(Duration::from_secs(1), priority)
        .await
        .expect("zero-credit outsiders starved a valid bound join");
}

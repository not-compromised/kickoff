//! LAN datagrams, fragmentation and the control stream over a real loopback
//! link (§3.4, §4.5, §6.3).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::*;
use iroh::endpoint::Connection;
use kickoff_net::{AdmittedSet, Link, NetError, PathStatus, Role, SESSION_ALPN, SessionNet};
use kickoff_wire::{
    BoundedVec, FRAGMENT_HEADER_LEN, GameState, GuestMsg, HostMsg, LAN_HEADER_LEN, MapId, PeerRef,
};

async fn recv(link: &Link) -> kickoff_wire::LanDatagram {
    tokio::time::timeout(WAIT, link.recv_lan())
        .await
        .expect("datagram timed out")
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fragmentation_round_trip_at_the_size_boundary() {
    let host = node(Role::Host).await;
    let guest = node(Role::Guest).await;
    let (host_link, guest_link) = pair(&host, &guest, peer(2, 1)).await;
    let max = settled_max(&guest_link).await;
    let whole = max - LAN_HEADER_LEN;
    let piece = whole - FRAGMENT_HEADER_LEN;
    let sizes = [
        0,
        1,
        whole - 1,
        whole,
        whole + 1,
        2 * piece,
        2 * piece + 1,
        3 * piece + 1,
        4 * piece,
    ];

    for (seed, &len) in sizes.iter().enumerate() {
        let sent = lan(len, seed as u8);
        guest_link.send_lan(&sent);
        let got = recv(&host_link).await;
        assert_eq!(
            got.payload, sent.payload,
            "payload of {len} bytes (limit {max})"
        );
        assert_eq!(
            (got.bcast, got.src_port, got.dst_port),
            (sent.bcast, sent.src_port, sent.dst_port)
        );
        assert_eq!(got.peer.get(), 2, "the slot comes from the link");
    }
    let health = guest_link.health();
    assert_eq!(health.sent, sizes.len() as u64);

    guest_link.send_lan(&lan(4 * piece + 1, 99));
    assert_eq!(
        guest_link.health().dropped_send,
        1,
        "more than four fragments must not be sent"
    );
    let marker = lan(3, 7);
    guest_link.send_lan(&marker);
    assert_eq!(
        recv(&host_link).await.payload,
        marker.payload,
        "the oversize datagram arrived"
    );

    let back = lan(3 * piece, 5);
    host_link.send_lan(&back);
    assert_eq!(
        recv(&guest_link).await.payload,
        back.payload,
        "host to guest"
    );
    assert_eq!(recv_health_drops(&host_link), 0);
}

fn recv_health_drops(link: &Link) -> u64 {
    let h = link.health();
    h.dropped_budget + h.dropped_malformed + h.dropped_reassembly
}

/// An admitted raw connection: the hostile guest owns every byte it sends.
struct Hostile {
    _ep: iroh::Endpoint,
    _ctl: iroh::endpoint::SendStream,
    conn: Connection,
}

async fn hostile(
    host: &SessionNet,
    legit: (iroh::EndpointId, PeerRef),
    p: PeerRef,
) -> (Hostile, Linked) {
    let ep = raw_endpoint().await;
    host.set_admitted([legit, (ep.id(), p)].into_iter().collect::<AdmittedSet>());
    let conn = ep.connect(host.addr(), SESSION_ALPN).await.unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    send.write_all(&[0]).await.unwrap();
    let link = Linked::from(
        tokio::time::timeout(WAIT, host.accept())
            .await
            .unwrap()
            .unwrap(),
    );
    (
        Hostile {
            _ep: ep,
            _ctl: send,
            conn,
        },
        link,
    )
}

fn first_fragment(frag_id: u16) -> bytes::Bytes {
    let [f0, f1] = frag_id.to_be_bytes();
    let header = [2, 0, 0x1e, 0x61, 0x36, 0xb1];
    raw_bytes(&[&header, &[f0, f1, 0x04, 0], &[0xAA; 1000]])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_23_fragment_flood_does_not_starve_a_legitimate_peer() {
    let host = node(Role::Host).await;
    let guest = node(Role::Guest).await;
    let good = peer(2, 1);
    host.set_admitted([(guest.id(), good)].into_iter().collect::<AdmittedSet>());
    let (accepted, dialed) = tokio::join!(host.accept(), dial(&host, &guest, good));
    let (host_link, guest_link) = (Linked::from(accepted.unwrap()), dialed.unwrap());
    let (attack, hostile_link) = hostile(&host, (guest.id(), good), peer(3, 1)).await;

    let stop = Arc::new(AtomicBool::new(false));
    let hostile_link = Arc::new(hostile_link);
    let drain = {
        let link = Arc::clone(&hostile_link);
        tokio::spawn(async move { while link.recv_lan().await.is_ok() {} })
    };
    let flood = {
        let stop = Arc::clone(&stop);
        tokio::spawn(async move {
            let mut id = 0u16;
            while !stop.load(Ordering::Relaxed) {
                for _ in 0..64 {
                    id = id.wrapping_add(1);
                    let _ = attack.conn.send_datagram(first_fragment(id));
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
    };
    let max = settled_max(&guest_link).await;
    let big = 3 * (max - LAN_HEADER_LEN - FRAGMENT_HEADER_LEN);
    let delivered = Arc::new(AtomicU64::new(0));
    let rx = {
        let delivered = Arc::clone(&delivered);
        tokio::spawn(async move {
            while let Ok(d) = host_link.recv_lan().await {
                assert_eq!(d.payload.len(), big);
                delivered.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    let sent = 200u64;
    for i in 0..sent {
        guest_link.send_lan(&lan(big, i as u8));
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    stop.store(true, Ordering::Relaxed);
    flood.await.unwrap();

    let got = delivered.load(Ordering::Relaxed);
    let h = hostile_link.health();
    assert!(
        h.dropped_reassembly + h.dropped_budget > 0,
        "the flood never hit a cap, so the test proved nothing: {h:?}"
    );
    assert!(
        got * 100 >= sent * 95,
        "legitimate peer starved: {got} of {sent} fragmented datagrams"
    );
    rx.abort();
    drain.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_stream_round_trip_and_cancel_safe_recv() {
    let host = node(Role::Host).await;
    let guest = node(Role::Guest).await;
    let (mut host_link, mut guest_link) = pair(&host, &guest, peer(2, 7)).await;

    let hello = tokio::time::timeout(WAIT, host_link.ctl().recv::<GuestMsg>())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        hello,
        GuestMsg::Hello {
            generation: kickoff_wire::Generation::new(7)
        }
    );

    let cancelled = tokio::time::timeout(
        Duration::from_millis(50),
        guest_link.ctl().recv::<HostMsg>(),
    )
    .await;
    assert!(cancelled.is_err(), "nothing was sent yet");
    host_link.ctl().send(&HostMsg::Ping).await.unwrap();
    host_link.ctl().send(&HostMsg::End).await.unwrap();
    let ping = tokio::time::timeout(WAIT, guest_link.ctl().recv::<HostMsg>())
        .await
        .unwrap()
        .unwrap();
    let end = tokio::time::timeout(WAIT, guest_link.ctl().recv::<HostMsg>())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((ping, end), (HostMsg::Ping, HostMsg::End));

    let have = BoundedVec::new((0..64u8).map(|i| MapId([i; 32])).collect()).unwrap();
    let status = GuestMsg::Status {
        game_state: GameState::Lobby,
        have,
    };
    guest_link.ctl().send(&status).await.unwrap();
    let got = tokio::time::timeout(WAIT, host_link.ctl().recv::<GuestMsg>())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, status);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_23_control_length_refused_before_allocation() {
    let host = node(Role::Host).await;
    let ep = raw_endpoint().await;
    host.set_admitted([(ep.id(), peer(2, 1))].into_iter().collect::<AdmittedSet>());
    let conn = ep.connect(host.addr(), SESSION_ALPN).await.unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    send.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    let mut link = Linked::from(
        tokio::time::timeout(WAIT, host.accept())
            .await
            .unwrap()
            .unwrap(),
    );
    let got = tokio::time::timeout(WAIT, link.ctl().recv::<GuestMsg>())
        .await
        .unwrap();
    assert_eq!(got.err(), Some(NetError::Protocol));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_23_control_messages_are_rate_limited() {
    let host = node(Role::Host).await;
    let guest = node(Role::Guest).await;
    let (mut host_link, mut guest_link) = pair(&host, &guest, peer(2, 1)).await;
    let sender = tokio::spawn(async move {
        for _ in 0..80 {
            guest_link.ctl().send(&GuestMsg::Pong).await.unwrap();
        }
        guest_link
    });
    let start = Instant::now();
    for _ in 0..81 {
        tokio::time::timeout(WAIT, host_link.ctl().recv::<GuestMsg>())
            .await
            .unwrap()
            .unwrap();
    }
    let took = start.elapsed();
    // 32 in the burst, then 32/s: the remaining 49 need at least 1.5 s.
    assert!(
        took >= Duration::from_millis(1400),
        "81 control messages in {took:?}"
    );
    drop(sender.await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_status_reports_direct_on_loopback() {
    let host = node(Role::Host).await;
    let guest = node(Role::Guest).await;
    let (host_link, guest_link) = pair(&host, &guest, peer(2, 1)).await;
    guest_link.send_lan(&lan(10, 1));
    recv(&host_link).await;
    assert_eq!(guest_link.path(), PathStatus::Direct);
    assert_eq!(host_link.path(), PathStatus::Direct);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_control_variant_closes_the_link_with_version() {
    let host = node(Role::Host).await;
    let ep = raw_endpoint().await;
    host.set_admitted([(ep.id(), peer(2, 1))].into_iter().collect::<AdmittedSet>());
    let conn = ep.connect(host.addr(), SESSION_ALPN).await.unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    send.write_all(&[0, 0, 0, 1, 0x7f]).await.unwrap();
    let mut link = Linked::from(
        tokio::time::timeout(WAIT, host.accept())
            .await
            .unwrap()
            .unwrap(),
    );
    let got = tokio::time::timeout(WAIT, link.ctl().recv::<GuestMsg>())
        .await
        .unwrap();
    assert_eq!(got.err(), Some(NetError::Version));
    let reason = tokio::time::timeout(WAIT, conn.closed()).await.unwrap();
    let iroh::endpoint::ConnectionError::ApplicationClosed(close) = reason else {
        panic!("closed with {reason:?}");
    };
    assert_eq!(close.error_code.into_inner(), 8, "VERSION");
}

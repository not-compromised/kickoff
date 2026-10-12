//! The LAN as two games see it: a guest and a host, each behind its own
//! `Lan`, with the test standing in for the links between them.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::*;
use kickoff_vlan::{LanError, LanHealth, open};

#[tokio::test(start_paused = true)]
async fn guest_and_host_games_talk_through_the_lan() {
    let (guest, guest_game) = node(2);
    let (host, host_game) = node(1);

    // The guest game resolves the host's address; Kickoff answers locally.
    guest_game
        .send_frame(Bytes::from(arp_request(2, ip(1))))
        .unwrap();
    assert!(
        recv_now(&guest).await.is_none(),
        "ARP never leaves the node"
    );
    let reply = game_receives(&guest_game).await.unwrap();
    assert_eq!(&reply[0..6], &mac(2), "addressed to the game");
    assert_eq!(&reply[12..14], &[0x08, 0x06]);
    assert_eq!(&reply[20..22], &[0, 2], "an ARP reply");
    assert_eq!(&reply[22..28], &mac(1), "the host's synthesized MAC");
    assert_eq!(&reply[28..32], &ip(1));

    let hello = Udp::unicast(2, 1, 50000, GAME_PORT).payload(b"hello");
    let d = game_sends(&guest, &guest_game, hello.frame())
        .await
        .unwrap();
    assert_eq!(
        (d.peer, d.bcast, d.src_port, d.dst_port),
        (slot(1), false, 50000, GAME_PORT)
    );
    assert_eq!(&d.payload[..], b"hello");

    // The host's link stamps the guest's slot; nothing in the packet says it.
    host.deliver(kickoff_wire::LanDatagram { peer: slot(2), ..d });
    let got = parse_udp(&game_receives(&host_game).await.unwrap());
    assert_eq!(
        got,
        Received {
            src_mac: mac(2),
            dst_mac: mac(1),
            src_ip: ip(2),
            dst_ip: ip(1),
            src_port: 50000,
            dst_port: GAME_PORT,
            payload: b"hello".to_vec(),
        }
    );

    // The listen server answers the guest's ephemeral port.
    let answer = Udp::unicast(1, 2, GAME_PORT, 50000).payload(b"welcome");
    let d = game_sends(&host, &host_game, answer.frame()).await.unwrap();
    assert_eq!(d.peer, slot(2));
    guest.deliver(kickoff_wire::LanDatagram { peer: slot(1), ..d });
    let got = parse_udp(&game_receives(&guest_game).await.unwrap());
    assert_eq!((got.src_ip, got.dst_ip), (ip(1), ip(2)));
    assert_eq!((got.src_port, got.dst_port), (GAME_PORT, 50000));
    assert_eq!(got.payload, b"welcome");

    assert_eq!(guest.health().from_game, 1);
    assert_eq!(guest.health().to_game, 1);
    assert_eq!(host.health().from_game, 1);
    assert_eq!(host.health().to_game, 1);
}

#[tokio::test(start_paused = true)]
async fn discovery_broadcast_reaches_guests_and_answers_come_back() {
    let (host, host_game) = node(1);
    let (guest, guest_game) = node(3);

    let beacon = Udp::broadcast(1, 40000, DISCOVERY_PORT).frame();
    let d = game_sends(&host, &host_game, beacon).await.unwrap();
    assert!(d.bcast);
    assert_eq!(
        d.peer,
        slot(1),
        "a broadcast is addressed to the host's star"
    );

    guest.deliver(d);
    let got = parse_udp(&game_receives(&guest_game).await.unwrap());
    assert_eq!((got.dst_mac, got.dst_ip), (BROADCAST_MAC, BROADCAST));
    assert_eq!((got.src_mac, got.src_ip), (mac(1), ip(1)));

    // Any guest may answer the host's beacon port: the broadcast opened it.
    host.deliver(datagram(3, DISCOVERY_PORT, 40000));
    host.deliver(datagram(5, DISCOVERY_PORT, 40000));
    assert_eq!(game_receives_all(&host_game).await.len(), 2);
}

#[tokio::test(start_paused = true)]
async fn guest_broadcast_goes_to_the_host() {
    let (guest, guest_game) = node(4);
    let query = Udp::broadcast(4, 41000, DISCOVERY_PORT).frame();
    let d = game_sends(&guest, &guest_game, query).await.unwrap();
    assert_eq!((d.peer, d.bcast), (slot(1), true));

    // The host's unicast answer to the query's source port passes.
    guest.deliver(datagram(1, DISCOVERY_PORT, 41000));
    assert!(game_receives(&guest_game).await.is_some());
}

#[tokio::test(start_paused = true)]
async fn a_reply_needs_a_flow_the_game_opened() {
    let (guest, guest_game) = node(2);
    guest.deliver(datagram(1, GAME_PORT, 50000));
    assert!(game_receives(&guest_game).await.is_none());
    assert_eq!(guest.health().dropped_filter, 1);

    game_sends(
        &guest,
        &guest_game,
        Udp::unicast(2, 1, 50000, GAME_PORT).frame(),
    )
    .await
    .unwrap();
    guest.deliver(datagram(1, GAME_PORT, 50000));
    assert!(game_receives(&guest_game).await.is_some());

    // The flow is the exact tuple: another remote port does not match it.
    guest.deliver(datagram(1, 7778, 50000));
    assert!(game_receives(&guest_game).await.is_none());
}

#[tokio::test(start_paused = true)]
async fn an_idle_flow_closes_after_30_seconds() {
    let (guest, guest_game) = node(2);
    let open_flow = Udp::unicast(2, 1, 50000, GAME_PORT).frame();
    game_sends(&guest, &guest_game, open_flow.clone())
        .await
        .unwrap();

    tokio::time::advance(Duration::from_secs(29)).await;
    guest.deliver(datagram(1, GAME_PORT, 50000));
    assert!(
        game_receives(&guest_game).await.is_some(),
        "still live at 29 s"
    );

    // Peer traffic does not refresh it; only the game's own does.
    tokio::time::advance(Duration::from_secs(2)).await;
    guest.deliver(datagram(1, GAME_PORT, 50000));
    assert!(
        game_receives(&guest_game).await.is_none(),
        "expired at 31 s"
    );

    game_sends(&guest, &guest_game, open_flow).await.unwrap();
    guest.deliver(datagram(1, GAME_PORT, 50000));
    assert!(
        game_receives(&guest_game).await.is_some(),
        "reopened by the game"
    );
}

#[tokio::test(start_paused = true)]
async fn recv_reports_closed_when_the_game_end_is_gone() {
    let (lan, game) = node(2);
    drop(game);
    assert_eq!(lan.recv().await.unwrap_err(), LanError::Closed);
    // Delivering to a gone game is a silent no-op, not an overload.
    lan.deliver(datagram(1, GAME_PORT, GAME_PORT));
    assert_eq!(lan.health(), LanHealth::default());
}

#[tokio::test(start_paused = true)]
async fn game_end_reports_closed_when_the_lan_is_gone() {
    let (lan, game) = node(2);
    drop(lan);
    assert_eq!(game.recv_frame().await.unwrap_err(), LanError::Closed);
    assert_eq!(game.send_frame(Bytes::new()).unwrap_err(), LanError::Closed);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn nstap_waits_for_m3() {
    let fd = std::os::fd::OwnedFd::from(std::fs::File::open("/dev/null").unwrap());
    let refused = open(
        kickoff_vlan::Adapter::NsTap(fd),
        kickoff_vlan::LanConfig { slot: slot(1) },
    );
    assert_eq!(refused.err(), Some(LanError::Unsupported));
}

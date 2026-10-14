//! The security invariants `vlan` holds a layer of (docs/SECURITY-INVARIANTS.md).
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::*;
use kickoff_wire::LanDatagram;

/// SI-18: a flow belongs to the admission it was opened under. When a slot's
/// generation changes, the next holder cannot answer the old holder's flows.
#[tokio::test(start_paused = true)]
async fn si_18_flows_do_not_survive_a_generation_change() {
    let (host, host_game) = node(1);
    for guest in [3, 4] {
        let probe = Udp::unicast(1, guest, 40000, GAME_PORT).frame();
        game_sends(&host, &host_game, probe).await.unwrap();
    }
    host.deliver(datagram(3, GAME_PORT, 40000));
    assert!(
        game_receives(&host_game).await.is_some(),
        "the flow is open"
    );

    // Slot 3 is kicked and re-admitted, or reconnects: a new generation.
    host.reset_peer(slot(3));
    host.deliver(datagram(3, GAME_PORT, 40000));
    assert!(
        game_receives(&host_game).await.is_none(),
        "the new generation answered a flow it did not open"
    );

    host.deliver(datagram(4, GAME_PORT, 40000));
    assert!(
        game_receives(&host_game).await.is_some(),
        "slot 4 is untouched"
    );
}

#[tokio::test(start_paused = true)]
async fn si_18_broadcast_reply_flows_follow_each_peers_generation() {
    let (host, game) = node(1);
    let beacon = Udp::broadcast(1, 40000, DISCOVERY_PORT).frame();
    game_sends(&host, &game, beacon.clone()).await.unwrap();
    for guest in [3, 4] {
        host.deliver(datagram(guest, DISCOVERY_PORT, 40000));
        assert!(game_receives(&game).await.is_some());
    }

    host.reset_peer(slot(3));
    host.deliver(datagram(3, DISCOVERY_PORT, 40000));
    assert!(
        game_receives(&game).await.is_none(),
        "a new generation inherited the previous broadcast's return permission"
    );
    host.deliver(datagram(4, DISCOVERY_PORT, 40000));
    assert!(
        game_receives(&game).await.is_some(),
        "resetting one recipient erased an unaffected guest's flow"
    );
    game_sends(&host, &game, beacon).await.unwrap();
    host.deliver(datagram(3, DISCOVERY_PORT, 40000));
    assert!(
        game_receives(&game).await.is_some(),
        "a fresh beacon reopens the flow"
    );
}

#[tokio::test(start_paused = true)]
async fn si_23_broadcast_and_unicast_share_the_per_peer_flow_limit() {
    let (host, game) = node(1);
    for port in 40000..40064 {
        game_sends(&host, &game, Udp::unicast(1, 3, port, GAME_PORT).frame())
            .await
            .unwrap();
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    for port in 45000..45016 {
        game_sends(
            &host,
            &game,
            Udp::broadcast(1, port, DISCOVERY_PORT).frame(),
        )
        .await
        .unwrap();
        tokio::time::advance(Duration::from_millis(100)).await;
    }
    let mut replies = 0;
    for port in 40000..40064 {
        host.deliver(datagram(3, GAME_PORT, port));
        replies += usize::from(game_receives(&game).await.is_some());
    }
    for port in 45000..45016 {
        host.deliver(datagram(3, DISCOVERY_PORT, port));
        replies += usize::from(game_receives(&game).await.is_some());
    }
    assert_eq!(
        replies, 64,
        "broadcast permissions exceeded the peer's combined flow limit"
    );
    host.deliver(datagram(3, DISCOVERY_PORT, 45015));
    assert!(
        game_receives(&game).await.is_some(),
        "the newest broadcast flow is retained"
    );
}

/// SI-21: a guest's LAN has one peer, the host. Whatever its game sends or a
/// misrouted datagram claims, it neither reaches nor hears another guest.
#[tokio::test(start_paused = true)]
async fn si_21_a_guest_lan_reaches_only_the_host() {
    let (guest, game) = node(2);

    let to_guest = Udp::unicast(2, 3, 50000, GAME_PORT).frame();
    assert!(game_sends(&guest, &game, to_guest).await.is_none());

    game.send_frame(Bytes::from(arp_request(2, ip(3)))).unwrap();
    assert!(recv_now(&guest).await.is_none());
    assert!(
        game_receives(&game).await.is_none(),
        "ARP for a guest unanswered"
    );

    let beacon = Udp::broadcast(2, 40000, DISCOVERY_PORT).frame();
    let d = game_sends(&guest, &game, beacon).await.unwrap();
    assert_eq!(d.peer, slot(1), "a guest's broadcast goes to the host only");

    for from in 2..=8 {
        guest.deliver(datagram(from, GAME_PORT, GAME_PORT));
        guest.deliver(broadcast(from, 40000, DISCOVERY_PORT));
    }
    assert!(
        game_receives(&game).await.is_none(),
        "no guest reached the game"
    );
    guest.deliver(datagram(1, GAME_PORT, GAME_PORT));
    assert!(game_receives(&game).await.is_some(), "the host still does");
}

/// SI-23: one peer flooding the host spends its own budget, not the others'.
#[tokio::test(start_paused = true)]
async fn si_23_a_flooding_peer_is_capped_and_the_others_get_through() {
    let (host, game) = node(1);
    let mut from_flooder = 0;
    for i in 0..5000 {
        host.deliver(datagram(2, 50000, GAME_PORT));
        if i % 100 == 0 {
            from_flooder += game_receives_all(&game).await.len();
        }
    }
    from_flooder += game_receives_all(&game).await.len();
    assert_eq!(from_flooder, 1000, "the per-peer burst");
    assert_eq!(host.health().dropped_overload, 4000);

    host.deliver(datagram(3, 50000, GAME_PORT));
    assert!(
        game_receives(&game).await.is_some(),
        "another peer is unaffected"
    );

    // 3000 pps refill: 100 ms buys 300 more.
    tokio::time::advance(Duration::from_millis(100)).await;
    for _ in 0..1000 {
        host.deliver(datagram(2, 50000, GAME_PORT));
    }
    assert_eq!(game_receives_all(&game).await.len(), 256, "the game queue");
    assert_eq!(host.health().to_game, 1000 + 1 + 256);
}

/// SI-23: the byte budget binds before the packet budget for full frames.
#[tokio::test(start_paused = true)]
async fn si_23_a_peer_is_capped_in_bytes() {
    let (host, game) = node(1);
    let full = LanDatagram {
        payload: Bytes::from(vec![0; 1472]),
        ..datagram(2, 50000, GAME_PORT)
    };
    let mut received = 0;
    for _ in 0..1000 {
        host.deliver(full.clone());
        received += game_receives_all(&game).await.len();
    }
    assert_eq!(received, 1_000_000 / 1472, "1 MB burst");
}

/// SI-23: every attempt pays before the filter looks at it, so forbidden
/// traffic cannot be sent for free.
#[tokio::test(start_paused = true)]
async fn si_23_forbidden_attempts_pay_the_budget() {
    let (host, game) = node(1);
    for _ in 0..1000 {
        host.deliver(datagram(2, GAME_PORT, 22));
    }
    assert_eq!(host.health().dropped_filter, 1000);
    host.deliver(datagram(2, 50000, GAME_PORT));
    assert!(game_receives(&game).await.is_none());
    assert_eq!(host.health().dropped_overload, 1);
}

/// SI-23: the game's queue has a fixed size; delivery past it drops and
/// counts instead of growing or blocking.
#[tokio::test(start_paused = true)]
async fn si_23_the_game_queue_is_bounded() {
    let (host, game) = node(1);
    for _ in 0..200 {
        for peer in 2..=8 {
            host.deliver(datagram(peer, 50000, GAME_PORT));
        }
    }
    assert_eq!(host.health().to_game, 256);
    assert_eq!(host.health().dropped_overload, 1400 - 256);
    assert_eq!(game_receives_all(&game).await.len(), 256);
}

/// SI-23 (§6.3): discovery broadcasts are limited to 10/s per sender, from
/// each peer and from the local game.
#[tokio::test(start_paused = true)]
async fn si_23_broadcasts_are_rate_limited_per_sender() {
    let (host, game) = node(1);
    for _ in 0..100 {
        host.deliver(broadcast(2, 40000, DISCOVERY_PORT));
        host.deliver(broadcast(3, 40000, DISCOVERY_PORT));
    }
    assert_eq!(
        game_receives_all(&game).await.len(),
        20,
        "10 from each sender"
    );

    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..100 {
        host.deliver(broadcast(2, 40000, DISCOVERY_PORT));
    }
    assert_eq!(
        game_receives_all(&game).await.len(),
        10,
        "10 more a second later"
    );

    for _ in 0..100 {
        game.send_frame(Bytes::from(
            Udp::broadcast(1, 40000, DISCOVERY_PORT).frame(),
        ))
        .unwrap();
    }
    assert_eq!(
        recv_all(&host).await.len(),
        10,
        "the local game's own beacons"
    );
}

/// SI-23: the flow table holds 64 flows per peer; a game opening more
/// replaces its least recently used flows instead of growing the table.
#[tokio::test(start_paused = true)]
async fn si_23_the_flow_table_holds_64_per_peer() {
    let (guest, game) = node(2);
    for port in 50000..50100 {
        game.send_frame(Bytes::from(Udp::unicast(2, 1, port, GAME_PORT).frame()))
            .unwrap();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(recv_now(&guest).await.is_some());
    }
    let mut answered = Vec::new();
    for port in 50000..50100 {
        guest.deliver(datagram(1, GAME_PORT, port));
        if game_receives(&game).await.is_some() {
            answered.push(port);
        }
    }
    assert_eq!(answered, (50036..50100).collect::<Vec<_>>());
}

/// SI-23: a generation change forgets the slot's flows but not its spent
/// budget, so reconnecting does not buy a flooding peer a fresh burst.
#[tokio::test(start_paused = true)]
async fn si_23_a_new_generation_does_not_refill_the_budget() {
    let (host, game) = node(1);
    for _ in 0..1000 {
        host.deliver(datagram(2, 50000, GAME_PORT));
    }
    assert_eq!(game_receives_all(&game).await.len(), 256, "the game queue");
    host.reset_peer(slot(2));
    host.deliver(datagram(2, 50000, GAME_PORT));
    assert!(game_receives(&game).await.is_none());
    assert_eq!(host.health().dropped_overload, 1000 - 256 + 1);
}

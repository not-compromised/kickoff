//! The pump (§2.4): game traffic between the host and each guest, and nothing
//! between guests (SI-21). Three in-process nodes; every game is a test
//! reading and writing frames.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use kickoff_net::Role;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broadcast_and_unicast_round_trip() {
    let host = host().await;
    let (a, b) = (Identity::new().await, Identity::new().await);
    let (ta, tb) = (host.bound(a.id()), host.bound(b.id()));
    let a = join(a, ta).await.unwrap();
    let b = join(b, tb).await.unwrap();
    assert_eq!((a.slot(), b.slot()), (2, 3));

    // The host's beacon reaches every guest, from slot 1.
    host.game
        .send_frame(udp(1, None, BEACON_PORT, BEACON_PORT, b"beacon"))
        .unwrap();
    for guest in [&a, &b] {
        let got = next_udp(&guest.game, WAIT).await.unwrap();
        assert_eq!(
            (got.from, got.bcast, got.dst_port, got.payload.as_slice()),
            (1, true, BEACON_PORT, &b"beacon"[..])
        );
    }

    // A guest's beacon reaches the host's game, and only it.
    a.game
        .send_frame(udp(2, None, BEACON_PORT, BEACON_PORT, b"from a"))
        .unwrap();
    let got = next_udp(&host.game, WAIT).await.unwrap();
    assert_eq!((got.from, got.bcast), (2, true));

    // Unicast both ways, to the addressed guest only.
    a.game
        .send_frame(udp(2, Some(1), 50_000, GAME_PORT, b"join"))
        .unwrap();
    let got = next_udp(&host.game, WAIT).await.unwrap();
    assert_eq!(
        (got.from, got.src_port, got.payload.as_slice()),
        (2, 50_000, &b"join"[..])
    );
    host.game
        .send_frame(udp(1, Some(2), GAME_PORT, 50_000, b"welcome"))
        .unwrap();
    let got = next_udp(&a.game, WAIT).await.unwrap();
    assert_eq!(
        (got.from, got.dst_port, got.payload.as_slice()),
        (1, 50_000, &b"welcome"[..])
    );
    host.game
        .send_frame(udp(1, Some(3), 40_000, GAME_PORT, b"for b"))
        .unwrap();
    let got = next_udp(&b.game, WAIT).await.unwrap();
    assert_eq!((got.from, got.payload.as_slice()), (1, &b"for b"[..]));
    assert_eq!(
        next_udp(&a.game, QUIET).await,
        None,
        "B's unicast reached A"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_21_guest_cannot_reach_another_guest() {
    let host = host().await;
    let (a, b) = (Identity::new().await, Identity::new().await);
    let (ta, tb) = (host.bound(a.id()), host.bound(b.id()));
    let a = join(a, ta).await.unwrap();
    // B is played at the link, so the test sees everything the host sends it.
    let b = RawGuest::join(b, &tb).await.unwrap();
    let (b_link, _b_ctl) = b.connect().await.unwrap();
    assert_eq!((a.slot(), b.slot().get()), (2, 3));

    a.game
        .send_frame(udp(2, None, BEACON_PORT, BEACON_PORT, b"beacon"))
        .unwrap();
    a.game
        .send_frame(udp(2, Some(3), GAME_PORT, GAME_PORT, b"to b"))
        .unwrap();
    a.game
        .send_frame(udp(2, Some(1), 50_000, GAME_PORT, b"to host"))
        .unwrap();
    let at_host = drain_udp(&host.game, QUIET).await;
    assert!(at_host.iter().all(|s| s.from == 2));
    assert!(
        at_host.iter().any(|s| s.bcast),
        "the host's game missed A's beacon"
    );
    assert!(at_host.iter().any(|s| s.payload == b"to host"));
    assert!(!at_host.iter().any(|s| s.payload == b"to b"));

    let leaked = tokio::time::timeout(QUIET, b_link.recv_lan()).await;
    assert!(
        leaked.is_err(),
        "the host forwarded A's traffic to B: {leaked:?}"
    );

    // A guest's session endpoint accepts nobody, another guest included.
    let other = session_net(Role::Guest).await;
    let direct = other.dial(b.net.addr(), b.admitted.pass).await;
    if let Ok((_link, mut ctl)) = direct {
        let hello = kickoff_wire::GuestMsg::Hello {
            generation: b.admitted.pass.generation,
        };
        let sent = ctl.send(&hello).await;
        let answered = tokio::time::timeout(QUIET, ctl.recv::<kickoff_wire::HostMsg>()).await;
        assert!(
            sent.is_err() || !matches!(answered, Ok(Ok(_))),
            "a guest's endpoint accepted a connection"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_leaving_ends_every_guest() {
    use kickoff_session::{Command, EndReason, SessionError, SessionEvent};

    let host = host().await;
    let (a, b) = (Identity::new().await, Identity::new().await);
    let (ta, tb) = (host.bound(a.id()), host.bound(b.id()));
    let mut a = join(a, ta).await.unwrap();
    let mut b = join(b, tb).await.unwrap();
    host.session.command(Command::Leave).await.unwrap();
    for guest in [&mut a, &mut b] {
        let ended = event(&mut guest.events, |e| match e {
            SessionEvent::Ended(reason) => Some(*reason),
            _ => None,
        })
        .await;
        assert_eq!(ended, EndReason::HostEnded);
    }
    assert_eq!(
        host.session.command(Command::Leave).await,
        Err(SessionError::Ended)
    );
}

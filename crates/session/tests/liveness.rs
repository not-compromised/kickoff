//! Link liveness (§4.5, PRIV-29): the host pings every link every 5 s and
//! closes one that sent no `Pong` for 15 s on the host clock.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use common::*;
use kickoff_session::{Clock, SessionEvent};
use kickoff_wire::HostMsg;

/// SI-23: an authenticated link that stops answering cannot hold its
/// connection; one that answers keeps it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_23_link_silent_for_15_s_closed() {
    let clock = Clock::system();
    let host = host_with(|o| o.clock = clock.clone()).await;

    // Alice reads the host's control messages and never answers a ping.
    let alice = Identity::new().await;
    let ticket = host.bound(alice.id());
    let alice = RawGuest::join(alice, &ticket).await.unwrap();
    let (alice_link, mut alice_ctl) = alice.connect().await.unwrap();
    let pings = Arc::new(AtomicU32::new(0));
    let reader = {
        let pings = Arc::clone(&pings);
        tokio::spawn(async move {
            while let Ok(msg) = alice_ctl.recv::<HostMsg>().await {
                if msg == HostMsg::Ping {
                    pings.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
    };

    // Bob is a real guest, which answers every ping.
    let bob = Identity::new().await;
    let ticket = host.bound(bob.id());
    let mut bob = join(bob, ticket).await.unwrap();

    // Each link's first ping comes 5 s after its link came up; once Bob has
    // answered his, 8 s on the host clock leaves Alice 15 s or more without
    // a pong at her next ping and Bob about 13 s.
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(pings.load(Ordering::SeqCst) >= 1, "the host never pinged");
    clock.advance(Duration::from_secs(8));
    let closed = tokio::time::timeout(Duration::from_secs(8), alice_link.closed()).await;
    assert!(closed.is_ok(), "a link silent for 15 s stayed open");
    reader.abort();

    // Past Bob's next ping, which falls about when Alice's link closed.
    let dropped = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(SessionEvent::Reconnecting | SessionEvent::Ended(_)) = bob.events.recv().await
            {
                return;
            }
        }
    })
    .await;
    assert!(dropped.is_err(), "the link that answered was closed");
    bob.game
        .send_frame(udp(3, Some(1), 50_000, GAME_PORT, b"still here"))
        .unwrap();
    let got = next_udp(&host.game, WAIT).await.unwrap();
    assert_eq!((got.from, got.payload.as_slice()), (3, &b"still here"[..]));
}

/// A zero-credit transport keeps QUIC alive while blocking the first roster.
/// The route's delivered datagram proves Hello was accepted before the clock moves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_23_blocked_control_write_cannot_suspend_pong_expiry() {
    let clock = Clock::system();
    let host = host_with(|o| o.clock = clock.clone()).await;
    let identity = Identity::new().await;
    let raw = raw_endpoint_with_window(std::net::Ipv4Addr::LOCALHOST, 0).await;
    let ticket = host.bound(identity.id());
    let admitted = identity
        .door
        .request_join(&ticket, raw_request(&ticket, raw.id()))
        .await
        .unwrap();
    let conn = raw
        .connect(admitted.session_addr, kickoff_net::SESSION_ALPN)
        .await
        .unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    send.write_all(
        &kickoff_wire::encode_framed(&kickoff_wire::GuestMsg::Hello {
            generation: admitted.pass.generation,
        })
        .unwrap(),
    )
    .await
    .unwrap();
    let packet = kickoff_wire::LanDatagram {
        peer: kickoff_wire::PeerSlot::HOST,
        bcast: false,
        src_port: 50_000,
        dst_port: GAME_PORT,
        payload: b"route is live".to_vec().into(),
    };
    let fragments = kickoff_wire::encode_datagram(&packet, 1, 1000).unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            for fragment in &fragments {
                conn.send_datagram(fragment.clone()).unwrap();
            }
            if next_udp(&host.game, Duration::from_millis(20))
                .await
                .is_some()
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(conn.close_reason().is_none());
    clock.advance(Duration::from_secs(15));
    assert!(
        tokio::time::timeout(Duration::from_secs(1), conn.closed())
            .await
            .is_ok(),
        "a blocked roster write suspended the absolute Pong deadline"
    );
}

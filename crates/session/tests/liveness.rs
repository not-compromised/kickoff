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

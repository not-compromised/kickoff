//! Kicks (§4.4, SI-18, SI-19): what a kicked identity can still do.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::*;
use kickoff_net::{NetError, Role};
use kickoff_session::{Command, EndReason, InviteKind, SessionEvent};
use kickoff_wire::{JoinRefused, KickReason, LanDatagram, PeerSlot};

fn to_host(n: u32) -> LanDatagram {
    LanDatagram {
        peer: PeerSlot::HOST,
        bcast: false,
        src_port: 50_000,
        dst_port: GAME_PORT,
        payload: n.to_be_bytes().to_vec().into(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_19_kicked_peer_datagrams_dropped() {
    let HostNode {
        identity: host_identity,
        session,
        game,
        ..
    } = host().await;
    let alice = Identity::new().await;
    let alice_id = alice.id();
    let ticket = session.invite(InviteKind::Bound(alice_id)).unwrap();
    let alice = RawGuest::join(alice, &ticket).await.unwrap();
    let slot = alice.slot().get();
    let (link, _ctl) = alice.connect().await.unwrap();
    let link = Arc::new(link);

    // Alice keeps sending, kick or no kick: 1000 datagrams a second, within budget.
    let stop = Arc::new(AtomicBool::new(false));
    let flood = {
        let (link, stop) = (Arc::clone(&link), Arc::clone(&stop));
        tokio::spawn(async move {
            let mut n = 0u32;
            while !stop.load(Ordering::Relaxed) {
                link.send_lan(&to_host(n));
                n += 1;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
    };
    let game = Arc::new(game);
    let seen = {
        let game = Arc::clone(&game);
        tokio::spawn(async move {
            let mut log = Vec::new();
            while let Some(s) = next_udp(&game, Duration::from_secs(2)).await {
                log.push((Instant::now(), s.from));
            }
            log
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    session.command(Command::Kick(alice_id)).await.unwrap();
    let kicked = Instant::now();
    tokio::time::sleep(Duration::from_secs(1)).await;
    stop.store(true, Ordering::Relaxed);
    flood.await.unwrap();
    let log = seen.await.unwrap();

    let before = log.iter().filter(|(_, from)| *from == slot).count();
    assert!(
        before > 50,
        "only {before} datagrams arrived before the kick"
    );
    // Anything read this long after the kick was delivered after it.
    let late = log
        .iter()
        .filter(|(at, from)| *from == slot && *at > kicked + Duration::from_millis(50))
        .count();
    assert_eq!(
        late, 0,
        "{late} datagrams from the kicked peer reached the game"
    );

    assert!(alice.connect().await.is_err(), "the kicked key redialed");
    let fresh = session.invite(InviteKind::Bound(alice_id)).unwrap();
    let net = session_net(Role::Guest).await;
    assert_eq!(
        request_join(&alice.identity, &net, &fresh).await.err(),
        Some(NetError::Refused(JoinRefused::Revoked))
    );
    drop(host_identity);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_19_kick_overrides_trust_and_every_ticket() {
    let alice = Identity::new().await;
    let alice_id = alice.id();
    let host = host_with(|o| o.trusted = vec![alice_id]).await;
    let first = host.bound(alice_id);
    let trusted_again = duplicate(&first);
    let bound = host.bound(alice_id);
    let bearer = host.bearer();

    let mut alice = join(alice, first).await.unwrap();
    host.session.command(Command::Kick(alice_id)).await.unwrap();
    let ended = event(&mut alice.events, |e| match e {
        SessionEvent::Ended(reason) => Some(*reason),
        _ => None,
    })
    .await;
    assert_eq!(ended, EndReason::Kicked(KickReason::Kicked));
    roster_slots(&host, &[1]).await;

    let identity = alice.identity;
    for ticket in [&bound, &bearer, &trusted_again] {
        let net = session_net(Role::Guest).await;
        assert_eq!(
            request_join(&identity, &net, ticket).await.err(),
            Some(NetError::Refused(JoinRefused::Revoked))
        );
    }

    // Only an explicit host action lifts it; then trust applies again.
    host.session
        .command(Command::Readmit(alice_id))
        .await
        .unwrap();
    let back = join(identity, trusted_again).await.unwrap();
    assert_eq!(back.slot(), 2);
}

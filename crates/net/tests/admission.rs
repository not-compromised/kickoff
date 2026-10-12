//! The session endpoint's admission hook (§4.3, §4.4) through the public API,
//! with hostile peers played by bare iroh endpoints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::*;
use kickoff_net::{AdmittedSet, JOIN_ALPN, NetError, Role, SESSION_ALPN};
use kickoff_wire::Generation;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_18_unknown_session_key_rejected_on_session_alpn() {
    let host = node(Role::Host).await;
    let admitted = node(Role::Guest).await;
    host.set_admitted(
        [(admitted.id(), peer(2, 1))]
            .into_iter()
            .collect::<AdmittedSet>(),
    );

    let stranger = raw_endpoint().await;
    let refused = raw_dial(&stranger, host.addr(), SESSION_ALPN).await;
    assert!(
        refused.is_err(),
        "an unadmitted key got a usable session connection"
    );

    let wrong_alpn = raw_dial(&stranger, host.addr(), JOIN_ALPN).await;
    assert!(
        wrong_alpn.is_err(),
        "the session endpoint spoke the join ALPN"
    );

    let link = dial(&host, &admitted, peer(2, 1)).await;
    assert!(link.is_ok(), "the admitted key was refused");
    let accepted = tokio::time::timeout(WAIT, host.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.0.peer().slot.get(), 2);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), host.accept())
            .await
            .is_err(),
        "the stranger's attempt surfaced as a link"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_18_one_live_connection_per_session_key() {
    let host = node(Role::Host).await;
    let guest = node(Role::Guest).await;
    let p = peer(3, 1);
    let (_host_link, _guest_link) = pair(&host, &guest, p).await;

    let mut extra = Vec::new();
    for _ in 0..20 {
        if let Ok(link) = dial(&host, &guest, p).await {
            extra.push(link);
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), host.accept())
            .await
            .is_err(),
        "a second live connection from one session key was handed out"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_18_republished_generation_closes_the_old_link() {
    let host = node(Role::Host).await;
    let guest = node(Role::Guest).await;
    let p = peer(4, 1);
    let (host_link, guest_link) = pair(&host, &guest, p).await;
    guest_link.send_lan(&lan(32, 1));
    let got = tokio::time::timeout(WAIT, host_link.recv_lan())
        .await
        .unwrap();
    assert!(got.is_ok(), "datagram before the bump");

    let bumped = kickoff_wire::PeerRef {
        generation: Generation::new(2),
        ..p
    };
    host.set_admitted([(guest.id(), bumped)].into_iter().collect::<AdmittedSet>());
    guest_link.send_lan(&lan(32, 2));
    let after = tokio::time::timeout(WAIT, host_link.recv_lan())
        .await
        .unwrap();
    assert_eq!(
        after.err(),
        Some(NetError::Closed),
        "a stale generation delivered"
    );
    tokio::time::timeout(WAIT, guest_link.closed())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_19_removed_key_cannot_reconnect() {
    let host = node(Role::Host).await;
    let guest = node(Role::Guest).await;
    let p = peer(5, 1);
    let (host_link, guest_link) = pair(&host, &guest, p).await;
    host.set_admitted(AdmittedSet::new());
    tokio::time::timeout(WAIT, guest_link.closed())
        .await
        .unwrap();
    drop((host_link, guest_link));

    let again = tokio::time::timeout(WAIT, dial(&host, &guest, p))
        .await
        .unwrap();
    if let Ok(mut link) = again {
        let closed = tokio::time::timeout(WAIT, link.ctl().recv::<kickoff_wire::HostMsg>()).await;
        assert!(
            matches!(closed, Ok(Err(_))),
            "a revoked key kept a working link"
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), host.accept())
            .await
            .is_err(),
        "a revoked key surfaced as a link"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_21_guest_session_endpoint_accepts_nothing() {
    let guest = node(Role::Guest).await;
    let other_guest = node(Role::Guest).await;
    let attacker = raw_endpoint().await;
    for alpn in [SESSION_ALPN, JOIN_ALPN] {
        assert!(raw_dial(&attacker, guest.addr(), alpn).await.is_err());
    }
    let dialed = tokio::time::timeout(WAIT, dial(&guest, &other_guest, peer(2, 1))).await;
    assert!(
        !matches!(dialed, Ok(Ok(_))),
        "guest A reached guest B's session endpoint"
    );
    assert_eq!(guest.accept().await.err(), Some(NetError::WrongRole));
}

/// SI-18, the publishing half: a set that bumps a key's generation closes its
/// live connection at once, with no traffic needed to notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_18_republished_generation_closes_an_idle_link() {
    let host = node(Role::Host).await;
    let guest = node(Role::Guest).await;
    let p = peer(4, 1);
    let (_host_link, guest_link) = pair(&host, &guest, p).await;
    let bumped = kickoff_wire::PeerRef {
        generation: Generation::new(2),
        ..p
    };
    host.set_admitted([(guest.id(), bumped)].into_iter().collect::<AdmittedSet>());
    assert!(
        tokio::time::timeout(WAIT, guest_link.closed())
            .await
            .is_ok(),
        "the stale link stayed open"
    );
}

/// SI-21: a guest's session endpoint refuses even a key it was told to admit,
/// so no admitted-set mistake can make a guest reachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_21_guest_refuses_even_a_key_it_was_told_to_admit() {
    let guest = node(Role::Guest).await;
    let attacker = raw_endpoint().await;
    guest.set_admitted(
        [(attacker.id(), peer(2, 1))]
            .into_iter()
            .collect::<AdmittedSet>(),
    );
    assert!(
        raw_dial(&attacker, guest.addr(), SESSION_ALPN)
            .await
            .is_err(),
        "a guest accepted a session connection"
    );
}

/// SI-23: an admitted key that completes the handshake and never opens its
/// control stream is dropped at the handshake deadline (5 s), so silent
/// connections cannot hold the 16 pending slots.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_23_silent_connection_closed_at_the_handshake_deadline() {
    let host = node(Role::Host).await;
    let silent = raw_endpoint().await;
    host.set_admitted(
        [(silent.id(), peer(2, 1))]
            .into_iter()
            .collect::<AdmittedSet>(),
    );
    let conn = tokio::time::timeout(WAIT, silent.connect(host.addr(), SESSION_ALPN))
        .await
        .unwrap()
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(8), conn.closed()).await;
    assert!(closed.is_ok(), "a silent connection outlived the deadline");
}

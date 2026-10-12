//! Reconnect (§4.4, §4.6): a dropped guest keeps its slot for the window,
//! under a new generation that shares nothing with the old one.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::*;
use kickoff_net::{CtlStream, Link};
use kickoff_session::Clock;
use kickoff_wire::{LanDatagram, PeerSlot};

fn to_host(src_port: u16, dst_port: u16, byte: u8) -> LanDatagram {
    LanDatagram {
        peer: PeerSlot::HOST,
        bcast: false,
        src_port,
        dst_port,
        payload: vec![byte; 16].into(),
    }
}

/// Redials until the host has noticed the old link is gone and lets the new
/// one in.
async fn redial(guest: &RawGuest) -> (Link, CtlStream) {
    tokio::time::timeout(WAIT, async {
        loop {
            if let Ok(connected) = guest.connect().await {
                return connected;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the redial was never admitted")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_inside_the_window_keeps_the_slot() {
    let host = host().await;
    let alice = Identity::new().await;
    let ticket = host.bound(alice.id());
    let alice = RawGuest::join(alice, &ticket).await.unwrap();
    let (link, ctl) = alice.connect().await.unwrap();
    link.send_lan(&to_host(50_000, GAME_PORT, 1));
    assert_eq!(next_udp(&host.game, WAIT).await.unwrap().from, 2);

    link.close();
    drop((link, ctl));
    let bob = Identity::new().await;
    let ticket = host.bound(bob.id());
    let bob = join(bob, ticket).await.unwrap();
    assert_eq!(
        bob.slot(),
        3,
        "the reconnecting guest's slot stays reserved"
    );

    let (link, _ctl) = redial(&alice).await;
    link.send_lan(&to_host(50_000, GAME_PORT, 2));
    let seen = next_udp(&host.game, WAIT).await.unwrap();
    assert_eq!((seen.from, seen.payload), (2, vec![2; 16]));
    roster_slots(&host, &[1, 2, 3]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_after_the_window_is_refused_and_frees_the_slot() {
    let clock = Clock::system();
    let host = host_with(|o| o.clock = clock.clone()).await;
    let alice = Identity::new().await;
    let ticket = host.bound(alice.id());
    let alice = RawGuest::join(alice, &ticket).await.unwrap();
    let (link, ctl) = alice.connect().await.unwrap();
    link.close();
    drop((link, ctl));

    outlast_window(&clock, &host, &[1]).await;
    assert!(alice.connect().await.is_err(), "evicted, yet redialed");

    let bob = Identity::new().await;
    let ticket = host.bound(bob.id());
    assert_eq!(join(bob, ticket).await.unwrap().slot(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_18_reconnect_forgets_the_old_generations_flows() {
    let host = host().await;
    let alice = Identity::new().await;
    let ticket = host.bound(alice.id());
    let alice = RawGuest::join(alice, &ticket).await.unwrap();
    let (link, ctl) = alice.connect().await.unwrap();

    // The host's game opens a flow to Alice from a port peers cannot reach
    // otherwise, and her reply is let in through it.
    host.game
        .send_frame(udp(1, Some(2), 30_000, GAME_PORT, b"open"))
        .unwrap();
    let opened = tokio::time::timeout(WAIT, link.recv_lan())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(opened.dst_port, GAME_PORT);
    link.send_lan(&to_host(GAME_PORT, 30_000, 1));
    let reply = next_udp(&host.game, WAIT).await.unwrap();
    assert_eq!((reply.from, reply.dst_port), (2, 30_000));

    link.close();
    drop((link, ctl));
    let (link, _ctl) = redial(&alice).await;
    link.send_lan(&to_host(GAME_PORT, 30_000, 2));
    assert_eq!(
        next_udp(&host.game, QUIET).await,
        None,
        "a flow from the old generation answered the new one"
    );
    link.send_lan(&to_host(50_000, GAME_PORT, 3));
    assert_eq!(
        next_udp(&host.game, WAIT).await.unwrap().payload,
        vec![3; 16]
    );
}

/// The guest side of §4.6, against a host the test plays with `kickoff-net`
/// directly: when its link drops, the guest redials with the same pass and
/// carries on once the host's roster arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guest_redials_after_a_drop_and_carries_on() {
    use kickoff_net::{AdmittedSet, Role};
    use kickoff_secret::Secret;
    use kickoff_session::SessionEvent;
    use kickoff_wire::{
        AdmitPass, Admitted, BoundedVec, Cap, Generation, GuestMsg, HostMsg, Member, Nonce,
        SessionId, Ticket,
    };

    let host_identity = Identity::new().await;
    let host_net = session_net(Role::Host).await;
    let alice = Identity::new().await;
    let alice_id = alice.id();
    let ticket = Secret::new(Ticket {
        door: host_identity.door.addr(),
        cap: Cap::new_for_door(
            host_identity.door.id(),
            SessionId([1; 16]),
            Some(alice_id),
            Nonce([2; 16]),
            iroh::Signature::from_bytes(&[0; 64]),
        ),
    });
    let slot = PeerSlot::new(2).unwrap();
    let pass = AdmitPass {
        slot,
        generation: Generation::new(1),
    };
    let roster = |epoch| HostMsg::Roster {
        epoch,
        members: BoundedVec::new(vec![
            Member {
                slot: PeerSlot::HOST,
                id: host_identity.id(),
                name: name("host"),
            },
            Member {
                slot,
                id: alice_id,
                name: name("guest"),
            },
        ])
        .unwrap(),
    };
    let admit = |generation: u64, key| {
        let peer = kickoff_wire::PeerRef {
            id: alice_id,
            slot,
            generation: Generation::new(generation),
        };
        [(key, peer)].into_iter().collect::<AdmittedSet>()
    };

    let joining = tokio::spawn(join(alice, ticket));
    let attempt = tokio::time::timeout(WAIT, host_identity.door.next_join())
        .await
        .unwrap()
        .unwrap();
    let key = attempt.request().session_key;
    host_net.set_admitted(admit(1, key));
    attempt
        .answer(Ok(Admitted {
            session_addr: host_net.addr(),
            pass,
        }))
        .await
        .unwrap();
    let (_link, mut ctl) = tokio::time::timeout(WAIT, host_net.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        ctl.recv::<GuestMsg>().await.unwrap(),
        GuestMsg::Hello { .. }
    ));
    ctl.send(&roster(1)).await.unwrap();
    let mut alice = joining.await.unwrap().unwrap();
    assert_eq!(alice.slot(), 2);

    // The host bumps the generation, which drops the guest's connection.
    host_net.set_admitted(admit(2, key));
    event(&mut alice.events, |e| {
        matches!(e, SessionEvent::Reconnecting).then_some(())
    })
    .await;
    let (link, mut ctl) = tokio::time::timeout(WAIT, host_net.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ctl.recv::<GuestMsg>().await.unwrap(),
        GuestMsg::Hello {
            generation: Generation::new(1)
        },
        "the redial presents the pass it was admitted with"
    );
    ctl.send(&roster(2)).await.unwrap();
    let epoch = event(&mut alice.events, |e| match e {
        SessionEvent::Roster { epoch, .. } => Some(*epoch),
        _ => None,
    })
    .await;
    assert_eq!(epoch, 2);

    link.send_lan(&LanDatagram {
        peer: PeerSlot::HOST,
        bcast: true,
        src_port: BEACON_PORT,
        dst_port: BEACON_PORT,
        payload: b"still here".to_vec().into(),
    });
    let got = next_udp(&alice.game, WAIT).await.unwrap();
    assert_eq!((got.from, got.payload.as_slice()), (1, &b"still here"[..]));
}

/// §4.6: a guest whose host stays unreachable for the 30 s reconnect window,
/// on the guest's clock, ends with `HostLost`, and not before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guest_reports_host_lost_after_the_reconnect_window() {
    use kickoff_net::{AdmittedSet, Role};
    use kickoff_secret::Secret;
    use kickoff_session::{EndReason, SessionEvent};
    use kickoff_wire::{
        AdmitPass, Admitted, BoundedVec, Cap, Generation, GuestMsg, HostMsg, Member, Nonce,
        PeerRef, SessionId, Ticket,
    };

    let host_identity = Identity::new().await;
    let host_net = session_net(Role::Host).await;
    let alice = Identity::new().await;
    let alice_id = alice.id();
    let ticket = Secret::new(Ticket {
        door: host_identity.door.addr(),
        cap: Cap::new_for_door(
            host_identity.door.id(),
            SessionId([1; 16]),
            Some(alice_id),
            Nonce([2; 16]),
            iroh::Signature::from_bytes(&[0; 64]),
        ),
    });
    let slot = PeerSlot::new(2).unwrap();
    let pass = AdmitPass {
        slot,
        generation: Generation::new(1),
    };
    let clock = Clock::system();
    let mut opts = join_opts("guest");
    opts.clock = clock.clone();

    let joining = tokio::spawn(join_with(alice, ticket, opts));
    let attempt = tokio::time::timeout(WAIT, host_identity.door.next_join())
        .await
        .unwrap()
        .unwrap();
    let key = attempt.request().session_key;
    let peer = PeerRef {
        id: alice_id,
        slot,
        generation: Generation::new(1),
    };
    host_net.set_admitted([(key, peer)].into_iter().collect::<AdmittedSet>());
    attempt
        .answer(Ok(Admitted {
            session_addr: host_net.addr(),
            pass,
        }))
        .await
        .unwrap();
    let (_link, mut ctl) = tokio::time::timeout(WAIT, host_net.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        ctl.recv::<GuestMsg>().await.unwrap(),
        GuestMsg::Hello { .. }
    ));
    let members = BoundedVec::new(vec![
        Member {
            slot: PeerSlot::HOST,
            id: host_identity.id(),
            name: name("host"),
        },
        Member {
            slot,
            id: alice_id,
            name: name("guest"),
        },
    ])
    .unwrap();
    ctl.send(&HostMsg::Roster { epoch: 1, members })
        .await
        .unwrap();
    let mut alice = joining.await.unwrap().unwrap();

    // The host forgets Alice: her connection closes and every redial is
    // refused at the handshake.
    host_net.set_admitted(AdmittedSet::new());
    event(&mut alice.events, |e| {
        matches!(e, SessionEvent::Reconnecting).then_some(())
    })
    .await;
    let early = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(SessionEvent::Ended(_)) = alice.events.recv().await {
                return;
            }
        }
    })
    .await;
    assert!(early.is_err(), "the guest gave up inside the window");

    clock.advance(Duration::from_secs(30));
    let ended = event(&mut alice.events, |e| match e {
        SessionEvent::Ended(reason) => Some(*reason),
        _ => None,
    })
    .await;
    assert_eq!(ended, EndReason::HostLost);
}

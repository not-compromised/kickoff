//! Joining through the host's door (§4.2-§4.4): who is admitted, how often a
//! capability admits, and what an unadmitted key gets from the session
//! endpoint.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use kickoff_net::{NetError, Role};
use kickoff_session::{ApprovalAction, Command, SessionError, SessionEvent};
use kickoff_wire::{BEARER_TTL, JoinRefused};

fn refused(result: Result<GuestNode, SessionError>) -> JoinRefused {
    match result {
        Err(SessionError::Refused(why)) => why,
        Err(other) => panic!("expected a refusal, got {other:?}"),
        Ok(guest) => panic!("admitted at slot {}", guest.slot()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bound_ticket_admits_its_invitee() {
    let mut host = host().await;
    let alice = Identity::new().await;
    let alice_id = alice.id();
    let ticket = host.bound(alice_id);

    let guest = join(alice, ticket).await.unwrap();
    assert_eq!(guest.slot(), 2);
    let members = guest.session.members();
    assert_eq!(members.len(), 2);
    assert_eq!(
        (members[0].slot.get(), members[0].id),
        (1, host.identity.id())
    );
    assert_eq!((members[1].slot.get(), members[1].id), (2, alice_id));
    let roster = event(&mut host.events, |e| match e {
        SessionEvent::Roster { members, .. } if members.len() == 2 => Some(members.clone()),
        _ => None,
    })
    .await;
    assert_eq!(roster, members);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_20_bearer_ticket_admits_once() {
    let mut host = host().await;
    let ticket = host.bearer();
    let alice = Identity::new().await;
    let alice_id = alice.id();
    let other = Identity::new().await;
    let copy = duplicate(&ticket);

    let joining = tokio::spawn(join(alice, ticket));
    let prompted = approval(&mut host).await;
    assert_eq!(
        (prompted.peer, prompted.action),
        (alice_id, ApprovalAction::AdmitBearer),
        "the approval shows the authenticated identity"
    );
    host.session
        .command(Command::Decide {
            approval: prompted.id,
            allow: true,
        })
        .await
        .unwrap();
    let alice = joining.await.unwrap().unwrap();
    assert_eq!(alice.slot(), 2);

    assert_eq!(refused(join(other, copy).await), JoinRefused::InvalidCap);
    roster_slots(&host, &[1, 2]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_20_one_capability_on_many_connections_admits_once() {
    let mut host = host().await;
    let ticket = host.bearer();
    let mut tries = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let copy = duplicate(&ticket);
        tries.spawn(async move {
            let identity = Identity::new().await;
            let net = session_net(Role::Guest).await;
            request_join(&identity, &net, &copy).await
        });
    }
    let prompted = approval(&mut host).await;
    host.session
        .command(Command::Decide {
            approval: prompted.id,
            allow: true,
        })
        .await
        .unwrap();
    let mut admitted = 0;
    while let Some(result) = tries.join_next().await {
        match result.unwrap() {
            Ok(_) => admitted += 1,
            // Busy while the first holder's approval is pending (one bearer
            // approval at a time), spent after.
            Err(NetError::Refused(JoinRefused::Busy | JoinRefused::InvalidCap)) => {}
            Err(other) => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(admitted, 1);
    let more = tokio::time::timeout(QUIET, async {
        loop {
            if let Ok(SessionEvent::ApprovalRequested(_)) = host.events.recv().await {
                return;
            }
        }
    })
    .await;
    assert!(more.is_err(), "a second prompt for one capability");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_20_bound_capability_raced_by_its_invitee_admits_once() {
    let host = host().await;
    let alice = Identity::new().await;
    let ticket = host.bound(alice.id());
    let attempts = (0..10).map(|_| async {
        let net = session_net(Role::Guest).await;
        request_join(&alice, &net, &ticket).await
    });
    let results = join_all(attempts).await;
    let admitted = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        admitted,
        1,
        "{:?}",
        results.iter().map(|r| r.as_ref().err()).collect::<Vec<_>>()
    );
    roster_slots(&host, &[1, 2]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_18_one_seat_per_identity_under_concurrent_joins() {
    let alice = Identity::new().await;
    let alice_id = alice.id();
    let host = host_with(|o| o.trusted = vec![alice_id]).await;
    let ticket = host.bearer();
    let attempts = (0..12).map(|_| async {
        let net = session_net(Role::Guest).await;
        request_join(&alice, &net, &ticket).await
    });
    let results = join_all(attempts).await;
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    for r in &results {
        if let Err(e) = r {
            assert_eq!(*e, NetError::Refused(JoinRefused::Busy));
        }
    }
    roster_slots(&host, &[1, 2]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_20_expired_bearer_ticket_refused() {
    let clock = kickoff_session::Clock::system();
    let host = host_with(|o| o.clock = clock.clone()).await;
    let bearer = host.bearer();
    let alice = Identity::new().await;
    let bound = host.bound(alice.id());
    clock.advance(BEARER_TTL);

    let bob = Identity::new().await;
    assert_eq!(refused(join(bob, bearer).await), JoinRefused::Expired);
    let alice = join(alice, bound).await.unwrap();
    assert_eq!(
        alice.slot(),
        2,
        "a bound invite lasts as long as the session"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_20_replayed_ticket_refused() {
    let clock = kickoff_session::Clock::system();
    let host = host_with(|o| o.clock = clock.clone()).await;
    let alice = Identity::new().await;
    let ticket = host.bound(alice.id());
    let replay = duplicate(&ticket);
    let alice = join(alice, ticket).await.unwrap();
    alice.session.command(Command::Leave).await.unwrap();
    outlast_window(&clock, &host, &[1]).await;

    assert_eq!(
        refused(join(alice.identity, replay).await),
        JoinRefused::InvalidCap
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_20_wrong_invitee_refused_and_the_ticket_survives() {
    let host = host().await;
    let alice = Identity::new().await;
    let ticket = host.bound(alice.id());
    let again = duplicate(&ticket);

    let mallory = Identity::new().await;
    assert_eq!(
        refused(join(mallory, ticket).await),
        JoinRefused::InvalidCap
    );
    let alice = join(alice, again).await.unwrap();
    assert_eq!(alice.slot(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_20_declined_prompt_spends_the_ticket() {
    let mut host = host().await;
    let ticket = host.bearer();
    let again = duplicate(&ticket);
    let alice = Identity::new().await;
    let alice_id = alice.id();
    let net = session_net(Role::Guest).await;
    let asking = tokio::spawn(async move {
        let r = request_join(&alice, &net, &ticket).await;
        (alice, r)
    });
    let prompted = approval(&mut host).await;
    assert_eq!(prompted.peer, alice_id);
    host.session
        .command(Command::Decide {
            approval: prompted.id,
            allow: false,
        })
        .await
        .unwrap();
    let (alice, declined) = asking.await.unwrap();
    assert_eq!(
        declined.err(),
        Some(NetError::Refused(JoinRefused::Declined))
    );

    assert_eq!(refused(join(alice, again).await), JoinRefused::InvalidCap);
    roster_slots(&host, &[1]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_20_ticket_from_a_previous_host_session_refused() {
    let identity = Identity::new().await;
    let (key, door) = (identity.key, identity.door);
    let first = host_as(
        Identity {
            key: key.expose(|k| kickoff_secret::Secret::new(k.clone())),
            door: std::sync::Arc::clone(&door),
        },
        |_| {},
    )
    .await;
    let alice = Identity::new().await;
    let old = first.bound(alice.id());
    drop(first);

    let _second = host_as(Identity { key, door }, |_| {}).await;
    assert_eq!(refused(join(alice, old).await), JoinRefused::WrongSession);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_18_claimed_session_key_refused_and_its_owner_unharmed() {
    let host = host().await;
    let alice = Identity::new().await;
    let ticket = host.bound(alice.id());
    let alice = RawGuest::join(alice, &ticket).await.unwrap();
    let (alice_link, _alice_ctl) = alice.connect().await.unwrap();

    // Mallory holds a valid invite but names Alice's session key.
    let mallory = Identity::new().await;
    let ticket = host.bound(mallory.id());
    let request = kickoff_wire::JoinRequest {
        cap: copy_cap(&ticket),
        session_key: alice.net.id(),
        name: name("mallory"),
        platform: kickoff_wire::Platform::Linux,
        game_build: kickoff_wire::BuildId::new("b").unwrap(),
        kickoff_version: kickoff_session::KICKOFF_VERSION,
    };
    let claimed = mallory.door.request_join(&ticket, request).await;
    assert_eq!(
        claimed.err(),
        Some(NetError::Refused(JoinRefused::InvalidCap))
    );

    tokio::time::sleep(QUIET).await;
    let frame = |n: u8| kickoff_wire::LanDatagram {
        peer: kickoff_wire::PeerSlot::HOST,
        bcast: false,
        src_port: 50_000,
        dst_port: GAME_PORT,
        payload: vec![n; 8].into(),
    };
    alice_link.send_lan(&frame(7));
    let got = next_udp(&host.game, WAIT)
        .await
        .expect("Alice's link still carries");
    assert_eq!((got.from, got.payload), (2, vec![7; 8]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_18_unknown_session_key_rejected() {
    let host = host().await;
    let alice = Identity::new().await;
    let ticket = host.bound(alice.id());
    let alice = RawGuest::join(alice, &ticket).await.unwrap();

    // A stranger who learned the session address and Alice's pass.
    let stranger = session_net(Role::Guest).await;
    let dialed = stranger
        .dial(alice.admitted.session_addr.clone(), alice.admitted.pass)
        .await;
    if let Ok((link, mut ctl)) = dialed {
        let _ = ctl
            .send(&kickoff_wire::GuestMsg::Hello {
                generation: alice.admitted.pass.generation,
            })
            .await;
        link.send_lan(&kickoff_wire::LanDatagram {
            peer: kickoff_wire::PeerSlot::HOST,
            bcast: false,
            src_port: 50_000,
            dst_port: GAME_PORT,
            payload: vec![1; 8].into(),
        });
        let roster = tokio::time::timeout(QUIET, ctl.recv::<kickoff_wire::HostMsg>()).await;
        assert!(!matches!(roster, Ok(Ok(_))), "the host spoke to a stranger");
    }
    assert!(next_udp(&host.game, QUIET).await.is_none());
    roster_slots(&host, &[1, 2]).await;
    assert!(
        alice.connect().await.is_ok(),
        "the admitted key still gets in"
    );
}

async fn join_all<F: std::future::Future>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output>
where
    F::Output: Send,
{
    let mut out = Vec::new();
    let pinned: Vec<_> = futures.into_iter().map(Box::pin).collect();
    let mut pending: Vec<_> = pinned.into_iter().map(Some).collect();
    std::future::poll_fn(|cx| {
        let mut busy = false;
        for slot in &mut pending {
            if let Some(f) = slot {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => {
                        out.push(v);
                        *slot = None;
                    }
                    std::task::Poll::Pending => busy = true,
                }
            }
        }
        if busy {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_major_version_refused_before_the_ticket_is_spent() {
    let host = host().await;
    let alice = Identity::new().await;
    let ticket = host.bound(alice.id());
    let net = session_net(Role::Guest).await;
    let mut version = kickoff_session::KICKOFF_VERSION;
    version.major += 1;
    let request = kickoff_wire::JoinRequest {
        cap: copy_cap(&ticket),
        session_key: net.id(),
        name: name("future"),
        platform: kickoff_wire::Platform::Linux,
        game_build: kickoff_wire::BuildId::new("b").unwrap(),
        kickoff_version: version,
    };
    assert_eq!(
        alice.door.request_join(&ticket, request).await.err(),
        Some(NetError::Refused(JoinRefused::Version))
    );
    assert_eq!(join(alice, ticket).await.unwrap().slot(), 2);
}

/// SI-23: an admitted key whose link never completes its `Hello` is closed
/// at the deadline, so a silent link cannot sit on its seat's connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_23_link_without_hello_closed_at_the_deadline() {
    let host = host().await;
    let alice = Identity::new().await;
    let ticket = host.bound(alice.id());
    let silent = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let request = kickoff_wire::JoinRequest {
        cap: copy_cap(&ticket),
        session_key: silent.id(),
        name: name("silent"),
        platform: kickoff_wire::Platform::Linux,
        game_build: kickoff_wire::BuildId::new("test-build").unwrap(),
        kickoff_version: kickoff_session::KICKOFF_VERSION,
    };
    let admitted = alice.door.request_join(&ticket, request).await.unwrap();
    let conn = silent
        .connect(admitted.session_addr, kickoff_net::SESSION_ALPN)
        .await
        .unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    // One byte of a length prefix: the host gets the link, never a message.
    send.write_all(&[0]).await.unwrap();
    // The deadline is 2 s; 4 s allows for the close to arrive, and fails a
    // deadline as long as the door's 5 s.
    let closed = tokio::time::timeout(std::time::Duration::from_secs(4), conn.closed()).await;
    assert!(
        closed.is_ok(),
        "a link that never said Hello outlived the deadline"
    );
}

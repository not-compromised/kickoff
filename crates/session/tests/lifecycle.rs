//! Ending is an admission boundary, before the graceful farewell completes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::*;
use kickoff_net::{CtlStream, NetError, Role};
use kickoff_session::{Command, EndReason, SessionError, SessionEvent};
use kickoff_wire::{GuestMsg, HostMsg, JoinRefused, LanDatagram, PeerSlot};

async fn end_message(ctl: &mut CtlStream) {
    tokio::time::timeout(WAIT, async {
        loop {
            if ctl.recv::<HostMsg>().await.unwrap() == HostMsg::End {
                return;
            }
        }
    })
    .await
    .expect("the established guest did not receive End");
}

// Poll Leave up to the peer's End message, then retain that future without
// polling it again until the adversarial operations finish. This makes the
// clear/drain boundary observable and prevents endpoint closure from hiding
// a late approval or route, regardless of network scheduling or grace timers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_41_end_refuses_bearer_join_after_final_clear() {
    let mut host = bearer_host().await;
    let holding = Identity::new().await;
    let holding_ticket = host.bound(holding.id());
    let holding = RawGuest::join(holding, &holding_ticket).await.unwrap();
    let (holding_link, mut holding_ctl) = holding.connect().await.unwrap();
    let late = Identity::new().await;
    let late_net = relay_session_net(Role::Guest).await;
    let ticket = host.bearer();

    let pending_identity = Identity::new().await;
    let pending_net = relay_session_net(Role::Guest).await;
    let pending_ticket = host.bearer();
    let pending_join = request_join(&pending_identity, &pending_net, &pending_ticket);
    tokio::pin!(pending_join);
    let old = tokio::select! {
        reply = &mut pending_join => panic!("bearer answered without approval: {reply:?}"),
        approval = approval(&mut host) => approval,
    };
    let mut approvals = host.session.approvals();
    assert_eq!(approvals.borrow().len(), 1);

    let leave = host.session.command(Command::Leave);
    tokio::pin!(leave);
    tokio::select! {
        result = &mut leave => panic!("Leave completed before farewell was read: {result:?}"),
        () = end_message(&mut holding_ctl) => {}
    }
    assert!(
        approvals.borrow().is_empty(),
        "the existing prompt survived end"
    );
    assert_eq!(
        host.session
            .command(Command::Decide {
                approval: old.id,
                allow: true
            })
            .await,
        Err(SessionError::Ended)
    );

    let late_join = request_join(&late, &late_net, &ticket);
    tokio::pin!(late_join);
    let reply = tokio::select! {
        reply = &mut late_join => reply,
        changed = approvals.wait_for(|pending| !pending.is_empty()) => {
            panic!("a join recreated approval state after the final clear: {changed:?}")
        }
        () = tokio::time::sleep(WAIT) => panic!("the late join was not refused"),
    };
    assert_eq!(reply.err(), Some(NetError::Refused(JoinRefused::Declined)));
    assert!(approvals.borrow().is_empty());
    assert!(
        tokio::time::timeout(WAIT, &mut pending_join)
            .await
            .unwrap()
            .is_err()
    );
    holding_link.close();
    leave.await.unwrap();
    assert!(host.session.approvals().borrow().is_empty());
    assert_eq!(
        event(&mut host.events, |event| match event {
            SessionEvent::Ended(reason) => Some(*reason),
            _ => None,
        })
        .await,
        EndReason::Left
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_18_end_refuses_delayed_hello_after_route_drain() {
    let host = host().await;
    let holding = Identity::new().await;
    let holding_ticket = host.bound(holding.id());
    let holding = RawGuest::join(holding, &holding_ticket).await.unwrap();
    let (holding_link, mut holding_ctl) = holding.connect().await.unwrap();
    let delayed = Identity::new().await;
    let delayed_ticket = host.bound(delayed.id());
    let delayed = RawGuest::join(delayed, &delayed_ticket).await.unwrap();
    let (delayed_link, mut delayed_ctl) = delayed
        .net
        .dial(delayed.admitted.session_addr.clone(), delayed.admitted.pass)
        .await
        .unwrap();

    let packet = LanDatagram {
        peer: PeerSlot::HOST,
        bcast: false,
        src_port: 50_000,
        dst_port: GAME_PORT,
        payload: b"late game frame".to_vec().into(),
    };
    holding_link.send_lan(&packet);
    assert!(
        next_udp(&host.game, WAIT).await.is_some(),
        "the live route never delivered"
    );

    let leave = host.session.command(Command::Leave);
    tokio::pin!(leave);
    tokio::select! {
        result = &mut leave => panic!("Leave completed before farewell was read: {result:?}"),
        () = end_message(&mut holding_ctl) => {}
    }
    let _ = delayed_ctl
        .send(&GuestMsg::Hello {
            generation: delayed.admitted.pass.generation,
        })
        .await;

    let traffic = async {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        loop {
            tick.tick().await;
            delayed_link.send_lan(&packet);
            holding_link.send_lan(&packet);
            host.game
                .send_frame(udp(1, None, BEACON_PORT, BEACON_PORT, b"after end"))
                .unwrap();
        }
    };
    tokio::pin!(traffic);
    tokio::select! {
        () = &mut traffic => unreachable!(),
        frame = next_udp(&host.game, Duration::from_millis(200)) => {
            assert!(frame.is_none(), "a route delivered a new frame after the end boundary: {frame:?}");
        }
        received = delayed_link.recv_lan() => {
            assert!(received.is_err(), "a late route sent a host frame after the end boundary: {received:?}");
        }
    }
    // Closure can win before the no-delivery observation period above.
    assert!(
        next_udp(&host.game, Duration::from_millis(200))
            .await
            .is_none()
    );
    assert!(
        tokio::time::timeout(WAIT, delayed_link.closed())
            .await
            .is_ok()
    );
    holding_link.close();
    leave.await.unwrap();
    assert!(host.session.approvals().borrow().is_empty());
}

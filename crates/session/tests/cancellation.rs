//! A cancelled command wait cannot strand a committed host transition.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use kickoff_session::{Command, EndReason, SessionError, SessionEvent};
use kickoff_wire::{HostMsg, KickReason};

async fn farewell(ctl: &mut kickoff_net::CtlStream, wanted: HostMsg) {
    tokio::time::timeout(WAIT, async {
        loop {
            if ctl.recv::<HostMsg>().await.unwrap() == wanted {
                return;
            }
        }
    })
    .await
    .expect("the committed command never reached its farewell");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_18_cancelled_host_leave_finishes_cleanup() {
    let mut host = host().await;
    let holding = Identity::new().await;
    let ticket = host.bound(holding.id());
    let holding = RawGuest::join(holding, &ticket).await.unwrap();
    let (link, mut ctl) = holding.connect().await.unwrap();

    // This admitted connection has no route yet. Its closure cannot be
    // supplied by the route's independent farewell task.
    let delayed = Identity::new().await;
    let delayed_ticket = host.bound(delayed.id());
    let delayed = RawGuest::join(delayed, &delayed_ticket).await.unwrap();
    let (unrouted, _unread) = delayed
        .net
        .dial(delayed.admitted.session_addr.clone(), delayed.admitted.pass)
        .await
        .unwrap();

    let mut leaving = Box::pin(host.session.command(Command::Leave));
    tokio::select! {
        biased;
        () = farewell(&mut ctl, HostMsg::End) => {}
        result = &mut leaving => panic!("Leave completed before farewell was read: {result:?}"),
    }
    // Dropping Box<Future> destroys the command itself, unlike dropping
    // a Pin<&mut Future> while its stack allocation is still alive.
    drop(leaving);

    let reason = event(&mut host.events, |event| match event {
        SessionEvent::Ended(reason) => Some(*reason),
        _ => None,
    })
    .await;
    assert_eq!(reason, EndReason::Left);
    assert!(
        tokio::time::timeout(WAIT, unrouted.closed()).await.is_ok(),
        "cancelled Leave did not close the unrouted session connection"
    );
    assert!(tokio::time::timeout(WAIT, link.closed()).await.is_ok());
    assert!(host.session.approvals().borrow().is_empty());
    assert_eq!(
        host.session.command(Command::Leave).await,
        Err(SessionError::Ended)
    );
    let redial = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        delayed
            .net
            .dial(delayed.admitted.session_addr.clone(), delayed.admitted.pass),
    )
    .await;
    assert!(
        !matches!(redial, Ok(Ok(_))),
        "cancelled Leave kept its endpoint reachable"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_18_cancelled_host_kick_publishes_removed_peer() {
    let mut host = host().await;
    let holding = Identity::new().await;
    let id = holding.id();
    let ticket = host.bound(id);
    let holding = RawGuest::join(holding, &ticket).await.unwrap();
    let (link, mut ctl) = holding.connect().await.unwrap();
    roster_slots(&host, &[1, 2]).await;

    let mut kicking = Box::pin(host.session.command(Command::Kick(id)));
    tokio::select! {
        biased;
        () = farewell(&mut ctl, HostMsg::Kick { reason: KickReason::Kicked }) => {}
        result = &mut kicking => panic!("Kick completed before farewell was read: {result:?}"),
    }
    drop(kicking);
    // No later invite/command can incidentally publish the removed seat.
    let members = event(&mut host.events, |event| match event {
        SessionEvent::Roster { members, .. } if members.iter().all(|member| member.id != id) => {
            Some(members.clone())
        }
        _ => None,
    })
    .await;
    assert_eq!(members.len(), 1);
    assert_eq!(members.first().unwrap().slot, kickoff_wire::PeerSlot::HOST);
    assert_eq!(host.session.members(), members);
    assert!(tokio::time::timeout(WAIT, link.closed()).await.is_ok());

    // Only after observing publication do we make a new request. The
    // revocation and the freed slot must agree with the published roster.
    let again = host.bound(id);
    assert_eq!(
        request_join(&holding.identity, &holding.net, &again)
            .await
            .err(),
        Some(kickoff_net::NetError::Refused(
            kickoff_wire::JoinRefused::Revoked
        ))
    );
    let newcomer = Identity::new().await;
    let newcomer_ticket = host.bound(newcomer.id());
    let newcomer = join(newcomer, newcomer_ticket).await.unwrap();
    assert_eq!(newcomer.slot(), 2);
    host.session.command(Command::Leave).await.unwrap();
}

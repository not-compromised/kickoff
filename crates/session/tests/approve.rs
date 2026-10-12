//! Approvals (§4.4, SI-41): a decision authorizes only the one immutable
//! object it names, while that object is current. Each test races an
//! approval against something that retires it, then has the same peer ask
//! again, so a decision that named the peer would land on the new request.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::*;
use kickoff_net::{NetError, Role};
use kickoff_session::{ApprovalAction, ApprovalId, Clock, Command, SessionError};
use kickoff_wire::{Admitted, JoinRefused};
use tokio::task::JoinHandle;

type Asking = JoinHandle<(Identity, Result<Admitted, NetError>)>;

/// A bearer join the test plays at the door, so the identity survives a
/// refusal and can ask again.
fn ask(identity: Identity, ticket: kickoff_secret::Secret<kickoff_wire::Ticket>) -> Asking {
    tokio::spawn(async move {
        let net = session_net(Role::Guest).await;
        let reply = request_join(&identity, &net, &ticket).await;
        (identity, reply)
    })
}

async fn answer(asking: Asking) -> (Identity, Result<Admitted, NetError>) {
    tokio::time::timeout(WAIT, asking)
        .await
        .expect("the join was never answered")
        .unwrap()
}

async fn decide(host: &HostNode, approval: ApprovalId, allow: bool) -> Result<(), SessionError> {
    host.session
        .command(Command::Decide { approval, allow })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_41_kick_retires_the_approval_and_its_id() {
    let mut host = bearer_host().await;
    let alice = Identity::new().await;
    let alice_id = alice.id();

    let asking = ask(alice, host.bearer());
    let old = approval(&mut host).await;
    host.session.command(Command::Kick(alice_id)).await.unwrap();
    let (alice, reply) = answer(asking).await;
    assert_eq!(reply.err(), Some(NetError::Refused(JoinRefused::Revoked)));
    assert_eq!(
        decide(&host, old.id, true).await,
        Err(SessionError::NoApproval)
    );

    // Readmitted, Alice asks again; the old dialog's answer must not count.
    host.session
        .command(Command::Readmit(alice_id))
        .await
        .unwrap();
    let asking = ask(alice, host.bearer());
    let new = approval(&mut host).await;
    assert_eq!(new.peer, alice_id);
    assert_eq!(
        decide(&host, old.id, true).await,
        Err(SessionError::NoApproval),
        "a kicked request's id decided its successor"
    );
    assert_eq!(*host.session.approvals().borrow(), vec![new.clone()]);
    roster_slots(&host, &[1]).await;

    decide(&host, new.id, true).await.unwrap();
    let (_, reply) = answer(asking).await;
    assert_eq!(reply.unwrap().pass.slot.get(), 2);
    assert_eq!(
        decide(&host, new.id, true).await,
        Err(SessionError::NoApproval),
        "an id decided twice"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_41_timed_out_approval_authorizes_nothing() {
    let clock = Clock::system();
    let mut host = bearer_host_with(|o| o.clock = clock.clone()).await;
    let bob = Identity::new().await;

    let asking = ask(bob, host.bearer());
    let old = approval(&mut host).await;
    clock.advance(Duration::from_secs(60));
    let (bob, reply) = answer(asking).await;
    assert_eq!(reply.err(), Some(NetError::Refused(JoinRefused::Declined)));
    assert!(host.session.approvals().borrow().is_empty());

    let asking = ask(bob, host.bearer());
    let new = approval(&mut host).await;
    assert_eq!(
        decide(&host, old.id, true).await,
        Err(SessionError::NoApproval),
        "a timed-out id decided its successor"
    );
    decide(&host, new.id, false).await.unwrap();
    let (_, reply) = answer(asking).await;
    assert_eq!(reply.err(), Some(NetError::Refused(JoinRefused::Declined)));
    roster_slots(&host, &[1]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_41_session_end_retires_every_approval() {
    let mut host = bearer_host().await;
    let carol = Identity::new().await;
    let asking = ask(carol, host.bearer());
    let pending = approval(&mut host).await;

    host.session.command(Command::Leave).await.unwrap();
    assert!(host.session.approvals().borrow().is_empty());
    assert_eq!(
        decide(&host, pending.id, true).await,
        Err(SessionError::Ended)
    );
    let (_, reply) = answer(asking).await;
    assert!(reply.is_err(), "admitted by an ended session");
}

/// One bearer approval is pending at a time; the second request is refused
/// at the door without spending its ticket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_41_second_bearer_join_refused_while_one_is_pending() {
    let mut host = bearer_host().await;
    let (alice, bob) = (Identity::new().await, Identity::new().await);
    let bob_ticket = host.bearer();
    let bob_again = duplicate(&bob_ticket);

    let alice_asking = ask(alice, host.bearer());
    let first = approval(&mut host).await;
    let (bob, reply) = answer(ask(bob, bob_ticket)).await;
    assert_eq!(reply.err(), Some(NetError::Refused(JoinRefused::Busy)));
    assert_eq!(*host.session.approvals().borrow(), vec![first.clone()]);

    decide(&host, first.id, false).await.unwrap();
    assert!(answer(alice_asking).await.1.is_err());

    let bob_asking = ask(bob, bob_again);
    let second = approval(&mut host).await;
    assert_eq!(second.action, ApprovalAction::AdmitBearer);
    decide(&host, second.id, true).await.unwrap();
    let (_, reply) = answer(bob_asking).await;
    assert_eq!(
        reply.unwrap().pass.slot.get(),
        2,
        "the refusal spent the ticket"
    );
}

/// Approvals do not ride only on the lossy event stream: a reader that never
/// drained its events still finds the pending one, and sees it go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_approvals_are_held_not_streamed() {
    let mut host = bearer_host().await;
    let mut pending = host.session.approvals();
    let dave = Identity::new().await;
    let asking = ask(dave, host.bearer());

    tokio::time::timeout(WAIT, pending.wait_for(|p| p.len() == 1))
        .await
        .unwrap()
        .unwrap();
    let held = pending.borrow().first().cloned().unwrap();
    assert_eq!(approval(&mut host).await, held);
    decide(&host, held.id, true).await.unwrap();
    tokio::time::timeout(WAIT, pending.wait_for(Vec::is_empty))
        .await
        .unwrap()
        .unwrap();
    assert!(answer(asking).await.1.is_ok());
}

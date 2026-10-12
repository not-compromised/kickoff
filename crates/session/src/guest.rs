//! The guest's runtime: join through the host's door, then carry the local
//! game's traffic to the host and back over one link, redialing it for the
//! reconnect window when it drops (§4.6). A guest has exactly one peer, the
//! host: its session endpoint accepts nothing and its LAN refuses every other
//! slot (SI-21).

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iroh_base::EndpointId;
use kickoff_net::{CtlStream, Door, Link, NetError, SessionNet};
use kickoff_secret::Secret;
use kickoff_vlan::{Adapter, Lan, LanConfig};
use kickoff_wire::{
    Admitted, Cap, GuestMsg, HostMsg, JoinRequest, LanDatagram, Member, PeerSlot, Ticket,
};
use tokio::sync::{broadcast, oneshot, watch};
use tokio::task::JoinSet;

use crate::{Clock, EndReason, JoinOpts, KICKOFF_VERSION, SessionError, SessionEvent};

/// The host's first roster must follow `Hello` within this (§4.3).
const ROSTER_DEADLINE: Duration = Duration::from_secs(5);
/// Redial backoff (§4.6): 250 ms doubling to 4 s, for 30 s on the guest's
/// clock.
const BACKOFF_FIRST: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(4);
const RECONNECT_WINDOW: Duration = Duration::from_secs(30);
const LEAVE_WAIT: Duration = Duration::from_secs(1);

pub(crate) struct Guest {
    slot: PeerSlot,
    leave: Mutex<Option<oneshot::Sender<()>>>,
    members: watch::Receiver<Vec<Member>>,
    ended: watch::Receiver<bool>,
}

struct Ctx {
    me: EndpointId,
    clock: Clock,
    admitted: Admitted,
    net: SessionNet,
    lan: Lan,
    events: broadcast::Sender<SessionEvent>,
    members: watch::Sender<Vec<Member>>,
    ended: watch::Sender<bool>,
}

enum Outcome {
    Leave,
    Lost,
    End(EndReason),
}

pub(crate) async fn start(
    door: &Door,
    net: SessionNet,
    adapter: Adapter,
    ticket: Secret<Ticket>,
    opts: JoinOpts,
    events: broadcast::Sender<SessionEvent>,
    tasks: &mut JoinSet<()>,
) -> Result<Guest, SessionError> {
    let request = JoinRequest {
        cap: ticket.expose(|t| copy_cap(&t.cap)),
        session_key: net.id(),
        name: opts.name,
        platform: opts.platform,
        game_build: opts.game_build,
        kickoff_version: KICKOFF_VERSION,
    };
    let admitted = door
        .request_join(&ticket, request)
        .await
        .map_err(|err| match err {
            NetError::Refused(why) => SessionError::Refused(why),
            err => SessionError::Net(err),
        })?;
    drop(ticket);
    let slot = admitted.pass.slot;
    let lan = kickoff_vlan::open(adapter, LanConfig { slot }).map_err(SessionError::Lan)?;
    let me = door.id();
    let (link, ctl, (epoch, members)) = connect(&net, &admitted, me).await?;
    let (members_tx, members_rx) = watch::channel(members.clone());
    let (ended_tx, ended_rx) = watch::channel(false);
    let _ = events.send(SessionEvent::Roster { epoch, members });
    let (leave_tx, leave_rx) = oneshot::channel();
    let ctx = Ctx {
        me,
        clock: opts.clock,
        admitted,
        net,
        lan,
        events,
        members: members_tx,
        ended: ended_tx,
    };
    tasks.spawn(run(ctx, link, ctl, epoch, leave_rx));
    Ok(Guest {
        slot,
        leave: Mutex::new(Some(leave_tx)),
        members: members_rx,
        ended: ended_rx,
    })
}

impl Guest {
    pub(crate) fn slot(&self) -> PeerSlot {
        self.slot
    }

    pub(crate) fn members(&self) -> Vec<Member> {
        self.members.borrow().clone()
    }

    pub(crate) async fn leave(&self) -> Result<(), SessionError> {
        let leave = self
            .leave
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or(SessionError::Ended)?;
        leave.send(()).map_err(|()| SessionError::Ended)?;
        let mut ended = self.ended.clone();
        let _ = tokio::time::timeout(LEAVE_WAIT, ended.wait_for(|ended| *ended)).await;
        Ok(())
    }
}

/// The capability travels in the request; the ticket around it stays secret
/// and is dropped (wiped) once the join is answered.
fn copy_cap(cap: &Cap) -> Cap {
    Cap {
        session_id: cap.session_id,
        invitee: cap.invitee,
        nonce: cap.nonce,
        sig: cap.sig,
    }
}

/// Dials the session endpoint and waits for the host's roster. A completed
/// dial is not admission (§4.3): only a roster that lists this identity at
/// the admitted slot is.
async fn connect(
    net: &SessionNet,
    admitted: &Admitted,
    me: EndpointId,
) -> Result<(Arc<Link>, CtlStream, (u64, Vec<Member>)), SessionError> {
    let (link, mut ctl) = net
        .dial(admitted.session_addr.clone(), admitted.pass)
        .await
        .map_err(SessionError::Net)?;
    let hello = GuestMsg::Hello {
        generation: admitted.pass.generation,
    };
    let first = async {
        ctl.send(&hello).await?;
        ctl.recv::<HostMsg>().await
    };
    match tokio::time::timeout(ROSTER_DEADLINE, first).await {
        Ok(Ok(HostMsg::Roster { epoch, members }))
            if members
                .as_slice()
                .iter()
                .any(|m| m.slot == admitted.pass.slot && m.id == me) =>
        {
            Ok((Arc::new(link), ctl, (epoch, members.as_slice().to_vec())))
        }
        _ => {
            link.close();
            Err(SessionError::NotAdmitted)
        }
    }
}

async fn run(
    ctx: Ctx,
    mut link: Arc<Link>,
    mut ctl: CtlStream,
    mut epoch: u64,
    mut leave: oneshot::Receiver<()>,
) {
    let reason = loop {
        let outcome = tokio::select! {
            biased;
            _ = &mut leave => Outcome::Leave,
            outcome = up(&ctx.lan, &link) => outcome,
            outcome = down(&ctx.lan, &link) => outcome,
            outcome = control(&ctx, &mut ctl, &mut epoch) => outcome,
        };
        match outcome {
            Outcome::Leave => break EndReason::Left,
            Outcome::End(reason) => break reason,
            Outcome::Lost => {
                link.close();
                let _ = ctx.events.send(SessionEvent::Reconnecting);
                match reconnect(&ctx, &mut leave).await {
                    Ok((next, next_ctl, (next_epoch, members))) => {
                        (link, ctl) = (next, next_ctl);
                        roster(&ctx, &mut epoch, next_epoch, members);
                    }
                    Err(reason) => break reason,
                }
            }
        }
    };
    link.close();
    ctx.net.close().await;
    ctx.ended.send_replace(true);
    let _ = ctx.events.send(SessionEvent::Ended(reason));
}

/// Local game → host. The local LAN yields only datagrams for the host.
async fn up(lan: &Lan, link: &Link) -> Outcome {
    loop {
        match lan.recv().await {
            Ok(datagram) => link.send_lan(&datagram),
            Err(_) => return Outcome::End(EndReason::LanClosed),
        }
    }
}

/// Host → local game, always as slot 1: a guest's only peer is the host.
async fn down(lan: &Lan, link: &Link) -> Outcome {
    loop {
        match link.recv_lan().await {
            Ok(datagram) => lan.deliver(LanDatagram {
                peer: PeerSlot::HOST,
                ..datagram
            }),
            Err(_) => return Outcome::Lost,
        }
    }
}

async fn control(ctx: &Ctx, ctl: &mut CtlStream, epoch: &mut u64) -> Outcome {
    loop {
        match ctl.recv::<HostMsg>().await {
            Ok(HostMsg::Roster {
                epoch: next,
                members,
            }) => roster(ctx, epoch, next, members.as_slice().to_vec()),
            Ok(HostMsg::Ping) => {
                if ctl.send(&GuestMsg::Pong).await.is_err() {
                    return Outcome::Lost;
                }
            }
            Ok(HostMsg::Kick { reason }) => return Outcome::End(EndReason::Kicked(reason)),
            Ok(HostMsg::End) => return Outcome::End(EndReason::HostEnded),
            // Map transfer and approval are M6.
            Ok(HostMsg::MapPick { .. }) => {}
            Err(_) => return Outcome::Lost,
        }
    }
}

/// Rosters only move forward; a stale or replayed one is ignored.
fn roster(ctx: &Ctx, epoch: &mut u64, next: u64, members: Vec<Member>) {
    if next <= *epoch {
        return;
    }
    *epoch = next;
    ctx.members.send_replace(members.clone());
    let _ = ctx.events.send(SessionEvent::Roster {
        epoch: next,
        members,
    });
}

async fn reconnect(
    ctx: &Ctx,
    leave: &mut oneshot::Receiver<()>,
) -> Result<(Arc<Link>, CtlStream, (u64, Vec<Member>)), EndReason> {
    let start = ctx.clock.now();
    let deadline = start.checked_add(RECONNECT_WINDOW).unwrap_or(start);
    let mut backoff = BACKOFF_FIRST;
    loop {
        tokio::select! {
            biased;
            _ = &mut *leave => return Err(EndReason::Left),
            () = ctx.clock.until(deadline) => return Err(EndReason::HostLost),
            connected = connect(&ctx.net, &ctx.admitted, ctx.me) => {
                if let Ok(connected) = connected {
                    return Ok(connected);
                }
            }
        }
        tokio::select! {
            biased;
            _ = &mut *leave => return Err(EndReason::Left),
            () = ctx.clock.until(deadline) => return Err(EndReason::HostLost),
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = backoff.saturating_mul(2).min(BACKOFF_MAX);
    }
}

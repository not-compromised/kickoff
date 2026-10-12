//! The host's runtime: the admission owner's decisions applied to the door,
//! the session endpoint, the routing table and the LAN, plus the pump.
//!
//! Every change of a seat happens under the admission lock and is applied in
//! the same critical section: routes first (which waits out deliveries in
//! flight), then the LAN's flow table, then the published admitted set and
//! roster. A link task changes only its own seat, and only through the owner.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use iroh_base::{EndpointId, SecretKey};
use kickoff_net::{CtlStream, Door, JoinAttempt, Link, NetError, SessionNet};
use kickoff_secret::Secret;
use kickoff_vlan::{Adapter, Lan, LanConfig};
use kickoff_wire::{
    AdmitPass, Admitted, BoundedVec, GuestMsg, HostMsg, JoinRefused, KickReason, LanDatagram,
    PeerRef, PeerSlot, Ticket,
};
use tokio::sync::{Semaphore, broadcast, oneshot, watch};
use tokio::task::JoinSet;

use crate::admission::{Admission, Joined};
use crate::budget::Bucket;
use crate::routes::{Route, Routes};
use crate::{Clock, Command, EndReason, HostOpts, InviteKind, SessionError, SessionEvent};

/// A bearer-invite prompt the owner leaves unanswered is declined.
const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);
/// From the link's arrival to its `Hello`.
const HELLO_DEADLINE: Duration = Duration::from_secs(5);
/// How long a link's task waits to send its last message and see the guest
/// close; the kick or end waiting on it allows a little longer.
const FAREWELL: Duration = Duration::from_millis(500);
const FAREWELL_WAIT: Duration = Duration::from_millis(750);
/// Join requests being answered at once; the door queues the rest.
const REPLIES: usize = 16;
/// How often the admission and reconnect windows are checked.
const SWEEP: Duration = Duration::from_millis(250);
/// Host fan-out (§6.3): 16 MB/s overall, charged per emitted copy.
const EGRESS_PER_SEC: u64 = 16_000_000;
const EGRESS_BURST: u64 = 2_000_000;

/// The last message a removed link's task sends, and how it says it did.
type Farewell = oneshot::Sender<(HostMsg, oneshot::Sender<()>)>;

pub(crate) struct Host {
    door: Arc<Door>,
    key: Secret<SecretKey>,
    net: SessionNet,
    lan: Lan,
    clock: Clock,
    admission: Mutex<Admission>,
    routes: Routes<Arc<Link>, Farewell>,
    prompts: Mutex<HashMap<EndpointId, oneshot::Sender<bool>>>,
    roster: watch::Sender<(u64, HostMsg)>,
    events: broadcast::Sender<SessionEvent>,
    /// Set once by whoever starts ending the session; `ended` follows after
    /// the goodbyes, which is what stops the tasks.
    ending: AtomicBool,
    ended: watch::Sender<bool>,
}

pub(crate) fn start(
    door: Arc<Door>,
    door_key: &Secret<SecretKey>,
    net: SessionNet,
    adapter: Adapter,
    opts: HostOpts,
    events: broadcast::Sender<SessionEvent>,
    tasks: &mut JoinSet<()>,
) -> Result<Arc<Host>, SessionError> {
    if door_key.expose(SecretKey::public) != door.id() {
        return Err(SessionError::WrongKey);
    }
    let lan = kickoff_vlan::open(
        adapter,
        LanConfig {
            slot: PeerSlot::HOST,
        },
    )
    .map_err(SessionError::Lan)?;
    let admission = Admission::new(door_key, net.id(), opts.name, opts.trusted)
        .map_err(SessionError::Invite)?;
    let (roster, _) = watch::channel((0, HostMsg::End));
    let host = Arc::new(Host {
        door,
        key: door_key.expose(|k| Secret::new(k.clone())),
        net,
        lan,
        clock: opts.clock,
        admission: Mutex::new(admission),
        routes: Routes::new(),
        prompts: Mutex::new(HashMap::new()),
        roster,
        events,
        ending: AtomicBool::new(false),
        ended: watch::channel(false).0,
    });
    host.publish(&host.admission());
    tasks.spawn(join_loop(Arc::clone(&host)));
    tasks.spawn(accept_loop(Arc::clone(&host)));
    tasks.spawn(pump(Arc::clone(&host)));
    tasks.spawn(sweep(Arc::clone(&host)));
    Ok(host)
}

enum Ended {
    Farewell(Option<(HostMsg, oneshot::Sender<()>)>),
    /// The route moved on under this link (kick, eviction).
    Stale,
    Lost,
    Evict,
}

impl Host {
    pub(crate) fn invite(&self, kind: InviteKind) -> Result<Secret<Ticket>, SessionError> {
        self.live()?;
        let invitee = match kind {
            InviteKind::Bound(id) => Some(id),
            InviteKind::Bearer => None,
        };
        let cap = {
            let mut adm = self.admission();
            let cap = adm
                .issue(&self.key, invitee, self.clock.now())
                .map_err(SessionError::Invite)?;
            self.publish(&adm);
            cap
        };
        Ok(Secret::new(Ticket {
            door: self.door.addr(),
            cap,
        }))
    }

    pub(crate) async fn command(&self, command: Command) -> Result<(), SessionError> {
        self.live()?;
        match command {
            Command::Kick(id) => self.kick(id).await,
            Command::Readmit(id) => {
                let mut adm = self.admission();
                adm.readmit(id);
                self.publish(&adm);
                Ok(())
            }
            Command::Approve(id) => self.answer_prompt(id, true),
            Command::Decline(id) => self.answer_prompt(id, false),
            Command::PickMap(_) => Err(SessionError::NotImplemented),
            Command::Leave => {
                self.end(EndReason::Left).await;
                Ok(())
            }
        }
    }

    pub(crate) fn members(&self) -> Vec<kickoff_wire::Member> {
        match &self.roster.borrow().1 {
            HostMsg::Roster { members, .. } => members.as_slice().to_vec(),
            _ => Vec::new(),
        }
    }

    fn live(&self) -> Result<(), SessionError> {
        if self.ending.load(Ordering::Acquire) {
            Err(SessionError::Ended)
        } else {
            Ok(())
        }
    }

    async fn kick(&self, id: EndpointId) -> Result<(), SessionError> {
        let route = {
            let mut adm = self.admission();
            let held = adm.kick(id).map_err(|_| SessionError::RevokedFull)?;
            held.and_then(|peer| self.unroute(peer))
        };
        if let Some(prompt) = self.prompts().remove(&id) {
            let _ = prompt.send(false);
        }
        if let Some(route) = route {
            let reason = KickReason::Kicked;
            farewell(route, HostMsg::Kick { reason }).await;
        }
        // Published after the farewell: until then the old connection is open,
        // so a redial is refused as a duplicate, and its route is already gone.
        self.publish(&self.admission());
        Ok(())
    }

    fn answer_prompt(&self, id: EndpointId, approve: bool) -> Result<(), SessionError> {
        let prompt = self.prompts().remove(&id).ok_or(SessionError::NoPrompt)?;
        prompt.send(approve).map_err(|_| SessionError::NoPrompt)
    }

    async fn end(&self, reason: EndReason) {
        if self.ending.swap(true, Ordering::AcqRel) {
            return;
        }
        self.prompts().clear();
        let mut goodbyes = JoinSet::new();
        for route in self.routes.drain() {
            goodbyes.spawn(farewell(route, HostMsg::End));
        }
        while goodbyes.join_next().await.is_some() {}
        self.ended.send_replace(true);
        self.net.close().await;
        let _ = self.events.send(SessionEvent::Ended(reason));
    }

    /// Takes `peer`'s route away, then forgets the flows the local game had
    /// with its slot, in that order, so no delivery of the old generation can
    /// land after the reset (SI-18).
    fn unroute(&self, peer: PeerRef) -> Option<Route<Arc<Link>, Farewell>> {
        let route = self.routes.remove(peer.slot, peer.generation);
        self.lan.reset_peer(peer.slot);
        route
    }

    fn link_lost(&self, peer: PeerRef) {
        let mut adm = self.admission();
        if adm.link_lost(peer, self.clock.now()).is_some() {
            drop(self.unroute(peer));
            self.publish(&adm);
        }
    }

    fn evict(&self, peer: PeerRef) {
        let mut adm = self.admission();
        if adm.evict(peer) {
            drop(self.unroute(peer));
            self.publish(&adm);
        }
    }

    /// Hands the owner's current state to the session endpoint, the door and
    /// the guests. Called with the admission lock held.
    fn publish(&self, adm: &Admission) {
        self.net.set_admitted(adm.admitted_set());
        self.door.set_priority(adm.priority());
        let (epoch, members) = adm.roster();
        let Ok(bounded) = BoundedVec::new(members.clone()) else {
            return;
        };
        let changed = self.roster.send_if_modified(|current| {
            let newer = current.0 != epoch;
            if newer {
                *current = (
                    epoch,
                    HostMsg::Roster {
                        epoch,
                        members: bounded,
                    },
                );
            }
            newer
        });
        if changed {
            let _ = self.events.send(SessionEvent::Roster { epoch, members });
        }
    }

    fn pass(&self, peer: PeerRef) -> Admitted {
        Admitted {
            session_addr: self.net.addr(),
            pass: AdmitPass {
                slot: peer.slot,
                generation: peer.generation,
            },
        }
    }

    async fn admit(&self, attempt: JoinAttempt) {
        let id = attempt.id();
        let decision = {
            let mut adm = self.admission();
            let decision = adm.join(id, attempt.request(), self.clock.now());
            if decision.is_ok() {
                self.publish(&adm);
            }
            decision
        };
        let reply = match decision {
            Ok(Joined::Admitted(peer)) => Ok(self.pass(peer)),
            Ok(Joined::Prompt) => self.prompt(id, attempt.request().name.clone()).await,
            Err(why) => Err(why),
        };
        let _ = attempt.answer(reply).await;
    }

    /// A bearer invite was redeemed: the seat is held until the owner answers.
    async fn prompt(
        &self,
        id: EndpointId,
        name: kickoff_wire::Name,
    ) -> Result<Admitted, JoinRefused> {
        let (tx, rx) = oneshot::channel();
        self.prompts().insert(id, tx);
        let _ = self.events.send(SessionEvent::JoinPrompt { id, name });
        let approved = matches!(tokio::time::timeout(PROMPT_TIMEOUT, rx).await, Ok(Ok(true)));
        self.prompts().remove(&id);
        let mut adm = self.admission();
        if !approved {
            adm.decline(id);
            return Err(JoinRefused::Declined);
        }
        let peer = adm
            .approve(id, self.clock.now())
            .ok_or(JoinRefused::Revoked)?;
        self.publish(&adm);
        Ok(self.pass(peer))
    }

    fn admission(&self) -> MutexGuard<'_, Admission> {
        // The owner's methods leave the table valid between statements and
        // never panic, so a poisoned lock is still sound.
        self.admission
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn prompts(&self) -> MutexGuard<'_, HashMap<EndpointId, oneshot::Sender<bool>>> {
        self.prompts.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

async fn farewell(route: Route<Arc<Link>, Farewell>, msg: HostMsg) {
    let (done, said) = oneshot::channel();
    if route.farewell.send((msg, done)).is_ok() {
        let _ = tokio::time::timeout(FAREWELL_WAIT, said).await;
    }
    route.link.close();
}

async fn join_loop(host: Arc<Host>) {
    let mut ended = host.ended.subscribe();
    let replies = Arc::new(Semaphore::new(REPLIES));
    let mut answering = JoinSet::new();
    loop {
        let attempt = tokio::select! {
            attempt = host.door.next_join() => attempt,
            _ = ended.wait_for(|ended| *ended) => break,
            Some(_) = answering.join_next(), if !answering.is_empty() => continue,
        };
        let Ok(attempt) = attempt else { break };
        let Ok(permit) = Arc::clone(&replies).acquire_owned().await else {
            break;
        };
        let host = Arc::clone(&host);
        answering.spawn(async move {
            host.admit(attempt).await;
            drop(permit);
        });
    }
}

async fn accept_loop(host: Arc<Host>) {
    let mut ended = host.ended.subscribe();
    let mut links = JoinSet::new();
    loop {
        tokio::select! {
            accepted = host.net.accept() => match accepted {
                Ok((link, ctl)) => {
                    links.spawn(serve(Arc::clone(&host), link, ctl));
                }
                Err(_) => break,
            },
            Some(_) = links.join_next(), if !links.is_empty() => {}
            _ = ended.wait_for(|ended| *ended) => break,
        }
    }
}

/// One admitted link, from its `Hello` until it is lost, evicted or removed.
async fn serve(host: Arc<Host>, link: Link, mut ctl: CtlStream) {
    let peer = link.peer();
    let link = Arc::new(link);
    let hello = tokio::time::timeout(HELLO_DEADLINE, ctl.recv::<GuestMsg>()).await;
    let Ok(Ok(GuestMsg::Hello { generation: pass })) = hello else {
        link.close();
        return;
    };
    let (farewell_tx, mut farewell_rx) = oneshot::channel();
    {
        let mut adm = host.admission();
        if !adm.link_up(peer, pass) {
            drop(adm);
            link.close();
            return;
        }
        host.lan.reset_peer(peer.slot);
        let route = Route {
            generation: peer.generation,
            link: Arc::clone(&link),
            farewell: farewell_tx,
        };
        if let Some(old) = host.routes.install(peer.slot, route) {
            old.link.close();
        }
        host.publish(&adm);
    }
    let ended = tokio::select! {
        biased;
        said = &mut farewell_rx => Ended::Farewell(said.ok()),
        ended = carry(&host, &link, peer) => ended,
        ended = control(&host, &mut ctl) => ended,
    };
    let farewell = match ended {
        Ended::Farewell(said) => said,
        Ended::Stale => tokio::time::timeout(FAREWELL, farewell_rx)
            .await
            .ok()
            .and_then(Result::ok),
        Ended::Lost => {
            host.link_lost(peer);
            None
        }
        // A peer over budget or off protocol gets no goodbye: its seat goes
        // now, and the published set closes the connection.
        Ended::Evict => {
            host.evict(peer);
            None
        }
    };
    if let Some((msg, done)) = farewell {
        // QUIC drops unread stream data when the connection closes, so the
        // guest, having read the message, is the one to close.
        let goodbye = async {
            if ctl.send(&msg).await.is_ok() {
                link.closed().await;
            }
        };
        let _ = tokio::time::timeout(FAREWELL, goodbye).await;
        let _ = done.send(());
    }
    link.close();
}

/// Guest → host game. The source slot is the link's, whatever the packet
/// says, and nothing here can reach another link (SI-21).
async fn carry(host: &Host, link: &Link, peer: PeerRef) -> Ended {
    loop {
        let datagram = match link.recv_lan().await {
            Ok(datagram) => datagram,
            Err(NetError::OverBudget) => return Ended::Evict,
            Err(_) => return Ended::Lost,
        };
        let datagram = LanDatagram {
            peer: peer.slot,
            ..datagram
        };
        if !host
            .routes
            .deliver(peer.slot, peer.generation, || host.lan.deliver(datagram))
        {
            return Ended::Stale;
        }
    }
}

async fn control(host: &Host, ctl: &mut CtlStream) -> Ended {
    let mut roster = host.roster.subscribe();
    roster.mark_changed();
    loop {
        tokio::select! {
            changed = roster.changed() => {
                if changed.is_err() {
                    return Ended::Lost;
                }
                let msg = roster.borrow_and_update().1.clone();
                if ctl.send(&msg).await.is_err() {
                    return Ended::Lost;
                }
            }
            msg = ctl.recv::<GuestMsg>() => match msg {
                // `Status` is informational and decides nothing (§3.4).
                Ok(GuestMsg::Status { .. } | GuestMsg::Pong) => {}
                Ok(GuestMsg::Hello { .. }) | Err(NetError::Protocol | NetError::Version) => {
                    return Ended::Evict;
                }
                Err(_) => return Ended::Lost,
            },
        }
    }
}

/// Host game → guests. A broadcast fans out to every routed link, a unicast
/// goes to its slot's link; each copy pays the egress budget first.
async fn pump(host: Arc<Host>) {
    let mut ended = host.ended.subscribe();
    let mut egress = Bucket::new(EGRESS_PER_SEC, EGRESS_BURST, Instant::now());
    loop {
        let datagram = tokio::select! {
            datagram = host.lan.recv() => datagram,
            _ = ended.wait_for(|ended| *ended) => break,
        };
        let Ok(datagram) = datagram else {
            host.end(EndReason::LanClosed).await;
            break;
        };
        let cost = u64::try_from(datagram.payload.len()).unwrap_or(u64::MAX);
        let send = |link: &Arc<Link>| {
            if egress.take(cost, Instant::now()) {
                link.send_lan(&datagram);
            }
        };
        if datagram.bcast {
            host.routes.to_all(send);
        } else {
            host.routes.to_slot(datagram.peer, send);
        }
    }
}

/// Frees seats whose admission or reconnect window ran out.
async fn sweep(host: Arc<Host>) {
    let mut ended = host.ended.subscribe();
    let mut tick = tokio::time::interval(SWEEP);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = ended.wait_for(|ended| *ended) => break,
        }
        let mut adm = host.admission();
        let due = adm.expired(host.clock.now());
        if due.is_empty() {
            continue;
        }
        for peer in due {
            if adm.evict(peer) {
                drop(host.unroute(peer));
            }
        }
        host.publish(&adm);
    }
}

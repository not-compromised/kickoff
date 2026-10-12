//! The host's runtime: the admission owner's decisions applied to the door,
//! the session endpoint, the routing table and the LAN, plus the pump.
//!
//! Every change of a seat happens under the admission lock and is applied in
//! the same critical section: routes first (which waits out deliveries in
//! flight), then the LAN's flow table, then the published admitted set and
//! roster. A link task changes only its own seat, and only through the owner.

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
use crate::approval::{Approval, ApprovalId};
use crate::budget::Bucket;
use crate::routes::{Route, Routes};
use crate::{Clock, Command, EndReason, HostOpts, InviteKind, SessionError, SessionEvent};

/// The host pings each link this often, and closes one that has sent no
/// `Pong` for `IDLE`, measured on the host clock (§4.5, PRIV-29).
const PING: Duration = Duration::from_secs(5);
const IDLE: Duration = Duration::from_secs(15);
/// How long a link's task waits to send its last message and see the guest
/// close; the kick or end waiting on it allows a little longer.
const FAREWELL: Duration = Duration::from_millis(500);
const FAREWELL_WAIT: Duration = Duration::from_millis(750);
/// Join requests being answered at once, including reserved priority replies.
const REPLIES: usize = 16;
const PRIORITY_REPLIES: usize = 8;
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
    /// The approvals now pending. A watch keeps the current set, so a reader
    /// that falls behind still sees every approval it can decide.
    approvals: watch::Sender<Vec<Approval>>,
    roster: watch::Sender<(u64, HostMsg)>,
    events: broadcast::Sender<SessionEvent>,
    /// Follows the admission owner's ending transition after the goodbyes.
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
        approvals: watch::channel(Vec::new()).0,
        roster,
        events,
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
        if kind == InviteKind::Bearer
            && !self.net.is_relay_only()
            && !cfg!(feature = "mutant-si31-bearer-direct")
        {
            return Err(SessionError::RequiresRelay);
        }
        let invitee = match kind {
            InviteKind::Bound(id) => Some(id),
            InviteKind::Bearer => None,
        };
        let cap = {
            let mut adm = self.live_admission()?;
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
                let mut adm = self.live_admission()?;
                adm.readmit(id);
                self.publish(&adm);
                Ok(())
            }
            Command::Decide { approval, allow } => self.decide(approval, allow),
            Command::PickMap(_) => Err(SessionError::NotImplemented),
            Command::Leave => {
                self.end(EndReason::Left).await;
                Ok(())
            }
        }
    }

    pub(crate) fn approvals(&self) -> watch::Receiver<Vec<Approval>> {
        self.approvals.subscribe()
    }

    pub(crate) fn members(&self) -> Vec<kickoff_wire::Member> {
        match &self.roster.borrow().1 {
            HostMsg::Roster { members, .. } => members.as_slice().to_vec(),
            _ => Vec::new(),
        }
    }

    fn live(&self) -> Result<(), SessionError> {
        self.live_admission().map(|_| ())
    }

    fn live_admission(&self) -> Result<MutexGuard<'_, Admission>, SessionError> {
        let adm = self.admission();
        if adm.is_ending() {
            Err(SessionError::Ended)
        } else {
            Ok(adm)
        }
    }

    async fn kick(&self, id: EndpointId) -> Result<(), SessionError> {
        let route = {
            let mut adm = self.live_admission()?;
            let held = adm.kick(id).map_err(|_| SessionError::RevokedFull)?;
            held.and_then(|peer| self.unroute(peer))
        };
        if let Some(route) = route {
            let reason = KickReason::Kicked;
            farewell(route, HostMsg::Kick { reason }).await;
        }
        // Published after the farewell: until then the old connection is open,
        // so a redial is refused as a duplicate, and its route is already gone.
        if let Ok(adm) = self.live_admission() {
            self.publish(&adm);
        }
        Ok(())
    }

    fn decide(&self, approval: ApprovalId, allow: bool) -> Result<(), SessionError> {
        let mut adm = self.live_admission()?;
        adm.decide(approval, allow, self.clock.now())
            .map_err(|_| SessionError::NoApproval)?;
        self.publish(&adm);
        Ok(())
    }

    async fn end(&self, reason: EndReason) {
        let routes = {
            let mut adm = self.admission();
            if adm.is_ending() {
                return;
            }
            adm.end();
            // Admission -> routes -> LAN; delivery never takes admission.
            // Drain waits out in-flight sends/deliveries before this boundary.
            let routes = self.routes.drain();
            self.publish(&adm);
            routes
        };
        let mut goodbyes = JoinSet::new();
        for route in routes {
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
        if !cfg!(feature = "mutant-si18-no-flow-reset") {
            self.lan.reset_peer(peer.slot);
        }
        route
    }

    fn link_lost(&self, peer: PeerRef) {
        let Ok(mut adm) = self.live_admission() else {
            return;
        };
        if adm.link_lost(peer, self.clock.now()).is_some() {
            drop(self.unroute(peer));
            self.publish(&adm);
        }
    }

    fn evict(&self, peer: PeerRef) {
        let Ok(mut adm) = self.live_admission() else {
            return;
        };
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
        let pending = adm.pending_approvals();
        self.approvals.send_if_modified(|current| {
            let newer = *current != pending;
            if newer {
                *current = pending;
            }
            newer
        });
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
        // Subscribed before the decision, so no retirement of the approval
        // can slip between it and the wait.
        let mut approvals = self.approvals.subscribe();
        let decision = {
            let mut adm = self.admission();
            let decision = if attempt.request().cap.invitee.is_none()
                && !adm.is_trusted(id)
                && !self.net.is_relay_only()
                && !cfg!(feature = "mutant-si31-bearer-admit-direct")
            {
                Err(JoinRefused::InvalidCap)
            } else {
                adm.join(id, attempt.request(), self.clock.now())
            };
            if let Ok(joined) = &decision {
                self.publish(&adm);
                if let Joined::Prompt(approval) = joined {
                    let _ = self
                        .events
                        .send(SessionEvent::ApprovalRequested(approval.clone()));
                }
            }
            decision
        };
        let reply = match decision {
            Ok(Joined::Admitted(peer)) => Ok(self.pass(peer)),
            Ok(Joined::Prompt(approval)) => self.decided(&approval, &mut approvals).await,
            Err(why) => Err(why),
        };
        let _ = attempt.answer(reply).await;
    }

    /// Waits until `approval` leaves the pending set (decided, kicked, timed
    /// out by the sweep, or the session ended), then answers as the table
    /// says.
    async fn decided(
        &self,
        approval: &Approval,
        approvals: &mut watch::Receiver<Vec<Approval>>,
    ) -> Result<Admitted, JoinRefused> {
        let mut ended = self.ended.subscribe();
        loop {
            if let Some(outcome) = self.admission().outcome(approval) {
                return outcome.map(|peer| self.pass(peer));
            }
            tokio::select! {
                changed = approvals.changed() => {
                    if changed.is_err() {
                        return Err(JoinRefused::Declined);
                    }
                }
                _ = ended.wait_for(|ended| *ended) => return Err(JoinRefused::Declined),
            }
        }
    }

    fn admission(&self) -> MutexGuard<'_, Admission> {
        // The owner's methods leave the table valid between statements and
        // never panic, so a poisoned lock is still sound.
        self.admission
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
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
    let replies = Arc::new(Semaphore::new(REPLIES - PRIORITY_REPLIES));
    let priority = Arc::new(Semaphore::new(PRIORITY_REPLIES));
    let mut answering = JoinSet::new();
    loop {
        while answering.try_join_next().is_some() {}
        let attempt = tokio::select! {
            attempt = host.door.next_join() => attempt,
            _ = ended.wait_for(|ended| *ended) => break,
            Some(_) = answering.join_next(), if !answering.is_empty() => continue,
        };
        let Ok(attempt) = attempt else { break };
        let pool = if attempt.is_priority() && !cfg!(feature = "mutant-si23-no-priority-replies") {
            &priority
        } else {
            &replies
        };
        let Ok(permit) = Arc::clone(pool).try_acquire_owned() else {
            drop(attempt);
            continue;
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
    let now = tokio::time::Instant::now();
    let deadline = if cfg!(feature = "mutant-si23-no-hello-deadline") {
        now.checked_add(Duration::from_secs(86_400)).unwrap_or(now)
    } else {
        let Some(deadline) = ctl.hello_deadline() else {
            link.close();
            return;
        };
        deadline
    };
    if deadline <= now {
        link.close();
        return;
    }
    let hello = tokio::time::timeout_at(deadline, ctl.recv::<GuestMsg>()).await;
    let Ok(Ok(GuestMsg::Hello { generation: pass })) = hello else {
        link.close();
        return;
    };
    if tokio::time::Instant::now() >= deadline {
        link.close();
        return;
    }
    let (farewell_tx, mut farewell_rx) = oneshot::channel();
    {
        let mut adm = host.admission();
        if !adm.link_up(peer, pass) {
            drop(adm);
            link.close();
            return;
        }
        if !cfg!(feature = "mutant-si18-no-flow-reset") {
            host.lan.reset_peer(peer.slot);
        }
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
        // Arm control deadlines before any game delivery becomes observable.
        ended = control(&host, &mut ctl) => ended,
        ended = carry(&host, &link, peer) => ended,
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
            Err(NetError::OverBudget) if !cfg!(feature = "mutant-si23-over-budget-is-a-drop") => {
                return Ended::Evict;
            }
            Err(_) => return Ended::Lost,
        };
        let datagram = LanDatagram {
            peer: peer.slot,
            ..datagram
        };
        #[cfg(feature = "mutant-si21-link-to-link")]
        if datagram.bcast {
            host.routes.to_all(|other| {
                if other.peer().slot != peer.slot {
                    other.send_lan(&datagram);
                }
            });
        }
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
    let start = tokio::time::Instant::now();
    let mut ping = tokio::time::interval_at(start.checked_add(PING).unwrap_or(start), PING);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_pong = host.clock.now();
    loop {
        let deadline = last_pong.checked_add(IDLE).unwrap_or(last_pong);
        tokio::select! {
            biased;
            _ = host.clock.until(deadline), if !cfg!(feature = "mutant-si23-no-idle-close") => {
                return Ended::Lost;
            }
            _ = ping.tick() => {
                let silent = host.clock.now().saturating_duration_since(last_pong);
                if silent >= IDLE && !cfg!(feature = "mutant-si23-no-idle-close") {
                    // Treated as a lost path: the seat waits out the
                    // reconnect window under a new generation.
                    return Ended::Lost;
                }
                if send_control(host, ctl, &HostMsg::Ping, deadline).await.is_err() {
                    return Ended::Lost;
                }
            }
            changed = roster.changed() => {
                if changed.is_err() {
                    return Ended::Lost;
                }
                let msg = roster.borrow_and_update().1.clone();
                if send_control(host, ctl, &msg, deadline).await.is_err() {
                    return Ended::Lost;
                }
            }
            msg = ctl.recv::<GuestMsg>() => match msg {
                Ok(GuestMsg::Pong) => last_pong = host.clock.now(),
                // `Status` is informational and decides nothing (§3.4).
                Ok(GuestMsg::Status { .. }) => {}
                Ok(GuestMsg::Hello { .. }) | Err(NetError::Protocol | NetError::Version) => {
                    return Ended::Evict;
                }
                Err(_) => return Ended::Lost,
            },
        }
    }
}

/// A control write uses only the remaining Pong window, including while
/// flow control blocks it. Status and roster updates cannot extend that window.
async fn send_control(
    host: &Host,
    ctl: &mut CtlStream,
    msg: &HostMsg,
    deadline: Instant,
) -> Result<(), NetError> {
    tokio::select! {
        biased;
        _ = host.clock.until(deadline), if !cfg!(feature = "mutant-si23-no-idle-close")
            && !cfg!(feature = "mutant-si23-pong-deadline-during-write") => Err(NetError::Closed),
        sent = ctl.send(msg) => sent,
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

/// Retires approvals past their timeout and frees seats whose admission or
/// reconnect window, or approval, ran out.
async fn sweep(host: Arc<Host>) {
    let mut ended = host.ended.subscribe();
    let mut tick = tokio::time::interval(SWEEP);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = ended.wait_for(|ended| *ended) => break,
        }
        let Ok(mut adm) = host.live_admission() else {
            continue;
        };
        let now = host.clock.now();
        let retired = adm.expire_approvals(now);
        let due = adm.expired(now);
        if due.is_empty() && !retired {
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

#[cfg(test)]
mod privacy_tests {
    use super::*;

    #[tokio::test]
    async fn si_31_direct_host_refuses_a_bearer_capability_at_admission() {
        let key = Secret::new(SecretKey::generate());
        let door = Arc::new(kickoff_net::door_loopback(&key).await.unwrap());
        let net = kickoff_net::session(
            &iroh::RelayMap::empty(),
            kickoff_net::IfaceAddr::loopback(),
            kickoff_net::Role::Host,
        )
        .await
        .unwrap();
        let (adapter, _game) = kickoff_vlan::mem_tap();
        let (events, _) = broadcast::channel(16);
        let mut tasks = JoinSet::new();
        let host = start(
            Arc::clone(&door),
            &key,
            net,
            adapter,
            HostOpts::new(kickoff_wire::Name::new("host").unwrap()),
            events,
            &mut tasks,
        )
        .unwrap();
        // Seed a valid bearer in the owner's ledger to drive admission alone.
        let cap = host
            .admission()
            .issue(&key, None, host.clock.now())
            .unwrap();
        let ticket = Secret::new(Ticket {
            door: door.addr(),
            cap,
        });
        let guest_key = Secret::new(SecretKey::generate());
        let guest_door = kickoff_net::door_loopback(&guest_key).await.unwrap();
        let request = kickoff_wire::JoinRequest {
            cap: ticket.expose(|ticket| kickoff_wire::Cap {
                session_id: ticket.cap.session_id,
                invitee: ticket.cap.invitee,
                nonce: ticket.cap.nonce,
                sig: ticket.cap.sig,
            }),
            session_key: SecretKey::generate().public(),
            name: kickoff_wire::Name::new("guest").unwrap(),
            platform: kickoff_wire::Platform::Linux,
            game_build: kickoff_wire::BuildId::new("test").unwrap(),
            kickoff_version: crate::KICKOFF_VERSION,
        };
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            guest_door.request_join(&ticket, request),
        )
        .await;
        assert!(matches!(
            result,
            Ok(Err(NetError::Refused(JoinRefused::InvalidCap)))
        ));
        assert!(host.approvals.borrow().is_empty());
    }
}

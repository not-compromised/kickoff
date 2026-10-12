//! The door: persistent identity, relay-only, `kickoff/join/1` only (§3.4, §4.3).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use iroh::endpoint::{
    Builder, ConnectError, ConnectingError, Connection, ConnectionError, Incoming, RecvStream,
    SendStream, TransportErrorCode, presets,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode};
use kickoff_secret::Secret;
use kickoff_secret::key::{IdentityKey, KeyEndpoint};
use kickoff_wire::{Admitted, JoinRefused, JoinReply, JoinRequest, Ticket};
use tokio::sync::{OwnedSemaphorePermit, mpsc};

use crate::budget::Window;
use crate::egress::{Egress, EgressGuard, IfaceAddr, SendGuard, View};
use crate::guarded::{self, Guarded};
use crate::incoming::Gate;
use crate::stream::{read_message, write_message};
use crate::{
    AbortOnDrop, CONNECT_DEADLINE, HANDSHAKE_DEADLINE, JOIN_ALPN, NetError, close, transport,
};

/// Invalid requests per identity and overall, per `INVALID_WINDOW` (§6.3).
const INVALID_PER_ID: u64 = 10;
const INVALID_GLOBAL: u64 = 60;
const INVALID_WINDOW: Duration = Duration::from_secs(60);
/// Identities whose invalid count is remembered; beyond it, unknown ids count
/// against the global limit only.
const INVALID_TRACKED: usize = 256;
/// Authenticated connections that have not sent their `JoinRequest` yet,
/// overall and per identity (§6.3).
const AWAITING: usize = 16;
const AWAITING_PER_ID: usize = 2;
/// Authenticated requests waiting for the admission owner.
const PRIORITY_QUEUE: usize = 8;
const GENERAL_QUEUE: usize = 16;
/// The host may be waiting on a native prompt (§4.2).
const REPLY_DEADLINE: Duration = Duration::from_secs(120);
/// How long `answer` waits for the guest to read the reply and close.
const ANSWER_LINGER: Duration = Duration::from_secs(5);

/// Relay-only, persistent identity. Runs only while hosting or while "friends
/// may join" is on. It has no IP transport, so it owns no UDP socket.
pub async fn door(id: &IdentityKey, relays: impl Into<crate::Relays>) -> Result<Door, NetError> {
    let policy = relays.into();
    let relays = &policy.map;
    let egress = Egress::new(relays.clone(), None);
    let ep = id
        .bind(
            Door::builder(id)
                .ca_tls_config(policy.tls)
                .relay_mode(RelayMode::Custom(relays.clone()))
                .hooks(EgressGuard::new(egress.clone())),
        )
        .await
        .map_err(|_| NetError::Bind)?;
    Ok(Door::serve(ep, egress, None))
}

/// The in-process adapter (design §2.3): the same door on 127.0.0.1 with no
/// relay, for tests and for nothing that leaves this host.
pub async fn door_loopback(id: &IdentityKey) -> Result<Door, NetError> {
    let bind = IfaceAddr::loopback();
    let egress = Egress::new(RelayMap::empty(), Some(bind));
    let view = View::current(bind, &[]).await;
    let make = || Door::builder(id).relay_mode(RelayMode::Disabled);
    let (ep, guarded) = guarded::bind_key(id, make, bind.ip(), &egress, view).await?;
    Ok(Door::serve(ep, egress, Some(guarded)))
}

pub struct Door {
    ep: KeyEndpoint,
    egress: Egress,
    queues: tokio::sync::Mutex<Queues>,
    priority: Arc<ArcSwap<HashSet<EndpointId>>>,
    _accept: AbortOnDrop,
    /// The loopback adapter's send guard; the relay-only door has none.
    guarded: Option<Guarded>,
}

struct Queues {
    priority: mpsc::Receiver<JoinAttempt>,
    general: mpsc::Receiver<JoinAttempt>,
}

impl Door {
    fn builder(_id: &IdentityKey) -> Builder {
        Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .alpns(vec![JOIN_ALPN.to_vec()])
            .transport_config(transport(1, false))
    }

    fn serve(ep: KeyEndpoint, egress: Egress, guarded: Option<Guarded>) -> Door {
        let (priority_tx, priority) = mpsc::channel(PRIORITY_QUEUE);
        let (general_tx, general) = mpsc::channel(GENERAL_QUEUE);
        let priority_ids = Arc::new(ArcSwap::from_pointee(HashSet::new()));
        let guard = guarded.as_ref().map(|g| Arc::clone(&g.guard));
        let accept = Acceptor {
            gate: Gate::new(guard.clone()),
            guard,
            awaiting: Arc::new(Awaiting::default()),
            limiter: Arc::new(Mutex::new(InvalidLimiter::default())),
            priority_ids: Arc::clone(&priority_ids),
            priority_tx,
            general_tx,
        };
        let task = tokio::spawn(accept.run(ep.clone()));
        Door {
            ep,
            egress,
            queues: tokio::sync::Mutex::new(Queues { priority, general }),
            priority: priority_ids,
            _accept: AbortOnDrop(task),
            guarded,
        }
    }

    pub fn id(&self) -> EndpointId {
        self.ep.id()
    }

    /// What a ticket may carry: compiled relay URLs only (the loopback adapter
    /// carries 127.0.0.1 instead).
    pub fn addr(&self) -> EndpointAddr {
        self.egress.publishable(self.ep.addr())
    }

    /// Identities whose requests use a queue that invalid traffic cannot fill
    /// and that the global invalid limit does not block (§6.3, NET-18): the
    /// trusted list and the invitees of outstanding bound tickets. Replaces the
    /// previous set.
    pub fn set_priority(&self, ids: impl IntoIterator<Item = EndpointId>) {
        self.priority.store(Arc::new(ids.into_iter().collect()));
    }

    /// Host: the next join request, from an identity TLS has authenticated.
    /// Pre-handshake and post-handshake budgets (§6.3) are charged before this
    /// returns.
    pub async fn next_join(&self) -> Result<JoinAttempt, NetError> {
        let mut queues = self.queues.lock().await;
        let Queues { priority, general } = &mut *queues;
        tokio::select! {
            biased;
            Some(attempt) = priority.recv() => Ok(attempt),
            Some(attempt) = general.recv() => Ok(attempt),
            else => Err(NetError::Closed),
        }
    }

    /// Guest: dials the ticket's door. Relay URLs in the ticket are used only
    /// when they equal an entry of the compiled map (SI-29).
    pub async fn request_join(
        &self,
        ticket: &Secret<Ticket>,
        request: JoinRequest,
    ) -> Result<Admitted, NetError> {
        let addr = self.egress.scope(&Ticket::door(ticket))?;
        let conn = match tokio::time::timeout(CONNECT_DEADLINE, self.ep.connect(addr, JOIN_ALPN))
            .await
        {
            Ok(Ok(conn)) => conn,
            Ok(Err(err)) if connect_busy(&err) => return Err(NetError::Refused(JoinRefused::Busy)),
            _ => return Err(NetError::Closed),
        };
        if let Some(guarded) = &self.guarded {
            guarded.guard.track(&conn);
        }
        let reply = tokio::time::timeout(REPLY_DEADLINE, exchange(&conn, &request)).await;
        let turned_away = conn.close_reason().as_ref().is_some_and(busy);
        conn.close(close::DONE, b"");
        match reply.map_err(|_| NetError::Closed)? {
            Ok(JoinReply::Admitted(admitted)) => Ok(admitted),
            Ok(JoinReply::Refused(why)) => Err(NetError::Refused(why)),
            Err(_) if turned_away => Err(NetError::Refused(JoinRefused::Busy)),
            Err(err) => Err(err),
        }
    }

    pub async fn close(&self) {
        self.ep.close().await;
    }
}

/// The door turned the connection away before reading a request: refused
/// before the handshake (pending slots or handshake rate full) or closed with
/// `BUSY` after it (awaiting slots or the invalid-request limit). To the
/// guest that is the host being busy.
fn connect_busy(err: &ConnectError) -> bool {
    match err {
        ConnectError::Connection { source, .. }
        | ConnectError::Connecting {
            source: ConnectingError::ConnectionError { source, .. },
            ..
        } => busy(source),
        _ => false,
    }
}

fn busy(err: &ConnectionError) -> bool {
    match err {
        ConnectionError::ConnectionClosed(close) => {
            close.error_code == TransportErrorCode::CONNECTION_REFUSED
        }
        ConnectionError::ApplicationClosed(app) => app.error_code == close::BUSY,
        _ => false,
    }
}

async fn exchange(conn: &Connection, request: &JoinRequest) -> Result<JoinReply, NetError> {
    let mut recv = kickoff_wire::prepare_message(request)
        .map_err(crate::stream::wire)?
        .transmit_quic(conn)
        .await
        .map_err(|_| NetError::Closed)?;
    read_message(&mut recv).await
}

/// One authenticated join request awaiting the admission owner's answer.
/// Dropping it closes the connection unanswered.
pub struct JoinAttempt {
    id: EndpointId,
    request: JoinRequest,
    conn: Connection,
    send: SendStream,
    limiter: Arc<Mutex<InvalidLimiter>>,
    priority: bool,
}

impl JoinAttempt {
    pub fn id(&self) -> EndpointId {
        self.id
    }

    /// Uses the reserved queue and reply capacity for bound/trusted identities.
    pub fn is_priority(&self) -> bool {
        self.priority
    }

    pub fn request(&self) -> &JoinRequest {
        &self.request
    }

    /// Refusals that mean a bad or stale capability count against the
    /// requester's invalid budget.
    pub async fn answer(mut self, reply: Result<Admitted, JoinRefused>) -> Result<(), NetError> {
        let reply = match reply {
            Ok(admitted) => JoinReply::Admitted(admitted),
            Err(why) => {
                if counts_as_invalid(why) {
                    lock(&self.limiter).record(Instant::now(), self.id);
                }
                JoinReply::Refused(why)
            }
        };
        let answer = async {
            write_message(&mut self.send, &reply).await?;
            self.send.finish().map_err(|_| NetError::Closed)?;
            let _ = self.conn.closed().await;
            Ok(())
        };
        if cfg!(feature = "mutant-si23-door-unbounded-reply") {
            answer.await
        } else {
            tokio::time::timeout(ANSWER_LINGER, answer)
                .await
                .unwrap_or(Err(NetError::Closed))
        }
    }
}

impl Drop for JoinAttempt {
    fn drop(&mut self) {
        self.conn.close(close::DONE, b"");
    }
}

fn counts_as_invalid(why: JoinRefused) -> bool {
    matches!(
        why,
        JoinRefused::InvalidCap
            | JoinRefused::WrongSession
            | JoinRefused::Expired
            | JoinRefused::Revoked
    )
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Acceptor {
    gate: Gate,
    guard: Option<Arc<SendGuard>>,
    awaiting: Arc<Awaiting>,
    limiter: Arc<Mutex<InvalidLimiter>>,
    priority_ids: Arc<ArcSwap<HashSet<EndpointId>>>,
    priority_tx: mpsc::Sender<JoinAttempt>,
    general_tx: mpsc::Sender<JoinAttempt>,
}

impl Acceptor {
    async fn run(self, ep: KeyEndpoint) {
        let this = Arc::new(self);
        while let Some(incoming) = ep.accept().await {
            let Some((incoming, pending)) = this.gate.admit(incoming) else {
                continue;
            };
            let this = Arc::clone(&this);
            tokio::spawn(async move {
                let deadline = if cfg!(feature = "mutant-si23-door-no-join-deadline") {
                    Duration::from_secs(86_400)
                } else {
                    HANDSHAKE_DEADLINE
                };
                let attempt = tokio::time::timeout(deadline, this.receive(incoming, pending)).await;
                if let Ok(Some(attempt)) = attempt {
                    this.enqueue(attempt);
                }
            });
        }
    }

    async fn receive(
        &self,
        incoming: Incoming,
        pending: OwnedSemaphorePermit,
    ) -> Option<JoinAttempt> {
        let conn = incoming.accept().ok()?.await.ok()?;
        drop(pending);
        let id = conn.remote_id();
        let Some(_waiting) = Awaiting::enter(&self.awaiting, id) else {
            conn.close(close::BUSY, b"");
            return None;
        };
        if let Some(guard) = &self.guard {
            guard.track(&conn);
        }
        let priority = self.priority_ids.load().contains(&id);
        if lock(&self.limiter).blocked(Instant::now(), id, priority) {
            conn.close(close::BUSY, b"");
            return None;
        }
        let (send, mut recv): (SendStream, RecvStream) = conn.accept_bi().await.ok()?;
        let request = match read_message::<JoinRequest>(&mut recv).await {
            Ok(request) => request,
            Err(NetError::Version) => {
                conn.close(close::VERSION, b"");
                return None;
            }
            Err(err) => {
                if err == NetError::Protocol {
                    lock(&self.limiter).record(Instant::now(), id);
                }
                conn.close(close::PROTOCOL, b"");
                return None;
            }
        };
        Some(JoinAttempt {
            id,
            request,
            conn,
            send,
            limiter: Arc::clone(&self.limiter),
            priority,
        })
    }

    fn enqueue(&self, mut attempt: JoinAttempt) {
        attempt.priority = self.priority_ids.load().contains(&attempt.id);
        let queue = if attempt.priority {
            &self.priority_tx
        } else {
            &self.general_tx
        };
        if let Err(full) = queue.try_send(attempt) {
            let attempt = full.into_inner();
            if cfg!(feature = "mutant-si23-door-unbounded-overflow") {
                tokio::spawn(attempt.answer(Err(JoinRefused::Busy)));
            } else {
                attempt.conn.close(close::BUSY, b"");
            }
        }
    }
}

/// Connections past their handshake that have not sent a `JoinRequest` yet.
#[derive(Debug, Default)]
struct Awaiting {
    counts: Mutex<(usize, HashMap<EndpointId, usize>)>,
}

/// One awaiting connection's place; dropping it frees the place.
struct Waiting {
    awaiting: Arc<Awaiting>,
    id: EndpointId,
}

impl Awaiting {
    fn enter(this: &Arc<Awaiting>, id: EndpointId) -> Option<Waiting> {
        let mut counts = lock(&this.counts);
        let (total, per_id) = &mut *counts;
        let mine = per_id.get(&id).copied().unwrap_or(0);
        let full = !cfg!(feature = "mutant-si23-door-no-awaiting-cap") && *total >= AWAITING;
        let own_full =
            !cfg!(feature = "mutant-si23-door-no-identity-cap") && mine >= AWAITING_PER_ID;
        if full || own_full {
            return None;
        }
        *total = total.saturating_add(1);
        per_id.insert(id, mine.saturating_add(1));
        Some(Waiting {
            awaiting: Arc::clone(this),
            id,
        })
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let mut counts = lock(&self.awaiting.counts);
        let (total, per_id) = &mut *counts;
        *total = total.saturating_sub(1);
        if let Some(mine) = per_id.get_mut(&self.id) {
            *mine = mine.saturating_sub(1);
            if *mine == 0 {
                per_id.remove(&self.id);
            }
        }
    }
}

#[derive(Default)]
struct InvalidLimiter {
    global: Option<Window>,
    per_id: HashMap<EndpointId, Window>,
}

impl InvalidLimiter {
    fn blocked(&mut self, now: Instant, id: EndpointId, priority: bool) -> bool {
        let own = self.per_id.get_mut(&id).is_some_and(|w| w.full(now));
        let global = !priority && self.global_window(now).full(now);
        !cfg!(feature = "mutant-si23-door-no-invalid-limit") && (own || global)
    }

    fn record(&mut self, now: Instant, id: EndpointId) {
        let _ = self.global_window(now).exceeded(now, 1);
        if !self.per_id.contains_key(&id) && self.per_id.len() >= INVALID_TRACKED {
            self.per_id.retain(|_, w| !w.expired(now));
        }
        if let Some(w) = self.per_id.get_mut(&id) {
            let _ = w.exceeded(now, 1);
        } else if self.per_id.len() < INVALID_TRACKED {
            let mut w = Window::new(now, INVALID_WINDOW, INVALID_PER_ID);
            let _ = w.exceeded(now, 1);
            self.per_id.insert(id, w);
        }
    }

    fn global_window(&mut self, now: Instant) -> &mut Window {
        self.global
            .get_or_insert_with(|| Window::new(now, INVALID_WINDOW, INVALID_GLOBAL))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn id(n: u8) -> EndpointId {
        SecretKey::from_bytes(&[n; 32]).public()
    }

    #[test]
    fn invalid_limit_blocks_the_identity_then_everyone_but_priority() {
        let t = Instant::now();
        let mut l = InvalidLimiter::default();
        for _ in 0..INVALID_PER_ID {
            assert!(!l.blocked(t, id(1), false));
            l.record(t, id(1));
        }
        assert!(l.blocked(t, id(1), false), "per-identity limit");
        assert!(!l.blocked(t, id(2), false));
        for n in 2..7 {
            for _ in 0..INVALID_PER_ID {
                l.record(t, id(n));
            }
        }
        assert!(l.blocked(t, id(9), false), "global limit");
        assert!(
            !l.blocked(t, id(9), true),
            "priority ids bypass the global limit"
        );
        assert!(l.blocked(t, id(1), true), "but not their own limit");
        let later = t + INVALID_WINDOW;
        assert!(!l.blocked(later, id(1), false), "the window resets");
    }

    #[test]
    fn invalid_limiter_memory_is_bounded() {
        let t = Instant::now();
        let mut l = InvalidLimiter::default();
        for n in 0..2000u32 {
            let key = SecretKey::from_bytes(&{
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&n.to_be_bytes());
                b
            });
            l.record(t, key.public());
        }
        assert!(l.per_id.len() <= INVALID_TRACKED);
    }

    #[derive(Debug)]
    struct FixtureGuard {
        _registration: kickoff_send_guard::Registration,
    }
    impl iroh::endpoint::EndpointHooks for FixtureGuard {}
    struct Unfiltered;
    impl kickoff_send_guard::Guard for Unfiltered {
        fn admit(&self, _: u64, _: std::net::SocketAddr) -> bool {
            true
        }
    }

    async fn blocked_client(ip: std::net::Ipv4Addr) -> Endpoint {
        let bind = std::net::UdpSocket::bind((ip, 0))
            .unwrap()
            .local_addr()
            .unwrap();
        let registration = kickoff_send_guard::register(bind, Arc::new(Unfiltered)).unwrap();
        Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .bind_addr(bind)
            .unwrap()
            .hooks(FixtureGuard {
                _registration: registration,
            })
            .relay_mode(RelayMode::Disabled)
            .transport_config(
                iroh::endpoint::QuicTransportConfig::builder()
                    .stream_receive_window(iroh::endpoint::VarInt::from_u32(0))
                    .receive_window(iroh::endpoint::VarInt::from_u32(0))
                    .keep_alive_interval(Duration::from_millis(100))
                    .build(),
            )
            .bind()
            .await
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn si_23_door_overflow_closes_without_retaining_reply_tasks() {
        let host = door_loopback(&IdentityKey::new(SecretKey::generate()))
            .await
            .unwrap();
        let request = JoinRequest {
            cap: kickoff_wire::Cap::new_for_door(
                host.id(),
                kickoff_wire::SessionId([0; 16]),
                None,
                kickoff_wire::Nonce([0; 16]),
                SecretKey::generate().sign(b"fixture"),
            ),
            session_key: SecretKey::generate().public(),
            name: kickoff_wire::Name::new("raw").unwrap(),
            platform: kickoff_wire::Platform::Linux,
            game_build: kickoff_wire::BuildId::new("b").unwrap(),
            kickoff_version: kickoff_wire::KickoffVersion {
                major: 0,
                minor: 1,
                patch: 0,
            },
        };
        let mut held = Vec::new();
        for n in 0..=GENERAL_QUEUE {
            let ip = std::net::Ipv4Addr::new(127, 0, 3, u8::try_from(n).unwrap().wrapping_add(1));
            let client = blocked_client(ip).await;
            let conn = client.connect(host.addr(), JOIN_ALPN).await.unwrap();
            let recv = kickoff_wire::prepare_message(&request)
                .unwrap()
                .transmit_quic(&conn)
                .await
                .unwrap();
            if n < GENERAL_QUEUE {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while host.queues.lock().await.general.len() != n.saturating_add(1) {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
                held.push((client, conn, recv));
            } else {
                assert!(
                    tokio::time::timeout(Duration::from_millis(500), conn.closed())
                        .await
                        .is_ok(),
                    "a full queue spawned and retained a blocked overflow reply"
                );
            }
        }
        assert_eq!(host.queues.lock().await.general.len(), GENERAL_QUEUE);
        assert!(
            held.iter()
                .all(|(_, conn, _)| conn.close_reason().is_none())
        );
    }
}

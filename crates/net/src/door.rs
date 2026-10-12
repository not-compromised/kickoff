//! The door: persistent identity, relay-only, `kickoff/join/1` only (§3.4, §4.3).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use iroh::endpoint::{Connection, Incoming, RecvStream, SendStream, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, SecretKey};
use kickoff_secret::Secret;
use kickoff_wire::{Admitted, JoinRefused, JoinReply, JoinRequest, Ticket};
use tokio::sync::{Semaphore, mpsc};

use crate::budget::Window;
use crate::egress::{Egress, EgressGuard, IfaceAddr};
use crate::stream::{read_message, write_message};
use crate::{
    AbortOnDrop, CONNECT_DEADLINE, HANDSHAKE_DEADLINE, JOIN_ALPN, NetError, PENDING_INCOMING,
    close, transport,
};

/// Invalid requests per identity and overall, per `INVALID_WINDOW` (§6.3).
const INVALID_PER_ID: u64 = 10;
const INVALID_GLOBAL: u64 = 60;
const INVALID_WINDOW: Duration = Duration::from_secs(60);
/// Identities whose invalid count is remembered; beyond it, unknown ids count
/// against the global limit only.
const INVALID_TRACKED: usize = 256;
/// Authenticated requests waiting for the admission owner.
const PRIORITY_QUEUE: usize = 8;
const GENERAL_QUEUE: usize = 16;
/// The host may be waiting on a native prompt (§4.2).
const REPLY_DEADLINE: Duration = Duration::from_secs(120);
/// How long `answer` waits for the guest to read the reply and close.
const ANSWER_LINGER: Duration = Duration::from_secs(5);

/// Relay-only, persistent identity. Runs only while hosting or while "friends
/// may join" is on.
pub async fn door(id: &Secret<SecretKey>, relays: &RelayMap) -> Result<Door, NetError> {
    let builder = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .relay_mode(RelayMode::Custom(relays.clone()));
    Door::bind(id, builder, Egress::new(relays.clone(), None)).await
}

/// The in-process adapter (design §2.3): the same door on 127.0.0.1 with no
/// relay, for tests and for nothing that leaves this host.
pub async fn door_loopback(id: &Secret<SecretKey>) -> Result<Door, NetError> {
    let bind = IfaceAddr::loopback();
    let builder = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .relay_mode(RelayMode::Disabled)
        .bind_addr((bind.ip(), 0))
        .map_err(|_| NetError::Bind)?;
    Door::bind(id, builder, Egress::new(RelayMap::empty(), Some(bind))).await
}

pub struct Door {
    ep: Endpoint,
    egress: Egress,
    queues: tokio::sync::Mutex<Queues>,
    priority: Arc<ArcSwap<HashSet<EndpointId>>>,
    _accept: AbortOnDrop,
}

struct Queues {
    priority: mpsc::Receiver<JoinAttempt>,
    general: mpsc::Receiver<JoinAttempt>,
}

impl Door {
    async fn bind(
        id: &Secret<SecretKey>,
        builder: iroh::endpoint::Builder,
        egress: Egress,
    ) -> Result<Door, NetError> {
        let ep = builder
            .secret_key(id.expose(SecretKey::clone))
            .alpns(vec![JOIN_ALPN.to_vec()])
            .transport_config(transport(1, false))
            .hooks(EgressGuard(egress.clone()))
            .bind()
            .await
            .map_err(|_| NetError::Bind)?;
        let (priority_tx, priority) = mpsc::channel(PRIORITY_QUEUE);
        let (general_tx, general) = mpsc::channel(GENERAL_QUEUE);
        let priority_ids = Arc::new(ArcSwap::from_pointee(HashSet::new()));
        let accept = Acceptor {
            limiter: Arc::new(Mutex::new(InvalidLimiter::default())),
            priority_ids: Arc::clone(&priority_ids),
            priority_tx,
            general_tx,
        };
        let task = tokio::spawn(accept.run(ep.clone()));
        Ok(Door {
            ep,
            egress,
            queues: tokio::sync::Mutex::new(Queues { priority, general }),
            priority: priority_ids,
            _accept: AbortOnDrop(task),
        })
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
        let addr = ticket.expose(|t| self.egress.scope(&t.door))?;
        let conn = tokio::time::timeout(CONNECT_DEADLINE, self.ep.connect(addr, JOIN_ALPN))
            .await
            .map_err(|_| NetError::Closed)?
            .map_err(|_| NetError::Closed)?;
        let reply = tokio::time::timeout(REPLY_DEADLINE, exchange(&conn, &request)).await;
        conn.close(close::DONE, b"");
        match reply.map_err(|_| NetError::Closed)?? {
            JoinReply::Admitted(admitted) => Ok(admitted),
            JoinReply::Refused(why) => Err(NetError::Refused(why)),
        }
    }

    pub async fn close(&self) {
        self.ep.close().await;
    }
}

async fn exchange(conn: &Connection, request: &JoinRequest) -> Result<JoinReply, NetError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|_| NetError::Closed)?;
    write_message(&mut send, request).await?;
    send.finish().map_err(|_| NetError::Closed)?;
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
}

impl JoinAttempt {
    pub fn id(&self) -> EndpointId {
        self.id
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
        write_message(&mut self.send, &reply).await?;
        self.send.finish().map_err(|_| NetError::Closed)?;
        let _ = tokio::time::timeout(ANSWER_LINGER, self.conn.closed()).await;
        Ok(())
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
    limiter: Arc<Mutex<InvalidLimiter>>,
    priority_ids: Arc<ArcSwap<HashSet<EndpointId>>>,
    priority_tx: mpsc::Sender<JoinAttempt>,
    general_tx: mpsc::Sender<JoinAttempt>,
}

impl Acceptor {
    async fn run(self, ep: Endpoint) {
        let this = Arc::new(self);
        let pending = Arc::new(Semaphore::new(PENDING_INCOMING));
        while let Some(incoming) = ep.accept().await {
            let Ok(permit) = Arc::clone(&pending).try_acquire_owned() else {
                incoming.refuse();
                continue;
            };
            if !incoming.remote_addr_validated() {
                if let Err(err) = incoming.retry() {
                    err.into_incoming().refuse();
                }
                continue;
            }
            let this = Arc::clone(&this);
            tokio::spawn(async move {
                let attempt =
                    tokio::time::timeout(HANDSHAKE_DEADLINE, this.receive(incoming)).await;
                drop(permit);
                if let Ok(Some(attempt)) = attempt {
                    this.enqueue(attempt);
                }
            });
        }
    }

    async fn receive(&self, incoming: Incoming) -> Option<JoinAttempt> {
        let conn = incoming.accept().ok()?.await.ok()?;
        let id = conn.remote_id();
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
        })
    }

    fn enqueue(&self, attempt: JoinAttempt) {
        let queue = if self.priority_ids.load().contains(&attempt.id) {
            &self.priority_tx
        } else {
            &self.general_tx
        };
        if let Err(full) = queue.try_send(attempt) {
            let attempt = full.into_inner();
            tokio::spawn(attempt.answer(Err(JoinRefused::Busy)));
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
        own || global
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
}

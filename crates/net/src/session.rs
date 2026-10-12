//! The per-session endpoint (§3.4, §4.3): fresh key, one bound interface
//! address or none, `kickoff/session/1`, and the admission hook.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;
use iroh::endpoint::{
    AfterHandshakeOutcome, Builder, Connection, EndpointHooks, Incoming, WeakConnectionHandle,
    presets,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode};
use kickoff_wire::{AdmitPass, PeerRef, PeerSlot};
use tokio::sync::{OwnedSemaphorePermit, mpsc};

use crate::egress::{Egress, EgressGuard, IfaceAddr, SendGuard, View};
use crate::guarded::{self, Guarded};
use crate::incoming::Gate;
use crate::link::{self, CtlStream, Link};
use crate::reassembly::GlobalBudget;
use crate::{
    AbortOnDrop, CONNECT_DEADLINE, HANDSHAKE_DEADLINE, NetError, SESSION_ALPN, close, transport,
};

/// Admitted links waiting for `accept`.
const ACCEPT_QUEUE: usize = 8;
/// Bidi streams a guest may hold open on the host: control plus three blobs (§6.3).
const HOST_BIDI: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Host,
    Guest,
}

/// Session keys the admission owner currently admits, each with the identity,
/// slot and generation it was admitted under. Published whole, so the hook
/// and every link read one consistent snapshot.
#[derive(Debug, Clone, Default)]
pub struct AdmittedSet(HashMap<EndpointId, PeerRef>);

impl AdmittedSet {
    pub fn new() -> AdmittedSet {
        AdmittedSet::default()
    }

    pub fn insert(&mut self, session_key: EndpointId, peer: PeerRef) {
        self.0.insert(session_key, peer);
    }

    fn get(&self, session_key: &EndpointId) -> Option<PeerRef> {
        self.0.get(session_key).copied()
    }
}

impl FromIterator<(EndpointId, PeerRef)> for AdmittedSet {
    fn from_iter<I: IntoIterator<Item = (EndpointId, PeerRef)>>(iter: I) -> Self {
        AdmittedSet(iter.into_iter().collect())
    }
}

/// State shared by the hook, the accept task and every host-side link.
#[derive(Debug, Default)]
pub(crate) struct Shared {
    admitted: ArcSwap<AdmittedSet>,
    /// At most one live connection per session key, with what it was admitted as.
    live: Mutex<HashMap<EndpointId, Live>>,
    pub(crate) frags: Arc<GlobalBudget>,
}

#[derive(Debug)]
struct Live {
    peer: PeerRef,
    conn: WeakConnectionHandle,
}

impl Live {
    fn is_open(&self) -> bool {
        self.conn
            .upgrade()
            .is_some_and(|c| c.close_reason().is_none())
    }
}

impl Shared {
    /// Whether `session_key` is still admitted as exactly `peer` (SI-18).
    pub(crate) fn is_current(&self, session_key: &EndpointId, peer: &PeerRef) -> bool {
        self.admitted.load().get(session_key).as_ref() == Some(peer)
    }

    fn live(&self) -> std::sync::MutexGuard<'_, HashMap<EndpointId, Live>> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Runs inside iroh after TLS and before the connection is handed out.
#[derive(Debug)]
struct AdmissionHook {
    shared: Arc<Shared>,
    role: Role,
}

impl EndpointHooks for AdmissionHook {
    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        if conn.side().is_client() {
            return AfterHandshakeOutcome::Accept;
        }
        let reject = |code| AfterHandshakeOutcome::Reject {
            error_code: code,
            reason: Vec::new(),
        };
        let guest = self.role == Role::Guest && !cfg!(feature = "mutant-si21-guest-serves");
        if guest || conn.alpn() != SESSION_ALPN {
            return reject(close::NOT_ADMITTED);
        }
        let key = conn.remote_id();
        let Some(peer) = self.shared.admitted.load().get(&key) else {
            if cfg!(feature = "mutant-si18-hook-admits-unknown") {
                return AfterHandshakeOutcome::Accept;
            }
            return reject(close::NOT_ADMITTED);
        };
        let mut live = self.shared.live();
        if !cfg!(feature = "mutant-si18-duplicate-connections")
            && live.get(&key).is_some_and(Live::is_open)
        {
            return reject(close::DUPLICATE);
        }
        live.insert(
            key,
            Live {
                peer,
                conn: conn.weak_handle(),
            },
        );
        AfterHandshakeOutcome::Accept
    }
}

/// How a session endpoint reaches peers (§3.4, R2-9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionBind {
    /// Direct paths from this one interface address, plus relays. Peers learn
    /// this address and the QAD public address.
    Direct(IfaceAddr),
    /// Relays only: no IP transport and no QAD probe, so the endpoint owns no
    /// UDP socket and no peer learns any address of this host.
    RelayOnly,
}

impl From<IfaceAddr> for SessionBind {
    fn from(addr: IfaceAddr) -> SessionBind {
        SessionBind::Direct(addr)
    }
}

/// Fresh key per session. A `Direct` endpoint is recreated by its owner when
/// the default route changes. An empty relay map makes a `Direct` endpoint
/// direct-only; a `RelayOnly` one needs at least one relay.
pub async fn session(
    relays: &RelayMap,
    bind: impl Into<SessionBind>,
    role: Role,
) -> Result<SessionNet, NetError> {
    let bind = bind.into();
    let view = match bind {
        SessionBind::Direct(iface) => Some(View::current(iface, &[]).await),
        SessionBind::RelayOnly => None,
    };
    bind_session(relays, view, role).await
}

/// `view` is `None` for a relay-only endpoint; tests pass a synthetic view.
async fn bind_session(
    relays: &RelayMap,
    view: Option<View>,
    role: Role,
) -> Result<SessionNet, NetError> {
    let relay_mode = if relays.is_empty() {
        RelayMode::Disabled
    } else {
        RelayMode::Custom(relays.clone())
    };
    let serves = role == Role::Host || cfg!(feature = "mutant-si21-guest-serves");
    let (alpns, bidi) = if serves {
        (vec![SESSION_ALPN.to_vec()], HOST_BIDI)
    } else {
        (Vec::new(), 0)
    };
    let shared = Arc::new(Shared::default());
    let make = || -> Builder {
        Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .relay_mode(relay_mode.clone())
            .alpns(alpns.clone())
            .transport_config(transport(bidi, true))
            .hooks(AdmissionHook {
                shared: Arc::clone(&shared),
                role,
            })
    };
    let (ep, egress, guarded) = match view {
        Some(view) => {
            let bind = view.bind();
            let egress = Egress::new(relays.clone(), Some(bind));
            let ip = if cfg!(feature = "mutant-si31-unbound") {
                std::net::Ipv4Addr::UNSPECIFIED
            } else {
                bind.ip()
            };
            let (ep, guarded) = guarded::bind(make, ip, &egress, view).await?;
            (ep, egress, Some(guarded))
        }
        None if relays.is_empty() => return Err(NetError::Bind),
        None => {
            let egress = Egress::new(relays.clone(), None);
            let builder = make().hooks(EgressGuard::new(egress.clone()));
            let builder = if cfg!(feature = "mutant-si31-relay-only-binds") {
                builder
                    .bind_addr((std::net::Ipv4Addr::UNSPECIFIED, 0))
                    .map_err(|_| NetError::Bind)?
            } else {
                builder
            };
            let ep = builder.bind().await.map_err(|_| NetError::Bind)?;
            (ep, egress, None)
        }
    };
    let guard = guarded.as_ref().map(|g| Arc::clone(&g.guard));
    let gate = Gate::new(guard.clone());
    let (tx, rx) = mpsc::channel(ACCEPT_QUEUE);
    let task = if serves {
        tokio::spawn(host_accept(
            ep.clone(),
            gate,
            Arc::clone(&shared),
            guard,
            tx,
        ))
    } else {
        tokio::spawn(refuse_all(ep.clone(), gate))
    };
    Ok(SessionNet {
        ep,
        role,
        egress,
        shared,
        links: tokio::sync::Mutex::new(rx),
        _accept: AbortOnDrop(task),
        guarded,
    })
}

pub struct SessionNet {
    ep: Endpoint,
    role: Role,
    egress: Egress,
    shared: Arc<Shared>,
    links: tokio::sync::Mutex<mpsc::Receiver<(Link, CtlStream)>>,
    _accept: AbortOnDrop,
    /// `None` for a relay-only endpoint, which has no IP transport.
    guarded: Option<Guarded>,
}

impl SessionNet {
    /// Whether this endpoint has no IP transport.
    pub fn is_relay_only(&self) -> bool {
        self.guarded.is_none()
    }

    /// This session's fresh key: what a guest puts in `JoinRequest::session_key`.
    pub fn id(&self) -> EndpointId {
        self.ep.id()
    }

    /// The bound interface address plus the QAD public address only.
    pub fn addr(&self) -> EndpointAddr {
        self.egress.publishable(self.ep.addr())
    }

    /// IP packets the send guard has dropped (§3.4), for health reporting.
    /// Always 0 for a relay-only endpoint.
    pub fn egress_denied(&self) -> u64 {
        self.guarded.as_ref().map_or(0, |g| g.guard.denied())
    }

    /// Host: replaces the admitted set. Live connections whose key left the
    /// set, or whose identity, slot or generation changed, are closed now;
    /// links also re-check on every datagram they touch.
    pub fn set_admitted(&self, set: AdmittedSet) {
        let set = Arc::new(set);
        self.shared.admitted.store(Arc::clone(&set));
        if cfg!(feature = "mutant-si18-set-admitted-keeps-stale") {
            return;
        }
        self.shared.live().retain(|key, live| {
            let keep = set.get(key) == Some(live.peer);
            if !keep && let Some(conn) = live.conn.upgrade() {
                conn.close(close::REVOKED, b"");
            }
            keep
        });
    }

    /// Guest.
    pub async fn dial(
        &self,
        host: EndpointAddr,
        pass: AdmitPass,
    ) -> Result<(Link, CtlStream), NetError> {
        if self.role != Role::Guest {
            return Err(NetError::WrongRole);
        }
        let addr = self.egress.scope(&host)?;
        let conn = tokio::time::timeout(CONNECT_DEADLINE, self.ep.connect(addr, SESSION_ALPN))
            .await
            .map_err(|_| NetError::Closed)?
            .map_err(|_| NetError::Closed)?;
        if let Some(guarded) = &self.guarded {
            guarded.guard.track(&conn);
        }
        let peer = PeerRef {
            id: host.id,
            slot: PeerSlot::HOST,
            generation: pass.generation,
        };
        Link::dial(conn, peer, Arc::clone(&self.shared.frags)).await
    }

    /// Host: only session keys holding a live admission pass get past the
    /// handshake hook.
    pub async fn accept(&self) -> Result<(Link, CtlStream), NetError> {
        if self.role != Role::Host {
            return Err(NetError::WrongRole);
        }
        self.links.lock().await.recv().await.ok_or(NetError::Closed)
    }

    pub async fn close(&self) {
        self.ep.close().await;
    }
}

async fn host_accept(
    ep: Endpoint,
    gate: Gate,
    shared: Arc<Shared>,
    guard: Option<Arc<SendGuard>>,
    tx: mpsc::Sender<(Link, CtlStream)>,
) {
    while let Some(incoming) = ep.accept().await {
        let Some((incoming, pending)) = gate.admit(incoming) else {
            continue;
        };
        let shared = Arc::clone(&shared);
        let guard = guard.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let deadline = if cfg!(feature = "mutant-si23-no-handshake-deadline") {
                std::time::Duration::from_secs(86_400)
            } else {
                HANDSHAKE_DEADLINE
            };
            let link = tokio::time::timeout(deadline, establish(incoming, pending, shared, guard));
            if let Ok(Ok(link)) = link.await {
                let _ = tx.try_send(link);
            }
        });
    }
}

/// The pending slot is held until the handshake completes; after it, only
/// admitted keys remain, one connection each.
async fn establish(
    incoming: Incoming,
    pending: OwnedSemaphorePermit,
    shared: Arc<Shared>,
    guard: Option<Arc<SendGuard>>,
) -> Result<(Link, CtlStream), NetError> {
    let conn = incoming
        .accept()
        .map_err(|_| NetError::Closed)?
        .await
        .map_err(|_| NetError::Closed)?;
    drop(pending);
    let key = conn.remote_id();
    let admitted = if cfg!(feature = "mutant-si18-no-establish-recheck") {
        shared.live().get(&key).map(|live| live.peer)
    } else {
        shared.admitted.load().get(&key)
    };
    let Some(peer) = admitted else {
        conn.close(close::NOT_ADMITTED, b"");
        return Err(NetError::Closed);
    };
    if let Some(guard) = &guard {
        guard.track(&conn);
    }
    link::Link::accept(conn, key, peer, shared).await
}

/// Guests accept nothing (SI-21): every attempt is refused before TLS.
async fn refuse_all(ep: Endpoint, gate: Gate) {
    while let Some(incoming) = ep.accept().await {
        gate.refuse(incoming);
    }
}

#[cfg(test)]
mod tests;

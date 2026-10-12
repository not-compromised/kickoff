//! The per-session endpoint (§3.4, §4.3): fresh key, one bound interface
//! address, `kickoff/session/1`, and the admission hook.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;
use iroh::endpoint::{
    AfterHandshakeOutcome, Connection, EndpointHooks, Incoming, WeakConnectionHandle, presets,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode};
use kickoff_wire::{AdmitPass, PeerRef, PeerSlot};
use tokio::sync::{Semaphore, mpsc};

use crate::egress::{Egress, EgressGuard, IfaceAddr};
use crate::link::{self, CtlStream, Link};
use crate::reassembly::GlobalBudget;
use crate::{
    AbortOnDrop, CONNECT_DEADLINE, HANDSHAKE_DEADLINE, NetError, PENDING_INCOMING, SESSION_ALPN,
    close, transport,
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
        if self.role == Role::Guest || conn.alpn() != SESSION_ALPN {
            return reject(close::NOT_ADMITTED);
        }
        let key = conn.remote_id();
        let Some(peer) = self.shared.admitted.load().get(&key) else {
            return reject(close::NOT_ADMITTED);
        };
        let mut live = self.shared.live();
        if live.get(&key).is_some_and(Live::is_open) {
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

/// Fresh key per session, recreated when the default route changes. An empty
/// relay map makes it direct-only.
pub async fn session(
    relays: &RelayMap,
    bind: IfaceAddr,
    role: Role,
) -> Result<SessionNet, NetError> {
    let relay_mode = if relays.is_empty() {
        RelayMode::Disabled
    } else {
        RelayMode::Custom(relays.clone())
    };
    let (alpns, bidi) = match role {
        Role::Host => (vec![SESSION_ALPN.to_vec()], HOST_BIDI),
        Role::Guest => (Vec::new(), 0),
    };
    let egress = Egress::new(relays.clone(), Some(bind));
    let shared = Arc::new(Shared::default());
    let ep = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr((bind.ip(), 0))
        .map_err(|_| NetError::Bind)?
        .relay_mode(relay_mode)
        .alpns(alpns)
        .transport_config(transport(bidi, true))
        .hooks(EgressGuard(egress.clone()))
        .hooks(AdmissionHook {
            shared: Arc::clone(&shared),
            role,
        })
        .bind()
        .await
        .map_err(|_| NetError::Bind)?;
    let (tx, rx) = mpsc::channel(ACCEPT_QUEUE);
    let task = match role {
        Role::Host => tokio::spawn(host_accept(ep.clone(), Arc::clone(&shared), tx)),
        Role::Guest => tokio::spawn(refuse_all(ep.clone())),
    };
    Ok(SessionNet {
        ep,
        role,
        egress,
        shared,
        links: tokio::sync::Mutex::new(rx),
        _accept: AbortOnDrop(task),
    })
}

pub struct SessionNet {
    ep: Endpoint,
    role: Role,
    egress: Egress,
    shared: Arc<Shared>,
    links: tokio::sync::Mutex<mpsc::Receiver<(Link, CtlStream)>>,
    _accept: AbortOnDrop,
}

impl SessionNet {
    /// This session's fresh key: what a guest puts in `JoinRequest::session_key`.
    pub fn id(&self) -> EndpointId {
        self.ep.id()
    }

    /// The bound interface address plus the QAD public address only.
    pub fn addr(&self) -> EndpointAddr {
        self.egress.publishable(self.ep.addr())
    }

    /// Host: replaces the admitted set. Live connections whose key left the
    /// set, or whose identity, slot or generation changed, are closed now;
    /// links also re-check on every datagram they touch.
    pub fn set_admitted(&self, set: AdmittedSet) {
        let set = Arc::new(set);
        self.shared.admitted.store(Arc::clone(&set));
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

async fn host_accept(ep: Endpoint, shared: Arc<Shared>, tx: mpsc::Sender<(Link, CtlStream)>) {
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
        let shared = Arc::clone(&shared);
        let tx = tx.clone();
        tokio::spawn(async move {
            let link = tokio::time::timeout(HANDSHAKE_DEADLINE, establish(incoming, shared)).await;
            drop(permit);
            if let Ok(Ok(link)) = link {
                let _ = tx.try_send(link);
            }
        });
    }
}

async fn establish(incoming: Incoming, shared: Arc<Shared>) -> Result<(Link, CtlStream), NetError> {
    let conn = incoming
        .accept()
        .map_err(|_| NetError::Closed)?
        .await
        .map_err(|_| NetError::Closed)?;
    let key = conn.remote_id();
    let Some(peer) = shared.admitted.load().get(&key) else {
        conn.close(close::NOT_ADMITTED, b"");
        return Err(NetError::Closed);
    };
    link::Link::accept(conn, key, peer, shared).await
}

/// Guests accept nothing (SI-21): every attempt is refused before TLS.
async fn refuse_all(ep: Endpoint) {
    while let Some(incoming) = ep.accept().await {
        incoming.refuse();
    }
}

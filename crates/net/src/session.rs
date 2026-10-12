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
    let serves = role == Role::Host || cfg!(feature = "mutant-si21-guest-serves");
    let (alpns, bidi) = if serves {
        (vec![SESSION_ALPN.to_vec()], HOST_BIDI)
    } else {
        (Vec::new(), 0)
    };
    let egress = Egress::new(relays.clone(), Some(bind));
    let shared = Arc::new(Shared::default());
    let ep = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr((
            if cfg!(feature = "mutant-si31-unbound") {
                std::net::Ipv4Addr::UNSPECIFIED
            } else {
                bind.ip()
            },
            0,
        ))
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
    let task = if serves {
        tokio::spawn(host_accept(ep.clone(), Arc::clone(&shared), tx))
    } else {
        tokio::spawn(refuse_all(ep.clone()))
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
            let deadline = if cfg!(feature = "mutant-si23-no-handshake-deadline") {
                std::time::Duration::from_secs(86_400)
            } else {
                HANDSHAKE_DEADLINE
            };
            let link = tokio::time::timeout(deadline, establish(incoming, shared)).await;
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
    let admitted = if cfg!(feature = "mutant-si18-no-establish-recheck") {
        shared.live().get(&key).map(|live| live.peer)
    } else {
        shared.admitted.load().get(&key)
    };
    let Some(peer) = admitted else {
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

#[cfg(test)]
mod tests {
    //! SI-18 holds an unknown or stale session key back in several layers.
    //! Each test here drives one layer alone, by hand, so removing just that
    //! layer (its `mutant-si18-*` feature) fails its test even though the
    //! other layers would still refuse the key end to end.

    use std::net::Ipv4Addr;
    use std::time::Duration;

    use iroh::SecretKey;
    use kickoff_wire::{Generation, GuestMsg, LanDatagram};

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    fn peer(generation: u64) -> PeerRef {
        PeerRef {
            id: SecretKey::generate().public(),
            slot: PeerSlot::new(2).unwrap(),
            generation: Generation::new(generation),
        }
    }

    async fn endpoint(serve: bool, hook: Option<AdmissionHook>) -> Endpoint {
        let alpns = if serve {
            vec![SESSION_ALPN.to_vec()]
        } else {
            Vec::new()
        };
        let builder = Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .relay_mode(RelayMode::Disabled)
            .alpns(alpns)
            .transport_config(transport(HOST_BIDI, true));
        match hook {
            Some(hook) => builder.hooks(hook),
            None => builder,
        }
        .bind()
        .await
        .unwrap()
    }

    /// `client` dials `host`; the host's side comes back unaccepted, so the
    /// test applies a layer to it by hand.
    async fn dial(
        host: &Endpoint,
        client: &Endpoint,
    ) -> (Incoming, tokio::task::JoinHandle<Option<Connection>>) {
        let (to, client) = (host.addr(), client.clone());
        let dialing = tokio::spawn(async move { client.connect(to, SESSION_ALPN).await.ok() });
        let incoming = tokio::time::timeout(WAIT, host.accept())
            .await
            .unwrap()
            .unwrap();
        (incoming, dialing)
    }

    fn admitted(entries: &[(EndpointId, PeerRef)]) -> Arc<AdmittedSet> {
        Arc::new(entries.iter().copied().collect())
    }

    /// Layer 1: the handshake hook refuses a key outside the admitted set
    /// before iroh hands the connection out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn si_18_handshake_hook_rejects_an_unadmitted_key() {
        let shared = Arc::new(Shared::default());
        let hook = AdmissionHook {
            shared: Arc::clone(&shared),
            role: Role::Host,
        };
        let host = endpoint(true, Some(hook)).await;
        let stranger = endpoint(false, None).await;
        let (incoming, _dialing) = dial(&host, &stranger).await;
        let handshake = tokio::time::timeout(WAIT, incoming.accept().unwrap())
            .await
            .unwrap();
        assert!(
            handshake.is_err(),
            "an unadmitted key got through the handshake hook"
        );
        assert!(shared.live().is_empty());
    }

    /// Layer 2: the key the hook admitted is looked up again once the
    /// connection is accepted. Here the owner removed it in between.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn si_18_admission_is_rechecked_after_the_handshake() {
        let shared = Arc::new(Shared::default());
        let host = endpoint(true, None).await;
        let guest = endpoint(false, None).await;
        // What the hook recorded when it admitted the key.
        let (first, _dialing) = dial(&host, &guest).await;
        let recorded = first.accept().unwrap().await.unwrap();
        shared.live().insert(
            guest.id(),
            Live {
                peer: peer(1),
                conn: recorded.weak_handle(),
            },
        );
        // The owner has since published a set without it.
        let (incoming, _dialing) = dial(&host, &guest).await;
        let established = tokio::time::timeout(WAIT, establish(incoming, shared)).await;
        assert!(
            matches!(established, Ok(Err(NetError::Closed))),
            "a key removed after the handshake was not refused"
        );
    }

    /// Layer 3: a link is handed out only if its generation is still current
    /// when the guest's control stream arrives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn si_18_link_refused_when_its_generation_moved_before_the_stream() {
        let shared = Arc::new(Shared::default());
        let host = endpoint(true, None).await;
        let guest = endpoint(false, None).await;
        let read_as = peer(1);
        let now = PeerRef {
            generation: Generation::new(2),
            ..read_as
        };
        shared.admitted.store(admitted(&[(guest.id(), now)]));
        let (incoming, dialing) = dial(&host, &guest).await;
        let conn = incoming.accept().unwrap().await.unwrap();
        let client = dialing.await.unwrap().unwrap();
        let (mut send, _recv) = client.open_bi().await.unwrap();
        send.write_all(&[0]).await.unwrap();
        let link = tokio::time::timeout(
            WAIT,
            Link::accept(conn, guest.id(), read_as, Arc::clone(&shared)),
        )
        .await
        .unwrap();
        assert!(
            link.is_err(),
            "a link was handed out under a generation that is no longer current"
        );
    }

    /// Layer 4: every datagram re-checks the generation, so a stale link
    /// whose connection is somehow still open delivers nothing. The set is
    /// swapped here without `set_admitted`, which would also close it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn si_18_each_datagram_rechecks_the_generation() {
        let host = session(&RelayMap::empty(), IfaceAddr::loopback(), Role::Host)
            .await
            .unwrap();
        let guest = session(&RelayMap::empty(), IfaceAddr::loopback(), Role::Guest)
            .await
            .unwrap();
        let p = peer(1);
        host.set_admitted([(guest.id(), p)].into_iter().collect());
        let pass = AdmitPass {
            slot: p.slot,
            generation: p.generation,
        };
        let (guest_link, mut ctl) = guest.dial(host.addr(), pass).await.unwrap();
        ctl.send(&GuestMsg::Hello {
            generation: p.generation,
        })
        .await
        .unwrap();
        let (host_link, _host_ctl) = tokio::time::timeout(WAIT, host.accept())
            .await
            .unwrap()
            .unwrap();

        let bumped = PeerRef {
            generation: Generation::new(2),
            ..p
        };
        host.shared
            .admitted
            .store(admitted(&[(guest.id(), bumped)]));
        guest_link.send_lan(&LanDatagram {
            peer: PeerSlot::HOST,
            bcast: false,
            src_port: 7777,
            dst_port: 7777,
            payload: bytes::Bytes::from_static(b"stale"),
        });
        let got = tokio::time::timeout(WAIT, host_link.recv_lan())
            .await
            .unwrap();
        assert_eq!(got.err(), Some(NetError::Closed), "a stale link delivered");
    }
}

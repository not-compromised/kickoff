//! In-process nodes: relay-only doors on a local HTTPS relay with a generated
//! trusted CA, Direct or RelayOnly session endpoints, and `vlan::Mem` games.
//! Each test plays the game through raw Ethernet frames and drives hostile
//! guests through `kickoff-net`. Every transport stays on this host.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use iroh::{EndpointId, RelayMap, SecretKey};
use kickoff_net::{CtlStream, Door, IfaceAddr, Link, NetError, Role, SessionNet};
use kickoff_secret::Secret;
use kickoff_session::{
    Approval, Clock, HostOpts, InviteKind, JoinOpts, KICKOFF_VERSION, Session, SessionError,
    SessionEvent,
};
use kickoff_vlan::{MemGame, mem_tap};
use kickoff_wire::{
    Admitted, Cap, GuestMsg, HostMsg, JoinRequest, Name, PeerSlot, Platform, Ticket,
};
use tokio::sync::broadcast;

pub const WAIT: Duration = Duration::from_secs(10);
pub const QUIET: Duration = Duration::from_millis(500);
pub const GAME_PORT: u16 = 7777;
pub const BEACON_PORT: u16 = 14001;

pub fn name(text: &str) -> Name {
    Name::new(text).unwrap()
}

pub async fn session_net(role: Role) -> SessionNet {
    kickoff_net::session(&test_relays(), IfaceAddr::loopback(), role)
        .await
        .unwrap()
}

fn test_relays() -> kickoff_net::Relays {
    static RELAYS: std::sync::OnceLock<kickoff_net::Relays> = std::sync::OnceLock::new();
    RELAYS
        .get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let (certs, server_config) =
                        iroh_relay::server::testing::self_signed_tls_certs_and_config();
                    let mut relay =
                        iroh_relay::server::RelayConfig::new((std::net::Ipv4Addr::LOCALHOST, 0));
                    relay.tls = Some(iroh_relay::server::TlsConfig::new(
                        (std::net::Ipv4Addr::LOCALHOST, 0),
                        iroh_relay::server::CertConfig::Manual { server_config },
                    ));
                    let mut config = iroh_relay::server::ServerConfig::default();
                    config.relay = Some(relay);
                    let server = iroh_relay::server::Server::spawn(config).await.unwrap();
                    let url: iroh::RelayUrl = format!("https://{}", server.https_addr().unwrap())
                        .parse()
                        .unwrap();
                    tx.send(kickoff_net::Relays::with_ca(
                        RelayMap::from(url),
                        iroh::tls::CaTlsConfig::custom_roots(certs),
                    ))
                    .unwrap();
                    std::future::pending::<()>().await;
                    drop(server);
                });
            });
            rx.recv().unwrap()
        })
        .clone()
}

pub async fn relay_session_net(role: Role) -> SessionNet {
    let net = kickoff_net::session(&test_relays(), kickoff_net::SessionBind::RelayOnly, role)
        .await
        .unwrap();
    tokio::time::timeout(WAIT, async {
        while net.addr().relay_urls().next().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    net
}

pub async fn bearer_host() -> HostNode {
    bearer_host_with(|_| {}).await
}

pub async fn bearer_host_with(configure: impl FnOnce(&mut HostOpts)) -> HostNode {
    let identity = Identity::new().await;
    let mut opts = HostOpts::new(name("host"));
    configure(&mut opts);
    let (adapter, game) = mem_tap();
    let session = kickoff_session::host(
        Arc::clone(&identity.door),
        &identity.key,
        relay_session_net(Role::Host).await,
        adapter,
        opts,
    )
    .await
    .unwrap();
    let events = session.events();
    HostNode {
        identity,
        session,
        game,
        events,
    }
}

/// A persistent identity: its key and its relay-only door.
pub struct Identity {
    pub key: Secret<SecretKey>,
    pub door: Arc<Door>,
}

impl Identity {
    pub async fn new() -> Identity {
        let key = Secret::new(SecretKey::generate());
        let door = Arc::new(kickoff_net::door(&key, &test_relays()).await.unwrap());
        tokio::time::timeout(WAIT, async {
            while door.addr().relay_urls().next().is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        Identity { key, door }
    }

    pub fn id(&self) -> EndpointId {
        self.door.id()
    }
}

pub struct HostNode {
    pub identity: Identity,
    pub session: Session,
    pub game: MemGame,
    pub events: broadcast::Receiver<SessionEvent>,
}

impl HostNode {
    pub fn bound(&self, invitee: EndpointId) -> Secret<Ticket> {
        self.session.invite(InviteKind::Bound(invitee)).unwrap()
    }

    pub fn bearer(&self) -> Secret<Ticket> {
        self.session.invite(InviteKind::Bearer).unwrap()
    }
}

pub async fn host() -> HostNode {
    host_with(|_| {}).await
}

pub async fn host_with(configure: impl FnOnce(&mut HostOpts)) -> HostNode {
    host_as(Identity::new().await, configure).await
}

pub async fn host_as(identity: Identity, configure: impl FnOnce(&mut HostOpts)) -> HostNode {
    let mut opts = HostOpts::new(name("host"));
    opts.clock = Clock::system();
    configure(&mut opts);
    let (adapter, game) = mem_tap();
    let session = kickoff_session::host(
        Arc::clone(&identity.door),
        &identity.key,
        session_net(Role::Host).await,
        adapter,
        opts,
    )
    .await
    .unwrap();
    let events = session.events();
    HostNode {
        identity,
        session,
        game,
        events,
    }
}

pub struct GuestNode {
    pub identity: Identity,
    pub session: Session,
    pub game: MemGame,
    pub events: broadcast::Receiver<SessionEvent>,
}

impl GuestNode {
    pub fn slot(&self) -> u8 {
        self.session.slot().get()
    }
}

pub fn join_opts(label: &str) -> JoinOpts {
    JoinOpts {
        name: name(label),
        platform: Platform::Linux,
        game_build: kickoff_wire::BuildId::new("test-build").unwrap(),
        clock: Clock::system(),
    }
}

pub async fn join(identity: Identity, ticket: Secret<Ticket>) -> Result<GuestNode, SessionError> {
    join_with(identity, ticket, join_opts("guest")).await
}

pub async fn join_with(
    identity: Identity,
    ticket: Secret<Ticket>,
    opts: JoinOpts,
) -> Result<GuestNode, SessionError> {
    let (adapter, game) = mem_tap();
    let net = if ticket.expose(|ticket| ticket.cap.invitee.is_none()) {
        relay_session_net(Role::Guest).await
    } else {
        session_net(Role::Guest).await
    };
    let session = kickoff_session::join(&identity.door, net, adapter, ticket, opts).await?;
    let events = session.events();
    Ok(GuestNode {
        identity,
        session,
        game,
        events,
    })
}

/// A guest whose every step is the test's: join request, dial, `Hello`.
pub struct RawGuest {
    pub identity: Identity,
    pub net: SessionNet,
    pub admitted: Admitted,
}

pub fn copy_cap(ticket: &Secret<Ticket>) -> Cap {
    ticket.expose(|t| Cap {
        session_id: t.cap.session_id,
        invitee: t.cap.invitee,
        nonce: t.cap.nonce,
        sig: t.cap.sig,
    })
}

/// The same ticket a second time, as a leaked or replayed link would carry
/// it. The copy is made field by field so no secret gains `Clone`.
pub fn duplicate(ticket: &Secret<Ticket>) -> Secret<Ticket> {
    let door = ticket.expose(|t| t.door.clone());
    Secret::new(Ticket {
        door,
        cap: copy_cap(ticket),
    })
}

pub async fn request_join(
    identity: &Identity,
    net: &SessionNet,
    ticket: &Secret<Ticket>,
) -> Result<Admitted, NetError> {
    let request = JoinRequest {
        cap: copy_cap(ticket),
        session_key: net.id(),
        name: name("raw"),
        platform: Platform::Linux,
        game_build: kickoff_wire::BuildId::new("test-build").unwrap(),
        kickoff_version: KICKOFF_VERSION,
    };
    identity.door.request_join(ticket, request).await
}

impl RawGuest {
    pub async fn join(identity: Identity, ticket: &Secret<Ticket>) -> Result<RawGuest, NetError> {
        let net = if ticket.expose(|ticket| ticket.cap.invitee.is_none()) {
            relay_session_net(Role::Guest).await
        } else {
            session_net(Role::Guest).await
        };
        let admitted = request_join(&identity, &net, ticket).await?;
        Ok(RawGuest {
            identity,
            net,
            admitted,
        })
    }

    pub fn slot(&self) -> PeerSlot {
        self.admitted.pass.slot
    }

    /// Dials and says `Hello`; `Ok` once the host's roster arrives.
    pub async fn connect(&self) -> Result<(Link, CtlStream), NetError> {
        let (link, mut ctl) = self
            .net
            .dial(self.admitted.session_addr.clone(), self.admitted.pass)
            .await?;
        ctl.send(&GuestMsg::Hello {
            generation: self.admitted.pass.generation,
        })
        .await?;
        match tokio::time::timeout(Duration::from_secs(2), ctl.recv::<HostMsg>()).await {
            Ok(Ok(HostMsg::Roster { .. })) => Ok((link, ctl)),
            _ => Err(NetError::Closed),
        }
    }
}

/// Waits for the host's next approval request.
pub async fn approval(host: &mut HostNode) -> Approval {
    event(&mut host.events, |e| match e {
        SessionEvent::ApprovalRequested(a) => Some(a.clone()),
        _ => None,
    })
    .await
}

/// Waits for the first event `pick` accepts.
pub async fn event<T>(
    events: &mut broadcast::Receiver<SessionEvent>,
    mut pick: impl FnMut(&SessionEvent) -> Option<T>,
) -> T {
    tokio::time::timeout(WAIT, async {
        loop {
            match events.recv().await {
                Ok(e) => {
                    if let Some(t) = pick(&e) {
                        return t;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("event stream ended: {e}"),
            }
        }
    })
    .await
    .expect("event did not arrive")
}

/// Waits until the host's roster lists exactly `slots`.
pub async fn roster_slots(host: &HostNode, slots: &[u8]) {
    tokio::time::timeout(WAIT, async {
        loop {
            let have: Vec<u8> = host
                .session
                .members()
                .iter()
                .map(|m| m.slot.get())
                .collect();
            if have == slots {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        let have: Vec<u8> = host
            .session
            .members()
            .iter()
            .map(|m| m.slot.get())
            .collect();
        panic!("roster {have:?}, wanted {slots:?}")
    });
}

/// Runs the host's clock past the reconnect window until the roster is
/// back to `slots`. Advancing again each round covers a host that noticed
/// the drop only after an earlier advance.
pub async fn outlast_window(clock: &Clock, host: &HostNode, slots: &[u8]) {
    tokio::time::timeout(WAIT, async {
        loop {
            clock.advance(Duration::from_secs(31));
            tokio::time::sleep(Duration::from_millis(300)).await;
            let have: Vec<u8> = host
                .session
                .members()
                .iter()
                .map(|m| m.slot.get())
                .collect();
            if have == slots {
                return;
            }
        }
    })
    .await
    .expect("the window never closed");
}

// --- Playing the game: raw Ethernet frames on the in-memory tap. ---

fn mac(slot: u8) -> [u8; 6] {
    [0x02, 0x4b, 0x4f, 0x00, 0x00, slot]
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A UDP frame the game at `from` sends: unicast to slot `to`, or a
/// broadcast when `to` is `None`.
pub fn udp(from: u8, to: Option<u8>, src_port: u16, dst_port: u16, payload: &[u8]) -> Bytes {
    let (dst_mac, dst_ip) = match to {
        Some(slot) => (mac(slot), [10, 75, 0, slot]),
        None => ([0xff; 6], [255; 4]),
    };
    let udp_len = (8 + payload.len()) as u16;
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(20 + udp_len).to_be_bytes());
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&[10, 75, 0, from]);
    ip[16..20].copy_from_slice(&dst_ip);
    let sum = checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    let mut f = Vec::with_capacity(42 + payload.len());
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&mac(from));
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(&ip);
    f.extend_from_slice(&src_port.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&udp_len.to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    f.into()
}

/// What a game saw in one frame Kickoff handed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// The slot in the source address: who Kickoff says sent it.
    pub from: u8,
    pub bcast: bool,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

pub fn seen(frame: &[u8]) -> Option<Seen> {
    if frame.len() < 42 || frame[12..14] != [0x08, 0x00] {
        return None;
    }
    let ip = &frame[14..34];
    let udp = &frame[34..42];
    let len = u16::from_be_bytes([udp[4], udp[5]]) as usize - 8;
    Some(Seen {
        from: ip[15],
        bcast: ip[16..20] == [255; 4],
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: frame[42..42 + len].to_vec(),
    })
}

/// The next UDP frame the game receives within `within`.
pub async fn next_udp(game: &MemGame, within: Duration) -> Option<Seen> {
    tokio::time::timeout(within, async {
        loop {
            let frame = game.recv_frame().await.ok()?;
            if let Some(s) = seen(&frame) {
                return Some(s);
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Every UDP frame the game receives until it has been quiet for `quiet`.
pub async fn drain_udp(game: &MemGame, quiet: Duration) -> Vec<Seen> {
    let mut all = Vec::new();
    while let Some(s) = next_udp(game, quiet).await {
        all.push(s);
    }
    all
}

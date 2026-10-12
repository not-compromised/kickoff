//! Two-node fixtures over loopback with relays disabled: the in-process
//! adapter design §2.3 names as the test seam. Nothing here leaves the host.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::time::Duration;

use bytes::Bytes;
use iroh::endpoint::{Connection, presets};
use iroh::{Endpoint, EndpointAddr, RelayMap, RelayMode, SecretKey};
use kickoff_net::{AdmittedSet, CtlStream, IfaceAddr, Link, Role, SessionNet, session};
use kickoff_wire::{AdmitPass, Generation, GuestMsg, LanDatagram, PeerRef, PeerSlot};

pub const WAIT: Duration = Duration::from_secs(5);

/// A link and its control stream, kept together for tests that drive both
/// from one task.
pub struct Linked {
    link: Link,
    ctl: CtlStream,
}

impl Linked {
    pub fn ctl(&mut self) -> &mut CtlStream {
        &mut self.ctl
    }
}

impl From<(Link, CtlStream)> for Linked {
    fn from((link, ctl): (Link, CtlStream)) -> Linked {
        Linked { link, ctl }
    }
}

impl std::ops::Deref for Linked {
    type Target = Link;
    fn deref(&self) -> &Link {
        &self.link
    }
}

pub async fn node(role: Role) -> SessionNet {
    session(&RelayMap::empty(), IfaceAddr::loopback(), role)
        .await
        .expect("loopback session endpoint")
}

pub fn peer(slot: u8, generation: u64) -> PeerRef {
    PeerRef {
        id: SecretKey::generate().public(),
        slot: PeerSlot::new(slot).unwrap(),
        generation: Generation::new(generation),
    }
}

pub fn pass(peer: PeerRef) -> AdmitPass {
    AdmitPass {
        slot: peer.slot,
        generation: peer.generation,
    }
}

/// Dials `host` from `guest` as `peer` and sends the guest's first control
/// message, which is what makes the control stream visible to the host.
pub async fn dial(
    host: &SessionNet,
    guest: &SessionNet,
    peer: PeerRef,
) -> Result<Linked, kickoff_net::NetError> {
    let mut link = Linked::from(guest.dial(host.addr(), pass(peer)).await?);
    link.ctl()
        .send(&GuestMsg::Hello {
            generation: peer.generation,
        })
        .await?;
    Ok(link)
}

/// An admitted host/guest pair: (host's link to the guest, guest's link to the host).
pub async fn pair(host: &SessionNet, guest: &SessionNet, peer: PeerRef) -> (Linked, Linked) {
    host.set_admitted([(guest.id(), peer)].into_iter().collect::<AdmittedSet>());
    let (accepted, dialed) = tokio::join!(
        tokio::time::timeout(WAIT, host.accept()),
        tokio::time::timeout(WAIT, dial(host, guest, peer)),
    );
    (accepted.unwrap().unwrap().into(), dialed.unwrap().unwrap())
}

/// A bare iroh endpoint with no Kickoff policy at all: the attacker's tool.
pub async fn raw_endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap()
}

/// Dials with a raw endpoint; `Ok` only if the connection survives the
/// server's post-handshake hook long enough to open and use a stream.
pub async fn raw_dial(ep: &Endpoint, to: EndpointAddr, alpn: &[u8]) -> Result<Connection, String> {
    let conn = tokio::time::timeout(WAIT, ep.connect(to, alpn))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("connect: {e}"))?;
    let (mut send, _recv) = conn.open_bi().await.map_err(|e| format!("open: {e}"))?;
    send.write_all(&[0, 0, 0, 1, 0])
        .await
        .map_err(|e| format!("write: {e}"))?;
    match tokio::time::timeout(Duration::from_millis(500), conn.closed()).await {
        Ok(reason) => Err(format!("closed: {reason}")),
        Err(_) => Ok(conn),
    }
}

pub fn lan(len: usize, seed: u8) -> LanDatagram {
    LanDatagram {
        peer: PeerSlot::HOST,
        bcast: seed.is_multiple_of(2),
        src_port: 7777,
        dst_port: 14001,
        payload: (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect::<Vec<u8>>()
            .into(),
    }
}

/// Waits until the path MTU stops moving, so a size boundary measured now
/// still holds when the datagram is sent.
pub async fn settled_max(link: &Link) -> usize {
    let mut last = 0;
    let mut stable = 0;
    while stable < 5 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = link.max_datagram_size().unwrap();
        stable = if now == last { stable + 1 } else { 0 };
        last = now;
    }
    last
}

pub fn raw_bytes(parts: &[&[u8]]) -> Bytes {
    parts.concat().into()
}

//! Peer transport over iroh (design §2.3, §3.4). Hides iroh, the relay map,
//! fragmentation, path status, candidate scoping and the egress policy.
//!
//! Two endpoints per node. The **door** carries the persistent identity, is
//! relay-only and speaks only `kickoff/join/1`. The **session** endpoint has a
//! fresh key per session, binds one interface address or is relay-only, and on
//! the host accepts `kickoff/session/1` only from session keys in the admitted
//! set the admission owner last published. Guests' session endpoints accept
//! nothing (SI-21). Only admitted peers learn a session endpoint's address
//! (SI-31). `egress` is the one place data becomes a destination, and its send
//! guard sees every IP packet, including those iroh addresses itself (SI-29).

mod budget;
mod door;
mod egress;
mod guarded;
mod incoming;
mod link;
mod reassembly;
mod session;
mod stream;

use std::time::Duration;

use iroh::endpoint::{QuicTransportConfig, VarInt};

pub use door::{Door, JoinAttempt, door, door_loopback};
pub use egress::IfaceAddr;
pub use link::{CtlStream, Link, LinkHealth, PathStatus};
pub use session::{AdmittedSet, Role, SessionBind, SessionNet, session};

use kickoff_wire::JoinRefused;

pub const JOIN_ALPN: &[u8] = b"kickoff/join/1";
pub const SESSION_ALPN: &[u8] = b"kickoff/session/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    #[error("not implemented yet")]
    NotImplemented,
    #[error("refused by the host: {0:?}")]
    Refused(JoinRefused),
    #[error("destination not allowed by the egress policy")]
    Egress,
    #[error("connection closed")]
    Closed,
    #[error("over budget")]
    OverBudget,
    #[error("peer sent malformed or oversized data")]
    Protocol,
    #[error("no usable default-route IPv4 address")]
    NoRoute,
    #[error("operation not available in this role")]
    WrongRole,
    #[error("endpoint could not bind")]
    Bind,
    #[error("peer speaks a newer protocol")]
    Version,
}

/// QUIC application close codes. Peers learn only the code, never a reason.
mod close {
    use iroh::endpoint::VarInt;

    pub(crate) const DONE: VarInt = VarInt::from_u32(0);
    pub(crate) const NOT_ADMITTED: VarInt = VarInt::from_u32(1);
    pub(crate) const DUPLICATE: VarInt = VarInt::from_u32(2);
    pub(crate) const STALE: VarInt = VarInt::from_u32(3);
    pub(crate) const REVOKED: VarInt = VarInt::from_u32(4);
    pub(crate) const OVER_BUDGET: VarInt = VarInt::from_u32(5);
    pub(crate) const PROTOCOL: VarInt = VarInt::from_u32(6);
    pub(crate) const BUSY: VarInt = VarInt::from_u32(7);
    pub(crate) const VERSION: VarInt = VarInt::from_u32(8);
}

/// Pre-handshake cap on each endpoint (§6.3): `Incoming`s beyond it are refused.
const PENDING_INCOMING: usize = 16;
/// From `Incoming` to a usable join request or session link (§4.3).
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
/// Outgoing dial, door or session.
const CONNECT_DEADLINE: Duration = Duration::from_secs(15);

/// Unread stream bytes a peer can make us buffer: per stream (above the 64 KiB
/// control maximum) and per connection.
const STREAM_WINDOW: u32 = 512 * 1024;
const CONNECTION_WINDOW: u32 = 2 * 1024 * 1024;

/// `bidi` is how many streams the remote may open towards us at once; nobody
/// opens unidirectional streams, and the door carries no datagrams.
fn transport(bidi: u32, datagrams: bool) -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(bidi))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(STREAM_WINDOW))
        .receive_window(VarInt::from_u32(CONNECTION_WINDOW))
        .datagram_receive_buffer_size(datagrams.then_some(link::DATAGRAM_RECEIVE_BUFFER))
        .build()
}

/// Aborts its task when the owning endpoint wrapper goes away.
#[derive(Debug)]
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

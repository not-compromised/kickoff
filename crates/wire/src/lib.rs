//! Kickoff's peer-facing formats: the LAN datagram header and fragments, join
//! and control messages, and tickets (design §4.2, §4.5).
//!
//! Every decoder here reads hostile bytes. Sizes are bounded by type, and each
//! decoder rejects an over-long input before it allocates. Decoding is strict:
//! unknown variants, trailing bytes and any encoding other than the one
//! `encode` would produce are refused, so a decoded value re-encodes to exactly
//! the bytes it came from.

mod addr;
mod bounded;
mod invite;
mod lan;
mod msg;
mod ticket;

#[cfg(test)]
mod schema_tests;

pub use bounded::{BoundedStr, BoundedVec};
pub use invite::{BEARER_TTL, InviteError, Invites, MAX_OUTSTANDING, Redeemed};
pub use lan::{
    DatagramKind, FRAGMENT_HEADER_LEN, FragmentHeader, Inbound, LAN_HEADER_LEN, LanDatagram,
    LanHeader, MAX_FRAGMENTS, decode_datagram, encode_datagram,
};
pub use msg::{
    AdmitPass, Admitted, BuildId, BundleBlob, GameState, GuestMsg, HostMsg, JoinRefused, JoinReply,
    JoinRequest, KickReason, KickoffVersion, LEN_PREFIX_LEN, MAX_CONTROL_LEN, MAX_HAVE,
    MAX_JOIN_LEN, MAX_NAME_LEN, Member, Name, Platform, WireMessage, decode, encode, encode_framed,
    frame_len,
};
pub use ticket::{Cap, MAX_TICKET_LEN, Nonce, SessionId, Ticket, encode_ticket, parse_ticket};

use iroh_base::EndpointId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Errors carry no input bytes, so a ticket or key can never reach a log line
/// through one (SI-30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WireError {
    #[error("not implemented yet")]
    NotImplemented,
    #[error("input exceeds {max} bytes or items")]
    TooLong { max: usize },
    #[error("malformed input")]
    Malformed,
    /// From a newer protocol: an unknown top-level message variant or ticket
    /// version. A control or join stream closes with `VERSION` (§4.5).
    #[error("unknown protocol version")]
    Version,
}

/// The LAN maximum (§4.1): the host plus seven guests.
pub const MAX_ROSTER: u8 = 8;

/// A roster position: 1 is the host, 2..=8 are guests in join order. It comes
/// from the authenticated link and is never read from a LAN datagram (§4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerSlot(u8);

impl PeerSlot {
    pub const HOST: PeerSlot = PeerSlot(1);

    pub fn new(slot: u8) -> Option<PeerSlot> {
        (1..=MAX_ROSTER).contains(&slot).then_some(PeerSlot(slot))
    }

    pub fn get(self) -> u8 {
        self.0
    }
}

impl Serialize for PeerSlot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_newtype_struct("PeerSlot", &self.0)
    }
}

impl<'de> Deserialize<'de> for PeerSlot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename = "PeerSlot")]
        struct Raw(u8);
        let Raw(slot) = Raw::deserialize(deserializer)?;
        PeerSlot::new(slot).ok_or_else(|| serde::de::Error::custom("slot out of range"))
    }
}

/// Bumped by the admission owner on every reconnect, kick and eviction. A
/// resource tagged with a generation that is no longer current is dropped at
/// its next touch (§4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Generation(u64);

impl Generation {
    pub fn new(value: u64) -> Generation {
        Generation(value)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

/// What a link, datagram, stream, flow or reassembly was admitted under (SI-18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerRef {
    pub id: EndpointId,
    pub slot: PeerSlot,
    pub generation: Generation,
}

/// BLAKE3 of a map package's exact bytes (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MapId(pub [u8; 32]);

//! The one owner of the virtual LAN's addressing: every MAC and IPv4 address
//! Kickoff synthesizes or checks is built here from a slot (§3.2).

use kickoff_wire::PeerSlot;

use crate::verdict::Reject;

pub(crate) type Mac = [u8; 6];
pub(crate) type Ipv4 = [u8; 4];

pub(crate) const BROADCAST_MAC: Mac = [0xff; 6];
pub(crate) const LIMITED_BROADCAST: Ipv4 = [255; 4];
pub(crate) const SUBNET_BROADCAST: Ipv4 = [10, 75, 0, 255];

pub(crate) fn mac(slot: PeerSlot) -> Mac {
    [0x02, 0x4b, 0x4f, 0x00, 0x00, slot.get()]
}

pub(crate) fn ip(slot: PeerSlot) -> Ipv4 {
    [10, 75, 0, slot.get()]
}

/// The slot an address in `10.75.0.0/24` names, if it names one.
pub(crate) fn slot_of(ip: Ipv4) -> Option<PeerSlot> {
    match ip {
        [10, 75, 0, host] => PeerSlot::new(host),
        _ => None,
    }
}

/// This node's place in the star: the host talks to every guest, a guest only
/// to the host (§2.4, SI-21).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Node {
    pub own: PeerSlot,
}

impl Node {
    pub fn is_host(self) -> bool {
        self.own == PeerSlot::HOST
    }

    /// Whether `peer` is a slot this node exchanges LAN traffic with. Checked
    /// on both paths, so neither a frame nor a misrouted datagram can make a
    /// guest's LAN reach another guest or wear this node's own address.
    pub fn check_peer(self, peer: PeerSlot) -> Result<(), Reject> {
        if peer == self.own {
            Err(Reject::OwnSlot)
        } else if self.is_host()
            || peer == PeerSlot::HOST
            || cfg!(feature = "mutant-si21-star-open")
        {
            Ok(())
        } else {
            Err(Reject::NotInStar)
        }
    }
}

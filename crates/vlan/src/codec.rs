//! The L2 frame codec between the game's tap and `LanDatagram` (§3.1 rule 1).
//! Only UDP over option-less, unfragmented IPv4 becomes a datagram; ARP
//! requests for a peer are answered locally and never leave this node.

use bytes::{BufMut, Bytes, BytesMut};
use kickoff_wire::{LanDatagram, PeerSlot};

use crate::addr::{self, Ipv4, Mac, Node};
use crate::verdict::Reject;

const ETH_LEN: usize = 14;
const IPV4_LEN: usize = 20;
const UDP_LEN: usize = 8;
const HEADERS: usize = ETH_LEN + IPV4_LEN + UDP_LEN;
/// Ethernet MTU 1500 plus its header; the tap carries no FCS.
pub(crate) const MAX_FRAME: usize = ETH_LEN + 1500;
pub(crate) const MAX_PAYLOAD: usize = MAX_FRAME - HEADERS;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: [u16; 3] = [0x8100, 0x88a8, 0x9100];
const PROTO_UDP: u8 = 17;
const ARP_LEN: usize = 28;
/// Hardware Ethernet, protocol IPv4, address lengths 6 and 4.
const ARP_ETHERNET_IPV4: [u8; 6] = [0, 1, 0x08, 0x00, 6, 4];
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;
const IP_FLAG_RESERVED: u16 = 0x8000;
const IP_FLAG_DF: u16 = 0x4000;
const IP_FLAG_MF: u16 = 0x2000;
const IP_FRAG_OFFSET: u16 = 0x1fff;
const TTL: u8 = 64;

pub(crate) enum FromGame {
    Udp(LanDatagram),
    /// An ARP request for this peer's address, to answer locally.
    ArpFor(PeerSlot),
}

/// Decodes one frame the local game sent. For a broadcast, `peer` is the host:
/// a guest's broadcast goes only to the host, and the host's fans out.
pub(crate) fn decode(frame: &Bytes, node: Node) -> Result<FromGame, Reject> {
    if frame.len() > MAX_FRAME {
        return Err(Reject::Oversize);
    }
    let mut c = Cursor(frame);
    let dst_mac: Mac = *c.take()?;
    let src_mac: Mac = *c.take()?;
    let ethertype = u16::from_be_bytes(*c.take()?);
    if src_mac != addr::mac(node.own) {
        return Err(Reject::ForeignSource);
    }
    match ethertype {
        ETHERTYPE_IPV4 => {}
        ETHERTYPE_ARP => return arp_request(c, dst_mac, node).map(FromGame::ArpFor),
        ETHERTYPE_IPV6 => return Err(Reject::Ipv6),
        t if ETHERTYPE_VLAN.contains(&t) => return Err(Reject::VlanTag),
        _ => return Err(Reject::NotIpv4),
    }

    let ip: &[u8; IPV4_LEN] = c.take()?;
    match (ip[0] >> 4, ip[0] & 0x0f) {
        (4, 5) => {}
        (4, 6..=15) => return Err(Reject::IpOptions),
        _ => return Err(Reject::BadIpHeader),
    }
    let flags = be16(ip[6], ip[7]);
    if flags & IP_FLAG_RESERVED != 0 {
        return Err(Reject::BadIpHeader);
    }
    if flags & (IP_FLAG_MF | IP_FRAG_OFFSET) != 0 {
        return Err(Reject::IpFragment);
    }
    if checksum(0, ip) != 0 {
        return Err(Reject::BadChecksum);
    }
    if ip[9] != PROTO_UDP {
        return Err(Reject::NotUdp);
    }
    let src_ip: Ipv4 = [ip[12], ip[13], ip[14], ip[15]];
    let dst_ip: Ipv4 = [ip[16], ip[17], ip[18], ip[19]];
    if src_ip != addr::ip(node.own) {
        return Err(Reject::ForeignSource);
    }
    let (peer, bcast) = destination(node, dst_mac, dst_ip)?;

    let ip_payload_len = usize::from(be16(ip[2], ip[3]))
        .checked_sub(IPV4_LEN)
        .ok_or(Reject::BadLength)?;
    let udp: &[u8; UDP_LEN] = c.take()?;
    let udp_len = be16(udp[4], udp[5]);
    // Bytes past the IP length are Ethernet padding and are ignored.
    if usize::from(udp_len) != ip_payload_len {
        return Err(Reject::BadLength);
    }
    let payload_len = ip_payload_len
        .checked_sub(UDP_LEN)
        .ok_or(Reject::BadLength)?;
    let payload = c.0.get(..payload_len).ok_or(Reject::BadLength)?;
    if [udp[6], udp[7]] != [0, 0]
        && checksum(
            checksum_add(pseudo_header(src_ip, dst_ip, udp_len), udp),
            payload,
        ) != 0
    {
        return Err(Reject::BadChecksum);
    }
    // `payload` borrows from `frame`, the precondition of `slice_ref`.
    let payload = frame.slice_ref(payload);
    Ok(FromGame::Udp(LanDatagram {
        peer,
        bcast,
        src_port: be16(udp[0], udp[1]),
        dst_port: be16(udp[2], udp[3]),
        payload,
    }))
}

fn destination(node: Node, dst_mac: Mac, dst_ip: Ipv4) -> Result<(PeerSlot, bool), Reject> {
    if dst_ip == addr::LIMITED_BROADCAST || dst_ip == addr::SUBNET_BROADCAST {
        if dst_mac != addr::BROADCAST_MAC {
            return Err(Reject::MacMismatch);
        }
        return Ok((PeerSlot::HOST, true));
    }
    let peer = addr::slot_of(dst_ip).ok_or(Reject::UnknownDestination)?;
    node.check_peer(peer)?;
    if dst_mac != addr::mac(peer) {
        return Err(Reject::MacMismatch);
    }
    Ok((peer, false))
}

fn arp_request(mut c: Cursor<'_>, dst_mac: Mac, node: Node) -> Result<PeerSlot, Reject> {
    let arp: &[u8; ARP_LEN] = c.take()?;
    if arp[..6] != ARP_ETHERNET_IPV4 || be16(arp[6], arp[7]) != ARP_REQUEST {
        return Err(Reject::ArpNotAnswered);
    }
    if arp[8..14] != addr::mac(node.own) {
        return Err(Reject::ForeignSource);
    }
    // A probe (sender 0.0.0.0) or a request for our own address must stay
    // unanswered, or the game would see an address conflict.
    if arp[14..18] != addr::ip(node.own) {
        return Err(Reject::ArpNotAnswered);
    }
    let peer = addr::slot_of([arp[24], arp[25], arp[26], arp[27]]).ok_or(Reject::ArpNotAnswered)?;
    node.check_peer(peer)?;
    if dst_mac != addr::BROADCAST_MAC && dst_mac != addr::mac(peer) {
        return Err(Reject::MacMismatch);
    }
    Ok(peer)
}

pub(crate) fn arp_reply(node: Node, peer: PeerSlot) -> Bytes {
    let mut f = BytesMut::with_capacity(ETH_LEN + ARP_LEN);
    f.put_slice(&addr::mac(node.own));
    f.put_slice(&addr::mac(peer));
    f.put_u16(ETHERTYPE_ARP);
    f.put_slice(&ARP_ETHERNET_IPV4);
    f.put_u16(ARP_REPLY);
    f.put_slice(&addr::mac(peer));
    f.put_slice(&addr::ip(peer));
    f.put_slice(&addr::mac(node.own));
    f.put_slice(&addr::ip(node.own));
    f.freeze()
}

/// The frame the local game receives for a datagram from `d.peer`. Source
/// addresses come only from the slot the link authenticated. `None` when the
/// payload cannot fit one frame; the filter has already refused those.
pub(crate) fn udp_frame(node: Node, d: &LanDatagram) -> Option<Bytes> {
    if d.payload.len() > MAX_PAYLOAD {
        return None;
    }
    let udp_len = u16::try_from(d.payload.len().checked_add(UDP_LEN)?).ok()?;
    let total_len = udp_len.checked_add(u16::try_from(IPV4_LEN).ok()?)?;
    let (dst_mac, dst_ip) = if d.bcast {
        (addr::BROADCAST_MAC, addr::LIMITED_BROADCAST)
    } else {
        (addr::mac(node.own), addr::ip(node.own))
    };
    let src_ip = addr::ip(d.peer);

    let ip = ipv4_header(total_len, src_ip, dst_ip);
    let mut udp = [0; UDP_LEN];
    udp[0..2].copy_from_slice(&d.src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&d.dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    let sum = checksum(
        checksum_add(pseudo_header(src_ip, dst_ip, udp_len), &udp),
        &d.payload,
    );
    // 0 means "no checksum" in UDP over IPv4, so a computed 0 is sent as its
    // one's-complement twin.
    let sum = if sum == 0 { 0xffff } else { sum };
    udp[6..8].copy_from_slice(&sum.to_be_bytes());

    let mut f = BytesMut::with_capacity(HEADERS.checked_add(d.payload.len())?);
    f.put_slice(&dst_mac);
    f.put_slice(&addr::mac(d.peer));
    f.put_u16(ETHERTYPE_IPV4);
    f.put_slice(&ip);
    f.put_slice(&udp);
    f.put_slice(&d.payload);
    Some(f.freeze())
}

fn ipv4_header(total_len: u16, src: Ipv4, dst: Ipv4) -> [u8; IPV4_LEN] {
    let mut h = [0; IPV4_LEN];
    h[0] = 0x45;
    h[2..4].copy_from_slice(&total_len.to_be_bytes());
    // Identification stays 0: DF is set, so it is never used (RFC 6864).
    h[6..8].copy_from_slice(&IP_FLAG_DF.to_be_bytes());
    h[8] = TTL;
    h[9] = PROTO_UDP;
    h[12..16].copy_from_slice(&src);
    h[16..20].copy_from_slice(&dst);
    let sum = checksum(0, &h);
    h[10..12].copy_from_slice(&sum.to_be_bytes());
    h
}

fn be16(high: u8, low: u8) -> u16 {
    u16::from_be_bytes([high, low])
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take<const N: usize>(&mut self) -> Result<&'a [u8; N], Reject> {
        let (head, rest) = self.0.split_first_chunk::<N>().ok_or(Reject::Truncated)?;
        self.0 = rest;
        Ok(head)
    }
}

fn pseudo_header(src: Ipv4, dst: Ipv4, udp_len: u16) -> u32 {
    let [l0, l1] = udp_len.to_be_bytes();
    let acc = checksum_add(checksum_add(0, &src), &dst);
    checksum_add(acc, &[0, PROTO_UDP, l0, l1])
}

/// RFC 1071 one's-complement sum, unfolded.
fn checksum_add(acc: u32, bytes: &[u8]) -> u32 {
    let (pairs, rest) = bytes.as_chunks::<2>();
    let acc = pairs.iter().fold(acc, |a, p| {
        a.wrapping_add(u32::from(u16::from_be_bytes(*p)))
    });
    match rest {
        [last] => acc.wrapping_add(u32::from(u16::from_be_bytes([*last, 0]))),
        _ => acc,
    }
}

/// Folded and complemented: 0 over a header that carries a correct checksum.
fn checksum(acc: u32, bytes: &[u8]) -> u16 {
    let mut sum = checksum_add(acc, bytes);
    loop {
        let [a, b, c, d] = sum.to_be_bytes();
        let (high, low) = (u16::from_be_bytes([a, b]), u16::from_be_bytes([c, d]));
        if high == 0 {
            return !low;
        }
        sum = u32::from(high).wrapping_add(u32::from(low));
    }
}

use bytes::{BufMut, Bytes, BytesMut};

use crate::{PeerSlot, WireError};

pub const LAN_HEADER_LEN: usize = 6;
pub const FRAGMENT_HEADER_LEN: usize = 4;
/// A LAN datagram too big for one QUIC datagram splits into at most this many
/// fragments (§3.4).
pub const MAX_FRAGMENTS: u8 = 4;

const KIND_LAN: u8 = 1;
const KIND_FRAGMENT: u8 = 2;
const FLAG_BCAST: u8 = 0b1;

/// One UDP datagram between a game and a peer's game. The wire carries UDP
/// tuples only: no Ethernet, IP, ARP or source address, so none can be
/// spoofed (§2.6). `peer` is the remote slot, taken from the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanDatagram {
    pub peer: PeerSlot,
    pub bcast: bool,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramKind {
    Lan,
    Fragment,
}

/// `kind:u8 | flags:u8 (bit0 broadcast) | src_port:u16 | dst_port:u16` (§4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanHeader {
    pub kind: DatagramKind,
    pub bcast: bool,
    pub src_port: u16,
    pub dst_port: u16,
}

impl LanHeader {
    /// Splits a received datagram into its header and the rest. Unknown kinds
    /// and any set flag bit other than bit 0 are malformed.
    pub fn decode(datagram: &[u8]) -> Result<(LanHeader, &[u8]), WireError> {
        let (&[kind, flags, s0, s1, d0, d1], rest) = datagram
            .split_first_chunk::<LAN_HEADER_LEN>()
            .ok_or(WireError::Malformed)?;
        let kind = match kind {
            KIND_LAN => DatagramKind::Lan,
            KIND_FRAGMENT => DatagramKind::Fragment,
            _ => return Err(WireError::Malformed),
        };
        if flags & !FLAG_BCAST != 0 {
            return Err(WireError::Malformed);
        }
        let header = LanHeader {
            kind,
            bcast: flags & FLAG_BCAST != 0,
            src_port: u16::from_be_bytes([s0, s1]),
            dst_port: u16::from_be_bytes([d0, d1]),
        };
        Ok((header, rest))
    }

    pub fn encode(&self) -> [u8; LAN_HEADER_LEN] {
        let kind = match self.kind {
            DatagramKind::Lan => KIND_LAN,
            DatagramKind::Fragment => KIND_FRAGMENT,
        };
        let [s0, s1] = self.src_port.to_be_bytes();
        let [d0, d1] = self.dst_port.to_be_bytes();
        [kind, u8::from(self.bcast), s0, s1, d0, d1]
    }
}

/// `frag_id:u16 | idx:u4 | count:u4 | reserved:u8` (§3.4), idx in the high
/// nibble. Decoding checks `2 <= count <= MAX_FRAGMENTS`, `idx < count`,
/// `reserved == 0` and a non-empty chunk; the receiver checks agreement with
/// the first fragment before allocating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    pub frag_id: u16,
    pub idx: u8,
    pub count: u8,
}

impl FragmentHeader {
    pub fn decode(bytes: &[u8]) -> Result<(FragmentHeader, &[u8]), WireError> {
        let (&[f0, f1, nibbles, reserved], chunk) = bytes
            .split_first_chunk::<FRAGMENT_HEADER_LEN>()
            .ok_or(WireError::Malformed)?;
        if reserved != 0 || chunk.is_empty() {
            return Err(WireError::Malformed);
        }
        let header = FragmentHeader {
            frag_id: u16::from_be_bytes([f0, f1]),
            idx: nibbles >> 4,
            count: nibbles & 0x0f,
        };
        header.check()?;
        Ok((header, chunk))
    }

    /// Refuses a header `decode` would refuse, so nothing invalid is sent.
    pub fn encode(&self) -> Result<[u8; FRAGMENT_HEADER_LEN], WireError> {
        self.check()?;
        let [f0, f1] = self.frag_id.to_be_bytes();
        Ok([f0, f1, (self.idx << 4) | self.count, 0])
    }

    fn check(&self) -> Result<(), WireError> {
        if !(2..=MAX_FRAGMENTS).contains(&self.count) || self.idx >= self.count {
            return Err(WireError::Malformed);
        }
        Ok(())
    }
}

/// A received QUIC datagram, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    Lan(LanDatagram),
    /// One piece of a larger LAN datagram. `header.kind` is `Fragment`; its
    /// ports and broadcast flag must agree across every piece.
    Fragment {
        header: LanHeader,
        fragment: FragmentHeader,
        chunk: Bytes,
    },
}

/// Decodes a QUIC datagram received on a link. `peer` is the link's slot:
/// the result's sender comes from the authenticated link, never from the
/// packet. The payload shares `datagram`'s buffer.
pub fn decode_datagram(peer: PeerSlot, datagram: Bytes) -> Result<Inbound, WireError> {
    let (header, rest) = LanHeader::decode(&datagram)?;
    match header.kind {
        DatagramKind::Lan => Ok(Inbound::Lan(LanDatagram {
            peer,
            bcast: header.bcast,
            src_port: header.src_port,
            dst_port: header.dst_port,
            payload: tail(&datagram, rest.len()),
        })),
        DatagramKind::Fragment => {
            let (fragment, chunk) = FragmentHeader::decode(rest)?;
            Ok(Inbound::Fragment {
                header,
                fragment,
                chunk: tail(&datagram, chunk.len()),
            })
        }
    }
}

/// The last `len` bytes of `buf`, without copying.
fn tail(buf: &Bytes, len: usize) -> Bytes {
    let start = buf.len().saturating_sub(len);
    buf.slice(start..)
}

/// Encodes `datagram` into QUIC datagrams of at most `max_datagram` bytes:
/// one LAN datagram when it fits, otherwise 2 to `MAX_FRAGMENTS` fragments
/// tagged `frag_id`. `datagram.peer` is not sent.
pub fn encode_datagram(
    datagram: &LanDatagram,
    frag_id: u16,
    max_datagram: usize,
) -> Result<Vec<Bytes>, WireError> {
    let payload = &datagram.payload;
    let mut header = LanHeader {
        kind: DatagramKind::Lan,
        bcast: datagram.bcast,
        src_port: datagram.src_port,
        dst_port: datagram.dst_port,
    };

    let whole = max_datagram
        .checked_sub(LAN_HEADER_LEN)
        .ok_or(WireError::TooLong { max: 0 })?;
    if payload.len() <= whole {
        let mut out = BytesMut::with_capacity(LAN_HEADER_LEN.saturating_add(payload.len()));
        out.put_slice(&header.encode());
        out.put_slice(payload);
        return Ok(vec![out.freeze()]);
    }

    let per_piece = whole.saturating_sub(FRAGMENT_HEADER_LEN);
    let most = per_piece.saturating_mul(usize::from(MAX_FRAGMENTS));
    if per_piece == 0 || payload.len() > most {
        return Err(WireError::TooLong {
            max: most.max(whole),
        });
    }
    header.kind = DatagramKind::Fragment;
    let pieces: Vec<&[u8]> = payload.chunks(per_piece).collect();
    let count = u8::try_from(pieces.len()).map_err(|_| WireError::Malformed)?;
    let mut out = Vec::with_capacity(pieces.len());
    for (idx, piece) in (0u8..).zip(pieces) {
        let fragment = FragmentHeader {
            frag_id,
            idx,
            count,
        }
        .encode()?;
        let mut buf = BytesMut::with_capacity(
            (LAN_HEADER_LEN + FRAGMENT_HEADER_LEN).saturating_add(piece.len()),
        );
        buf.put_slice(&header.encode());
        buf.put_slice(&fragment);
        buf.put_slice(piece);
        out.push(buf.freeze());
    }
    Ok(out)
}

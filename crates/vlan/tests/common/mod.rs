//! A test-side game: builds the frames a game's network stack would put on
//! its tap and parses what Kickoff hands back, written from the design
//! (§3.1, §3.2) rather than from the crate's codec.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use bytes::Bytes;
use kickoff_vlan::{Lan, LanConfig, MemGame, mem_tap, open};
use kickoff_wire::{LanDatagram, PeerSlot};

pub const GAME_PORT: u16 = 7777;
pub const DISCOVERY_PORT: u16 = 14001;
pub const BROADCAST: [u8; 4] = [255, 255, 255, 255];
pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];
pub const DENYLIST: &[u16] = &[
    22, 53, 67, 68, 137, 138, 1900, 5353, 5355, 9002, 47984, 47990, 48010, 49123, 49124, 53317,
];

pub fn slot(n: u8) -> PeerSlot {
    PeerSlot::new(n).unwrap()
}

pub fn mac(n: u8) -> [u8; 6] {
    [0x02, 0x4b, 0x4f, 0x00, 0x00, n]
}

pub fn ip(n: u8) -> [u8; 4] {
    [10, 75, 0, n]
}

pub fn node(own: u8) -> (Lan, MemGame) {
    let (adapter, game) = mem_tap();
    let lan = open(adapter, LanConfig { slot: slot(own) }).unwrap();
    (lan, game)
}

/// A UDP frame as the game at slot `from` would send it.
#[derive(Clone, Debug)]
pub struct Udp {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

impl Udp {
    pub fn unicast(from: u8, to: u8, src_port: u16, dst_port: u16) -> Udp {
        Udp {
            src_mac: mac(from),
            dst_mac: mac(to),
            src_ip: ip(from),
            dst_ip: ip(to),
            src_port,
            dst_port,
            payload: b"kickoff".to_vec(),
        }
    }

    pub fn broadcast(from: u8, src_port: u16, dst_port: u16) -> Udp {
        Udp {
            dst_mac: BROADCAST_MAC,
            dst_ip: BROADCAST,
            ..Udp::unicast(from, 1, src_port, dst_port)
        }
    }

    pub fn payload(mut self, payload: &[u8]) -> Udp {
        self.payload = payload.to_vec();
        self
    }

    pub fn frame(&self) -> Vec<u8> {
        let udp_len = 8 + self.payload.len();
        let total = 20 + udp_len;
        let mut ip = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0x40,
            0,
            64,
            17,
            0,
            0,
        ];
        ip.extend_from_slice(&self.src_ip);
        ip.extend_from_slice(&self.dst_ip);
        let sum = inet_checksum(&ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());

        let mut udp = Vec::new();
        udp.extend_from_slice(&self.src_port.to_be_bytes());
        udp.extend_from_slice(&self.dst_port.to_be_bytes());
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(&self.payload);
        let sum = udp_checksum(self.src_ip, self.dst_ip, &udp);
        udp[6..8].copy_from_slice(&sum.to_be_bytes());

        let mut f = Vec::new();
        f.extend_from_slice(&self.dst_mac);
        f.extend_from_slice(&self.src_mac);
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&udp);
        f
    }
}

/// Recomputes the IPv4 header checksum after a test edits the header, so the
/// frame is rejected for the edit and not for a stale checksum.
pub fn fix_ip_checksum(frame: &mut [u8]) {
    frame[24..26].copy_from_slice(&[0, 0]);
    let sum = inet_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&sum.to_be_bytes());
}

pub fn arp_request(from: u8, target: [u8; 4]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&BROADCAST_MAC);
    f.extend_from_slice(&mac(from));
    f.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0x00, 6, 4, 0, 1]);
    f.extend_from_slice(&mac(from));
    f.extend_from_slice(&ip(from));
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&target);
    f
}

pub fn inet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for pair in bytes.chunks(2) {
        let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum(src: [u8; 4], dst: [u8; 4], udp: &[u8]) -> u16 {
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    match inet_checksum(&pseudo) {
        0 => 0xffff,
        s => s,
    }
}

/// A frame Kickoff handed to the game, with both checksums verified.
#[derive(Debug, PartialEq, Eq)]
pub struct Received {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

pub fn parse_udp(f: &[u8]) -> Received {
    assert_eq!(&f[12..14], &[0x08, 0x00], "not IPv4");
    let ip = &f[14..34];
    assert_eq!(ip[0], 0x45, "IPv4 without options");
    assert_eq!(ip[9], 17, "UDP");
    assert_eq!(inet_checksum(ip), 0, "IPv4 header checksum");
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    assert_eq!(total, f.len() - 14, "IPv4 total length");
    let udp = &f[34..];
    assert_eq!(usize::from(u16::from_be_bytes([udp[4], udp[5]])), udp.len());
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&ip[12..20]);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    assert_ne!(&udp[6..8], &[0, 0], "UDP checksum present");
    assert_eq!(inet_checksum(&pseudo), 0, "UDP checksum");
    Received {
        dst_mac: f[0..6].try_into().unwrap(),
        src_mac: f[6..12].try_into().unwrap(),
        src_ip: ip[12..16].try_into().unwrap(),
        dst_ip: ip[16..20].try_into().unwrap(),
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: udp[8..].to_vec(),
    }
}

pub fn datagram(peer: u8, src_port: u16, dst_port: u16) -> LanDatagram {
    LanDatagram {
        peer: slot(peer),
        bcast: false,
        src_port,
        dst_port,
        payload: Bytes::from_static(b"kickoff"),
    }
}

pub fn broadcast(peer: u8, src_port: u16, dst_port: u16) -> LanDatagram {
    LanDatagram {
        bcast: true,
        ..datagram(peer, src_port, dst_port)
    }
}

/// The game sends `frame`; returns what `Lan::recv` yields for it, if
/// anything, without waiting for later frames.
pub async fn game_sends(lan: &Lan, game: &MemGame, frame: Vec<u8>) -> Option<LanDatagram> {
    game.send_frame(Bytes::from(frame)).unwrap();
    recv_now(lan).await
}

/// The next datagram if one is ready, after the queued frames are processed.
pub async fn recv_now(lan: &Lan) -> Option<LanDatagram> {
    // A fresh coop budget, so a pending `recv` means the queue is empty.
    tokio::task::yield_now().await;
    tokio::select! {
        biased;
        d = lan.recv() => Some(d.unwrap()),
        () = std::future::ready(()) => None,
    }
}

/// Every datagram the queued frames produce.
pub async fn recv_all(lan: &Lan) -> Vec<LanDatagram> {
    let mut out = Vec::new();
    loop {
        let before = lan.health();
        match recv_now(lan).await {
            Some(d) => out.push(d),
            None if lan.health() == before => return out,
            None => {}
        }
    }
}

/// The next frame the game receives, if one is queued.
pub async fn game_receives(game: &MemGame) -> Option<Bytes> {
    tokio::task::yield_now().await;
    tokio::select! {
        biased;
        f = game.recv_frame() => Some(f.unwrap()),
        () = std::future::ready(()) => None,
    }
}

pub async fn game_receives_all(game: &MemGame) -> Vec<Bytes> {
    let mut out = Vec::new();
    while let Some(f) = game_receives(game).await {
        out.push(f);
    }
    out
}

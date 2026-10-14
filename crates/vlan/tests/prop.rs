//! Properties over arbitrary sequences of game frames (valid, mutated and raw
//! bytes, since the game is assumed compromised) and peer datagrams: nothing
//! panics, nothing reaches a denylisted port, nothing wears a slot other than
//! the one it came from, and no unicast reaches a port the game did not open.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::collections::HashSet;
use std::time::Duration;

use bytes::Bytes;
use common::*;
use kickoff_wire::LanDatagram;
use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

#[derive(Debug, Clone)]
enum Op {
    /// The local game puts a frame on its tap.
    Game(Vec<u8>),
    /// A peer's link hands `deliver` a datagram stamped with its slot.
    Peer(LanDatagram),
    /// The admission owner reports a generation change for a slot.
    Reset(u8),
    Advance(u64),
}

fn port() -> impl Strategy<Value = u16> {
    prop_oneof![
        Just(GAME_PORT),
        Just(DISCOVERY_PORT),
        Just(0),
        proptest::sample::select(DENYLIST),
        40000..40004u16,
        any::<u16>(),
    ]
}

/// Mostly slots in the roster, sometimes an address no slot owns.
fn host_byte() -> impl Strategy<Value = u8> {
    prop_oneof![4 => 1..=8u8, 1 => any::<u8>()]
}

/// Usually `usual`, sometimes any other address, so each address check is
/// reached both with the rest of the frame valid and with it invalid.
fn mostly(usual: u8) -> impl Strategy<Value = u8> {
    prop_oneof![4 => Just(usual), 1 => host_byte()]
}

/// A UDP frame as the game at slot `own` would send it, with each address
/// independently replaced now and then.
fn udp_frame(own: u8) -> impl Strategy<Value = Vec<u8>> {
    let to = prop_oneof![Just(1u8), host_byte()];
    let addresses = (mostly(own), mostly(own), to).prop_flat_map(|(ip_from, mac_from, to)| {
        (Just(ip_from), Just(mac_from), Just(to), mostly(to))
    });
    (
        addresses,
        port(),
        port(),
        any::<bool>(),
        proptest::collection::vec(any::<u8>(), 0..1500),
    )
        .prop_map(
            move |((ip_from, mac_from, to, mac_to), src_port, dst_port, bcast, payload)| {
                let udp = if bcast {
                    Udp::broadcast(own, src_port, dst_port)
                } else {
                    Udp {
                        dst_mac: mac(mac_to),
                        ..Udp::unicast(own, to, src_port, dst_port)
                    }
                };
                Udp {
                    src_ip: ip(ip_from),
                    src_mac: mac(mac_from),
                    ..udp
                }
                .payload(&payload)
                .frame()
            },
        )
}

/// A valid-looking frame with a few bytes changed, the IPv4 checksum fixed
/// or not, so mutations reach the checks behind the checksum.
fn mutated(base: impl Strategy<Value = Vec<u8>>) -> impl Strategy<Value = Vec<u8>> {
    (
        base,
        proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..4),
        any::<bool>(),
    )
        .prop_map(|(mut frame, edits, fix)| {
            for (at, value) in edits {
                if !frame.is_empty() {
                    let i = at.index(frame.len());
                    frame[i] = value;
                }
            }
            if fix && frame.len() >= 34 {
                fix_ip_checksum(&mut frame);
            }
            frame
        })
}

fn game_frame(own: u8) -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => mutated(udp_frame(own)),
        1 => mutated((mostly(own), host_byte()).prop_map(|(from, to)| arp_request(from, ip(to)))),
        1 => proptest::collection::vec(any::<u8>(), 0..1600),
    ]
}

fn peer_datagram() -> impl Strategy<Value = LanDatagram> {
    (
        1..=8u8,
        any::<bool>(),
        port(),
        port(),
        prop_oneof![0..1600usize, Just(1472), Just(1473), Just(1252), Just(1253)],
    )
        .prop_map(|(peer, bcast, src_port, dst_port, len)| LanDatagram {
            peer: slot(peer),
            bcast,
            src_port,
            dst_port,
            payload: Bytes::from(vec![0x5a; len]),
        })
}

fn op(own: u8) -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => game_frame(own).prop_map(Op::Game),
        5 => peer_datagram().prop_map(Op::Peer),
        1 => (1..=8u8).prop_map(Op::Reset),
        1 => (0..40_000u64).prop_map(Op::Advance),
    ]
}

/// Who may answer a flow the game opened: one slot, or every guest when the
/// host's game broadcast.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Scope {
    Slot(u8),
    AnyGuest,
}

/// What the game has ever opened. Expiry and eviction only shrink the real
/// table, so a delivery this model cannot explain is a filter bug.
struct Opened(HashSet<(Scope, u16, u16)>);

impl Opened {
    fn record(&mut self, own: u8, d: &LanDatagram) {
        let scope = match (d.bcast, own) {
            (true, 1) => Scope::AnyGuest,
            (true, _) => Scope::Slot(1),
            (false, _) => Scope::Slot(d.peer.get()),
        };
        self.0.insert((scope, d.src_port, d.dst_port));
    }

    fn explains(&self, own: u8, from: u8, local: u16, remote: u16) -> bool {
        self.0.contains(&(Scope::Slot(from), local, remote))
            || (own == 1 && self.0.contains(&(Scope::AnyGuest, local, remote)))
    }
}

fn denied(port: u16) -> bool {
    port == 0 || DENYLIST.contains(&port) || (47984..=48010).contains(&port)
}

fn in_star(own: u8, peer: u8) -> bool {
    peer != own && (own == 1 || peer == 1)
}

async fn run(own: u8, ops: Vec<Op>) -> Result<(), TestCaseError> {
    let (lan, game) = node(own);
    let mut opened = Opened(HashSet::new());
    for op in ops {
        match op {
            Op::Game(frame) => {
                let from_own = frame.get(6..12) == Some(&mac(own)[..]);
                let from_own_ip = frame.get(26..30) == Some(&ip(own)[..]);
                game.send_frame(Bytes::from(frame)).unwrap();
                for d in recv_all(&lan).await {
                    prop_assert!(from_own && from_own_ip, "a foreign source left the node");
                    prop_assert!(!denied(d.src_port) && !denied(d.dst_port));
                    if d.bcast {
                        prop_assert_eq!(d.peer, slot(1));
                        prop_assert_eq!(d.dst_port, DISCOVERY_PORT);
                    } else {
                        prop_assert!(in_star(own, d.peer.get()));
                    }
                    opened.record(own, &d);
                }
                for reply in game_receives_all(&game).await {
                    prop_assert_eq!(&reply[12..14], &[0x08, 0x06], "only ARP replies");
                    prop_assert_eq!(&reply[0..6], &mac(own));
                    let answered = reply[31];
                    prop_assert_eq!(&reply[22..28], &mac(answered));
                    prop_assert!(in_star(own, answered));
                }
            }
            Op::Peer(d) => {
                let sent = d.clone();
                lan.deliver(d);
                for frame in game_receives_all(&game).await {
                    let got = parse_udp(&frame);
                    let from = sent.peer.get();
                    prop_assert!(in_star(own, from), "slot {} reached slot {}", from, own);
                    prop_assert_eq!((got.src_mac, got.src_ip), (mac(from), ip(from)));
                    prop_assert!(!denied(got.src_port) && !denied(got.dst_port));
                    prop_assert_eq!(
                        (got.src_port, got.dst_port, &got.payload[..]),
                        (sent.src_port, sent.dst_port, &sent.payload[..])
                    );
                    if sent.bcast {
                        prop_assert_eq!((got.dst_mac, got.dst_ip), (BROADCAST_MAC, BROADCAST));
                        prop_assert_eq!(got.dst_port, DISCOVERY_PORT);
                    } else {
                        prop_assert_eq!((got.dst_mac, got.dst_ip), (mac(own), ip(own)));
                        prop_assert!(
                            got.dst_port == GAME_PORT
                                || got.dst_port == DISCOVERY_PORT
                                || opened.explains(own, from, got.dst_port, got.src_port),
                            "unsolicited delivery to port {}",
                            got.dst_port
                        );
                    }
                }
            }
            Op::Reset(n) => {
                lan.reset_peer(slot(n));
                opened.0.retain(|&(scope, _, _)| scope != Scope::Slot(n));
            }
            Op::Advance(ms) => tokio::time::advance(Duration::from_millis(ms)).await,
        }
    }
    Ok(())
}

fn config() -> Config {
    Config {
        cases: 512,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        ..Config::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn no_input_reaches_a_denied_port_or_wears_a_foreign_slot(
        (own, ops) in (1..=8u8).prop_flat_map(|own| (Just(own), proptest::collection::vec(op(own), 1..64))),
    ) {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(run(own, ops))?;
    }
}

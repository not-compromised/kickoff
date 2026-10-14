//! Every forbidden case, each asserting its exact drop reason at the filter's
//! internal seam and its health counter through the public `Mem` path.

#[path = "../tests/common/mod.rs"]
mod common;

use bytes::Bytes;
use common::*;
use kickoff_wire::LanDatagram;
use tokio::time::Instant;

use crate::addr::Node;
use crate::codec::{self, FromGame};
use crate::filter::Filter;
use crate::verdict::{Class, Reject};
use crate::{Lan, LanHealth};

enum Input {
    /// A frame the local game at slot `own` puts on its tap.
    FromGame(Vec<u8>),
    /// A datagram a peer's link hands to `deliver`.
    FromPeer(LanDatagram),
}

struct Case {
    name: String,
    own: u8,
    input: Input,
    reason: Reject,
}

fn game(name: &str, own: u8, frame: Vec<u8>, reason: Reject) -> Case {
    Case {
        name: name.into(),
        own,
        input: Input::FromGame(frame),
        reason,
    }
}

fn peer(name: &str, own: u8, d: LanDatagram, reason: Reject) -> Case {
    Case {
        name: name.into(),
        own,
        input: Input::FromPeer(d),
        reason,
    }
}

fn edit(udp: &Udp, f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut frame = udp.frame();
    f(&mut frame);
    frame
}

fn edit_ip(udp: &Udp, f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    edit(udp, |frame| {
        f(frame);
        fix_ip_checksum(frame);
    })
}

/// The guest at slot 2 asking for the host's MAC, edited.
fn edit_arp(f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut frame = arp_request(2, ip(1));
    f(&mut frame);
    frame
}

#[rustfmt::skip]
fn cases() -> Vec<Case> {
    use Reject::*;
    let to_host = Udp::unicast(2, 1, 50000, GAME_PORT);
    let mut c = vec![
        // Malformed.
        game("empty frame", 2, vec![], Truncated),
        game("short Ethernet header", 2, to_host.frame()[..13].to_vec(), Truncated),
        game("frame over the MTU", 2, to_host.clone().payload(&[0; 1473]).frame(), Oversize),
        game("IPv4 header cut short", 2, to_host.frame()[..30].to_vec(), Truncated),
        game("UDP header cut short", 2, to_host.frame()[..38].to_vec(), Truncated),
        game("IP version 6 in an IPv4 frame", 2, edit_ip(&to_host, |f| f[14] = 0x65), BadIpHeader),
        game("IHL below 5", 2, edit_ip(&to_host, |f| f[14] = 0x44), BadIpHeader),
        game("reserved IP flag", 2, edit_ip(&to_host, |f| f[20] |= 0x80), BadIpHeader),
        game("bad IPv4 checksum", 2, edit(&to_host, |f| f[24] ^= 0xff), BadChecksum),
        game("IP total length under 20", 2, edit_ip(&to_host, |f| f[16..18].copy_from_slice(&[0, 19])), BadLength),
        game("IP total length past the frame", 2, edit_ip(&to_host, |f| {
            f[16..18].copy_from_slice(&[0x05, 0xdc]);
            f[38..40].copy_from_slice(&[0x05, 0xc8]);
        }), BadLength),
        game("UDP length disagrees with IP", 2, edit(&to_host, |f| f[39] ^= 1), BadLength),
        game("UDP length under 8", 2, edit_ip(&to_host, |f| {
            f[16..18].copy_from_slice(&[0, 24]);
            f[38..40].copy_from_slice(&[0, 4]);
        }), BadLength),
        game("bad UDP checksum", 2, edit(&to_host, |f| f[42] ^= 0xff), BadChecksum),
        // Not UDP over plain IPv4.
        game("IPv6", 2, edit(&to_host, |f| f[12..14].copy_from_slice(&[0x86, 0xdd])), Ipv6),
        game("802.1Q tag", 2, edit(&to_host, |f| f[12..14].copy_from_slice(&[0x81, 0x00])), VlanTag),
        game("802.1ad tag", 2, edit(&to_host, |f| f[12..14].copy_from_slice(&[0x88, 0xa8])), VlanTag),
        game("LLDP", 2, edit(&to_host, |f| f[12..14].copy_from_slice(&[0x88, 0xcc])), NotIpv4),
        game("IP options", 2, edit_ip(&to_host, |f| f[14] = 0x46), IpOptions),
        game("more-fragments flag", 2, edit_ip(&to_host, |f| f[20] |= 0x20), IpFragment),
        game("fragment offset", 2, edit_ip(&to_host, |f| f[21] = 1), IpFragment),
        game("TCP", 2, edit_ip(&to_host, |f| f[23] = 6), NotUdp),
        game("ICMP", 2, edit_ip(&to_host, |f| f[23] = 1), NotUdp),
        // Addresses.
        game("another slot's source MAC", 2, Udp { src_mac: mac(3), ..to_host.clone() }.frame(), ForeignSource),
        game("another slot's source IP", 2, Udp { src_ip: ip(3), ..to_host.clone() }.frame(), ForeignSource),
        game("source IP outside the subnet", 2, Udp { src_ip: [192, 168, 1, 2], ..to_host.clone() }.frame(), ForeignSource),
        game("to its own address", 2, Udp::unicast(2, 2, 50000, GAME_PORT).frame(), OwnSlot),
        game("guest to guest", 2, Udp::unicast(2, 3, 50000, GAME_PORT).frame(), NotInStar),
        game("to the internet", 2, Udp { dst_ip: [8, 8, 8, 8], ..to_host.clone() }.frame(), UnknownDestination),
        game("to a slot past the roster", 1, Udp::unicast(1, 9, GAME_PORT, 50000).frame(), UnknownDestination),
        game("to the network address", 1, Udp { dst_ip: ip(0), ..Udp::unicast(1, 2, GAME_PORT, 50000) }.frame(), UnknownDestination),
        game("multicast", 2, Udp { dst_ip: [224, 0, 0, 251], dst_mac: [0x01, 0, 0x5e, 0, 0, 0xfb], ..to_host.clone() }.frame(), UnknownDestination),
        game("unicast IP, broadcast MAC", 2, Udp { dst_mac: BROADCAST_MAC, ..to_host.clone() }.frame(), MacMismatch),
        game("unicast IP, another slot's MAC", 1, Udp { dst_mac: mac(3), ..Udp::unicast(1, 2, GAME_PORT, 50000) }.frame(), MacMismatch),
        game("broadcast IP, unicast MAC", 2, Udp { dst_mac: mac(1), ..Udp::broadcast(2, 40000, DISCOVERY_PORT) }.frame(), MacMismatch),
        // ARP.
        game("ARP reply from the game", 2, edit_arp(|a| a[21] = 2), ArpNotAnswered),
        game("ARP for Ethernet over another protocol", 2, edit_arp(|a| a[17] = 0x01), ArpNotAnswered),
        game("ARP probe", 2, edit_arp(|a| a[28..32].copy_from_slice(&[0; 4])), ArpNotAnswered),
        game("ARP for its own address", 2, arp_request(2, ip(2)), OwnSlot),
        game("ARP for another guest", 2, arp_request(2, ip(3)), NotInStar),
        game("ARP outside the subnet", 2, arp_request(2, [192, 168, 1, 1]), ArpNotAnswered),
        game("ARP sender MAC not the game's", 2, edit_arp(|a| a[22..28].copy_from_slice(&mac(3))), ForeignSource),
        game("ARP to another slot's MAC", 2, edit_arp(|a| a[0..6].copy_from_slice(&mac(3))), MacMismatch),
        game("ARP cut short", 2, arp_request(2, ip(1))[..30].to_vec(), Truncated),
        // Ports.
        game("source port 0", 2, Udp::unicast(2, 1, 0, GAME_PORT).frame(), ZeroPort),
        game("destination port 0", 1, Udp::unicast(1, 2, GAME_PORT, 0).frame(), ZeroPort),
        game("neither port a game port", 2, Udp::unicast(2, 1, 50000, 50001).frame(), NotGamePort),
        game("broadcast to the game port", 2, Udp::broadcast(2, 40000, GAME_PORT).frame(), BroadcastNotDiscovery),
        game("broadcast to a random port", 1, Udp::broadcast(1, 40000, 50000).frame(), BroadcastNotDiscovery),
        game("oversized broadcast", 2, Udp::broadcast(2, 40000, DISCOVERY_PORT).payload(&[0; 1253]).frame(), BroadcastTooLarge),
        // From peers.
        peer("a peer wearing this node's slot", 1, datagram(1, GAME_PORT, GAME_PORT), OwnSlot),
        peer("another guest, at a guest", 2, datagram(3, GAME_PORT, GAME_PORT), NotInStar),
        peer("payload larger than one frame", 1, LanDatagram { payload: Bytes::from(vec![0; 1473]), ..datagram(2, 50000, GAME_PORT) }, PayloadTooLarge),
        peer("source port 0", 1, datagram(2, 0, GAME_PORT), ZeroPort),
        peer("destination port 0", 2, datagram(1, GAME_PORT, 0), ZeroPort),
        peer("unsolicited to a non-game port", 2, datagram(1, GAME_PORT, 50000), NotGamePort),
        peer("unsolicited to the host's non-game port", 1, datagram(4, 50000, 50001), NotGamePort),
        peer("broadcast to the game port", 2, broadcast(1, 40000, GAME_PORT), BroadcastNotDiscovery),
        peer("oversized broadcast", 1, LanDatagram { payload: Bytes::from(vec![0; 1253]), ..broadcast(2, 40000, DISCOVERY_PORT) }, BroadcastTooLarge),
    ];
    for &port in DENYLIST {
        c.push(game(&format!("game to denylisted {port}"), 2, Udp::unicast(2, 1, 50000, port).frame(), DeniedPort));
        c.push(game(&format!("game from denylisted {port}"), 2, Udp::unicast(2, 1, port, GAME_PORT).frame(), DeniedPort));
        c.push(game(&format!("game broadcast from denylisted {port}"), 1, Udp::broadcast(1, port, DISCOVERY_PORT).frame(), DeniedPort));
        c.push(peer(&format!("peer to denylisted {port}"), 1, datagram(2, GAME_PORT, port), DeniedPort));
        c.push(peer(&format!("peer from denylisted {port}"), 2, datagram(1, port, GAME_PORT), DeniedPort));
        c.push(peer(&format!("peer broadcast to denylisted {port}"), 2, broadcast(1, GAME_PORT, port), DeniedPort));
    }
    c
}

/// The reason at the internal seam: codec, then filter.
fn reason(own: u8, input: &Input) -> Result<(), Reject> {
    let node = Node { own: slot(own) };
    let mut filter = Filter::new(node, Instant::now());
    match input {
        Input::FromGame(frame) => match codec::decode(&Bytes::from(frame.clone()), node)? {
            FromGame::ArpFor(_) => Ok(()),
            FromGame::Udp(d) => filter.outbound(&d, Instant::now()),
        },
        Input::FromPeer(d) => filter.inbound(d, Instant::now()),
    }
}

fn counted(health: LanHealth, class: Class) -> bool {
    let expected = |c| u64::from(class == c);
    health
        == LanHealth {
            from_game: 0,
            to_game: 0,
            dropped_filter: expected(Class::Filter),
            dropped_malformed: expected(Class::Malformed),
            dropped_overload: expected(Class::Overload),
        }
}

async fn through_lan(lan: &Lan, game_end: &crate::MemGame, input: Input) -> bool {
    match input {
        Input::FromGame(frame) => game_sends(lan, game_end, frame).await.is_some(),
        Input::FromPeer(d) => {
            lan.deliver(d);
            game_receives(game_end).await.is_some()
        }
    }
}

#[tokio::test(start_paused = true)]
async fn every_forbidden_case_drops_with_its_reason() {
    let mut failures = Vec::new();
    for case in cases() {
        let got = reason(case.own, &case.input);
        if got != Err(case.reason) {
            failures.push(format!(
                "{}: expected {:?}, got {got:?}",
                case.name, case.reason
            ));
            continue;
        }
        let (lan, game_end) = node(case.own);
        if through_lan(&lan, &game_end, case.input).await {
            failures.push(format!("{}: passed through the LAN", case.name));
        }
        if !counted(lan.health(), case.reason.class()) {
            failures.push(format!("{}: health {:?}", case.name, lan.health()));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The table above is only meaningful if each row differs from a frame that
/// passes by the one property it names.
#[tokio::test(start_paused = true)]
async fn the_unedited_frames_pass() {
    let (guest, guest_game) = node(2);
    for frame in [
        Udp::unicast(2, 1, 50000, GAME_PORT).frame(),
        Udp::unicast(2, 1, GAME_PORT, 50000).frame(),
        Udp::broadcast(2, 40000, DISCOVERY_PORT).frame(),
        Udp::broadcast(2, 40000, DISCOVERY_PORT)
            .payload(&[0; 1252])
            .frame(),
        Udp::unicast(2, 1, 50000, GAME_PORT)
            .payload(&[0; 1472])
            .frame(),
        Udp {
            dst_ip: [10, 75, 0, 255],
            ..Udp::broadcast(2, 40000, DISCOVERY_PORT)
        }
        .frame(),
    ] {
        assert!(game_sends(&guest, &guest_game, frame).await.is_some());
    }
    guest.deliver(datagram(1, GAME_PORT, 50000));
    guest.deliver(broadcast(1, 40000, DISCOVERY_PORT));
    assert_eq!(game_receives_all(&guest_game).await.len(), 2);
    guest_game
        .send_frame(Bytes::from(arp_request(2, ip(1))))
        .unwrap();
    assert!(recv_now(&guest).await.is_none());
    assert!(game_receives(&guest_game).await.is_some());

    let (host, host_game) = node(1);
    for frame in [
        Udp::unicast(1, 2, GAME_PORT, 50000).frame(),
        Udp::unicast(1, 8, GAME_PORT, 50000).frame(),
        Udp::broadcast(1, 40000, DISCOVERY_PORT).frame(),
    ] {
        assert!(game_sends(&host, &host_game, frame).await.is_some());
    }
    host.deliver(datagram(2, 50000, GAME_PORT));
    host.deliver(datagram(8, 50000, GAME_PORT));
    host.deliver(LanDatagram {
        payload: Bytes::from(vec![0; 1472]),
        ..datagram(3, 50000, GAME_PORT)
    });
    assert_eq!(game_receives_all(&host_game).await.len(), 3);
    assert_eq!(
        guest.health().dropped_filter + host.health().dropped_filter,
        0
    );
}

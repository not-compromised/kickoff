#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod harness;

use bytes::Bytes;
use kickoff_wire::{
    DatagramKind, FragmentHeader, Inbound, LAN_HEADER_LEN, LanDatagram, LanHeader, MAX_FRAGMENTS,
    PeerSlot, WireError, decode_datagram, encode_datagram,
};
use proptest::prelude::*;

fn slot(n: u8) -> PeerSlot {
    PeerSlot::new(n).unwrap()
}

#[test]
fn header_refuses_unknown_kind_reserved_flags_and_short_input() {
    assert!(LanHeader::decode(&[1, 1, 0, 1, 0, 2]).is_ok());
    assert_eq!(
        LanHeader::decode(&[3, 0, 0, 1, 0, 2]).unwrap_err(),
        WireError::Malformed
    );
    assert_eq!(
        LanHeader::decode(&[0, 0, 0, 1, 0, 2]).unwrap_err(),
        WireError::Malformed
    );
    assert_eq!(
        LanHeader::decode(&[1, 0b10, 0, 1, 0, 2]).unwrap_err(),
        WireError::Malformed
    );
    assert_eq!(
        LanHeader::decode(&[1, 0, 0, 1, 0]).unwrap_err(),
        WireError::Malformed
    );
}

#[test]
fn fragment_header_refuses_what_the_receiver_must_not_allocate_for() {
    let frag = |nibbles: u8, reserved: u8| [0, 7, nibbles, reserved, 0xaa];
    assert!(FragmentHeader::decode(&frag(0x12, 0)).is_ok());
    assert!(FragmentHeader::decode(&frag(0x34, 0)).is_ok());
    for (nibbles, reserved) in [
        (0x05, 0), // count above MAX_FRAGMENTS
        (0x0f, 0),
        (0x22, 0), // idx == count
        (0x42, 0), // idx > count
        (0x01, 0), // a single fragment is not a fragment
        (0x00, 0),
        (0x02, 1), // reserved must be zero
    ] {
        assert_eq!(
            FragmentHeader::decode(&frag(nibbles, reserved)).unwrap_err(),
            WireError::Malformed,
            "{nibbles:#04x} {reserved}"
        );
    }
    assert_eq!(
        FragmentHeader::decode(&[0, 7, 0x02, 0]).unwrap_err(),
        WireError::Malformed,
        "empty chunk"
    );
    let bad = FragmentHeader {
        frag_id: 1,
        idx: 4,
        count: 4,
    };
    assert_eq!(bad.encode().unwrap_err(), WireError::Malformed);
}

#[test]
fn sender_slot_comes_from_the_link_never_the_packet() {
    // Every byte of the packet that could name a sender is varied; the
    // decoded sender is the link's slot every time.
    for first in 0..=u8::MAX {
        let packet = Bytes::from(vec![1, 0, first, first, first, first, first]);
        if let Ok(Inbound::Lan(datagram)) = decode_datagram(slot(3), packet) {
            assert_eq!(datagram.peer, slot(3));
        }
    }
}

#[test]
fn oversize_datagram_is_refused_not_truncated() {
    let datagram = LanDatagram {
        peer: PeerSlot::HOST,
        bcast: false,
        src_port: 7777,
        dst_port: 7777,
        payload: Bytes::from(vec![0; 4 * (100 - 10) + 1]),
    };
    assert!(matches!(
        encode_datagram(&datagram, 0, 100),
        Err(WireError::TooLong { .. })
    ));
    assert!(matches!(
        encode_datagram(&datagram, 0, 5),
        Err(WireError::TooLong { .. })
    ));
}

proptest! {
    #[test]
    fn datagram_round_trips_through_at_most_four_fragments(
        bcast in any::<bool>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        frag_id in any::<u16>(),
        max_datagram in 11usize..1500,
        payload_seed in proptest::collection::vec(any::<u8>(), 0..6000),
        link in 1u8..=8,
    ) {
        let room = 4 * (max_datagram - LAN_HEADER_LEN - 4);
        let payload = &payload_seed[..payload_seed.len().min(room.max(max_datagram - LAN_HEADER_LEN))];
        let sent = LanDatagram {
            peer: PeerSlot::HOST,
            bcast,
            src_port,
            dst_port,
            payload: Bytes::copy_from_slice(payload),
        };
        let wire = encode_datagram(&sent, frag_id, max_datagram).unwrap();
        prop_assert!(!wire.is_empty() && wire.len() <= usize::from(MAX_FRAGMENTS));
        prop_assert!(wire.iter().all(|d| d.len() <= max_datagram));

        let mut chunks = Vec::new();
        for (expected_idx, datagram) in wire.iter().enumerate() {
            match decode_datagram(slot(link), datagram.clone()).unwrap() {
                Inbound::Lan(got) => {
                    prop_assert_eq!(wire.len(), 1);
                    prop_assert_eq!(&got, &LanDatagram { peer: slot(link), ..sent.clone() });
                }
                Inbound::Fragment { header, fragment, chunk } => {
                    prop_assert_eq!(header.kind, DatagramKind::Fragment);
                    prop_assert_eq!((header.bcast, header.src_port, header.dst_port), (bcast, src_port, dst_port));
                    prop_assert_eq!(fragment.frag_id, frag_id);
                    prop_assert_eq!(usize::from(fragment.idx), expected_idx);
                    prop_assert_eq!(usize::from(fragment.count), wire.len());
                    chunks.extend_from_slice(&chunk);
                }
            }
        }
        if wire.len() > 1 {
            prop_assert_eq!(chunks.as_slice(), payload);
        }
    }

    #[test]
    fn lan_harness_holds_for_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..64)) {
        harness::lan(&data);
    }

    #[test]
    fn lan_harness_holds_near_valid_headers(
        kind in 0u8..4,
        flags in 0u8..4,
        rest in proptest::collection::vec(any::<u8>(), 0..32),
        link in any::<u8>(),
    ) {
        let mut data = vec![link, kind, flags];
        data.extend_from_slice(&rest);
        harness::lan(&data);
    }
}

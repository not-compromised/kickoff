//! One harness per hostile input, shared by the cargo-fuzz targets
//! (`crates/wire/fuzz`) and the proptest suites, so CI exercises the same
//! properties the nightly fuzzer does. Each function takes arbitrary bytes and
//! panics only when a decoder breaks its contract.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use bytes::Bytes;
use kickoff_wire::{
    DatagramKind, GuestMsg, HostMsg, Inbound, JoinReply, JoinRequest, MAX_FRAGMENTS, MAX_HAVE,
    MAX_NAME_LEN, PeerSlot, WireMessage, decode, decode_datagram, encode, encode_datagram,
    encode_ticket, parse_ticket,
};

/// A QUIC datagram from a link. The first byte picks the link's slot.
pub fn lan(data: &[u8]) {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    let link_slot = PeerSlot::new(pick % 8 + 1).unwrap();
    let input = Bytes::copy_from_slice(rest);
    match decode_datagram(link_slot, input.clone()) {
        Ok(Inbound::Lan(datagram)) => {
            assert_eq!(datagram.peer, link_slot, "sender must come from the link");
            let again = encode_datagram(&datagram, 0, usize::MAX).unwrap();
            assert_eq!(again, vec![input], "a decoded datagram re-encodes exactly");
        }
        Ok(Inbound::Fragment {
            header,
            fragment,
            chunk,
        }) => {
            assert_eq!(header.kind, DatagramKind::Fragment);
            assert!((2..=MAX_FRAGMENTS).contains(&fragment.count));
            assert!(fragment.idx < fragment.count);
            assert!(!chunk.is_empty());
            let mut again = header.encode().to_vec();
            again.extend_from_slice(&fragment.encode().unwrap());
            again.extend_from_slice(&chunk);
            assert_eq!(again, rest, "a decoded fragment re-encodes exactly");
        }
        Err(_) => {}
    }
}

/// A join or control message body, tried as every message type.
pub fn control(data: &[u8]) {
    if let Some(GuestMsg::Status { have, .. }) = strict::<GuestMsg>(data) {
        assert!(have.as_slice().len() <= MAX_HAVE);
    }
    if let Some(HostMsg::Roster { members, .. }) = strict::<HostMsg>(data) {
        assert!(members.as_slice().len() <= 8);
        for member in members.as_slice() {
            assert!((1..=8).contains(&member.slot.get()));
            name_ok(member.name.as_str());
        }
    }
    if let Some(request) = strict::<JoinRequest>(data) {
        name_ok(request.name.as_str());
        assert!(request.game_build.as_str().len() <= 64);
    }
    if let Some(JoinReply::Admitted(admitted)) = strict::<JoinReply>(data) {
        assert!((1..=8).contains(&admitted.pass.slot.get()));
        assert!(admitted.session_addr.relay_urls().count() <= 4);
        assert!(admitted.session_addr.ip_addrs().count() <= 8);
    }
}

fn strict<M: WireMessage>(data: &[u8]) -> Option<M> {
    let msg = decode::<M>(data).ok()?;
    assert!(data.len() <= M::MAX_LEN);
    assert_eq!(
        encode(&msg).unwrap().as_ref(),
        data,
        "a decoded message re-encodes exactly"
    );
    Some(msg)
}

fn name_ok(name: &str) {
    assert!(name.len() <= MAX_NAME_LEN);
    assert!(!name.chars().any(char::is_control));
}

/// Ticket text, tried both as given and as the base32 body of a ticket so the
/// fuzzer reaches the binary layer without learning base32.
pub fn ticket(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        ticket_text(text);
    }
    let body = data_encoding::BASE32_NOPAD
        .encode(data)
        .to_ascii_lowercase();
    ticket_text(&format!("kickoff1{body}"));
}

fn ticket_text(text: &str) {
    let Ok(ticket) = parse_ticket(text) else {
        return;
    };
    let door = kickoff_wire::Ticket::door(&ticket);
    assert_eq!(door.ip_addrs().count(), 0, "a door has no direct address");
    assert!((1..=4).contains(&door.relay_urls().count()));
    for url in door.relay_urls() {
        assert!(url.to_string().starts_with("https://"));
    }
    let again = encode_ticket(&ticket).unwrap();
    assert!(again.ct_eq(text.to_ascii_lowercase().as_bytes()));
}

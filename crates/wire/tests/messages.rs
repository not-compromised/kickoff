#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

mod harness;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::Bytes;
use iroh_base::{EndpointAddr, EndpointId, RelayUrl, SecretKey, Signature, TransportAddr};
use kickoff_wire::{
    AdmitPass, Admitted, BoundedVec, BuildId, BundleBlob, Cap, GameState, Generation, GuestMsg,
    HostMsg, JoinRefused, JoinReply, JoinRequest, KickReason, KickoffVersion, MAX_CONTROL_LEN,
    MAX_JOIN_LEN, MapId, Member, Name, Nonce, PeerSlot, Platform, SessionId, WireError, decode,
    encode, encode_framed, frame_len,
};
use proptest::prelude::*;

fn endpoint_id() -> impl Strategy<Value = EndpointId> {
    any::<[u8; 32]>().prop_map(|b| SecretKey::from_bytes(&b).public())
}

fn slot() -> impl Strategy<Value = PeerSlot> {
    (1u8..=8).prop_map(|n| PeerSlot::new(n).unwrap())
}

fn name() -> impl Strategy<Value = Name> {
    "\\PC{0,8}".prop_filter_map("fits in 32 bytes", |s| Name::new(&s).ok())
}

fn relay() -> impl Strategy<Value = RelayUrl> {
    ("[a-z0-9]{1,12}", prop::option::of(1u16..)).prop_map(|(host, port)| {
        let port = port.map(|p| format!(":{p}")).unwrap_or_default();
        format!("https://{host}.relay.example.{port}/")
            .parse()
            .unwrap()
    })
}

// serde's compact form of an IPv6 socket address keeps only ip and port.
fn socket_addr() -> impl Strategy<Value = SocketAddr> {
    prop_oneof![
        (any::<[u8; 4]>(), any::<u16>())
            .prop_map(|(ip, port)| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))),
        (any::<[u8; 16]>(), any::<u16>()).prop_map(|(ip, port)| SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(ip),
            port,
            0,
            0
        ))),
    ]
}

fn session_addr() -> impl Strategy<Value = EndpointAddr> {
    (
        endpoint_id(),
        prop::collection::btree_set(relay(), 0..=4),
        prop::collection::btree_set(socket_addr(), 0..=8),
    )
        .prop_map(|(id, relays, ips)| {
            EndpointAddr::from_parts(
                id,
                relays
                    .into_iter()
                    .map(TransportAddr::Relay)
                    .chain(ips.into_iter().map(TransportAddr::Ip)),
            )
        })
}

fn guest_msg() -> impl Strategy<Value = GuestMsg> {
    let state = prop_oneof![
        Just(GameState::Unknown),
        Just(GameState::Menu),
        Just(GameState::Lobby),
        Just(GameState::Match),
    ];
    prop_oneof![
        any::<u64>().prop_map(|g| GuestMsg::Hello {
            generation: Generation::new(g)
        }),
        (state, prop::collection::vec(any::<[u8; 32]>(), 0..=64)).prop_map(|(game_state, have)| {
            GuestMsg::Status {
                game_state,
                have: BoundedVec::new(have.into_iter().map(MapId).collect()).unwrap(),
            }
        }),
        Just(GuestMsg::Pong),
    ]
}

fn host_msg() -> impl Strategy<Value = HostMsg> {
    let member =
        (slot(), endpoint_id(), name()).prop_map(|(slot, id, name)| Member { slot, id, name });
    let reason = prop_oneof![
        Just(KickReason::Kicked),
        Just(KickReason::Evicted),
        Just(KickReason::ProtocolViolation),
        Just(KickReason::OverBudget),
    ];
    prop_oneof![
        (any::<u64>(), prop::collection::vec(member, 0..=8)).prop_map(|(epoch, members)| {
            HostMsg::Roster {
                epoch,
                members: BoundedVec::new(members).unwrap(),
            }
        }),
        prop::collection::vec(any::<u8>(), 0..2048).prop_map(|b| HostMsg::MapPick {
            bundle: BundleBlob(Bytes::from(b))
        }),
        reason.prop_map(|reason| HostMsg::Kick { reason }),
        Just(HostMsg::Ping),
        Just(HostMsg::End),
    ]
}

fn join_reply() -> impl Strategy<Value = JoinReply> {
    let refused = prop_oneof![
        Just(JoinRefused::Revoked),
        Just(JoinRefused::InvalidCap),
        Just(JoinRefused::WrongSession),
        Just(JoinRefused::Expired),
        Just(JoinRefused::Full),
        Just(JoinRefused::Busy),
        Just(JoinRefused::Declined),
        Just(JoinRefused::Version),
    ];
    prop_oneof![
        (session_addr(), slot(), any::<u64>()).prop_map(|(session_addr, slot, g)| {
            JoinReply::Admitted(Admitted {
                session_addr,
                pass: AdmitPass {
                    slot,
                    generation: Generation::new(g),
                },
            })
        }),
        refused.prop_map(JoinReply::Refused),
    ]
}

/// `JoinRequest` has no `Debug` (it carries a capability), so proptest
/// generates its parts and each test builds the request.
#[derive(Debug, Clone)]
struct RequestParts {
    sid: [u8; 16],
    invitee: Option<EndpointId>,
    nonce: [u8; 16],
    sig: Signature,
    session_key: EndpointId,
    name: Name,
    linux: bool,
    build: String,
    version: (u16, u16, u16),
}

impl RequestParts {
    fn build(&self) -> JoinRequest {
        let (major, minor, patch) = self.version;
        JoinRequest {
            cap: Cap::new(
                SessionId(self.sid),
                self.invitee,
                Nonce(self.nonce),
                self.sig,
            ),
            session_key: self.session_key,
            name: self.name.clone(),
            platform: if self.linux {
                Platform::Linux
            } else {
                Platform::Windows
            },
            game_build: BuildId::new(&self.build).unwrap(),
            kickoff_version: KickoffVersion {
                major,
                minor,
                patch,
            },
        }
    }
}

fn join_request() -> impl Strategy<Value = RequestParts> {
    (
        (
            any::<[u8; 16]>(),
            prop::option::of(endpoint_id()),
            any::<[u8; 16]>(),
            any::<[u8; 32]>(),
        ),
        endpoint_id(),
        name(),
        any::<bool>(),
        "[ -~]{0,64}",
        any::<(u16, u16, u16)>(),
    )
        .prop_map(
            |((sid, invitee, nonce, sig_seed), session_key, name, linux, build, version)| {
                RequestParts {
                    sid,
                    invitee,
                    nonce,
                    sig: SecretKey::from_bytes(&sig_seed).sign(b"x"),
                    session_key,
                    name,
                    linux,
                    build,
                    version,
                }
            },
        )
}

fn same_request(a: &JoinRequest, b: &JoinRequest) -> bool {
    encode(a).unwrap().as_ref() == encode(b).unwrap().as_ref()
}

proptest! {
    #[test]
    fn guest_messages_round_trip(msg in guest_msg()) {
        prop_assert_eq!(decode::<GuestMsg>(&encode(&msg).unwrap()).unwrap(), msg);
    }

    #[test]
    fn host_messages_round_trip(msg in host_msg()) {
        prop_assert_eq!(decode::<HostMsg>(&encode(&msg).unwrap()).unwrap(), msg);
    }

    #[test]
    fn join_replies_round_trip(reply in join_reply()) {
        prop_assert_eq!(decode::<JoinReply>(&encode(&reply).unwrap()).unwrap(), reply);
    }

    #[test]
    fn join_requests_round_trip(parts in join_request()) {
        let request = parts.build();
        let bytes = encode(&request).unwrap();
        let back = decode::<JoinRequest>(&bytes).unwrap();
        prop_assert!(same_request(&request, &back));
    }

    #[test]
    fn framed_messages_announce_their_length(msg in host_msg()) {
        let framed = encode_framed(&msg).unwrap();
        let len = frame_len::<HostMsg>(framed[..4].try_into().unwrap()).unwrap();
        prop_assert_eq!(len, framed.len() - 4);
        prop_assert_eq!(decode::<HostMsg>(&framed[4..]).unwrap(), msg);
    }

    #[test]
    fn control_harness_holds_for_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..256)) {
        harness::control(&data);
    }

    #[test]
    fn control_harness_holds_for_mutated_valid_messages(
        msg in host_msg(),
        reply in join_reply(),
        parts in join_request(),
        flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
    ) {
        for mut bytes in [
            encode(&msg).unwrap().to_vec(),
            encode(&reply).unwrap().to_vec(),
            encode(&parts.build()).unwrap().to_vec(),
        ] {
            for (at, value) in &flips {
                let i = at.index(bytes.len());
                bytes[i] = *value;
            }
            harness::control(&bytes);
        }
    }
}

#[test]
fn trailing_bytes_and_overlong_varints_are_malformed() {
    let ping = encode(&HostMsg::Ping).unwrap().to_vec();
    assert!(decode::<HostMsg>(&ping).is_ok());

    let mut trailing = ping.clone();
    trailing.push(0);
    assert_eq!(
        decode::<HostMsg>(&trailing).unwrap_err(),
        WireError::Malformed
    );

    // Variant 3 (Ping) spelled as a two-byte varint.
    assert_eq!(
        decode::<HostMsg>(&[0x83, 0x00]).unwrap_err(),
        WireError::Malformed
    );
    assert_eq!(decode::<HostMsg>(&[]).unwrap_err(), WireError::Malformed);
    // An unknown nested variant (GameState has four) is malformed, not new.
    assert_eq!(
        decode::<GuestMsg>(&[1, 4, 0]).unwrap_err(),
        WireError::Malformed
    );
}

/// §4.5: an unknown variant closes with `VERSION`, so the caller must be able
/// to tell one from a malformed message.
#[test]
fn unknown_top_level_variant_is_a_version_error() {
    assert_eq!(decode::<HostMsg>(&[5]).unwrap_err(), WireError::Version);
    assert_eq!(decode::<GuestMsg>(&[3]).unwrap_err(), WireError::Version);
    assert_eq!(
        decode::<JoinReply>(&[2, 0]).unwrap_err(),
        WireError::Version
    );
    // Index 300 as a two-byte varint.
    assert_eq!(
        decode::<HostMsg>(&[0xac, 0x02]).unwrap_err(),
        WireError::Version
    );
    // The last known variant still decodes.
    assert!(decode::<HostMsg>(&[4]).is_ok());
    assert!(decode::<GuestMsg>(&[2]).is_ok());
}

#[test]
fn roster_slots_outside_the_lan_are_refused() {
    // A roster slot outside 1..=8 cannot be decoded, so a host message cannot
    // name a ninth peer or slot 0.
    let roster = |slot: u8| {
        let mut b = vec![0u8, 1, 1, slot];
        b.extend_from_slice(SecretKey::from_bytes(&[7; 32]).public().as_bytes());
        b.push(0);
        b
    };
    assert!(decode::<HostMsg>(&roster(2)).is_ok());
    assert_eq!(
        decode::<HostMsg>(&roster(0)).unwrap_err(),
        WireError::Malformed
    );
    assert_eq!(
        decode::<HostMsg>(&roster(9)).unwrap_err(),
        WireError::Malformed
    );
}

#[test]
fn si_23_declared_length_beyond_bound_refused_before_allocating() {
    // Status { game_state: Unknown, have: <declared u32::MAX entries> } in
    // seven bytes. The bound itself is checked against the claim in
    // `bounded`'s unit test; here the whole decode path refuses it.
    let huge = [1u8, 0, 0xff, 0xff, 0xff, 0xff, 0x0f];
    assert_eq!(decode::<GuestMsg>(&huge).unwrap_err(), WireError::Malformed);

    // A complete list one past the bound is refused, not truncated.
    let mut over = vec![1u8, 0, 65];
    over.extend(std::iter::repeat_n(0u8, 65 * 32));
    assert_eq!(decode::<GuestMsg>(&over).unwrap_err(), WireError::Malformed);
    let mut at = vec![1u8, 0, 64];
    at.extend(std::iter::repeat_n(0u8, 64 * 32));
    assert!(decode::<GuestMsg>(&at).is_ok());

    // A 33-byte name is refused.
    let mut roster = vec![0u8, 1, 1, 2];
    roster.extend_from_slice(SecretKey::from_bytes(&[7; 32]).public().as_bytes());
    roster.push(33);
    roster.extend(std::iter::repeat_n(b'a', 33));
    assert_eq!(
        decode::<HostMsg>(&roster).unwrap_err(),
        WireError::Malformed
    );
}

#[test]
fn si_23_oversize_messages_refused_both_ways() {
    let big = HostMsg::MapPick {
        bundle: BundleBlob(Bytes::from(vec![0; MAX_CONTROL_LEN])),
    };
    assert_eq!(
        encode(&big).err().unwrap(),
        WireError::TooLong {
            max: MAX_CONTROL_LEN
        }
    );
    assert_eq!(
        decode::<HostMsg>(&vec![0; MAX_CONTROL_LEN + 1]).unwrap_err(),
        WireError::TooLong {
            max: MAX_CONTROL_LEN
        }
    );
    assert_eq!(
        decode::<JoinReply>(&vec![0; MAX_JOIN_LEN + 1]).unwrap_err(),
        WireError::TooLong { max: MAX_JOIN_LEN }
    );
}

#[test]
fn si_23_frame_prefix_checked_before_the_body_is_read() {
    let announce = |n: u32| n.to_be_bytes();
    assert_eq!(frame_len::<HostMsg>(announce(1)).unwrap(), 1);
    assert_eq!(
        frame_len::<HostMsg>(announce(MAX_CONTROL_LEN as u32)).unwrap(),
        MAX_CONTROL_LEN
    );
    assert_eq!(
        frame_len::<HostMsg>(announce(MAX_CONTROL_LEN as u32 + 1)).unwrap_err(),
        WireError::TooLong {
            max: MAX_CONTROL_LEN
        }
    );
    assert_eq!(
        frame_len::<JoinRequest>(announce(MAX_JOIN_LEN as u32 + 1)).unwrap_err(),
        WireError::TooLong { max: MAX_JOIN_LEN }
    );
    assert_eq!(
        frame_len::<JoinRequest>(announce(u32::MAX)).unwrap_err(),
        WireError::TooLong { max: MAX_JOIN_LEN }
    );
    assert_eq!(
        frame_len::<HostMsg>(announce(0)).unwrap_err(),
        WireError::Malformed
    );
}

#[test]
fn admitted_refuses_custom_transports_and_oversize_address_sets() {
    let id = SecretKey::from_bytes(&[1; 32]).public();
    let reply = |addr: EndpointAddr| {
        JoinReply::Admitted(Admitted {
            session_addr: addr,
            pass: AdmitPass {
                slot: PeerSlot::new(2).unwrap(),
                generation: Generation::new(1),
            },
        })
    };
    let custom = EndpointAddr::from_parts(
        id,
        [TransportAddr::Custom(iroh_base::CustomAddr::from_parts(
            1, b"x",
        ))],
    );
    assert!(encode(&reply(custom)).is_err());
    let many = EndpointAddr::from_parts(
        id,
        (0..9u16).map(|p| TransportAddr::Ip(SocketAddr::from(([192, 0, 2, 1], p)))),
    );
    assert!(encode(&reply(many)).is_err());
}

#[test]
fn signature_bytes_are_not_validated_by_the_decoder() {
    // Decoding only carries the signature; checking it is `Invites::redeem`'s
    // job, which the ticket suite covers.
    let request = JoinRequest {
        cap: Cap::new(
            SessionId([0; 16]),
            None,
            Nonce([0; 16]),
            Signature::from_bytes(&[0xff; 64]),
        ),
        session_key: SecretKey::from_bytes(&[2; 32]).public(),
        name: Name::new("p").unwrap(),
        platform: Platform::Linux,
        game_build: BuildId::new("b").unwrap(),
        kickoff_version: KickoffVersion {
            major: 0,
            minor: 1,
            patch: 0,
        },
    };
    let back = decode::<JoinRequest>(&encode(&request).unwrap()).unwrap();
    assert!(same_request(&request, &back));
}

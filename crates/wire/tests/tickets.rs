#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::string_slice
)]

mod harness;

use std::fmt::{Debug, Display};
use std::sync::{Barrier, Mutex};
use std::time::{Duration, Instant};

use iroh_base::{EndpointAddr, EndpointId, RelayUrl, SecretKey, Signature};
use kickoff_secret::Secret;
use kickoff_wire::{
    BEARER_TTL, Cap, InviteError, Invites, JoinRefused, JoinRequest, MAX_OUTSTANDING,
    MAX_TICKET_LEN, Nonce, Redeemed, SessionId, Ticket, WireError, encode_ticket, parse_ticket,
};
use proptest::prelude::*;

// Inherent methods win over trait methods only when their bounds hold, so
// `probe` answers "does T implement the trait" at compile time.
macro_rules! implements {
    ($ty:ty: $($bound:tt)+) => {{
        struct Probe<T: ?Sized>(std::marker::PhantomData<T>);
        #[allow(dead_code)]
        trait Fallback {
            fn probe(&self) -> bool {
                false
            }
        }
        impl<T: ?Sized> Fallback for Probe<T> {}
        #[allow(dead_code)]
        impl<T: ?Sized + $($bound)+> Probe<T> {
            fn probe(&self) -> bool {
                true
            }
        }
        Probe::<$ty>(std::marker::PhantomData).probe()
    }};
}

fn key(n: u8) -> Secret<SecretKey> {
    Secret::new(SecretKey::from_bytes(&[n; 32]))
}

fn id(n: u8) -> EndpointId {
    SecretKey::from_bytes(&[n; 32]).public()
}

fn relay() -> RelayUrl {
    "https://use1-1.relay.n0.iroh.link./".parse().unwrap()
}

fn door(key: &Secret<SecretKey>) -> EndpointAddr {
    EndpointAddr::new(key.expose(SecretKey::public)).with_relay_url(relay())
}

fn copy(cap: &Cap) -> Cap {
    Cap {
        session_id: cap.session_id,
        invitee: cap.invitee,
        nonce: cap.nonce,
        sig: cap.sig,
    }
}

fn ticket_text(door_key: &Secret<SecretKey>, cap: &Cap) -> String {
    let ticket = Ticket {
        door: door(door_key),
        cap: copy(cap),
    };
    encode_ticket(&ticket).unwrap().expose(String::clone)
}

/// What a guest's join request carries after the ticket went through text.
fn cap_from_text(text: &str) -> Cap {
    parse_ticket(text).unwrap().expose(|t| copy(&t.cap))
}

#[test]
fn ticket_round_trips_through_text() {
    let door_key = key(1);
    let mut invites = Invites::new(&door_key).unwrap();
    let t0 = Instant::now();
    for invitee in [Some(id(2)), None] {
        let cap = invites.issue(&door_key, invitee, t0).unwrap();
        let text = ticket_text(&door_key, &cap);
        assert!(text.starts_with("kickoff1"));
        assert!(text.len() <= MAX_TICKET_LEN);
        let parsed = parse_ticket(&text).unwrap();
        parsed.expose(|t| {
            assert_eq!(t.door, door(&door_key));
            assert!(t.cap.session_id == cap.session_id);
            assert_eq!(t.cap.invitee, invitee);
            assert!(t.cap.nonce == cap.nonce);
            assert_eq!(t.cap.sig, cap.sig);
        });
        let requester = invitee.unwrap_or(id(9));
        assert!(invites.redeem(&cap_from_text(&text), requester, t0).is_ok());
    }
}

#[test]
fn ticket_text_accepts_either_case_and_nothing_else() {
    let door_key = key(1);
    let mut invites = Invites::new(&door_key).unwrap();
    let cap = invites.issue(&door_key, None, Instant::now()).unwrap();
    let text = ticket_text(&door_key, &cap);

    assert!(parse_ticket(&text.to_ascii_uppercase()).is_ok());
    for bad in [
        String::new(),
        "kickoff1".to_owned(),
        text.replacen("kickoff1", "kickoff2", 1),
        format!("{text}a"),
        format!("{text}="),
        format!(" {text}"),
        format!("kickoff://join/{}", &text[8..]),
        text[..text.len() - 1].to_owned(),
    ] {
        assert_eq!(parse_ticket(&bad).err(), Some(WireError::Malformed));
    }
    assert_eq!(
        parse_ticket(&"k".repeat(MAX_TICKET_LEN + 1)).err(),
        Some(WireError::TooLong {
            max: MAX_TICKET_LEN
        })
    );
}

#[test]
fn ticket_from_a_newer_version_is_a_version_error() {
    let door_key = key(1);
    let mut invites = Invites::new(&door_key).unwrap();
    let cap = invites.issue(&door_key, None, Instant::now()).unwrap();
    let text = ticket_text(&door_key, &cap);
    let mut bytes = data_encoding::BASE32_NOPAD
        .decode(text[8..].to_ascii_uppercase().as_bytes())
        .unwrap();
    for (v, want) in [(2u8, WireError::Version), (0, WireError::Malformed)] {
        bytes[0] = v;
        let edited = format!(
            "kickoff1{}",
            data_encoding::BASE32_NOPAD
                .encode(&bytes)
                .to_ascii_lowercase()
        );
        assert_eq!(parse_ticket(&edited).err(), Some(want));
    }
}

#[test]
fn si_29_ticket_cannot_carry_direct_address() {
    let door_key = key(1);
    let mut invites = Invites::new(&door_key).unwrap();
    let cap = invites.issue(&door_key, None, Instant::now()).unwrap();

    // Refused when minted: a door is relay-only.
    for ip in [
        "127.0.0.1:7777",
        "192.168.1.10:1",
        "[::1]:443",
        "100.64.0.1:9",
    ] {
        let ticket = Ticket {
            door: door(&door_key).with_ip_addr(ip.parse().unwrap()),
            cap: copy(&cap),
        };
        assert!(encode_ticket(&ticket).is_err(), "{ip}");
    }

    // Refused when parsed: splice an address list (one IPv4 loopback entry,
    // in the form `Admitted` uses) after the door's relays. The ticket form
    // has no field for it, so the result cannot decode.
    let text = ticket_text(&door_key, &cap);
    let mut bytes = data_encoding::BASE32_NOPAD
        .decode(text[8..].to_ascii_uppercase().as_bytes())
        .unwrap();
    let relays_end = 1 + 32 + 1 + 1 + relay().to_string().len();
    for (i, b) in [1u8, 0, 127, 0, 0, 1, 0x61].into_iter().enumerate() {
        bytes.insert(relays_end + i, b);
    }
    let forged = format!(
        "kickoff1{}",
        data_encoding::BASE32_NOPAD
            .encode(&bytes)
            .to_ascii_lowercase()
    );
    assert!(parse_ticket(&forged).is_err());

    // Relay text that is not plain https never reaches the URL parser's
    // output. Whether an https relay is in the compiled map is net::egress's
    // check.
    for url in ["http://relay.example./", "file:///etc/passwd"] {
        let ticket = Ticket {
            door: EndpointAddr::new(door_key.expose(SecretKey::public))
                .with_relay_url(url.parse().unwrap()),
            cap: copy(&cap),
        };
        assert!(encode_ticket(&ticket).is_err(), "{url}");
    }
}

#[test]
fn si_30_caps_tickets_and_join_requests_cannot_be_printed_cloned_or_serialized() {
    assert!(implements!(Signature: Debug));
    assert!(implements!(Signature: serde::Serialize));
    assert!(implements!(Signature: Clone));

    assert!(!implements!(Cap: Debug));
    assert!(!implements!(Cap: Display));
    assert!(!implements!(Cap: Clone));
    assert!(!implements!(Cap: serde::Serialize));
    assert!(!implements!(Ticket: Debug));
    assert!(!implements!(Ticket: Clone));
    assert!(!implements!(Ticket: serde::Serialize));
    assert!(!implements!(JoinRequest: Debug));
    assert!(!implements!(JoinRequest: Clone));
    assert!(!implements!(JoinRequest: serde::Serialize));
    assert!(!implements!(Nonce: Debug));
    assert!(!implements!(SessionId: Debug));
    assert!(!implements!(Invites: Debug));
}

#[test]
fn si_30_ticket_errors_carry_no_input() {
    let canary = "c4n4ryzq";
    let door_key = key(1);
    let mut invites = Invites::new(&door_key).unwrap();
    let cap = invites.issue(&door_key, None, Instant::now()).unwrap();
    let text = ticket_text(&door_key, &cap);
    for bad in [
        format!("kickoff1{canary}"),
        format!("{canary}{text}"),
        format!("{text}{canary}"),
        format!("kickoff1{}", canary.repeat(300)),
    ] {
        let err = parse_ticket(&bad).err().unwrap();
        for shown in [format!("{err}"), format!("{err:?}")] {
            assert!(!shown.contains(canary), "{shown}");
            assert!(!shown.contains(&text[8..16]), "{shown}");
        }
    }
}

#[test]
fn si_20_capability_admits_at_most_once() {
    let door_key = key(1);
    let invites = Mutex::new(Invites::new(&door_key).unwrap());
    let t0 = Instant::now();
    for invitee in [Some(id(2)), None] {
        let cap = invites
            .lock()
            .unwrap()
            .issue(&door_key, invitee, t0)
            .unwrap();
        let requester = invitee.unwrap_or(id(3));
        let racers = 32;
        let start = Barrier::new(racers);
        let admitted: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..racers)
                .map(|_| {
                    let cap = copy(&cap);
                    let (start, invites) = (&start, &invites);
                    scope.spawn(move || {
                        start.wait();
                        invites.lock().unwrap().redeem(&cap, requester, t0).is_ok()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum()
        });
        assert_eq!(admitted, 1, "invitee {invitee:?}");
    }
}

#[test]
fn si_20_replayed_capability_refused() {
    let door_key = key(1);
    let mut invites = Invites::new(&door_key).unwrap();
    let t0 = Instant::now();

    let bound = invites.issue(&door_key, Some(id(2)), t0).unwrap();
    assert_eq!(invites.redeem(&bound, id(2), t0), Ok(Redeemed::Bound));
    let replay = cap_from_text(&ticket_text(&door_key, &bound));
    assert_eq!(
        invites.redeem(&replay, id(2), t0),
        Err(JoinRefused::InvalidCap)
    );

    let bearer = invites.issue(&door_key, None, t0).unwrap();
    assert_eq!(invites.redeem(&bearer, id(3), t0), Ok(Redeemed::Bearer));
    assert_eq!(
        invites.redeem(&bearer, id(4), t0),
        Err(JoinRefused::InvalidCap)
    );
    assert_eq!(
        invites.redeem(&bearer, id(3), t0),
        Err(JoinRefused::InvalidCap)
    );
}

#[test]
fn si_20_ticket_from_another_session_or_host_process_refused() {
    // Same door key, a second ledger: what a restarted host process holds.
    let door_key = key(1);
    let mut before = Invites::new(&door_key).unwrap();
    let mut after = Invites::new(&door_key).unwrap();
    let t0 = Instant::now();
    for invitee in [Some(id(2)), None] {
        let cap = before.issue(&door_key, invitee, t0).unwrap();
        assert_eq!(
            after.redeem(&cap, invitee.unwrap_or(id(3)), t0),
            Err(JoinRefused::WrongSession)
        );
    }
}

#[test]
fn si_20_bearer_validity_uses_host_monotonic_clock() {
    let door_key = key(1);
    let mut invites = Invites::new(&door_key).unwrap();
    let t0 = Instant::now();

    let fresh = invites.issue(&door_key, None, t0).unwrap();
    let just_in_time = t0 + BEARER_TTL - Duration::from_millis(1);
    assert_eq!(
        invites.redeem(&fresh, id(3), just_in_time),
        Ok(Redeemed::Bearer)
    );

    let stale = invites.issue(&door_key, None, t0).unwrap();
    assert_eq!(
        invites.redeem(&stale, id(3), t0 + BEARER_TTL),
        Err(JoinRefused::Expired)
    );
    // Expiry spent it: a later attempt does not get a second answer.
    assert_eq!(
        invites.redeem(&stale, id(3), t0),
        Err(JoinRefused::InvalidCap)
    );

    // A bound invite lasts as long as the session.
    let bound = invites.issue(&door_key, Some(id(2)), t0).unwrap();
    let much_later = t0 + Duration::from_secs(48 * 3600);
    assert_eq!(
        invites.redeem(&bound, id(2), much_later),
        Ok(Redeemed::Bound)
    );
}

#[test]
fn bound_invite_refuses_other_identities_and_stays_valid() {
    let door_key = key(1);
    let mut invites = Invites::new(&door_key).unwrap();
    let t0 = Instant::now();
    let cap = invites.issue(&door_key, Some(id(2)), t0).unwrap();
    for stranger in [id(3), id(4), door_key.expose(SecretKey::public)] {
        assert_eq!(
            invites.redeem(&cap, stranger, t0),
            Err(JoinRefused::InvalidCap)
        );
    }
    assert_eq!(invites.redeem(&cap, id(2), t0), Ok(Redeemed::Bound));
}

#[test]
fn caps_from_another_door_refused() {
    let door_key = key(1);
    let other = key(5);
    let mut ours = Invites::new(&door_key).unwrap();
    let mut theirs = Invites::new(&other).unwrap();
    let t0 = Instant::now();
    let foreign = theirs.issue(&other, None, t0).unwrap();
    assert_eq!(
        ours.redeem(&foreign, id(3), t0),
        Err(JoinRefused::InvalidCap)
    );
    assert_eq!(
        ours.issue(&other, None, t0).err(),
        Some(InviteError::WrongKey)
    );
}

#[test]
fn ledger_capacity_is_fixed_and_expired_bearers_make_room() {
    let door_key = key(1);
    let mut invites = Invites::new(&door_key).unwrap();
    let t0 = Instant::now();
    for _ in 0..MAX_OUTSTANDING {
        invites.issue(&door_key, None, t0).unwrap();
    }
    assert_eq!(
        invites.issue(&door_key, Some(id(2)), t0).err(),
        Some(InviteError::Full)
    );
    assert!(
        invites
            .issue(&door_key, Some(id(2)), t0 + BEARER_TTL)
            .is_ok()
    );
}

proptest! {
    #[test]
    fn ticket_signature_covers_every_field(
        bound in any::<bool>(),
        field in 0usize..5,
        bit in 0usize..512,
    ) {
        let door_key = key(1);
        let mut invites = Invites::new(&door_key).unwrap();
        let t0 = Instant::now();
        let invitee = bound.then(|| id(2));
        let requester = invitee.unwrap_or(id(3));
        let cap = invites.issue(&door_key, invitee, t0).unwrap();

        let mut forged = copy(&cap);
        match field {
            0 => forged.session_id.0[bit % 128 / 8] ^= 1 << (bit % 8),
            1 => forged.nonce.0[bit % 128 / 8] ^= 1 << (bit % 8),
            2 => {
                let mut sig = cap.sig.to_bytes();
                sig[bit / 8] ^= 1 << (bit % 8);
                forged.sig = Signature::from_bytes(&sig);
            }
            3 => forged.invitee = if bound { None } else { Some(requester) },
            _ => forged.invitee = Some(id(4 + u8::from(bound))),
        }
        prop_assert!(invites.redeem(&forged, requester, t0).is_err());
        if field == 4 {
            prop_assert!(invites.redeem(&forged, id(4 + u8::from(bound)), t0).is_err());
        }
        // A refused forgery leaves the real capability unspent.
        prop_assert!(invites.redeem(&cap, requester, t0).is_ok());
    }

    #[test]
    fn ticket_harness_holds_for_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        harness::ticket(&data);
    }

    #[test]
    fn ticket_harness_holds_for_mutated_valid_tickets(
        invitee in any::<bool>(),
        flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
    ) {
        let door_key = key(1);
        let mut invites = Invites::new(&door_key).unwrap();
        let cap = invites.issue(&door_key, invitee.then(|| id(2)), Instant::now()).unwrap();
        let text = ticket_text(&door_key, &cap);
        let mut bytes = data_encoding::BASE32_NOPAD
            .decode(text[8..].to_ascii_uppercase().as_bytes())
            .unwrap();
        harness::ticket(&bytes);
        for (at, value) in &flips {
            let i = at.index(bytes.len());
            bytes[i] = *value;
        }
        harness::ticket(&bytes);
    }
}

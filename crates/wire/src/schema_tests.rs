//! SI-3: no peer message can express "EAC on", a game path, a launch option or
//! a write outside the copy. The check walks the traced wire schema of every
//! peer-facing message rather than a list of today's fields, so a field added
//! tomorrow is checked without anyone remembering to.

use std::collections::BTreeSet;

use bytes::Bytes;
use iroh_base::{EndpointAddr, EndpointId, RelayUrl, SecretKey, Signature};
use serde_reflection::{
    ContainerFormat, Format, Named, Registry, Samples, Tracer, TracerConfig, VariantFormat,
};

use crate::addr::DoorRepr;
use crate::msg::JoinRequestRepr;
use crate::ticket::{CapRepr, TicketRepr};
use crate::{
    AdmitPass, Admitted, BoundedVec, BundleBlob, Cap, GameState, Generation, GuestMsg, HostMsg,
    JoinRefused, JoinReply, JoinRequest, KickReason, KickoffVersion, MapId, Member, Name, Nonce,
    PeerSlot, Platform, SessionId,
};

/// Words that name what SI-3 forbids a peer to express. Matched against every
/// container, variant and field name, split into words.
const FORBIDDEN_WORDS: &[&str] = &[
    "path",
    "file",
    "dir",
    "folder",
    "url",
    "uri",
    "eac",
    "anticheat",
    "launch",
    "arg",
    "args",
    "argv",
    "cmd",
    "command",
    "exec",
    "exe",
    "env",
    "shell",
    "script",
    "write",
    "install",
    "mode",
];

/// The only places a peer may put free-form text or bytes, and why each is
/// harmless. Anything else that decodes to a string or a byte run fails.
const FREE_FORM_ALLOWED: &[(&str, &str)] = &[
    // Display text: bounded, no control characters, never a path (§2.3 RelName).
    ("Member", "name"),
    ("JoinRequest", "name"),
    // Compared against the local build; never opened or executed.
    ("JoinRequest", "game_build"),
    // Relay destinations: plain https only, and used only if they equal an
    // entry in the compiled relay map (net::egress, SI-29).
    ("Addr", "relays"),
    ("DoorAddr", "relays"),
    // Opaque; decoded only inside kickoff-parse's sandbox (§5.6).
    ("HostMsg::MapPick", "bundle"),
];

fn words(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    for c in name.chars() {
        if c == '_' || c == ':' {
            out.push(std::mem::take(&mut word));
        } else if c.is_uppercase() {
            out.push(std::mem::take(&mut word));
            word.extend(c.to_lowercase());
        } else {
            word.push(c);
        }
    }
    out.push(word);
    out.retain(|w| !w.is_empty());
    out
}

fn is_free_form(format: &Format) -> bool {
    match format {
        Format::Str | Format::Bytes => true,
        Format::Seq(inner) => matches!(**inner, Format::U8 | Format::I8) || is_free_form(inner),
        Format::Option(inner) => is_free_form(inner),
        Format::TupleArray { content, .. } => is_free_form(content),
        Format::Tuple(items) => items.iter().any(is_free_form),
        Format::Map { key, value } => is_free_form(key) || is_free_form(value),
        _ => false,
    }
}

/// Every (owner, field) in the schema with its format. Unnamed fields get
/// their position as a name.
fn fields(registry: &Registry) -> Vec<(String, String, Format)> {
    fn named(owner: &str, list: &[Named<Format>], out: &mut Vec<(String, String, Format)>) {
        for field in list {
            out.push((owner.to_owned(), field.name.clone(), field.value.clone()));
        }
    }
    fn unnamed(owner: &str, list: &[Format], out: &mut Vec<(String, String, Format)>) {
        for (i, format) in list.iter().enumerate() {
            out.push((owner.to_owned(), i.to_string(), format.clone()));
        }
    }
    let mut out = Vec::new();
    for (name, container) in registry {
        match container {
            ContainerFormat::UnitStruct => {}
            ContainerFormat::NewTypeStruct(format) => {
                unnamed(name, std::slice::from_ref(format), &mut out);
            }
            ContainerFormat::TupleStruct(list) => unnamed(name, list, &mut out),
            ContainerFormat::Struct(list) => named(name, list, &mut out),
            ContainerFormat::Enum(variants) => {
                for variant in variants.values() {
                    let owner = format!("{name}::{}", variant.name);
                    match &variant.value {
                        VariantFormat::Unit | VariantFormat::Variable(_) => {}
                        VariantFormat::NewType(format) => {
                            unnamed(&owner, std::slice::from_ref(format), &mut out);
                        }
                        VariantFormat::Tuple(list) => unnamed(&owner, list, &mut out),
                        VariantFormat::Struct(list) => named(&owner, list, &mut out),
                    }
                }
            }
        }
    }
    out
}

/// Every container and variant name in the schema.
fn names(registry: &Registry) -> Vec<String> {
    let mut out = Vec::new();
    for (name, container) in registry {
        out.push(name.clone());
        if let ContainerFormat::Enum(variants) = container {
            out.extend(variants.values().map(|v| format!("{name}::{}", v.name)));
        }
    }
    out
}

fn id(n: u8) -> EndpointId {
    SecretKey::from_bytes(&[n; 32]).public()
}

fn cap() -> Cap {
    Cap {
        session_id: SessionId([1; 16]),
        invitee: Some(id(2)),
        nonce: Nonce([3; 16]),
        sig: Signature::from_bytes(&[4; 64]),
    }
}

/// The traced schema of every message a peer can send or Kickoff decodes from
/// peer-supplied text: join and control messages, and tickets.
fn peer_schema() -> Registry {
    let relay: RelayUrl = "https://relay.example./".parse().unwrap();
    let session_addr = EndpointAddr::new(id(1))
        .with_relay_url(relay.clone())
        .with_ip_addr("192.0.2.1:7777".parse().unwrap());
    let door = EndpointAddr::new(id(1)).with_relay_url(relay);
    let name = Name::new("player").unwrap();

    let mut tracer = Tracer::new(
        TracerConfig::default()
            .record_samples_for_structs(true)
            .record_samples_for_tuple_structs(true)
            .default_u8_value(1)
            .default_borrowed_str_value("https://relay.example./"),
    );
    let mut samples = Samples::new();
    let request = JoinRequestRepr::from_request(&JoinRequest {
        cap: cap(),
        session_key: id(5),
        name: name.clone(),
        platform: Platform::Linux,
        game_build: crate::BuildId::new("build").unwrap(),
        kickoff_version: KickoffVersion {
            major: 0,
            minor: 1,
            patch: 0,
        },
    });
    tracer.trace_value(&mut samples, &request).unwrap();
    let reply = JoinReply::Admitted(Admitted {
        session_addr,
        pass: AdmitPass {
            slot: PeerSlot::HOST,
            generation: Generation::new(1),
        },
    });
    tracer.trace_value(&mut samples, &reply).unwrap();
    let ticket = TicketRepr::new(
        DoorRepr::from_addr(&door).unwrap(),
        CapRepr::from_cap(&cap()),
    );
    tracer.trace_value(&mut samples, &ticket).unwrap();
    for msg in [
        GuestMsg::Hello {
            generation: Generation::new(1),
        },
        GuestMsg::Status {
            game_state: GameState::Lobby,
            have: BoundedVec::new(vec![MapId([7; 32])]).unwrap(),
        },
    ] {
        tracer.trace_value(&mut samples, &msg).unwrap();
    }
    for msg in [
        HostMsg::Roster {
            epoch: 1,
            members: BoundedVec::new(vec![Member {
                slot: PeerSlot::HOST,
                id: id(1),
                name,
            }])
            .unwrap(),
        },
        HostMsg::MapPick {
            bundle: BundleBlob(Bytes::from_static(b"bundle")),
        },
        HostMsg::Kick {
            reason: KickReason::Kicked,
        },
    ] {
        tracer.trace_value(&mut samples, &msg).unwrap();
    }
    // Deserialization tracing reaches every variant, including ones no
    // sample above constructs. Field-less enums go first: the containers
    // below need all their variants known.
    tracer.trace_simple_type::<Platform>().unwrap();
    tracer.trace_simple_type::<GameState>().unwrap();
    tracer.trace_simple_type::<KickReason>().unwrap();
    tracer.trace_simple_type::<JoinRefused>().unwrap();
    tracer.trace_type::<JoinRequestRepr>(&samples).unwrap();
    tracer.trace_type::<JoinReply>(&samples).unwrap();
    tracer.trace_type::<GuestMsg>(&samples).unwrap();
    tracer.trace_type::<HostMsg>(&samples).unwrap();
    tracer.trace_type::<TicketRepr>(&samples).unwrap();
    tracer.registry().unwrap()
}

#[test]
fn si_3_peer_messages_cannot_express_eac_paths_or_launch_options() {
    let registry = peer_schema();
    for name in ["JoinRequest", "JoinReply", "GuestMsg", "HostMsg", "Ticket"] {
        assert!(registry.contains_key(name), "{name} was not traced");
    }

    let mut every_name = names(&registry);
    every_name.extend(fields(&registry).into_iter().map(|(_, field, _)| field));
    for name in &every_name {
        for word in words(name) {
            assert!(
                !FORBIDDEN_WORDS.contains(&word.as_str()),
                "{name} names something SI-3 forbids a peer to express"
            );
        }
    }

    let allowed: BTreeSet<(&str, &str)> = FREE_FORM_ALLOWED.iter().copied().collect();
    let mut seen = BTreeSet::new();
    for (owner, field, format) in fields(&registry) {
        if is_free_form(&format) {
            assert!(
                allowed.contains(&(owner.as_str(), field.as_str())),
                "{owner}.{field} carries free-form text or bytes ({format:?}); \
                 a peer could put a path, URL or launch option there"
            );
            seen.insert((owner, field));
        }
    }
    // A stale allowlist entry would quietly admit a future field of that name.
    for (owner, field) in &allowed {
        assert!(
            seen.contains(&((*owner).to_owned(), (*field).to_owned())),
            "allowlisted {owner}.{field} no longer exists"
        );
    }
}

/// `decode` tells a newer peer's message from a malformed one by each type's
/// variant count, so the count must track the enum.
#[test]
fn variant_counts_match_the_messages() {
    use crate::msg::sealed::Sealed;

    fn count(registry: &Registry, name: &str) -> Option<u32> {
        match registry.get(name)? {
            ContainerFormat::Enum(variants) => u32::try_from(variants.len()).ok(),
            _ => None,
        }
    }
    let registry = peer_schema();
    assert_eq!(count(&registry, "JoinReply"), JoinReply::VARIANTS);
    assert_eq!(count(&registry, "GuestMsg"), GuestMsg::VARIANTS);
    assert_eq!(count(&registry, "HostMsg"), HostMsg::VARIANTS);
    assert_eq!(count(&registry, "JoinRequest"), JoinRequest::VARIANTS);
}

#[test]
fn schema_words_split_snake_and_camel_case() {
    assert_eq!(words("game_build"), ["game", "build"]);
    assert_eq!(words("HostMsg::MapPick"), ["host", "msg", "map", "pick"]);
    assert_eq!(words("eacMode"), ["eac", "mode"]);
}

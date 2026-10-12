//! `Ticket = "kickoff1" + base32(postcard{ v: 1, door, cap })`, at most
//! `MAX_TICKET_LEN` bytes (§4.2). Tickets are secrets (§6.4): they exist only
//! as `Secret<Ticket>`, and neither they nor the capabilities inside them
//! implement `Debug`, `Clone` or a serde trait.

use data_encoding::BASE32_NOPAD;
use iroh_base::{EndpointAddr, EndpointId, Signature};
use kickoff_secret::SecretBuffer;
use kickoff_secret::key::IdentityKey;
use kickoff_secret::{OwnedSecret, Secret, Wipe};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::WireError;
use crate::addr::DoorRepr;

pub const MAX_TICKET_LEN: usize = 2 * 1024;

const TICKET_PREFIX: &str = "kickoff1";
const TICKET_VERSION: u8 = 1;
/// Domain separation for capability signatures. The door key also signs TLS
/// handshakes, whose signed content starts with 64 spaces, so no capability
/// message can double as a handshake signature or the reverse.
const CAP_CONTEXT: &[u8] = b"kickoff/cap/1\0";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 16]);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce(pub [u8; 16]);

/// Signed by the door key over every other field and the door's identity.
/// `invitee: Some` is a bound invite; `None` is a bearer invite. Either admits
/// at most once (SI-20); see `Invites`.
pub struct Cap {
    value: Secret<CapValue>,
}

pub(crate) struct CapValue {
    issuer: Option<EndpointId>,
    pub(crate) session_id: SessionId,
    pub(crate) invitee: Option<EndpointId>,
    pub(crate) nonce: Nonce,
    pub(crate) sig: [u8; 64],
}

/// Constructible only by the wire owner. Coherence prevents another crate
/// from assigning a different consumer to any of these secret kinds.
#[cfg(not(feature = "mutant-si30-open-owner"))]
pub struct WireConsumer {
    _private: (),
}
#[cfg(not(feature = "mutant-si30-open-owner"))]
pub(crate) const OWNER: WireConsumer = WireConsumer { _private: () };
#[cfg(feature = "mutant-si30-open-owner")]
pub type WireConsumer = ();
#[cfg(feature = "mutant-si30-open-owner")]
pub(crate) const OWNER: WireConsumer = ();

impl OwnedSecret for CapValue {
    type Consumer = WireConsumer;
}
impl Wipe for CapValue {
    fn wipe(&mut self) {
        self.session_id.0.zeroize();
        self.nonce.0.zeroize();
        self.sig.zeroize();
        #[cfg(test)]
        WIPE_AUDIT.with(|audit| {
            audit.borrow_mut().push(
                self.session_id.0 == [0; 16] && self.nonce.0 == [0; 16] && self.sig == [0; 64],
            )
        });
    }
}

#[cfg(feature = "mutant-si30-cap-debug")]
impl std::fmt::Debug for Cap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cap")
    }
}

impl Cap {
    /// Accepts caller-owned input, but never returns its raw fields.
    pub fn new(
        session_id: SessionId,
        invitee: Option<EndpointId>,
        nonce: Nonce,
        sig: Signature,
    ) -> Self {
        Self {
            value: Secret::new(CapValue {
                issuer: None,
                session_id,
                invitee,
                nonce,
                sig: sig.to_bytes(),
            }),
        }
    }
    /// Caller-owned raw inputs can identify their intended door. Existing
    /// protected capabilities have no operation that changes this authority.
    pub fn new_for_door(
        issuer: EndpointId,
        session_id: SessionId,
        invitee: Option<EndpointId>,
        nonce: Nonce,
        sig: Signature,
    ) -> Self {
        Self {
            value: Secret::new(CapValue {
                issuer: Some(issuer),
                session_id,
                invitee,
                nonce,
                sig: sig.to_bytes(),
            }),
        }
    }
    pub(crate) fn issuing_door(&self) -> Option<EndpointId> {
        self.read(|cap| cap.issuer)
    }
    pub fn invitee(&self) -> Option<EndpointId> {
        self.read(|cap| cap.invitee)
    }
    pub fn copy_for_join(&self) -> Self {
        self.read(|cap| Self {
            value: Secret::new(CapValue {
                issuer: cap.issuer,
                session_id: cap.session_id,
                invitee: cap.invitee,
                nonce: cap.nonce,
                sig: cap.sig,
            }),
        })
    }
    pub(crate) fn read<R>(&self, operation: impl FnOnce(&CapValue) -> R) -> R {
        self.value.expose(&OWNER, operation)
    }
    pub(crate) fn sign(
        door_key: &IdentityKey,
        session_id: SessionId,
        invitee: Option<EndpointId>,
        nonce: Nonce,
    ) -> Self {
        let msg = signed_message(&door_key.public(), &session_id, invitee.as_ref(), &nonce);
        Self::new_for_door(
            door_key.public(),
            session_id,
            invitee,
            nonce,
            door_key.sign(&msg),
        )
    }
    pub(crate) fn verify(&self, door: &EndpointId) -> bool {
        self.read(|cap| {
            let msg = signed_message(door, &cap.session_id, cap.invitee.as_ref(), &cap.nonce);
            door.verify(&msg, &Signature::from_bytes(&cap.sig)).is_ok()
        })
    }
}

/// The bytes the door key signs: every capability field and the door's own
/// identity. The single owner of that layout; `sign` and `verify` both call it.
fn signed_message(
    door: &EndpointId,
    session_id: &SessionId,
    invitee: Option<&EndpointId>,
    nonce: &Nonce,
) -> SecretBuffer {
    let mut msg = SecretBuffer::with_capacity(CAP_CONTEXT.len().saturating_add(32 + 16 + 33 + 16));
    msg.extend_from_slice(CAP_CONTEXT);
    msg.extend_from_slice(door.as_bytes());
    msg.extend_from_slice(&session_id.0);
    match invitee {
        Some(id) => {
            msg.push(1);
            msg.extend_from_slice(id.as_bytes());
        }
        None => msg.push(0),
    }
    msg.extend_from_slice(&nonce.0);
    msg
}

/// The door's addresses are authentic only as far as the channel that carried
/// the ticket; TLS pins the door identity, so an edited address can only break
/// the dial (§4.2). The door is relay-only, so a ticket carries no direct
/// address: one that does fails to parse (SI-29).
pub struct Ticket {
    pub door: EndpointAddr,
    pub cap: Cap,
}

impl OwnedSecret for Ticket {
    type Consumer = WireConsumer;
}
impl Wipe for Ticket {
    fn wipe(&mut self) { /* The nested Secret<CapValue> wipes when this ticket drops. */
    }
}

impl Ticket {
    pub fn door(ticket: &Secret<Self>) -> EndpointAddr {
        ticket.expose(&OWNER, |t| t.door.clone())
    }
    pub fn is_bearer(ticket: &Secret<Self>) -> bool {
        ticket.expose(&OWNER, |t| t.cap.invitee().is_none())
    }
    pub fn join_cap(ticket: &Secret<Self>) -> Cap {
        ticket.expose(&OWNER, |t| t.cap.copy_for_join())
    }
}

/// Protected textual encoding shared by wire and IPC. Plaintext remains
/// inside the wire consumer during parsing and designated transmission.
pub struct TicketTextValue(String);
impl Wipe for TicketTextValue {
    fn wipe(&mut self) {
        self.0.zeroize();
    }
}
impl OwnedSecret for TicketTextValue {
    type Consumer = WireConsumer;
}
impl AsRef<[u8]> for TicketTextValue {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
impl TicketTextValue {
    pub fn protect(text: String) -> Secret<Self> {
        Secret::new(Self(text))
    }
    pub fn is_alphanumeric(text: &Secret<Self>) -> bool {
        text.expose(&OWNER, |t| {
            (1..=MAX_TICKET_LEN).contains(&t.0.len())
                && t.0.bytes().all(|b| b.is_ascii_alphanumeric())
        })
    }
    #[cfg(feature = "mutant-si30-ticket-transport")]
    pub fn transport(text: &Secret<Self>) -> SecretBuffer {
        text.expose(&OWNER, |t| SecretBuffer::copy_from(t.0.as_bytes()))
    }
    #[cfg(all(test, not(feature = "mutant-si30-ticket-transport")))]
    pub(crate) fn transport(text: &Secret<Self>) -> SecretBuffer {
        text.expose(&OWNER, |t| SecretBuffer::copy_from(t.0.as_bytes()))
    }

    /// The sole string field of a postcard enum variant, framed for IPC.
    /// The borrowed representation stays within the designated wire consumer.
    pub fn postcard_frame(
        text: &Secret<Self>,
        variant: u32,
    ) -> Result<crate::Transmission, WireError> {
        text.expose(&OWNER, |t| {
            if t.0.len() > MAX_TICKET_LEN {
                return Err(WireError::TooLong {
                    max: MAX_TICKET_LEN,
                });
            }
            // Postcard enums encode the variant index followed by its fields.
            let body = crate::msg::postcard_write(
                &(variant, t.0.as_str()),
                MAX_TICKET_LEN.saturating_add(10),
            )?;
            crate::Transmission::local(body)
        })
    }

    pub fn parse(text: &Secret<Self>) -> Result<Secret<Ticket>, WireError> {
        text.expose(&OWNER, |t| parse_ticket(&t.0))
    }
}

mod signature_bytes {
    use serde::{
        Deserializer, Serializer,
        de::{Error, SeqAccess, Visitor},
        ser::SerializeTuple,
    };
    use zeroize::Zeroizing;
    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_tuple(64)?;
        for byte in bytes {
            sequence.serialize_element(byte)?;
        }
        sequence.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        struct Bytes;
        impl<'de> Visitor<'de> for Bytes {
            type Value = [u8; 64];
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("64 signature bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = Zeroizing::new([0; 64]);
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = sequence
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                }
                Ok(*bytes)
            }
        }
        deserializer.deserialize_tuple(64, Bytes)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "Cap")]
pub(crate) struct CapRepr {
    session_id: [u8; 16],
    invitee: Option<EndpointId>,
    nonce: [u8; 16],
    #[serde(with = "signature_bytes")]
    sig: [u8; 64],
}

impl CapRepr {
    pub(crate) fn from_cap(cap: &Cap) -> CapRepr {
        cap.read(|cap| CapRepr {
            session_id: cap.session_id.0,
            invitee: cap.invitee,
            nonce: cap.nonce.0,
            sig: cap.sig,
        })
    }

    pub(crate) fn into_cap(self) -> Cap {
        Cap {
            value: Secret::new(CapValue {
                issuer: None,
                session_id: SessionId(self.session_id),
                invitee: self.invitee,
                nonce: Nonce(self.nonce),
                sig: self.sig,
            }),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "Ticket")]
pub(crate) struct TicketRepr {
    v: u8,
    door: DoorRepr,
    cap: CapRepr,
}

impl TicketRepr {
    pub(crate) fn new(door: DoorRepr, cap: CapRepr) -> TicketRepr {
        TicketRepr {
            v: TICKET_VERSION,
            door,
            cap,
        }
    }
}

impl Drop for CapRepr {
    fn drop(&mut self) {
        if !cfg!(feature = "mutant-si30-cap-repr-no-wipe") {
            self.session_id.zeroize();
            self.nonce.zeroize();
            self.sig.zeroize();
        }
        #[cfg(test)]
        WIPE_AUDIT.with(|audit| {
            audit
                .borrow_mut()
                .push(self.session_id == [0; 16] && self.nonce == [0; 16] && self.sig == [0; 64])
        });
    }
}

#[cfg(test)]
thread_local! { static WIPE_AUDIT: std::cell::RefCell<Vec<bool>> = const { std::cell::RefCell::new(Vec::new()) }; }

fn ticket_bytes(ticket: &Ticket) -> Result<SecretBuffer, WireError> {
    let repr = TicketRepr::new(
        DoorRepr::from_addr(&ticket.door)?,
        CapRepr::from_cap(&ticket.cap),
    );
    crate::msg::postcard_write(&repr, MAX_TICKET_LEN)
}

/// Accepts the text in either case (QR codes carry upper case). Anything but
/// the canonical encoding of the result is `Malformed`, and no error carries
/// any of the input.
pub fn parse_ticket(text: &str) -> Result<Secret<Ticket>, WireError> {
    if text.len() > MAX_TICKET_LEN {
        return Err(WireError::TooLong {
            max: MAX_TICKET_LEN,
        });
    }
    let prefix = text
        .get(..TICKET_PREFIX.len())
        .ok_or(WireError::Malformed)?;
    let body = text
        .get(TICKET_PREFIX.len()..)
        .ok_or(WireError::Malformed)?;
    if !prefix.eq_ignore_ascii_case(TICKET_PREFIX) {
        return Err(WireError::Malformed);
    }
    let uppercase = Zeroizing::new(body.to_ascii_uppercase());
    let len = BASE32_NOPAD
        .decode_len(uppercase.len())
        .map_err(|_| WireError::Malformed)?;
    let mut bytes = SecretBuffer::zeroed(len);
    let used = BASE32_NOPAD
        .decode_mut(uppercase.as_bytes(), &mut bytes)
        .map_err(|_| WireError::Malformed)?;
    bytes.truncate(used);
    match bytes.first() {
        Some(&TICKET_VERSION) => {}
        Some(&v) if v > TICKET_VERSION => return Err(WireError::Version),
        _ => return Err(WireError::Malformed),
    }
    let (repr, rest) =
        postcard::take_from_bytes::<TicketRepr>(&bytes).map_err(|_| WireError::Malformed)?;
    if !rest.is_empty() {
        return Err(WireError::Malformed);
    }
    let door = repr.door.to_addr()?;
    let cap = repr.cap.into_cap();
    if !cfg!(feature = "mutant-si30-ticket-issuer-unchecked") && !cap.verify(&door.id) {
        return Err(WireError::Malformed);
    }
    let cap = cap.read(|raw| {
        Cap::new_for_door(
            door.id,
            raw.session_id,
            raw.invitee,
            raw.nonce,
            Signature::from_bytes(&raw.sig),
        )
    });
    let ticket = Ticket { door, cap };
    if ticket_bytes(&ticket)?.as_ref() != bytes.as_ref() {
        return Err(WireError::Malformed);
    }
    Ok(Secret::new(ticket))
}

/// Refuses a door address with a direct address or no relay.
pub fn encode_ticket(ticket: &Secret<Ticket>) -> Result<Secret<TicketTextValue>, WireError> {
    ticket.expose(&OWNER, |ticket| {
        if !cfg!(feature = "mutant-si30-ticket-issuer-unchecked")
            && (ticket.cap.issuing_door() != Some(ticket.door.id)
                || !ticket.cap.verify(&ticket.door.id))
        {
            return Err(WireError::Malformed);
        }
        let bytes = ticket_bytes(ticket)?;
        let len = TICKET_PREFIX
            .len()
            .saturating_add(BASE32_NOPAD.encode_len(bytes.len()));
        if len > MAX_TICKET_LEN {
            return Err(WireError::TooLong {
                max: MAX_TICKET_LEN,
            });
        }
        let mut text = SecretBuffer::zeroed(len);
        let (prefix, body) = text.split_at_mut(TICKET_PREFIX.len());
        prefix.copy_from_slice(TICKET_PREFIX.as_bytes());
        BASE32_NOPAD.encode_mut(&bytes, body);
        body.make_ascii_lowercase();
        // The final string allocation is protected before any secret is copied.
        let mut out = TicketTextValue(String::with_capacity(len));
        out.0
            .push_str(std::str::from_utf8(&text).map_err(|_| WireError::Malformed)?);
        Ok(Secret::new(out))
    })
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use iroh_base::SecretKey;
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn si_30_ticket_and_join_values_wipe_on_success_and_decode_errors() {
        WIPE_AUDIT.with(|audit| audit.borrow_mut().clear());
        let key = key(1);
        let addr = EndpointAddr::new(key.public())
            .with_relay_url("https://relay.example./".parse().unwrap());
        let ticket = Secret::new(Ticket {
            door: addr,
            cap: Cap::sign(&key, SessionId([7; 16]), None, Nonce([9; 16])),
        });
        let encoded = encode_ticket(&ticket).unwrap();
        let parsed = TicketTextValue::parse(&encoded).unwrap();
        let request = crate::JoinRequest {
            cap: Ticket::join_cap(&parsed),
            session_key: id(2),
            name: crate::Name::new("guest").unwrap(),
            platform: crate::Platform::Linux,
            game_build: crate::BuildId::new("fixture").unwrap(),
            kickoff_version: crate::KickoffVersion {
                major: 0,
                minor: 0,
                patch: 0,
            },
        };
        let mut body = crate::prepare_message(&request).unwrap().copy_body();
        let decoded = crate::decode::<crate::JoinRequest>(&body).unwrap();
        drop(decoded);
        body.push(0);
        assert!(crate::decode::<crate::JoinRequest>(&body).is_err());
        body.truncate(40);
        assert!(crate::decode::<crate::JoinRequest>(&body).is_err());
        drop((request, parsed, ticket));
        WIPE_AUDIT.with(|audit| {
            let audit = audit.borrow();
            assert!(
                audit.len() >= 8,
                "real ticket, join, canonical and error representations were dropped"
            );
            assert!(
                audit.iter().all(|wiped| *wiped),
                "a live capability representation contained secret bytes after its wipe"
            );
        });
    }

    fn key(n: u8) -> IdentityKey {
        IdentityKey::new(SecretKey::from_bytes(&[n; 32]))
    }

    fn id(n: u8) -> EndpointId {
        SecretKey::from_bytes(&[n; 32]).public()
    }

    fn flip<const N: usize>(mut bytes: [u8; N], bit: usize) -> [u8; N] {
        bytes[bit / 8 % N] ^= 1 << (bit % 8);
        bytes
    }

    // The host's ledger also refuses most of these, so this checks the
    // signature alone: a capability is unforgeable even where the ledger is
    // not consulted.
    proptest! {
        #[test]
        fn signature_covers_every_cap_field_and_the_door(
            bound in any::<bool>(),
            field in 0usize..6,
            bit in 0usize..512,
        ) {
            let door_key = key(1);
            let door = id(1);
            let invitee = bound.then(|| id(2));
            let cap = Cap::sign(&door_key, SessionId([7; 16]), invitee, Nonce([9; 16]));
            prop_assert!(cap.verify(&door));

            let cap = cap.read(|c| CapValue { issuer: c.issuer, session_id: c.session_id, invitee: c.invitee, nonce: c.nonce, sig: c.sig });
            let mut forged = CapValue { issuer: cap.issuer, session_id: cap.session_id, invitee, nonce: cap.nonce, sig: cap.sig };
            let mut checked_door = door;
            match field {
                0 => forged.session_id = SessionId(flip(cap.session_id.0, bit)),
                1 => forged.nonce = Nonce(flip(cap.nonce.0, bit)),
                2 => forged.sig = flip(cap.sig, bit),
                3 => forged.invitee = if bound { None } else { Some(door) },
                4 => forged.invitee = Some(id(3)),
                _ => checked_door = id(3),
            }
            prop_assert!(!Cap::new(forged.session_id, forged.invitee, forged.nonce, Signature::from_bytes(&forged.sig)).verify(&checked_door));
        }
    }
}

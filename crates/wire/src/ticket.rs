//! `Ticket = "kickoff1" + base32(postcard{ v: 1, door, cap })`, at most
//! `MAX_TICKET_LEN` bytes (§4.2). Tickets are secrets (§6.4): they exist only
//! as `Secret<Ticket>`, and neither they nor the capabilities inside them
//! implement `Debug`, `Clone` or a serde trait.

use data_encoding::BASE32_NOPAD;
use iroh_base::{EndpointAddr, EndpointId, SecretKey, Signature};
use kickoff_secret::Secret;
use serde::{Deserialize, Serialize};

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
    pub session_id: SessionId,
    pub invitee: Option<EndpointId>,
    pub nonce: Nonce,
    pub sig: Signature,
}

#[cfg(feature = "mutant-si30-cap-debug")]
impl std::fmt::Debug for Cap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cap")
    }
}

impl Cap {
    pub(crate) fn sign(
        door_key: &Secret<SecretKey>,
        session_id: SessionId,
        invitee: Option<EndpointId>,
        nonce: Nonce,
    ) -> Cap {
        door_key.expose(|key| {
            let msg = signed_message(&key.public(), &session_id, invitee.as_ref(), &nonce);
            Cap {
                session_id,
                invitee,
                nonce,
                sig: key.sign(&msg),
            }
        })
    }

    pub(crate) fn verify(&self, door: &EndpointId) -> bool {
        let msg = signed_message(door, &self.session_id, self.invitee.as_ref(), &self.nonce);
        door.verify(&msg, &self.sig).is_ok()
    }
}

/// The bytes the door key signs: every capability field and the door's own
/// identity. The single owner of that layout; `sign` and `verify` both call it.
fn signed_message(
    door: &EndpointId,
    session_id: &SessionId,
    invitee: Option<&EndpointId>,
    nonce: &Nonce,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(CAP_CONTEXT.len().saturating_add(32 + 16 + 33 + 16));
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

/// The capability is the secret part; the door's address is public.
impl kickoff_secret::Wipe for Ticket {
    fn wipe(&mut self) {
        kickoff_secret::Wipe::wipe(&mut self.cap.session_id.0);
        kickoff_secret::Wipe::wipe(&mut self.cap.nonce.0);
        self.cap.sig = Signature::from_bytes(&[0; 64]);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "Cap")]
pub(crate) struct CapRepr {
    session_id: [u8; 16],
    invitee: Option<EndpointId>,
    nonce: [u8; 16],
    sig: Signature,
}

impl CapRepr {
    pub(crate) fn from_cap(cap: &Cap) -> CapRepr {
        CapRepr {
            session_id: cap.session_id.0,
            invitee: cap.invitee,
            nonce: cap.nonce.0,
            sig: cap.sig,
        }
    }

    pub(crate) fn into_cap(self) -> Cap {
        Cap {
            session_id: SessionId(self.session_id),
            invitee: self.invitee,
            nonce: Nonce(self.nonce),
            sig: self.sig,
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

fn ticket_bytes(ticket: &Ticket) -> Result<Vec<u8>, WireError> {
    let repr = TicketRepr::new(
        DoorRepr::from_addr(&ticket.door)?,
        CapRepr::from_cap(&ticket.cap),
    );
    postcard::to_allocvec(&repr).map_err(|_| WireError::Malformed)
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
    let bytes = BASE32_NOPAD
        .decode(body.to_ascii_uppercase().as_bytes())
        .map_err(|_| WireError::Malformed)?;
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
    let ticket = Ticket {
        door: repr.door.to_addr()?,
        cap: repr.cap.into_cap(),
    };
    if ticket_bytes(&ticket)? != bytes {
        return Err(WireError::Malformed);
    }
    Ok(Secret::new(ticket))
}

/// Refuses a door address with a direct address or no relay.
pub fn encode_ticket(ticket: &Ticket) -> Result<Secret<String>, WireError> {
    let body = BASE32_NOPAD
        .encode(&ticket_bytes(ticket)?)
        .to_ascii_lowercase();
    let text = format!("{TICKET_PREFIX}{body}");
    if text.len() > MAX_TICKET_LEN {
        return Err(WireError::TooLong {
            max: MAX_TICKET_LEN,
        });
    }
    Ok(Secret::new(text))
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn key(n: u8) -> Secret<SecretKey> {
        Secret::new(SecretKey::from_bytes(&[n; 32]))
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

            let mut forged = Cap { session_id: cap.session_id, invitee, nonce: cap.nonce, sig: cap.sig };
            let mut checked_door = door;
            match field {
                0 => forged.session_id = SessionId(flip(cap.session_id.0, bit)),
                1 => forged.nonce = Nonce(flip(cap.nonce.0, bit)),
                2 => forged.sig = Signature::from_bytes(&flip(cap.sig.to_bytes(), bit)),
                3 => forged.invitee = if bound { None } else { Some(door) },
                4 => forged.invitee = Some(id(3)),
                _ => checked_door = id(3),
            }
            prop_assert!(!forged.verify(&checked_door));
        }
    }
}

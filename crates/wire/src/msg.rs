//! Join and control messages (§4.3, §4.5). No variant carries a path, URL, EAC
//! mode or launch option (SI-3).

use bytes::Bytes;
use iroh_base::{EndpointAddr, EndpointId};
use kickoff_secret::SecretBuffer;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ticket::CapRepr;
use crate::{
    BoundedStr, BoundedVec, Cap, Generation, MAX_ROSTER, MapId, PeerSlot, Transmission, WireError,
};

pub const MAX_JOIN_LEN: usize = 4 * 1024;
pub const MAX_CONTROL_LEN: usize = 64 * 1024;
pub const MAX_NAME_LEN: usize = 32;
pub const MAX_HAVE: usize = 64;
/// Join and control messages travel as `len:u32 (big-endian) | body` (§4.5).
pub const LEN_PREFIX_LEN: usize = 4;
const MAX_BUILD_ID_LEN: usize = 64;
const MAX_ROSTER_LEN: usize = MAX_ROSTER as usize;

pub type Name = BoundedStr<MAX_NAME_LEN>;
pub type BuildId = BoundedStr<MAX_BUILD_ID_LEN>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Linux,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KickoffVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

/// Guest → host on `kickoff/join/1`, at most `MAX_JOIN_LEN` bytes. Carries a
/// capability, so it has no `Debug`.
pub struct JoinRequest {
    pub cap: Cap,
    pub session_key: EndpointId,
    pub name: Name,
    pub platform: Platform,
    pub game_build: BuildId,
    pub kickoff_version: KickoffVersion,
}

/// The pass a guest dials the session endpoint with. Only `Admitted` and the
/// first `Roster` mean admission; a completed `connect()` does not (§4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmitPass {
    pub slot: PeerSlot,
    pub generation: Generation,
}

/// `session_addr` is the host's session endpoint, which the guest learns here
/// for the first time (SI-31).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admitted {
    #[serde(with = "crate::addr::session")]
    pub session_addr: EndpointAddr,
    pub pass: AdmitPass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JoinRefused {
    Revoked,
    InvalidCap,
    WrongSession,
    Expired,
    Full,
    Busy,
    Declined,
    Version,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JoinReply {
    Admitted(Admitted),
    Refused(JoinRefused),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GameState {
    Unknown,
    Menu,
    Lobby,
    Match,
}

/// Guest → host control. `Status` is informational and never decides
/// scheduling (§3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestMsg {
    Hello {
        generation: Generation,
    },
    Status {
        game_state: GameState,
        have: BoundedVec<MapId, MAX_HAVE>,
    },
    Pong,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub slot: PeerSlot,
    pub id: EndpointId,
    pub name: Name,
}

/// A bundle manifest's bytes, carried opaque. Only `kickoff-parse` decodes it
/// (§5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleBlob(pub Bytes);

impl Serialize for BundleBlob {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for BundleBlob {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Borrowed, so the copy is bounded by the message the decoder already
        // length-checked.
        let bytes = <&[u8]>::deserialize(deserializer)?;
        Ok(BundleBlob(Bytes::copy_from_slice(bytes)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KickReason {
    Kicked,
    Evicted,
    ProtocolViolation,
    OverBudget,
}

/// Host → guest control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostMsg {
    Roster {
        epoch: u64,
        members: BoundedVec<Member, MAX_ROSTER_LEN>,
    },
    MapPick {
        bundle: BundleBlob,
    },
    Kick {
        reason: KickReason,
    },
    Ping,
    End,
    #[cfg(feature = "mutant-si3-path-field")]
    Launch {
        path: std::path::PathBuf,
    },
}

/// `JoinRequest` carries a capability, so it implements no serde trait of its
/// own (SI-30); this is its wire form.
#[derive(Serialize, Deserialize)]
#[serde(rename = "JoinRequest")]
pub(crate) struct JoinRequestRepr {
    cap: CapRepr,
    session_key: EndpointId,
    name: Name,
    platform: Platform,
    game_build: BuildId,
    kickoff_version: KickoffVersion,
}

impl JoinRequestRepr {
    pub(crate) fn from_request(request: &JoinRequest) -> JoinRequestRepr {
        JoinRequestRepr {
            cap: CapRepr::from_cap(&request.cap),
            session_key: request.session_key,
            name: request.name.clone(),
            platform: request.platform,
            game_build: request.game_build.clone(),
            kickoff_version: request.kickoff_version,
        }
    }
}

pub(crate) mod sealed {
    use crate::WireError;

    /// The encoding of each message, reachable only through `encode` and
    /// `decode`, so every decode goes through the strict path.
    pub trait Sealed: Sized {
        /// The number of top-level variants, for an enum.
        const VARIANTS: Option<u32>;
        fn write(&self) -> Result<super::Transmission, WireError>;
        fn read(bytes: &[u8]) -> Result<(Self, &[u8]), WireError>;
    }
    pub trait Public {
        fn write_public(&self) -> Result<super::SecretBuffer, WireError>;
    }
}

/// A message with a postcard encoding and a fixed size cap. Sealed: the set of
/// messages that can cross the wire is this crate's to define.
pub trait WireMessage: Sized + sealed::Sealed {
    const MAX_LEN: usize;
}

/// Messages whose complete encoding contains no protected secret. The sealed
/// supertrait prevents another crate from adding a secret-bearing message.
pub trait PublicWireMessage: WireMessage + sealed::Public {}

pub(crate) fn postcard_write<T: Serialize>(
    value: &T,
    max: usize,
) -> Result<SecretBuffer, WireError> {
    let len = postcard::experimental::serialized_size(value).map_err(|_| WireError::Malformed)?;
    if !cfg!(feature = "mutant-si23-no-message-cap") && len > max {
        return Err(WireError::TooLong { max });
    }
    let mut out = SecretBuffer::zeroed(len);
    postcard::to_slice(value, &mut out).map_err(|_| WireError::Malformed)?;
    Ok(out)
}

fn postcard_read<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<(T, &'a [u8]), WireError> {
    postcard::take_from_bytes(bytes).map_err(|_| WireError::Malformed)
}

macro_rules! wire_message {
    ($($ty:ty => $max:expr, $variants:expr);+ $(;)?) => {$(
        impl sealed::Sealed for $ty {
            const VARIANTS: Option<u32> = Some($variants);
            fn write(&self) -> Result<Transmission, WireError> {
                Transmission::new(postcard_write(self, <Self as WireMessage>::MAX_LEN)?)
            }
            fn read(bytes: &[u8]) -> Result<(Self, &[u8]), WireError> {
                postcard_read(bytes)
            }
        }
        impl WireMessage for $ty {
            const MAX_LEN: usize = $max;
        }
        impl sealed::Public for $ty {
            fn write_public(&self) -> Result<SecretBuffer, WireError> {
                postcard_write(self, <Self as WireMessage>::MAX_LEN)
            }
        }
        impl PublicWireMessage for $ty {}
    )+};
}

wire_message! {
    JoinReply => MAX_JOIN_LEN, 2;
    GuestMsg => MAX_CONTROL_LEN, 3;
    HostMsg => MAX_CONTROL_LEN, 5;
}

impl sealed::Sealed for JoinRequest {
    const VARIANTS: Option<u32> = None;

    fn write(&self) -> Result<Transmission, WireError> {
        Transmission::join(
            postcard_write(&JoinRequestRepr::from_request(self), Self::MAX_LEN)?,
            self.cap.issuing_door(),
        )
    }

    fn read(bytes: &[u8]) -> Result<(Self, &[u8]), WireError> {
        let (repr, rest) = postcard_read::<JoinRequestRepr>(bytes)?;
        let request = JoinRequest {
            cap: repr.cap.into_cap(),
            session_key: repr.session_key,
            name: repr.name,
            platform: repr.platform,
            game_build: repr.game_build,
            kickoff_version: repr.kickoff_version,
        };
        Ok((request, rest))
    }
}

impl WireMessage for JoinRequest {
    const MAX_LEN: usize = MAX_JOIN_LEN;
}

/// The message body, without the length prefix.
pub fn encode<M: PublicWireMessage>(msg: &M) -> Result<SecretBuffer, WireError> {
    let body = msg.write_public()?;
    if !cfg!(feature = "mutant-si23-no-message-cap") && body.len() > M::MAX_LEN {
        return Err(WireError::TooLong { max: M::MAX_LEN });
    }
    Ok(body)
}

/// Decodes one message body. A top-level variant this build does not know is
/// `Version`, which the caller closes with `VERSION` (§4.5). Anything else but
/// the exact bytes `encode` would produce for the result is `Malformed`:
/// trailing bytes, over-long varints, unsorted or duplicate address sets,
/// unknown nested variants.
pub fn decode<M: WireMessage>(bytes: &[u8]) -> Result<M, WireError> {
    if !cfg!(feature = "mutant-si23-no-message-cap") && bytes.len() > M::MAX_LEN {
        return Err(WireError::TooLong { max: M::MAX_LEN });
    }
    if let (Some(known), Ok((index, _))) = (M::VARIANTS, postcard_read::<u32>(bytes))
        && index >= known
    {
        return Err(WireError::Version);
    }
    let (msg, rest) = M::read(bytes)?;
    if !rest.is_empty() || !msg.write()?.matches(bytes) {
        return Err(WireError::Malformed);
    }
    Ok(msg)
}

/// `len:u32 | body`, ready to write to a join or control stream.
pub fn encode_framed<M: PublicWireMessage>(msg: &M) -> Result<SecretBuffer, WireError> {
    let body = encode(msg)?;
    let len = u32::try_from(body.len()).map_err(|_| WireError::TooLong { max: M::MAX_LEN })?;
    let mut framed = SecretBuffer::with_capacity(LEN_PREFIX_LEN.saturating_add(body.len()));
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&body);
    Ok(framed)
}

/// The body length a received prefix announces, checked against `M::MAX_LEN`
/// so the reader can refuse before it allocates the body.
pub fn frame_len<M: WireMessage>(prefix: [u8; LEN_PREFIX_LEN]) -> Result<usize, WireError> {
    let len = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| WireError::TooLong { max: M::MAX_LEN })?;
    if !cfg!(feature = "mutant-si23-no-frame-cap") && len > M::MAX_LEN {
        return Err(WireError::TooLong { max: M::MAX_LEN });
    }
    if len == 0 {
        return Err(WireError::Malformed);
    }
    Ok(len)
}

/// Prepares a bounded frame without exposing its serialized body to holders.
pub fn prepare_message<M: WireMessage>(msg: &M) -> Result<Transmission, WireError> {
    let transmission = msg.write()?;
    if !cfg!(feature = "mutant-si23-no-message-cap") && transmission.body_len() > M::MAX_LEN {
        return Err(WireError::TooLong { max: M::MAX_LEN });
    }
    Ok(transmission)
}

#[cfg(feature = "mutant-si30-public-join-encoder")]
impl sealed::Public for JoinRequest {
    fn write_public(&self) -> Result<SecretBuffer, WireError> {
        postcard_write(&JoinRequestRepr::from_request(self), Self::MAX_LEN)
    }
}
#[cfg(feature = "mutant-si30-public-join-encoder")]
impl PublicWireMessage for JoinRequest {}

#[cfg(test)]
pub(crate) fn encode_owned<M: WireMessage>(msg: &M) -> Result<SecretBuffer, WireError> {
    Ok(prepare_message(msg)?.copy_body())
}

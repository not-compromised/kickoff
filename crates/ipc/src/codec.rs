//! The byte layout of every local-channel message, and the only code that
//! reads one. Decoding is strict: a tag nobody defined, a non-canonical value
//! or a trailing byte is `Malformed`, never a best guess.

use iroh_base::EndpointId;

use kickoff_secret::diag::{
    Component, Counter, Field, Flag, MAX_FIELDS, PathKind, PathRole, Report, StateKey, StateValue,
    Version,
};
use kickoff_wire::{MapId, TicketTextValue};
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::command::{ApprovalId, InviteFor, Op, Refusal, Reply, TicketText};
use crate::{ChannelRole, IpcError, MAX_REPLY_FRAME, MAX_REQUEST_FRAME, PROTOCOL_VERSION};

// The hello and welcome layouts are frozen: they are the one format every
// version must read, so a peer from any release gets a clean `Version` refusal.
const HELLO_MAGIC: [u8; 2] = *b"KO";
pub(crate) const HELLO_LEN: usize = 5;
pub(crate) const WELCOME_LEN: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Welcome {
    Ok,
    Version,
    Role,
}

pub(crate) fn role_tag(role: ChannelRole) -> u8 {
    match role {
        ChannelRole::Cli => 1,
        ChannelRole::UiMain => 2,
        ChannelRole::Overlay => 3,
        ChannelRole::Gamebox => 4,
        ChannelRole::ServiceClient => 5,
    }
}

fn role_from_tag(tag: u8) -> Option<ChannelRole> {
    [
        ChannelRole::Cli,
        ChannelRole::UiMain,
        ChannelRole::Overlay,
        ChannelRole::Gamebox,
        ChannelRole::ServiceClient,
    ]
    .into_iter()
    .find(|r| role_tag(*r) == tag)
}

pub(crate) fn encode_hello(version: u16, role: ChannelRole) -> [u8; HELLO_LEN] {
    let [m0, m1] = HELLO_MAGIC;
    let [v0, v1] = version.to_be_bytes();
    [m0, m1, v0, v1, role_tag(role)]
}

/// The server's reading of a hello: the role it asks for, or the welcome
/// that refuses it. A version mismatch wins over everything else, so an old
/// client always learns that it is old.
pub(crate) fn decode_hello(bytes: &[u8]) -> Result<ChannelRole, Welcome> {
    let mut r = Reader::new(bytes);
    let magic = r.array::<2>().map_err(|_| Welcome::Version)?;
    let version = r.u16().map_err(|_| Welcome::Version)?;
    let version_ok = cfg!(feature = "mutant-si10-skip-version") || version == PROTOCOL_VERSION;
    if magic != HELLO_MAGIC || !version_ok {
        return Err(Welcome::Version);
    }
    let role = r.u8().map_err(|_| Welcome::Version)?;
    r.finish().map_err(|_| Welcome::Version)?;
    match role_from_tag(role) {
        Some(role @ (ChannelRole::Cli | ChannelRole::UiMain | ChannelRole::Overlay)) => Ok(role),
        #[cfg(feature = "mutant-si10-any-role")]
        Some(role) => Ok(role),
        Some(ChannelRole::Gamebox | ChannelRole::ServiceClient) | None => Err(Welcome::Role),
    }
}

pub(crate) fn encode_welcome(welcome: Welcome) -> [u8; WELCOME_LEN] {
    let [v0, v1] = PROTOCOL_VERSION.to_be_bytes();
    let status = match welcome {
        Welcome::Ok => 0,
        Welcome::Version => 1,
        Welcome::Role => 2,
    };
    [v0, v1, status]
}

pub(crate) fn decode_welcome(bytes: &[u8]) -> Result<(), IpcError> {
    let mut r = Reader::new(bytes);
    let version = r.u16()?;
    let status = r.u8()?;
    r.finish()?;
    if !cfg!(feature = "mutant-si10-client-skips-version") && version != PROTOCOL_VERSION {
        return Err(IpcError::Version);
    }
    match status {
        0 => Ok(()),
        1 => Err(IpcError::Version),
        2 => Err(IpcError::Role),
        _ => Err(IpcError::Malformed),
    }
}

// These private representations keep serde off public secret-bearing types.
#[derive(Serialize, Deserialize)]
enum CliRepr<T> {
    Status,
    Host,
    Join(T),
    Invite(InviteRepr),
    Leave,
    Doctor,
    ToggleOverlay,
}
#[derive(Serialize, Deserialize)]
enum UiRepr<T> {
    Status,
    Host,
    Join(T),
    Invite(InviteRepr),
    Kick([u8; 32]),
    Decide { approval: [u8; 16], allow: bool },
    PickMap([u8; 32]),
    Leave,
    Doctor,
}
#[derive(Serialize, Deserialize)]
enum OverlayRepr {
    Status,
}
#[derive(Serialize, Deserialize)]
enum InviteRepr {
    Friend([u8; 32]),
    Bearer,
}
#[derive(Serialize, Deserialize)]
enum RefusalRepr {
    Unknown,
    Busy,
    NotHost,
    Failed,
}
#[derive(Serialize, Deserialize)]
enum ReplyRepr<T> {
    Done,
    Refused(RefusalRepr),
    Invite(T),
    Report(ReportRepr),
}

pub(crate) enum Payload {
    Plain(Zeroizing<Vec<u8>>),
    Ticket(kickoff_wire::Transmission),
}
impl Payload {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Plain(body) => body.len(),
            Self::Ticket(frame) => frame.body_len(),
        }
    }
    #[cfg(target_os = "linux")]
    pub(crate) async fn send(
        self,
        stream: &mut kickoff_local::DataOnly,
        kind: kickoff_local::PeerKind,
    ) -> Result<(), IpcError> {
        match self {
            Self::Plain(body) => crate::frame::write_frame(stream, &body).await,
            Self::Ticket(frame) => {
                let mut peer = stream.installed_peer(kind)?;
                tokio::time::timeout(crate::WRITE_DEADLINE, frame.transmit_local(&mut peer))
                    .await
                    .map_err(|_| IpcError::Timeout)?
                    .map_err(|_| IpcError::Closed)
            }
        }
    }
}
fn ticket_payload(ticket: &TicketText) -> Result<Payload, IpcError> {
    TicketTextValue::postcard_frame(ticket.secret(), 2)
        .map(Payload::Ticket)
        .map_err(|_| IpcError::Malformed)
}

fn write<T: Serialize>(value: &T, max: usize) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    let mut out = Zeroizing::new(vec![0; max]);
    let len = postcard::to_slice(value, &mut out)
        .map_err(|_| IpcError::Malformed)?
        .len();
    out.truncate(len);
    Ok(out)
}
fn read<'a, T: Deserialize<'a> + Serialize>(bytes: &'a [u8]) -> Result<T, IpcError> {
    let (value, rest) = postcard::take_from_bytes(bytes).map_err(|_| IpcError::Malformed)?;
    if !rest.is_empty() {
        return Err(IpcError::Malformed);
    }
    if write(&value, bytes.len())?.as_slice() != bytes {
        return Err(IpcError::Malformed);
    }
    Ok(value)
}
fn invite(i: InviteFor) -> InviteRepr {
    match i {
        InviteFor::Friend(id) => InviteRepr::Friend(*id.as_bytes()),
        InviteFor::Bearer => InviteRepr::Bearer,
    }
}
fn get_id(bytes: [u8; 32]) -> Result<EndpointId, IpcError> {
    EndpointId::from_bytes(&bytes).map_err(|_| IpcError::Malformed)
}
fn get_invite(i: InviteRepr) -> Result<InviteFor, IpcError> {
    Ok(match i {
        InviteRepr::Friend(bytes) => InviteFor::Friend(get_id(bytes)?),
        InviteRepr::Bearer => InviteFor::Bearer,
    })
}
fn get_ticket(text: &str) -> Result<TicketText, IpcError> {
    if !TicketText::alphabet_ok(text.as_bytes()) {
        return Err(IpcError::Malformed);
    }
    TicketText::new(TicketTextValue::protect(text.to_owned()))
}

pub(crate) fn encode_op(role: ChannelRole, op: &Op) -> Result<Payload, IpcError> {
    match role {
        ChannelRole::Cli => {
            let repr: CliRepr<()> = match op {
                Op::Status => CliRepr::Status,
                Op::Host => CliRepr::Host,
                Op::Join(t) => return ticket_payload(t),
                Op::Invite(i) => CliRepr::Invite(invite(*i)),
                Op::Leave => CliRepr::Leave,
                Op::Doctor => CliRepr::Doctor,
                Op::ToggleOverlay => CliRepr::ToggleOverlay,
                _ => return Err(IpcError::Role),
            };
            write(&repr, MAX_REQUEST_FRAME).map(Payload::Plain)
        }
        ChannelRole::UiMain => {
            let repr: UiRepr<()> = match op {
                Op::Status => UiRepr::Status,
                Op::Host => UiRepr::Host,
                Op::Join(t) => return ticket_payload(t),
                Op::Invite(i) => UiRepr::Invite(invite(*i)),
                Op::Kick(id) => UiRepr::Kick(*id.as_bytes()),
                Op::Decide { approval, allow } => UiRepr::Decide {
                    approval: approval.to_bytes(),
                    allow: *allow,
                },
                Op::PickMap(map) => UiRepr::PickMap(map.0),
                Op::Leave => UiRepr::Leave,
                Op::Doctor => UiRepr::Doctor,
                _ => return Err(IpcError::Role),
            };
            write(&repr, MAX_REQUEST_FRAME).map(Payload::Plain)
        }
        ChannelRole::Overlay if matches!(op, Op::Status) => {
            write(&OverlayRepr::Status, MAX_REQUEST_FRAME).map(Payload::Plain)
        }
        _ => Err(IpcError::Role),
    }
}
pub(crate) fn decode_op(role: ChannelRole, bytes: &[u8]) -> Result<Op, IpcError> {
    let op = match role {
        ChannelRole::Cli => match read::<CliRepr<&str>>(bytes)? {
            CliRepr::Status => Op::Status,
            CliRepr::Host => Op::Host,
            CliRepr::Join(t) => Op::Join(get_ticket(t)?),
            CliRepr::Invite(i) => Op::Invite(get_invite(i)?),
            CliRepr::Leave => Op::Leave,
            CliRepr::Doctor => Op::Doctor,
            CliRepr::ToggleOverlay => Op::ToggleOverlay,
        },
        ChannelRole::UiMain => match read::<UiRepr<&str>>(bytes)? {
            UiRepr::Status => Op::Status,
            UiRepr::Host => Op::Host,
            UiRepr::Join(t) => Op::Join(get_ticket(t)?),
            UiRepr::Invite(i) => Op::Invite(get_invite(i)?),
            UiRepr::Kick(id) => Op::Kick(get_id(id)?),
            UiRepr::Decide { approval, allow } => Op::Decide {
                approval: ApprovalId::from_bytes(approval),
                allow,
            },
            UiRepr::PickMap(map) => Op::PickMap(MapId(map)),
            UiRepr::Leave => Op::Leave,
            UiRepr::Doctor => Op::Doctor,
        },
        ChannelRole::Overlay => {
            let OverlayRepr::Status = read(bytes)?;
            Op::Status
        }
        _ => return Err(IpcError::Role),
    };
    Ok(op)
}
fn refusal(r: Refusal) -> RefusalRepr {
    match r {
        Refusal::Unknown => RefusalRepr::Unknown,
        Refusal::Busy => RefusalRepr::Busy,
        Refusal::NotHost => RefusalRepr::NotHost,
        Refusal::Failed => RefusalRepr::Failed,
    }
}
fn get_refusal(r: RefusalRepr) -> Refusal {
    match r {
        RefusalRepr::Unknown => Refusal::Unknown,
        RefusalRepr::Busy => Refusal::Busy,
        RefusalRepr::NotHost => Refusal::NotHost,
        RefusalRepr::Failed => Refusal::Failed,
    }
}
pub(crate) fn encode_reply(reply: &Reply) -> Result<Payload, IpcError> {
    let repr: ReplyRepr<()> = match reply {
        Reply::Done => ReplyRepr::Done,
        Reply::Refused(r) => ReplyRepr::Refused(refusal(*r)),
        Reply::Invite(t) => return ticket_payload(t),
        Reply::Report(r) => ReplyRepr::Report(ReportRepr(r.clone())),
    };
    write(&repr, MAX_REPLY_FRAME).map(Payload::Plain)
}
pub(crate) fn decode_reply(bytes: &[u8]) -> Result<Reply, IpcError> {
    let reply = match read::<ReplyRepr<&str>>(bytes)? {
        ReplyRepr::Done => Reply::Done,
        ReplyRepr::Refused(r) => Reply::Refused(get_refusal(r)),
        ReplyRepr::Invite(t) => Reply::Invite(get_ticket(t)?),
        ReplyRepr::Report(r) => Reply::Report(r.0),
    };
    Ok(reply)
}

#[derive(Serialize, Deserialize)]
enum FieldRepr {
    Count(u8, u64),
    Flag(u8, bool),
    Version(u8, u16, u16, u16),
    State(u8, u8),
    PathType(u8, u8),
}
impl From<Field> for FieldRepr {
    fn from(f: Field) -> Self {
        match f {
            Field::Count(k, n) => Self::Count(k.tag(), n),
            Field::Flag(k, b) => Self::Flag(k.tag(), b),
            Field::Version(k, v) => Self::Version(k.tag(), v.major, v.minor, v.patch),
            Field::State(k, v) => Self::State(k.tag(), v.tag()),
            Field::PathType(k, v) => Self::PathType(k.tag(), v.tag()),
        }
    }
}
impl TryFrom<FieldRepr> for Field {
    type Error = IpcError;
    fn try_from(f: FieldRepr) -> Result<Self, Self::Error> {
        fn known<T>(v: Option<T>) -> Result<T, IpcError> {
            v.ok_or(IpcError::Malformed)
        }
        Ok(match f {
            FieldRepr::Count(k, n) => Self::Count(known(Counter::from_tag(k))?, n),
            FieldRepr::Flag(k, b) => Self::Flag(known(Flag::from_tag(k))?, b),
            FieldRepr::Version(k, major, minor, patch) => Self::Version(
                known(Component::from_tag(k))?,
                Version {
                    major,
                    minor,
                    patch,
                },
            ),
            FieldRepr::State(k, v) => Self::State(
                known(StateKey::from_tag(k))?,
                known(StateValue::from_tag(v))?,
            ),
            FieldRepr::PathType(k, v) => {
                Self::PathType(known(PathRole::from_tag(k))?, known(PathKind::from_tag(v))?)
            }
        })
    }
}
struct ReportRepr(Report);
impl Serialize for ReportRepr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.0.fields().len()))?;
        for f in self.0.fields() {
            seq.serialize_element(&FieldRepr::from(*f))?;
        }
        seq.end()
    }
}
impl<'de> Deserialize<'de> for ReportRepr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = ReportRepr;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a bounded diagnostics report")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                if seq.size_hint().is_some_and(|len| len > MAX_FIELDS) {
                    return Err(serde::de::Error::custom("report too large"));
                }
                let mut report = Report::new();
                while let Some(field) = seq.next_element::<FieldRepr>()? {
                    report
                        .push(Field::try_from(field).map_err(serde::de::Error::custom)?)
                        .map_err(|_| serde::de::Error::custom("report too large"))?;
                }
                Ok(ReportRepr(report))
            }
        }
        d.deserialize_seq(Fields)
    }
}

/// The fixed handshake uses big-endian integers independently of postcard.
struct Reader<'a> {
    rest: &'a [u8],
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], IpcError> {
        let (head, tail) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or(IpcError::Malformed)?;
        self.rest = tail;
        Ok(*head)
    }
    fn u8(&mut self) -> Result<u8, IpcError> {
        let [b] = self.array()?;
        Ok(b)
    }
    fn u16(&mut self) -> Result<u16, IpcError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn finish(self) -> Result<(), IpcError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(IpcError::Malformed)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use kickoff_wire::MAX_TICKET_LEN;
    fn ticket(text: &str) -> TicketText {
        TicketText::new(TicketTextValue::protect(text.to_owned())).unwrap()
    }
    fn id(seed: u8) -> EndpointId {
        iroh_base::SecretKey::from_bytes(&[seed; 32]).public()
    }
    fn every_op() -> Vec<Op> {
        vec![
            Op::Status,
            Op::Host,
            Op::Join(ticket("kickoff1ABC234")),
            Op::Invite(InviteFor::Friend(id(1))),
            Op::Invite(InviteFor::Bearer),
            Op::Kick(id(2)),
            Op::Decide {
                approval: ApprovalId::from_bytes([3; 16]),
                allow: true,
            },
            Op::Decide {
                approval: ApprovalId::from_bytes([4; 16]),
                allow: false,
            },
            Op::PickMap(MapId([9; 32])),
            Op::Leave,
            Op::Doctor,
            Op::ToggleOverlay,
        ]
    }
    #[test]
    fn ops_round_trip_and_reject_every_truncation_and_trailing_byte() {
        for role in [ChannelRole::Cli, ChannelRole::UiMain, ChannelRole::Overlay] {
            for op in every_op() {
                let Ok(Payload::Plain(bytes)) = encode_op(role, &op) else {
                    continue;
                };
                let got = decode_op(role, &bytes).unwrap();
                let Payload::Plain(again) = encode_op(role, &got).unwrap() else {
                    panic!("nonsecret control");
                };
                assert_eq!(again.as_slice(), bytes.as_slice());
                assert_eq!(format!("{got:?}"), format!("{op:?}"));
                for cut in 0..bytes.len() {
                    assert_eq!(
                        decode_op(role, &bytes[..cut]).err(),
                        Some(IpcError::Malformed)
                    );
                }
                let mut longer = bytes.to_vec();
                longer.push(0);
                assert_eq!(decode_op(role, &longer).err(), Some(IpcError::Malformed));
            }
        }
    }
    #[test]
    fn unknown_and_noncanonical_variants_are_malformed() {
        for role in [ChannelRole::Cli, ChannelRole::UiMain, ChannelRole::Overlay] {
            for tag in 9..=u8::MAX {
                assert!(decode_op(role, &[tag]).is_err());
            }
            assert_eq!(decode_op(role, &[0x80, 0]).err(), Some(IpcError::Malformed));
        }
        assert_eq!(
            decode_op(ChannelRole::Cli, &[3, 2]).err(),
            Some(IpcError::Malformed)
        );
    }
    #[test]
    fn invalid_endpoint_id_is_malformed() {
        let bad = (0..=u8::MAX)
            .map(|b| [b; 32])
            .find(|b| EndpointId::from_bytes(b).is_err())
            .unwrap();
        let bytes = postcard::to_allocvec(&UiRepr::<&str>::Kick(bad)).unwrap();
        assert_eq!(
            decode_op(ChannelRole::UiMain, &bytes).err(),
            Some(IpcError::Malformed)
        );
    }
    #[test]
    fn decide_takes_a_canonical_boolean() {
        let mut bytes = vec![5];
        bytes.extend_from_slice(&[5; 16]);
        bytes.push(2);
        assert_eq!(
            decode_op(ChannelRole::UiMain, &bytes).err(),
            Some(IpcError::Malformed)
        );
    }
    #[test]
    fn ticket_length_is_checked_before_reading() {
        assert_eq!(
            decode_op(ChannelRole::Cli, &[2, 0xff, 0xff, 3]).err(),
            Some(IpcError::Malformed)
        );
        assert_eq!(
            decode_op(ChannelRole::Cli, &[2, 0]).err(),
            Some(IpcError::Malformed)
        );
        let oversized = "A".repeat(MAX_TICKET_LEN + 1);
        let bytes = postcard::to_allocvec(&CliRepr::Join(oversized.as_str())).unwrap();
        assert_eq!(
            decode_op(ChannelRole::Cli, &bytes).err(),
            Some(IpcError::Malformed)
        );
    }
    #[test]
    fn replies_round_trip() {
        let mut report = Report::new();
        for f in [
            Field::Count(Counter::IpcPeersRejected, 7),
            Field::Flag(Flag::SessionActive, true),
            Field::Version(
                Component::IpcProtocol,
                Version {
                    major: 1,
                    minor: 2,
                    patch: 3,
                },
            ),
            Field::State(StateKey::SessionRole, StateValue::Host),
            Field::PathType(PathRole::RuntimeDir, PathKind::Directory),
        ] {
            report.push(f).unwrap();
        }
        let replies = [
            Reply::Done,
            Reply::Report(report),
            Reply::Refused(Refusal::Unknown),
            Reply::Refused(Refusal::Busy),
            Reply::Refused(Refusal::NotHost),
            Reply::Refused(Refusal::Failed),
        ];
        for reply in replies {
            let Payload::Plain(bytes) = encode_reply(&reply).unwrap() else {
                panic!("nonsecret control");
            };
            let got = decode_reply(&bytes).unwrap();
            let Payload::Plain(again) = encode_reply(&got).unwrap() else {
                panic!("nonsecret control");
            };
            assert_eq!(again.as_slice(), bytes.as_slice());
            for cut in 0..bytes.len() {
                assert_eq!(decode_reply(&bytes[..cut]).err(), Some(IpcError::Malformed));
            }
            let mut longer = bytes.to_vec();
            longer.push(0);
            assert!(decode_reply(&longer).is_err());
        }
    }
    #[test]
    fn borrowed_ticket_fixtures_decode_before_protecting() {
        let expected = "kickoff1ABC234";
        let join = postcard::to_allocvec(&CliRepr::Join(expected)).unwrap();
        let Op::Join(ticket) = decode_op(ChannelRole::Cli, &join).unwrap() else {
            panic!("join");
        };
        assert!(ticket.secret().ct_eq(expected.as_bytes()));
        let invite = postcard::to_allocvec(&ReplyRepr::Invite(expected)).unwrap();
        let Reply::Invite(ticket) = decode_reply(&invite).unwrap() else {
            panic!("invite");
        };
        assert!(ticket.secret().ct_eq(expected.as_bytes()));
    }
    #[test]
    fn report_count_is_checked_before_reading_fields() {
        let mut bytes = vec![3];
        bytes.extend(postcard::to_allocvec(&(MAX_FIELDS + 1)).unwrap());
        assert_eq!(decode_reply(&bytes).err(), Some(IpcError::Malformed));
    }
    #[test]
    fn non_canonical_flag_is_malformed() {
        assert_eq!(
            decode_reply(&[3, 1, 1, Flag::SessionActive.tag(), 2]).err(),
            Some(IpcError::Malformed)
        );
    }
    #[test]
    fn hello_is_checked_version_first() {
        assert_eq!(
            decode_hello(&encode_hello(PROTOCOL_VERSION, ChannelRole::Cli)),
            Ok(ChannelRole::Cli)
        );
        for role in [ChannelRole::Cli, ChannelRole::Gamebox] {
            assert_eq!(
                decode_hello(&encode_hello(PROTOCOL_VERSION.wrapping_add(1), role)),
                Err(Welcome::Version)
            );
        }
        for role in [ChannelRole::Gamebox, ChannelRole::ServiceClient] {
            assert_eq!(
                decode_hello(&encode_hello(PROTOCOL_VERSION, role)),
                Err(Welcome::Role)
            );
        }
        assert_eq!(decode_hello(b"KO"), Err(Welcome::Version));
        assert_eq!(decode_hello(b"XX\0\x01\x01"), Err(Welcome::Version));
    }
    #[test]
    fn decoders_survive_arbitrary_bytes() {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = usize::from(next().to_le_bytes()[0] % 64);
            let bytes: Vec<u8> = (0..len).map(|_| next().to_le_bytes()[0]).collect();
            for role in [ChannelRole::Cli, ChannelRole::UiMain, ChannelRole::Overlay] {
                let _ = decode_op(role, &bytes);
            }
            let _ = decode_reply(&bytes);
            let _ = decode_hello(&bytes);
            let _ = decode_welcome(&bytes);
        }
    }
}

//! The byte layout of every local-channel message, and the only code that
//! reads one. Decoding is strict: a tag nobody defined, a non-canonical value
//! or a trailing byte is `Malformed`, never a best guess.

use iroh_base::EndpointId;
use kickoff_secret::Secret;
use kickoff_secret::diag::{
    Component, Counter, Field, Flag, MAX_FIELDS, PathKind, PathRole, Report, StateKey, StateValue,
    Version,
};
use kickoff_wire::{MAX_TICKET_LEN, MapId};
use zeroize::Zeroizing;

use crate::command::{InviteFor, Op, Refusal, Reply, TicketText};
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

// Op tags. Retired tags are never reused; a new command takes a new tag and
// bumps PROTOCOL_VERSION.
const OP_STATUS: u8 = 1;
const OP_HOST: u8 = 2;
const OP_JOIN: u8 = 3;
const OP_INVITE: u8 = 4;
const OP_KICK: u8 = 5;
const OP_APPROVE: u8 = 6;
const OP_PICK_MAP: u8 = 7;
const OP_LEAVE: u8 = 8;
const OP_DOCTOR: u8 = 9;
const OP_TOGGLE_OVERLAY: u8 = 10;

const INVITE_FRIEND: u8 = 1;
const INVITE_BEARER: u8 = 2;

/// Zeroized on drop: a `Join` carries a ticket. The buffer is allocated at
/// its frame maximum so no push reallocates and leaves a ticket copy behind.
pub(crate) fn encode_op(op: &Op) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_FRAME));
    match op {
        Op::Status => out.push(OP_STATUS),
        Op::Host => out.push(OP_HOST),
        Op::Join(ticket) => {
            out.push(OP_JOIN);
            put_ticket(&mut out, ticket)?;
        }
        Op::Invite(InviteFor::Friend(id)) => {
            out.extend_from_slice(&[OP_INVITE, INVITE_FRIEND]);
            out.extend_from_slice(id.as_bytes());
        }
        Op::Invite(InviteFor::Bearer) => out.extend_from_slice(&[OP_INVITE, INVITE_BEARER]),
        Op::Kick(id) => {
            out.push(OP_KICK);
            out.extend_from_slice(id.as_bytes());
        }
        Op::Approve(id) => {
            out.push(OP_APPROVE);
            out.extend_from_slice(id.as_bytes());
        }
        Op::PickMap(map) => {
            out.push(OP_PICK_MAP);
            out.extend_from_slice(&map.0);
        }
        Op::Leave => out.push(OP_LEAVE),
        Op::Doctor => out.push(OP_DOCTOR),
        Op::ToggleOverlay => out.push(OP_TOGGLE_OVERLAY),
    }
    Ok(out)
}

pub(crate) fn decode_op(bytes: &[u8]) -> Result<Op, IpcError> {
    let mut r = Reader::new(bytes);
    let op = match r.u8()? {
        OP_STATUS => Op::Status,
        OP_HOST => Op::Host,
        OP_JOIN => Op::Join(get_ticket(&mut r)?),
        OP_INVITE => match r.u8()? {
            INVITE_FRIEND => Op::Invite(InviteFor::Friend(get_id(&mut r)?)),
            INVITE_BEARER => Op::Invite(InviteFor::Bearer),
            _ => return Err(IpcError::Malformed),
        },
        OP_KICK => Op::Kick(get_id(&mut r)?),
        OP_APPROVE => Op::Approve(get_id(&mut r)?),
        OP_PICK_MAP => Op::PickMap(MapId(r.array::<32>()?)),
        OP_LEAVE => Op::Leave,
        OP_DOCTOR => Op::Doctor,
        OP_TOGGLE_OVERLAY => Op::ToggleOverlay,
        _ => return Err(IpcError::Malformed),
    };
    r.finish()?;
    Ok(op)
}

const REPLY_DONE: u8 = 1;
const REPLY_REFUSED: u8 = 2;
const REPLY_INVITE: u8 = 3;
const REPLY_REPORT: u8 = 4;

fn refusal_tag(refusal: Refusal) -> u8 {
    match refusal {
        Refusal::Unknown => 1,
        Refusal::Busy => 2,
        Refusal::NotHost => 3,
        Refusal::Failed => 4,
    }
}

fn refusal_from_tag(tag: u8) -> Option<Refusal> {
    [
        Refusal::Unknown,
        Refusal::Busy,
        Refusal::NotHost,
        Refusal::Failed,
    ]
    .into_iter()
    .find(|r| refusal_tag(*r) == tag)
}

const FIELD_COUNT: u8 = 1;
const FIELD_FLAG: u8 = 2;
const FIELD_VERSION: u8 = 3;
const FIELD_STATE: u8 = 4;
const FIELD_PATH_TYPE: u8 = 5;

pub(crate) fn encode_reply(reply: &Reply) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_REPLY_FRAME));
    match reply {
        Reply::Done => out.push(REPLY_DONE),
        Reply::Refused(refusal) => out.extend_from_slice(&[REPLY_REFUSED, refusal_tag(*refusal)]),
        Reply::Invite(ticket) => {
            out.push(REPLY_INVITE);
            put_ticket(&mut out, ticket)?;
        }
        Reply::Report(report) => {
            out.push(REPLY_REPORT);
            let count = u16::try_from(report.fields().len()).map_err(|_| IpcError::Malformed)?;
            out.extend_from_slice(&count.to_be_bytes());
            for field in report.fields() {
                put_field(&mut out, field);
            }
        }
    }
    Ok(out)
}

pub(crate) fn decode_reply(bytes: &[u8]) -> Result<Reply, IpcError> {
    let mut r = Reader::new(bytes);
    let reply = match r.u8()? {
        REPLY_DONE => Reply::Done,
        REPLY_REFUSED => Reply::Refused(refusal_from_tag(r.u8()?).ok_or(IpcError::Malformed)?),
        REPLY_INVITE => Reply::Invite(get_ticket(&mut r)?),
        REPLY_REPORT => {
            let count = usize::from(r.u16()?);
            if count > MAX_FIELDS {
                return Err(IpcError::Malformed);
            }
            let mut report = Report::new();
            for _ in 0..count {
                report
                    .push(get_field(&mut r)?)
                    .map_err(|_| IpcError::Malformed)?;
            }
            Reply::Report(report)
        }
        _ => return Err(IpcError::Malformed),
    };
    r.finish()?;
    Ok(reply)
}

fn put_ticket(out: &mut Vec<u8>, ticket: &TicketText) -> Result<(), IpcError> {
    ticket.secret().expose(|text| {
        let len = u16::try_from(text.len()).map_err(|_| IpcError::Malformed)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(text.as_bytes());
        Ok(())
    })
}

fn get_ticket(r: &mut Reader<'_>) -> Result<TicketText, IpcError> {
    let len = usize::from(r.u16()?);
    if len > MAX_TICKET_LEN {
        return Err(IpcError::Malformed);
    }
    let bytes = r.bytes(len)?;
    // Checked on the borrowed bytes first, so a rejected ticket is never
    // copied out of the zeroizing frame buffer.
    if !TicketText::alphabet_ok(bytes) {
        return Err(IpcError::Malformed);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| IpcError::Malformed)?;
    TicketText::new(Secret::new(text.to_owned()))
}

fn get_id(r: &mut Reader<'_>) -> Result<EndpointId, IpcError> {
    EndpointId::from_bytes(&r.array::<32>()?).map_err(|_| IpcError::Malformed)
}

fn put_field(out: &mut Vec<u8>, field: &Field) {
    match *field {
        Field::Count(key, n) => {
            out.extend_from_slice(&[FIELD_COUNT, key.tag()]);
            out.extend_from_slice(&n.to_be_bytes());
        }
        Field::Flag(key, b) => out.extend_from_slice(&[FIELD_FLAG, key.tag(), u8::from(b)]),
        Field::Version(key, v) => {
            out.extend_from_slice(&[FIELD_VERSION, key.tag()]);
            for part in [v.major, v.minor, v.patch] {
                out.extend_from_slice(&part.to_be_bytes());
            }
        }
        Field::State(key, value) => {
            out.extend_from_slice(&[FIELD_STATE, key.tag(), value.tag()]);
        }
        Field::PathType(role, kind) => {
            out.extend_from_slice(&[FIELD_PATH_TYPE, role.tag(), kind.tag()]);
        }
    }
}

fn get_field(r: &mut Reader<'_>) -> Result<Field, IpcError> {
    fn known<T>(found: Option<T>) -> Result<T, IpcError> {
        found.ok_or(IpcError::Malformed)
    }
    Ok(match r.u8()? {
        FIELD_COUNT => Field::Count(known(Counter::from_tag(r.u8()?))?, r.u64()?),
        FIELD_FLAG => {
            let key = known(Flag::from_tag(r.u8()?))?;
            let value = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(IpcError::Malformed),
            };
            Field::Flag(key, value)
        }
        FIELD_VERSION => Field::Version(
            known(Component::from_tag(r.u8()?))?,
            Version {
                major: r.u16()?,
                minor: r.u16()?,
                patch: r.u16()?,
            },
        ),
        FIELD_STATE => Field::State(
            known(StateKey::from_tag(r.u8()?))?,
            known(StateValue::from_tag(r.u8()?))?,
        ),
        FIELD_PATH_TYPE => Field::PathType(
            known(PathRole::from_tag(r.u8()?))?,
            known(PathKind::from_tag(r.u8()?))?,
        ),
        _ => return Err(IpcError::Malformed),
    })
}

/// A cursor over hostile bytes; every read is checked, none indexes.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { rest: bytes }
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], IpcError> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(IpcError::Malformed)?;
        self.rest = tail;
        Ok(head)
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
        let [b] = self.array::<1>()?;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, IpcError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, IpcError> {
        Ok(u64::from_be_bytes(self.array()?))
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

    fn ticket(text: &str) -> TicketText {
        TicketText::new(Secret::new(text.to_owned())).unwrap()
    }

    fn id(seed: u8) -> EndpointId {
        iroh_base::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn every_op() -> Vec<Op> {
        vec![
            Op::Status,
            Op::Host,
            Op::Join(ticket("kickoff1ABCDEF234567")),
            Op::Invite(InviteFor::Friend(id(1))),
            Op::Invite(InviteFor::Bearer),
            Op::Kick(id(2)),
            Op::Approve(id(3)),
            Op::PickMap(MapId([9; 32])),
            Op::Leave,
            Op::Doctor,
            Op::ToggleOverlay,
        ]
    }

    fn same_op(a: &Op, b: &Op) -> bool {
        match (a, b) {
            (Op::Join(x), Op::Join(y)) => y.secret().expose(|y| x.secret().ct_eq(y.as_bytes())),
            _ => format!("{a:?}") == format!("{b:?}"),
        }
    }

    #[test]
    fn ops_round_trip_and_reject_every_truncation_and_trailing_byte() {
        for op in every_op() {
            let bytes = encode_op(&op).unwrap();
            assert!(same_op(&decode_op(&bytes).unwrap(), &op), "{op:?}");
            for cut in 0..bytes.len() {
                assert_eq!(decode_op(&bytes[..cut]).err(), Some(IpcError::Malformed));
            }
            let mut longer = bytes.to_vec();
            longer.push(0);
            assert_eq!(decode_op(&longer).err(), Some(IpcError::Malformed));
        }
    }

    #[test]
    fn unknown_tags_are_malformed() {
        let known: Vec<u8> = every_op()
            .iter()
            .map(|op| encode_op(op).unwrap()[0])
            .collect();
        for tag in 0..=u8::MAX {
            if !known.contains(&tag) {
                assert_eq!(decode_op(&[tag]).err(), Some(IpcError::Malformed));
            }
        }
        assert_eq!(decode_op(&[OP_INVITE, 3]).err(), Some(IpcError::Malformed));
    }

    #[test]
    fn invalid_endpoint_id_is_malformed() {
        // Some 32-byte strings are not ed25519 points; find one.
        let bad = (0..=u8::MAX)
            .map(|b| [b; 32])
            .find(|bytes| EndpointId::from_bytes(bytes).is_err())
            .expect("an invalid point encoding");
        for tag in [OP_KICK, OP_APPROVE] {
            let mut bytes = vec![tag];
            bytes.extend_from_slice(&bad);
            assert_eq!(decode_op(&bytes).err(), Some(IpcError::Malformed));
        }
    }

    #[test]
    fn ticket_length_is_checked_before_reading() {
        let mut bytes = vec![OP_JOIN];
        bytes.extend_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(decode_op(&bytes).err(), Some(IpcError::Malformed));
        assert_eq!(decode_op(&[OP_JOIN, 0, 0]).err(), Some(IpcError::Malformed));
    }

    #[test]
    fn replies_round_trip() {
        let mut report = Report::new();
        report
            .push(Field::Count(Counter::IpcPeersRejected, 7))
            .unwrap();
        report.push(Field::Flag(Flag::SessionActive, true)).unwrap();
        report
            .push(Field::Version(
                Component::IpcProtocol,
                Version {
                    major: 1,
                    minor: 2,
                    patch: 3,
                },
            ))
            .unwrap();
        report
            .push(Field::State(StateKey::SessionRole, StateValue::Host))
            .unwrap();
        report
            .push(Field::PathType(PathRole::RuntimeDir, PathKind::Directory))
            .unwrap();
        let bytes = encode_reply(&Reply::Report(report.clone())).unwrap();
        match decode_reply(&bytes).unwrap() {
            Reply::Report(got) => assert_eq!(got, report),
            other => panic!("{other:?}"),
        }
        for refusal in [
            Refusal::Unknown,
            Refusal::Busy,
            Refusal::NotHost,
            Refusal::Failed,
        ] {
            let bytes = encode_reply(&Reply::Refused(refusal)).unwrap();
            assert!(matches!(decode_reply(&bytes).unwrap(), Reply::Refused(r) if r == refusal));
        }
        let bytes = encode_reply(&Reply::Invite(ticket("kickoff1XYZ"))).unwrap();
        assert!(matches!(decode_reply(&bytes).unwrap(), Reply::Invite(_)));
        for cut in 0..bytes.len() {
            assert!(decode_reply(&bytes[..cut]).is_err());
        }
    }

    #[test]
    fn report_count_is_checked_before_reading_fields() {
        let mut bytes = vec![REPLY_REPORT];
        bytes.extend_from_slice(&u16::try_from(MAX_FIELDS + 1).unwrap().to_be_bytes());
        assert_eq!(decode_reply(&bytes).err(), Some(IpcError::Malformed));
    }

    #[test]
    fn non_canonical_flag_is_malformed() {
        let bytes = [REPLY_REPORT, 0, 1, FIELD_FLAG, Flag::SessionActive.tag(), 2];
        assert_eq!(decode_reply(&bytes).err(), Some(IpcError::Malformed));
    }

    #[test]
    fn hello_is_checked_version_first() {
        let hello = encode_hello(PROTOCOL_VERSION, ChannelRole::Cli);
        assert_eq!(decode_hello(&hello), Ok(ChannelRole::Cli));
        let other = PROTOCOL_VERSION.wrapping_add(1);
        assert_eq!(
            decode_hello(&encode_hello(other, ChannelRole::Cli)),
            Err(Welcome::Version)
        );
        assert_eq!(
            decode_hello(&encode_hello(other, ChannelRole::Gamebox)),
            Err(Welcome::Version)
        );
        for role in [ChannelRole::Gamebox, ChannelRole::ServiceClient] {
            assert_eq!(
                decode_hello(&encode_hello(PROTOCOL_VERSION, role)),
                Err(Welcome::Role)
            );
        }
        assert_eq!(decode_hello(b"KO"), Err(Welcome::Version));
        assert_eq!(decode_hello(b"XX\0\x01\x01"), Err(Welcome::Version));
    }

    /// No input panics and none decodes with bytes left over (fuzz stand-in;
    /// the nightly fuzzer runs the same entry points).
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
            let _ = decode_op(&bytes);
            let _ = decode_reply(&bytes);
            let _ = decode_hello(&bytes);
            let _ = decode_welcome(&bytes);
        }
    }
}

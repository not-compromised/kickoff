//! The role-scoped command enums and the replies. Every role's commands map
//! into one internal `Op` set; each role decodes its own fixed postcard
//! enum. Decoding uses the authenticated channel role; commands outside
//! that role are refused before dispatch.

use std::fmt;

use iroh_base::EndpointId;
use kickoff_secret::Secret;
use kickoff_secret::diag::Report;
use kickoff_wire::{MAX_TICKET_LEN, MapId, TicketTextValue};

use crate::{ChannelRole, IpcError};

/// A ticket string in transit from the CLI or the UI to kickoffd, which
/// parses it with `kickoff_wire::parse_ticket`. Its alphabet is the ticket
/// encoding's (`kickoff1` plus base32), so it cannot hold a path, a URL, an
/// option or whitespace (SI-3); the `kickoff://join/` prefix is stripped by
/// the caller.
pub struct TicketText(Secret<TicketTextValue>);

impl TicketText {
    pub fn new(text: Secret<TicketTextValue>) -> Result<TicketText, IpcError> {
        if cfg!(feature = "mutant-si3-ticket-text-any") || TicketTextValue::is_alphanumeric(&text) {
            Ok(TicketText(text))
        } else {
            Err(IpcError::Malformed)
        }
    }

    /// The whole rule: 1 to `MAX_TICKET_LEN` ASCII letters and digits. No
    /// `/`, `.`, `:`, `\`, `-`, `%` or whitespace, so no path, URL, option
    /// or escape fits.
    pub(crate) fn alphabet_ok(bytes: &[u8]) -> bool {
        (1..=MAX_TICKET_LEN).contains(&bytes.len())
            && (cfg!(feature = "mutant-si3-ticket-text-any")
                || bytes.iter().all(u8::is_ascii_alphanumeric))
    }

    pub fn secret(&self) -> &Secret<TicketTextValue> {
        &self.0
    }
}

impl fmt::Debug for TicketText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if cfg!(feature = "mutant-si30-ticket-text-debug") {
            return write!(
                f,
                "TicketText({})",
                String::from_utf8_lossy(&TicketTextValue::transport(&self.0))
            );
        }
        f.write_str("TicketText(<redacted>)")
    }
}

pub use kickoff_wire::ApprovalId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteFor {
    /// A bound invite for one identity.
    Friend(EndpointId),
    /// A single-use bearer invite.
    Bearer,
}

#[derive(Debug)]
pub enum CliCommand {
    Status,
    Host,
    Join(TicketText),
    Invite(InviteFor),
    Leave,
    Doctor,
    ToggleOverlay,
}

/// The UI main window's Rust layer, never the webview. `Decide` is sent only
/// by the native dialog path, and names an approval object, not a peer
/// (§2.7, §4.4).
#[derive(Debug)]
pub enum UiCommand {
    Status,
    Host,
    Join(TicketText),
    Invite(InviteFor),
    Kick(EndpointId),
    Decide { approval: ApprovalId, allow: bool },
    PickMap(MapId),
    Leave,
    Doctor,
}

/// The overlay can only read status (§2.7); it can never decide an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayCommand {
    Status,
}

/// What `Channel::recv` yields: the command decoded under the channel's role.
#[derive(Debug)]
pub enum Request {
    Cli(CliCommand),
    UiMain(UiCommand),
    Overlay(OverlayCommand),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Unknown,
    Busy,
    NotHost,
    Failed,
}

#[derive(Debug)]
pub enum Reply {
    Done,
    Refused(Refusal),
    /// Only on `Cli` and `UiMain` channels; the overlay never sees a ticket.
    Invite(TicketText),
    Report(Report),
}

impl Reply {
    pub(crate) fn allowed_for(&self, role: ChannelRole) -> bool {
        match self {
            Reply::Invite(_) => matches!(role, ChannelRole::Cli | ChannelRole::UiMain),
            Reply::Done | Reply::Refused(_) | Reply::Report(_) => true,
        }
    }
}

/// The internal union of role commands, independent of their wire enums.
#[derive(Debug)]
pub enum Op {
    Status,
    Host,
    Join(TicketText),
    Invite(InviteFor),
    Kick(EndpointId),
    Decide { approval: ApprovalId, allow: bool },
    PickMap(MapId),
    Leave,
    Doctor,
    ToggleOverlay,
}

impl From<CliCommand> for Op {
    fn from(c: CliCommand) -> Op {
        match c {
            CliCommand::Status => Op::Status,
            CliCommand::Host => Op::Host,
            CliCommand::Join(t) => Op::Join(t),
            CliCommand::Invite(i) => Op::Invite(i),
            CliCommand::Leave => Op::Leave,
            CliCommand::Doctor => Op::Doctor,
            CliCommand::ToggleOverlay => Op::ToggleOverlay,
        }
    }
}

impl From<UiCommand> for Op {
    fn from(c: UiCommand) -> Op {
        match c {
            UiCommand::Status => Op::Status,
            UiCommand::Host => Op::Host,
            UiCommand::Join(t) => Op::Join(t),
            UiCommand::Invite(i) => Op::Invite(i),
            UiCommand::Kick(id) => Op::Kick(id),
            UiCommand::Decide { approval, allow } => Op::Decide { approval, allow },
            UiCommand::PickMap(m) => Op::PickMap(m),
            UiCommand::Leave => Op::Leave,
            UiCommand::Doctor => Op::Doctor,
        }
    }
}

impl From<OverlayCommand> for Op {
    fn from(c: OverlayCommand) -> Op {
        match c {
            OverlayCommand::Status => Op::Status,
        }
    }
}

impl Op {
    /// The role scoping: `None` means the role has no such command, which the
    /// server treats exactly like an unknown tag.
    pub(crate) fn for_role(self, role: ChannelRole) -> Option<Request> {
        match role {
            ChannelRole::Cli => Some(Request::Cli(match self {
                Op::Status => CliCommand::Status,
                Op::Host => CliCommand::Host,
                Op::Join(t) => CliCommand::Join(t),
                Op::Invite(i) => CliCommand::Invite(i),
                Op::Leave => CliCommand::Leave,
                Op::Doctor => CliCommand::Doctor,
                Op::ToggleOverlay => CliCommand::ToggleOverlay,
                Op::Kick(_) | Op::Decide { .. } | Op::PickMap(_) => return None,
            })),
            ChannelRole::UiMain => Some(Request::UiMain(match self {
                Op::Status => UiCommand::Status,
                Op::Host => UiCommand::Host,
                Op::Join(t) => UiCommand::Join(t),
                Op::Invite(i) => UiCommand::Invite(i),
                Op::Kick(id) => UiCommand::Kick(id),
                Op::Decide { approval, allow } => UiCommand::Decide { approval, allow },
                Op::PickMap(m) => UiCommand::PickMap(m),
                Op::Leave => UiCommand::Leave,
                Op::Doctor => UiCommand::Doctor,
                Op::ToggleOverlay => return None,
            })),
            ChannelRole::Overlay => match self {
                Op::Status => Some(Request::Overlay(OverlayCommand::Status)),
                _ => None,
            },
            ChannelRole::Gamebox | ChannelRole::ServiceClient => None,
        }
    }
}

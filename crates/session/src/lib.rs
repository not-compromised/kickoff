//! A Kickoff session (design §2.3, §4). Hides admission, capabilities,
//! generations, reconnect, budgets and the pump.
//!
//! One admission owner decides every authorization, keyed by identity and
//! generation; revocation overrides trust and tickets (§4.4). The host pump
//! routes between each guest link and the local LAN only: no link-to-link path
//! exists (§2.4, SI-21). A datagram's source slot is the slot of the link it
//! arrived on, never anything in the packet.

mod admission;
mod approval;
mod budget;
mod clock;
mod guest;
mod host;
mod routes;

use std::sync::Arc;

use iroh_base::{EndpointId, SecretKey};
use kickoff_net::{Door, NetError, SessionNet};
use kickoff_secret::Secret;
use kickoff_vlan::{Adapter, LanError};
use kickoff_wire::{
    BuildId, InviteError, JoinRefused, KickReason, KickoffVersion, MapId, Member, Name, PeerSlot,
    Platform, Ticket,
};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinSet;

pub use approval::{Approval, ApprovalAction, ApprovalId};
pub use clock::Clock;

/// What this build announces in `JoinRequest`. A host admits a guest of the
/// same major version (the same minor too, before 1.0).
pub const KICKOFF_VERSION: KickoffVersion = KickoffVersion {
    major: parse_u16(env!("CARGO_PKG_VERSION_MAJOR")),
    minor: parse_u16(env!("CARGO_PKG_VERSION_MINOR")),
    patch: parse_u16(env!("CARGO_PKG_VERSION_PATCH")),
};

#[expect(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "const evaluation of the crate's own version: any overflow or bad digit fails the build"
)]
const fn parse_u16(digits: &str) -> u16 {
    let bytes = digits.as_bytes();
    let mut value: u16 = 0;
    let mut i = 0;
    while i < bytes.len() {
        assert!(
            bytes[i].is_ascii_digit(),
            "version component is not a number"
        );
        value = value * 10 + (bytes[i] - b'0') as u16;
        i += 1;
    }
    value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    #[error("not implemented yet")]
    NotImplemented,
    #[error("only the host can do that")]
    NotHost,
    #[error("the session has ended")]
    Ended,
    #[error("the door key does not match the door")]
    WrongKey,
    #[error("refused by the host: {0:?}")]
    Refused(JoinRefused),
    #[error("the host did not confirm admission")]
    NotAdmitted,
    #[error("that approval is not pending: decided, retired or timed out")]
    NoApproval,
    #[error("too many revoked identities")]
    RevokedFull,
    #[error("invite: {0}")]
    Invite(InviteError),
    #[error("network: {0}")]
    Net(NetError),
    #[error("LAN adapter: {0}")]
    Lan(LanError),
}

#[derive(Debug, Clone)]
pub struct HostOpts {
    /// Shown to guests as slot 1.
    pub name: Name,
    /// Persistent identities that may join without a ticket. A kick overrides
    /// them for the session's lifetime (SI-19).
    pub trusted: Vec<EndpointId>,
    /// Invite validity and the admission and reconnect windows run on it.
    pub clock: Clock,
}

impl HostOpts {
    pub fn new(name: Name) -> HostOpts {
        HostOpts {
            name,
            trusted: Vec::new(),
            clock: Clock::system(),
        }
    }
}

/// What a guest tells the host about itself in its `JoinRequest`.
#[derive(Debug, Clone)]
pub struct JoinOpts {
    pub name: Name,
    pub platform: Platform,
    pub game_build: BuildId,
    /// The reconnect window runs on it.
    pub clock: Clock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteKind {
    /// For one identity; single use, valid while the session lives, admitted
    /// without a prompt.
    Bound(EndpointId),
    /// Single use, 15 minutes by the host's monotonic clock, admitted only
    /// once the owner allows its `ApprovalAction::AdmitBearer` approval.
    Bearer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Command {
    /// Host: revoke for the session's lifetime and disconnect.
    Kick(EndpointId),
    /// Host: lift a kick's revocation. Admits nothing by itself.
    Readmit(EndpointId),
    /// Decide one approval object, which the decision consumes. Only the
    /// native dialog path may send it (§2.7, SI-41).
    Decide {
        approval: ApprovalId,
        allow: bool,
    },
    PickMap(MapId),
    Leave,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// This node left.
    Left,
    /// The host ended the session.
    HostEnded,
    /// A guest's link stayed down for the whole reconnect window.
    HostLost,
    Kicked(KickReason),
    /// The local game's adapter closed.
    LanClosed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEvent {
    /// The host and every admitted guest; `epoch` increases with each change.
    Roster {
        epoch: u64,
        members: Vec<Member>,
    },
    /// An approval waits for the owner's native dialog. A slow receiver can
    /// lose this event; `Session::approvals` cannot lose a pending approval.
    ApprovalRequested(Approval),
    /// A guest's link to the host dropped; it is redialing.
    Reconnecting,
    Ended(EndReason),
}

/// Events are dropped for a receiver that falls this far behind.
const EVENTS: usize = 64;

/// Hosts a session: admits guests through `door`, carries their LAN traffic
/// over `net` and delivers it to the game on `adapter`, as slot 1.
pub async fn host(
    door: Arc<Door>,
    door_key: &Secret<SecretKey>,
    net: SessionNet,
    adapter: Adapter,
    opts: HostOpts,
) -> Result<Session, SessionError> {
    let (events, _) = broadcast::channel(EVENTS);
    let mut tasks = JoinSet::new();
    let host = host::start(
        door,
        door_key,
        net,
        adapter,
        opts,
        events.clone(),
        &mut tasks,
    )?;
    Ok(Session {
        role: Role::Host(host),
        events,
        _tasks: tasks,
    })
}

/// Joins the session `ticket` invites to. Returns once the host has admitted
/// this node and sent its first roster (§4.3); the game on `adapter` then
/// sits at the slot the host assigned.
pub async fn join(
    door: &Door,
    net: SessionNet,
    adapter: Adapter,
    ticket: Secret<Ticket>,
    opts: JoinOpts,
) -> Result<Session, SessionError> {
    let (events, _) = broadcast::channel(EVENTS);
    let mut tasks = JoinSet::new();
    let guest = guest::start(door, net, adapter, ticket, opts, events.clone(), &mut tasks).await?;
    Ok(Session {
        role: Role::Guest(guest),
        events,
        _tasks: tasks,
    })
}

enum Role {
    Host(Arc<host::Host>),
    Guest(guest::Guest),
}

/// Dropping a session stops every task it runs.
pub struct Session {
    role: Role,
    events: broadcast::Sender<SessionEvent>,
    _tasks: JoinSet<()>,
}

impl Session {
    /// Host only; a guest session gets `NotHost`.
    pub fn invite(&self, kind: InviteKind) -> Result<Secret<Ticket>, SessionError> {
        match &self.role {
            Role::Host(host) => host.invite(kind),
            Role::Guest(_) => Err(SessionError::NotHost),
        }
    }

    pub fn events(&self) -> broadcast::Receiver<SessionEvent> {
        self.events.subscribe()
    }

    /// The approvals pending now, at most one per kind. A watch holds the
    /// current set, so however far a reader falls behind, it misses only
    /// approvals that can no longer be decided. Empty on a guest until M6.
    pub fn approvals(&self) -> watch::Receiver<Vec<Approval>> {
        match &self.role {
            Role::Host(host) => host.approvals(),
            Role::Guest(_) => watch::channel(Vec::new()).1,
        }
    }

    /// This node's slot: 1 on the host, the admitted slot on a guest.
    pub fn slot(&self) -> PeerSlot {
        match &self.role {
            Role::Host(_) => PeerSlot::HOST,
            Role::Guest(guest) => guest.slot(),
        }
    }

    /// The host and every admitted guest, as of the latest roster.
    pub fn members(&self) -> Vec<Member> {
        match &self.role {
            Role::Host(host) => host.members(),
            Role::Guest(guest) => guest.members(),
        }
    }

    pub async fn command(&self, command: Command) -> Result<(), SessionError> {
        match (&self.role, command) {
            (Role::Host(host), command) => host.command(command).await,
            (Role::Guest(guest), Command::Leave) => guest.leave().await,
            // A guest creates no approvals until map installs (M6).
            (Role::Guest(_), Command::Decide { .. }) => Err(SessionError::NoApproval),
            (Role::Guest(_), _) => Err(SessionError::NotHost),
        }
    }
}

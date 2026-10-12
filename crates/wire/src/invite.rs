//! The host's ledger of the capabilities it issued this session (§4.2, §4.4).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use iroh_base::{EndpointId, SecretKey};
use kickoff_secret::Secret;

use crate::{Cap, JoinRefused, Nonce, SessionId};

/// A bearer invite is valid this long after issue, by the host's monotonic
/// clock.
pub const BEARER_TTL: Duration = Duration::from_secs(15 * 60);
/// Outstanding invites per session. A fixed capacity keeps the ledger from
/// growing on the host's behalf (SI-23).
pub const MAX_OUTSTANDING: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    #[error("the signing key is not this door's key")]
    WrongKey,
    #[error("too many outstanding invites")]
    Full,
    #[error("the operating system's random source failed")]
    Entropy,
}

/// How a redeemed capability was issued. A bearer invite needs the host's
/// approval in a native prompt before the guest is admitted (§4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redeemed {
    Bound,
    Bearer,
}

struct Outstanding {
    invitee: Option<EndpointId>,
    issued: Instant,
}

/// Every capability this host process issued for one session and has not seen
/// redeemed. It lives in memory only, under a fresh random `SessionId`, so a
/// ticket from an earlier session or host process can never match (SI-20).
///
/// Time is passed in as an `Instant`, which is monotonic by type: moving the
/// wall clock cannot revive an expired invite.
pub struct Invites {
    door: EndpointId,
    session_id: SessionId,
    outstanding: HashMap<Nonce, Outstanding>,
}

fn random<const N: usize>() -> Result<[u8; N], InviteError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| InviteError::Entropy)?;
    Ok(bytes)
}

impl Invites {
    pub fn new(door_key: &Secret<SecretKey>) -> Result<Invites, InviteError> {
        Ok(Invites {
            door: door_key.expose(SecretKey::public),
            session_id: SessionId(random()?),
            outstanding: HashMap::with_capacity(MAX_OUTSTANDING),
        })
    }

    /// Signs a new single-use capability: bound to `invitee` when it is
    /// `Some`, a bearer invite otherwise.
    pub fn issue(
        &mut self,
        door_key: &Secret<SecretKey>,
        invitee: Option<EndpointId>,
        now: Instant,
    ) -> Result<Cap, InviteError> {
        if door_key.expose(SecretKey::public) != self.door {
            return Err(InviteError::WrongKey);
        }
        if self.outstanding.len() >= MAX_OUTSTANDING {
            self.outstanding
                .retain(|_, entry| !expired(entry.invitee, entry.issued, now));
        }
        if self.outstanding.len() >= MAX_OUTSTANDING {
            return Err(InviteError::Full);
        }
        let nonce = Nonce(random()?);
        if self.outstanding.contains_key(&nonce) {
            return Err(InviteError::Entropy);
        }
        self.outstanding.insert(
            nonce,
            Outstanding {
                invitee,
                issued: now,
            },
        );
        Ok(Cap::sign(door_key, self.session_id, invitee, nonce))
    }

    /// Spends `cap` for `requester`, the identity the door's TLS handshake
    /// authenticated. Succeeds at most once per capability; every later call
    /// is refused. It spends the capability whatever the caller decides next
    /// (a declined prompt revokes it), so check version and roster space
    /// first. A bound capability presented by anyone but its invitee is
    /// refused and stays unspent.
    pub fn redeem(
        &mut self,
        cap: &Cap,
        requester: EndpointId,
        now: Instant,
    ) -> Result<Redeemed, JoinRefused> {
        if !cap.verify(&self.door) {
            return Err(JoinRefused::InvalidCap);
        }
        if cap.session_id != self.session_id {
            return Err(JoinRefused::WrongSession);
        }
        let entry = self
            .outstanding
            .get(&cap.nonce)
            .ok_or(JoinRefused::InvalidCap)?;
        if entry.invitee != cap.invitee || entry.invitee.is_some_and(|id| id != requester) {
            return Err(JoinRefused::InvalidCap);
        }
        let invitee = entry.invitee;
        let issued = entry.issued;
        self.outstanding.remove(&cap.nonce);
        if expired(invitee, issued, now) {
            return Err(JoinRefused::Expired);
        }
        Ok(match invitee {
            Some(_) => Redeemed::Bound,
            None => Redeemed::Bearer,
        })
    }
}

/// Bound invites last as long as the session; bearer invites `BEARER_TTL`.
fn expired(invitee: Option<EndpointId>, issued: Instant, now: Instant) -> bool {
    invitee.is_none() && now.saturating_duration_since(issued) >= BEARER_TTL
}

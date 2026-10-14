//! Approvals (§4.4, R2-14, SI-41): immutable objects that one decision
//! consumes. Pure state, owned by the admission owner, which creates,
//! consumes and retires them under its lock.
//!
//! An id names one object, never a peer: once its object is decided,
//! retired or timed out, the id authorizes nothing, even for the same peer
//! asking again.

use std::time::{Duration, Instant};

use iroh_base::EndpointId;
use kickoff_wire::{Generation, MapId};

/// An approval left unanswered this long authorizes nothing.
pub(crate) const APPROVAL_TTL: Duration = Duration::from_secs(60);

pub use kickoff_wire::ApprovalId;

fn new_id(peer: &EndpointId) -> Option<ApprovalId> {
    if cfg!(feature = "mutant-si41-approve-by-peer") {
        return peer
            .as_bytes()
            .first_chunk()
            .copied()
            .map(ApprovalId::from_bytes);
    }
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).ok()?;
    Some(ApprovalId::from_bytes(bytes))
}

/// What the host's or player's native dialog shows, and the only thing a
/// decision can authorize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub id: ApprovalId,
    pub action: ApprovalAction,
    /// The identity the door's TLS handshake authenticated.
    pub peer: EndpointId,
    /// The peer's generation when it asked; any change retires the approval.
    pub generation: Generation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalAction {
    /// Admit a guest that presented a bearer invite.
    AdmitBearer,
    /// Install a map the host picked (M6).
    InstallMap { map: MapId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// One approval per kind is pending already.
    Busy,
    /// The operating system's random source failed.
    Entropy,
}

struct Entry {
    approval: Approval,
    created: Instant,
}

/// At most one pending approval per action kind (§6.3).
#[derive(Default)]
pub(crate) struct Approvals {
    admit: Option<Entry>,
    map: Option<Entry>,
}

impl Approvals {
    /// A new approval for `peer` at `generation`. A second bearer admission
    /// is refused while one is pending; a newer map pick replaces the pending
    /// one, whose id then stops working.
    pub(crate) fn request(
        &mut self,
        action: ApprovalAction,
        peer: EndpointId,
        generation: Generation,
        now: Instant,
    ) -> Result<Approval, Refused> {
        if action == ApprovalAction::AdmitBearer && self.bearer_pending() {
            return Err(Refused::Busy);
        }
        let approval = Approval {
            id: new_id(&peer).ok_or(Refused::Entropy)?,
            action,
            peer,
            generation,
        };
        *self.kind_mut(action) = Some(Entry {
            approval: approval.clone(),
            created: now,
        });
        Ok(approval)
    }

    pub(crate) fn bearer_pending(&self) -> bool {
        !cfg!(feature = "mutant-si41-two-bearer-approvals") && self.admit.is_some()
    }

    /// Consumes the approval `id` names if it is still current: once taken,
    /// no later call finds it.
    pub(crate) fn take(&mut self, id: ApprovalId, now: Instant) -> Option<Approval> {
        let slot = [&mut self.admit, &mut self.map]
            .into_iter()
            .find(|e| e.as_ref().is_some_and(|e| e.approval.id == id))?;
        let entry = slot.take()?;
        live(&entry, now).then_some(entry.approval)
    }

    /// True while `id` is pending, timed out or not: the sweep retires it.
    pub(crate) fn contains(&self, id: ApprovalId) -> bool {
        self.entries().any(|e| e.approval.id == id)
    }

    /// True while `id` is pending and inside its timeout.
    pub(crate) fn current(&self, id: ApprovalId, now: Instant) -> bool {
        self.entries().any(|e| e.approval.id == id && live(e, now))
    }

    /// `peer` was kicked, evicted or moved to a new generation.
    pub(crate) fn retire_peer(&mut self, peer: EndpointId) {
        if cfg!(feature = "mutant-si41-survives-peer-change") {
            return;
        }
        for slot in [&mut self.admit, &mut self.map] {
            if slot.as_ref().is_some_and(|e| e.approval.peer == peer) {
                *slot = None;
            }
        }
    }

    /// Drops the approvals whose timeout ran out; true if there were any.
    pub(crate) fn expire(&mut self, now: Instant) -> bool {
        let mut any = false;
        for slot in [&mut self.admit, &mut self.map] {
            if slot.as_ref().is_some_and(|e| !live(e, now)) {
                *slot = None;
                any = true;
            }
        }
        any
    }

    /// The session ended.
    pub(crate) fn clear(&mut self) {
        *self = Approvals::default();
    }

    pub(crate) fn pending(&self) -> Vec<Approval> {
        self.entries().map(|e| e.approval.clone()).collect()
    }

    fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.admit.iter().chain(&self.map)
    }

    fn kind_mut(&mut self, action: ApprovalAction) -> &mut Option<Entry> {
        match action {
            ApprovalAction::AdmitBearer => &mut self.admit,
            ApprovalAction::InstallMap { .. } => &mut self.map,
        }
    }
}

fn live(entry: &Entry, now: Instant) -> bool {
    cfg!(feature = "mutant-si41-no-approval-timeout")
        || now.saturating_duration_since(entry.created) < APPROVAL_TTL
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;

    fn peer(n: u8) -> EndpointId {
        SecretKey::from_bytes(&[n; 32]).public()
    }

    fn map(n: u8) -> ApprovalAction {
        ApprovalAction::InstallMap {
            map: MapId([n; 32]),
        }
    }

    /// Every way an approval dies, each against the same peer asking again:
    /// the old id authorizes nothing, and only the newest object decides.
    #[test]
    fn si_41_an_approval_dies_with_its_moment() {
        let t = Instant::now();
        let g = Generation::new;
        let mut a = Approvals::default();

        // Single use.
        let first = a.request(map(1), peer(1), g(1), t).unwrap();
        assert_eq!(a.take(first.id, t), Some(first.clone()));
        assert_eq!(a.take(first.id, t), None, "an id decided twice");

        // A newer map pick replaces the pending one.
        let old = a.request(map(1), peer(1), g(1), t).unwrap();
        let new = a.request(map(2), peer(1), g(1), t).unwrap();
        assert_ne!(old.id, new.id);
        assert_eq!(a.take(old.id, t), None, "a replaced map pick decided");
        assert_eq!(a.take(new.id, t).map(|x| x.action), Some(map(2)));

        // A kick or a reconnect (the peer's generation moved).
        let old = a
            .request(ApprovalAction::AdmitBearer, peer(2), g(5), t)
            .unwrap();
        a.retire_peer(peer(2));
        let new = a
            .request(ApprovalAction::AdmitBearer, peer(2), g(6), t)
            .unwrap();
        assert_eq!(
            a.take(old.id, t),
            None,
            "an approval outlived its generation"
        );
        assert_eq!(a.take(new.id, t).map(|x| x.generation), Some(g(6)));

        // The timeout.
        let old = a
            .request(ApprovalAction::AdmitBearer, peer(3), g(7), t)
            .unwrap();
        let late = t + APPROVAL_TTL;
        assert!(!a.current(old.id, late));
        assert!(a.expire(late));
        let new = a
            .request(ApprovalAction::AdmitBearer, peer(3), g(8), late)
            .unwrap();
        assert_eq!(
            a.take(old.id, late),
            None,
            "an approval outlived its timeout"
        );
        assert!(a.current(new.id, late));

        // The end of the session.
        a.clear();
        assert_eq!(a.take(new.id, late), None);
        assert!(a.pending().is_empty());
    }

    /// One bearer admission waits at a time; another kind is independent.
    #[test]
    fn si_41_one_pending_approval_per_kind() {
        let t = Instant::now();
        let mut a = Approvals::default();
        let first = a
            .request(ApprovalAction::AdmitBearer, peer(1), Generation::new(1), t)
            .unwrap();
        assert_eq!(
            a.request(ApprovalAction::AdmitBearer, peer(2), Generation::new(2), t),
            Err(Refused::Busy)
        );
        let pick = a.request(map(1), peer(9), Generation::new(3), t).unwrap();
        assert_eq!(a.pending(), vec![first.clone(), pick]);
        assert!(a.take(first.id, t).is_some());
        assert!(
            a.request(ApprovalAction::AdmitBearer, peer(2), Generation::new(2), t)
                .is_ok()
        );
    }
}

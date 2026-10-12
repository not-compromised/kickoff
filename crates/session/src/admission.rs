//! The admission owner (§4.4): the one place that decides who holds a seat,
//! under which generation, and who is revoked. Pure state, no I/O; the host
//! runtime applies what it decides while holding its lock, so every
//! published admitted set, roster and route agrees with one state of this
//! table.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use iroh_base::{EndpointId, SecretKey};
use kickoff_net::AdmittedSet;
use kickoff_secret::Secret;
use kickoff_wire::{
    Cap, Generation, InviteError, Invites, JoinRefused, JoinRequest, KickoffVersion, MAX_ROSTER,
    Member, Name, PeerRef, PeerSlot, Redeemed,
};

use crate::KICKOFF_VERSION;

/// Guest seats: slots 2..=8.
const SEATS: usize = MAX_ROSTER as usize - 1;
/// An admitted guest must connect to the session endpoint within this.
pub(crate) const ADMIT_WINDOW: Duration = Duration::from_secs(30);
/// A guest whose link dropped keeps its seat this long (§4.6).
pub(crate) const RECONNECT_WINDOW: Duration = Duration::from_secs(30);
/// Revocations are host actions, but the table still has a fixed size.
pub(crate) const MAX_REVOKED: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// A bearer-invite guest waiting on the owner's native prompt. Holds the
    /// seat so the answer cannot find the roster full, but is not admitted.
    Prompting,
    Admitted {
        since: Instant,
    },
    Live,
    Reconnecting {
        since: Instant,
    },
}

struct Seat {
    id: EndpointId,
    session_key: EndpointId,
    name: Name,
    /// The generation in the guest's pass; its `Hello` must carry it.
    pass: Generation,
    /// Current. Bumped when the link drops, so nothing the old link left
    /// queued survives into the reconnect.
    generation: Generation,
    state: State,
}

impl Seat {
    fn admitted(&self) -> bool {
        self.state != State::Prompting
    }

    fn holds(&self, peer: &PeerRef) -> bool {
        self.id == peer.id && self.generation == peer.generation
    }
}

pub(crate) enum Joined {
    Admitted(PeerRef),
    /// Bearer invite: admitted only after `approve`.
    Prompt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RevokedFull;

pub(crate) struct Admission {
    host: Member,
    /// The host's own session key and door identity: no guest may claim them.
    host_keys: [EndpointId; 2],
    trusted: HashSet<EndpointId>,
    revoked: HashSet<EndpointId>,
    /// Invitees of bound tickets not yet redeemed, for the door's priority
    /// queue (§6.3, NET-18).
    bound: HashSet<EndpointId>,
    invites: Invites,
    seats: [Option<Seat>; SEATS],
    last_generation: u64,
    epoch: u64,
}

impl Admission {
    pub(crate) fn new(
        door_key: &Secret<SecretKey>,
        host_session_key: EndpointId,
        host_name: Name,
        trusted: impl IntoIterator<Item = EndpointId>,
    ) -> Result<Admission, InviteError> {
        let door = door_key.expose(SecretKey::public);
        Ok(Admission {
            host: Member {
                slot: PeerSlot::HOST,
                id: door,
                name: host_name,
            },
            host_keys: [door, host_session_key],
            trusted: trusted.into_iter().collect(),
            revoked: HashSet::new(),
            bound: HashSet::new(),
            invites: Invites::new(door_key)?,
            seats: Default::default(),
            last_generation: 0,
            epoch: 1,
        })
    }

    pub(crate) fn issue(
        &mut self,
        door_key: &Secret<SecretKey>,
        invitee: Option<EndpointId>,
        now: Instant,
    ) -> Result<Cap, InviteError> {
        let cap = self.invites.issue(door_key, invitee, now)?;
        if let Some(id) = invitee
            && self.bound.len() < kickoff_wire::MAX_OUTSTANDING
        {
            self.bound.insert(id);
        }
        Ok(cap)
    }

    /// Decides a join request from `id`, the identity the door's TLS handshake
    /// authenticated. Every refusal that does not depend on the capability
    /// comes first, so a bound invite is never spent on a refusal (wire's
    /// `Invites::redeem` spends whatever happens next).
    pub(crate) fn join(
        &mut self,
        id: EndpointId,
        request: &JoinRequest,
        now: Instant,
    ) -> Result<Joined, JoinRefused> {
        let trust_wins =
            cfg!(feature = "mutant-si19-trust-overrides-kick") && self.trusted.contains(&id);
        if self.revoked.contains(&id) && !trust_wins {
            return Err(JoinRefused::Revoked);
        }
        if !compatible(request.kickoff_version) {
            return Err(JoinRefused::Version);
        }
        if !cfg!(feature = "mutant-si18-two-seats-per-identity") && self.seat_of(id).is_some() {
            return Err(JoinRefused::Busy);
        }
        // A session key names exactly one admission in the published set; a
        // claimed duplicate would overwrite another guest's entry.
        let key = request.session_key;
        if !cfg!(feature = "mutant-si18-claimed-session-key")
            && (self.host_keys.contains(&key)
                || self.seats.iter().flatten().any(|s| s.session_key == key))
        {
            return Err(JoinRefused::InvalidCap);
        }
        let index = self
            .seats
            .iter()
            .position(Option::is_none)
            .ok_or(JoinRefused::Full)?;
        let redeemed = if self.trusted.contains(&id) {
            Redeemed::Bound
        } else {
            self.invites.redeem(&request.cap, id, now)?
        };
        let generation = self.next_generation().ok_or(JoinRefused::Busy)?;
        let slot = slot_of(index).ok_or(JoinRefused::Full)?;
        let state = match redeemed {
            Redeemed::Bound => State::Admitted { since: now },
            Redeemed::Bearer => State::Prompting,
        };
        let seat = self.seats.get_mut(index).ok_or(JoinRefused::Full)?;
        *seat = Some(Seat {
            id,
            session_key: key,
            name: request.name.clone(),
            pass: generation,
            generation,
            state,
        });
        self.bound.remove(&id);
        Ok(match redeemed {
            Redeemed::Bound => {
                self.bump_epoch();
                Joined::Admitted(PeerRef {
                    id,
                    slot,
                    generation,
                })
            }
            Redeemed::Bearer => Joined::Prompt,
        })
    }

    /// The owner approved `id`'s prompt. `None` if it is no longer prompting
    /// (kicked meanwhile).
    pub(crate) fn approve(&mut self, id: EndpointId, now: Instant) -> Option<PeerRef> {
        let (index, seat) = self.seat_mut(id)?;
        if seat.state != State::Prompting {
            return None;
        }
        seat.state = State::Admitted { since: now };
        let peer = peer_of(index, seat)?;
        self.bump_epoch();
        Some(peer)
    }

    /// Frees a seat still waiting on its prompt.
    pub(crate) fn decline(&mut self, id: EndpointId) {
        for seat in &mut self.seats {
            if seat
                .as_ref()
                .is_some_and(|s| s.id == id && s.state == State::Prompting)
            {
                *seat = None;
            }
        }
    }

    /// A link arrived for `peer` and its first message was `Hello { pass }`.
    /// True if that makes the seat live.
    pub(crate) fn link_up(&mut self, peer: PeerRef, pass: Generation) -> bool {
        if cfg!(feature = "mutant-si18-link-up-any") {
            return index_of(peer.slot)
                .and_then(|i| self.seats.get(i))
                .is_some_and(Option::is_some);
        }
        match self.seat_at_mut(peer) {
            Some(seat) if seat.pass == pass => match seat.state {
                State::Admitted { .. } | State::Reconnecting { .. } => {
                    seat.state = State::Live;
                    true
                }
                State::Prompting | State::Live => false,
            },
            _ => false,
        }
    }

    /// The live link for `peer` is gone. The seat waits `RECONNECT_WINDOW`
    /// under a new generation; the returned `PeerRef` is what a redial will
    /// be admitted as.
    pub(crate) fn link_lost(&mut self, peer: PeerRef, now: Instant) -> Option<PeerRef> {
        if !self.seat_at(peer).is_some_and(|s| s.state == State::Live) {
            return None;
        }
        let generation = self.next_generation()?;
        let seat = self.seat_at_mut(peer)?;
        seat.generation = generation;
        seat.state = State::Reconnecting { since: now };
        Some(PeerRef { generation, ..peer })
    }

    /// Revokes `id` for the session's lifetime, over the trusted list and
    /// every ticket (SI-19), and frees its seat. Returns what the seat held.
    pub(crate) fn kick(&mut self, id: EndpointId) -> Result<Option<PeerRef>, RevokedFull> {
        if !self.revoked.contains(&id) && self.revoked.len() >= MAX_REVOKED {
            return Err(RevokedFull);
        }
        if !cfg!(feature = "mutant-si19-kick-does-not-revoke") {
            self.revoked.insert(id);
        }
        self.bound.remove(&id);
        Ok(self.remove(id))
    }

    /// The explicit host action that lifts a revocation. It admits nothing by
    /// itself: the identity still needs a ticket or the trusted list.
    pub(crate) fn readmit(&mut self, id: EndpointId) {
        self.revoked.remove(&id);
    }

    /// Frees `peer`'s seat if it still holds that generation.
    pub(crate) fn evict(&mut self, peer: PeerRef) -> bool {
        if self.seat_at(peer).is_none() {
            return false;
        }
        self.remove(peer.id).is_some()
    }

    /// Seats whose admission or reconnect window ran out.
    pub(crate) fn expired(&self, now: Instant) -> Vec<PeerRef> {
        let late =
            |since: Instant, window: Duration| now.saturating_duration_since(since) >= window;
        self.seats
            .iter()
            .enumerate()
            .filter_map(|(index, seat)| {
                let seat = seat.as_ref()?;
                let due = match seat.state {
                    State::Admitted { since } => late(since, ADMIT_WINDOW),
                    State::Reconnecting { since } => late(since, RECONNECT_WINDOW),
                    State::Prompting | State::Live => false,
                };
                due.then(|| peer_of(index, seat)).flatten()
            })
            .collect()
    }

    /// Session keys the session endpoint may accept, each with the identity,
    /// slot and generation it is admitted under.
    pub(crate) fn admitted_set(&self) -> AdmittedSet {
        self.seats
            .iter()
            .enumerate()
            .filter_map(|(index, seat)| {
                let seat = seat.as_ref().filter(|s| s.admitted())?;
                Some((seat.session_key, peer_of(index, seat)?))
            })
            .collect()
    }

    pub(crate) fn priority(&self) -> Vec<EndpointId> {
        self.trusted
            .iter()
            .chain(&self.bound)
            .filter(|id| !self.revoked.contains(*id))
            .copied()
            .collect()
    }

    /// The host and every admitted guest, in slot order.
    pub(crate) fn roster(&self) -> (u64, Vec<Member>) {
        let guests = self.seats.iter().enumerate().filter_map(|(index, seat)| {
            let seat = seat.as_ref().filter(|s| s.admitted())?;
            Some(Member {
                slot: slot_of(index)?,
                id: seat.id,
                name: seat.name.clone(),
            })
        });
        let members = std::iter::once(self.host.clone()).chain(guests).collect();
        (self.epoch, members)
    }

    fn remove(&mut self, id: EndpointId) -> Option<PeerRef> {
        let (index, _) = self.seat_mut(id)?;
        let seat = self.seats.get_mut(index)?.take()?;
        if seat.admitted() {
            self.bump_epoch();
        }
        peer_of(index, &seat)
    }

    fn seat_of(&self, id: EndpointId) -> Option<usize> {
        self.seats
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.id == id))
    }

    fn seat_mut(&mut self, id: EndpointId) -> Option<(usize, &mut Seat)> {
        let index = self.seat_of(id)?;
        Some((index, self.seats.get_mut(index)?.as_mut()?))
    }

    fn seat_at(&self, peer: PeerRef) -> Option<&Seat> {
        self.seats
            .get(index_of(peer.slot)?)?
            .as_ref()
            .filter(|s| s.holds(&peer))
    }

    fn seat_at_mut(&mut self, peer: PeerRef) -> Option<&mut Seat> {
        self.seats
            .get_mut(index_of(peer.slot)?)?
            .as_mut()
            .filter(|s| s.holds(&peer))
    }

    /// One counter for the whole session, so a generation is never reused,
    /// not even by another identity in the same slot.
    fn next_generation(&mut self) -> Option<Generation> {
        self.last_generation = self.last_generation.checked_add(1)?;
        Some(Generation::new(self.last_generation))
    }

    fn bump_epoch(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
    }
}

fn compatible(theirs: KickoffVersion) -> bool {
    theirs.major == KICKOFF_VERSION.major
        && (KICKOFF_VERSION.major != 0 || theirs.minor == KICKOFF_VERSION.minor)
}

fn slot_of(index: usize) -> Option<PeerSlot> {
    PeerSlot::new(u8::try_from(index.checked_add(2)?).ok()?)
}

fn index_of(slot: PeerSlot) -> Option<usize> {
    usize::from(slot.get()).checked_sub(2)
}

fn peer_of(index: usize, seat: &Seat) -> Option<PeerRef> {
    Some(PeerRef {
        id: seat.id,
        slot: slot_of(index)?,
        generation: seat.generation,
    })
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use std::collections::HashMap;

    use iroh_base::Signature;
    use kickoff_wire::{BuildId, Nonce, Platform, SessionId};
    use proptest::prelude::*;

    use super::*;

    const IDS: u8 = 12;
    /// Identities below this are on the trusted list, so their joins need no
    /// capability; the rest present a forged one.
    const TRUSTED: u8 = 6;

    fn key(n: u8) -> EndpointId {
        SecretKey::from_bytes(&[n.wrapping_add(1); 32]).public()
    }

    fn request(session_key: EndpointId) -> JoinRequest {
        JoinRequest {
            cap: Cap {
                session_id: SessionId([0; 16]),
                invitee: None,
                nonce: Nonce([0; 16]),
                sig: Signature::from_bytes(&[0; 64]),
            },
            session_key,
            name: Name::new("guest").unwrap(),
            platform: Platform::Linux,
            game_build: BuildId::new("b").unwrap(),
            kickoff_version: KICKOFF_VERSION,
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        /// `session_key` indexes a small pool, so collisions happen.
        Join {
            who: u8,
            session_key: u8,
        },
        LinkUp(u8),
        LinkLost(u8),
        Kick(u8),
        Readmit(u8),
        Evict(u8),
        Wait(u64),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => (0..IDS, 0..16u8).prop_map(|(who, session_key)| Op::Join { who, session_key }),
            3 => (0..IDS).prop_map(Op::LinkUp),
            2 => (0..IDS).prop_map(Op::LinkLost),
            1 => (0..IDS).prop_map(Op::Kick),
            1 => (0..IDS).prop_map(Op::Readmit),
            1 => (0..IDS).prop_map(Op::Evict),
            1 => (0..40u64).prop_map(Op::Wait),
        ]
    }

    fn seat(adm: &Admission, id: EndpointId) -> Option<(PeerRef, Generation)> {
        let index = adm.seat_of(id)?;
        let s = adm.seats.get(index)?.as_ref()?;
        Some((peer_of(index, s)?, s.pass))
    }

    /// SI-18, the session's layer under net's: a link makes a seat live only
    /// if it names the seat's identity and current generation, its `Hello`
    /// carries the pass, and the seat has no live link already.
    #[test]
    fn si_18_link_up_needs_the_seat_generation_and_pass() {
        let door = Secret::new(SecretKey::from_bytes(&[200; 32]));
        let host_key = SecretKey::from_bytes(&[201; 32]).public();
        let mut adm =
            Admission::new(&door, host_key, Name::new("host").unwrap(), [key(0)]).unwrap();
        let session_key = SecretKey::from_bytes(&[150; 32]).public();
        let Ok(Joined::Admitted(peer)) = adm.join(key(0), &request(session_key), Instant::now())
        else {
            panic!("a trusted identity is admitted");
        };
        let pass = peer.generation;
        let wrong = Generation::new(999);
        assert!(!adm.link_up(
            PeerRef {
                generation: wrong,
                ..peer
            },
            pass
        ));
        assert!(!adm.link_up(PeerRef { id: key(1), ..peer }, pass));
        assert!(!adm.link_up(peer, wrong), "a Hello without the pass");
        assert!(adm.link_up(peer, pass));
        assert!(!adm.link_up(peer, pass), "a second link for a live seat");
    }

    proptest! {
        /// Whatever happens, in any order: one seat per identity and per
        /// session key, no seat for a revoked identity, a generation never
        /// names two admissions, and the roster's epoch moves with it.
        #[test]
        fn si_18_admission_table_invariants_hold_for_any_sequence(
            ops in proptest::collection::vec(op(), 1..120)
        ) {
            let door = Secret::new(SecretKey::from_bytes(&[200; 32]));
            let host_key = SecretKey::from_bytes(&[201; 32]).public();
            let mut adm = Admission::new(
                &door,
                host_key,
                Name::new("host").unwrap(),
                (0..TRUSTED).map(key),
            )
            .unwrap();
            let mut now = Instant::now();
            let mut named: HashMap<Generation, (EndpointId, PeerSlot)> = HashMap::new();
            let mut last_roster = adm.roster();

            for op in ops {
                match op {
                    Op::Join { who, session_key } => {
                        let sk = SecretKey::from_bytes(&[session_key.wrapping_add(100); 32]).public();
                        let joined = adm.join(key(who), &request(sk), now);
                        if adm.revoked.contains(&key(who)) {
                            prop_assert_eq!(joined.err(), Some(JoinRefused::Revoked));
                        } else if who >= TRUSTED {
                            prop_assert!(joined.is_err(), "a forged capability admitted");
                        }
                    }
                    Op::LinkUp(who) => {
                        if let Some((peer, pass)) = seat(&adm, key(who)) {
                            adm.link_up(peer, pass);
                        }
                    }
                    Op::LinkLost(who) => {
                        if let Some((peer, _)) = seat(&adm, key(who)) {
                            adm.link_lost(peer, now);
                        }
                    }
                    Op::Kick(who) => {
                        adm.kick(key(who)).unwrap();
                    }
                    Op::Readmit(who) => adm.readmit(key(who)),
                    Op::Evict(who) => {
                        if let Some((peer, _)) = seat(&adm, key(who)) {
                            prop_assert!(adm.evict(peer));
                        }
                    }
                    Op::Wait(secs) => {
                        now += Duration::from_secs(secs);
                        for peer in adm.expired(now) {
                            prop_assert!(adm.evict(peer));
                        }
                    }
                }

                let seats: Vec<&Seat> = adm.seats.iter().flatten().collect();
                let ids: HashSet<_> = seats.iter().map(|s| s.id).collect();
                let keys: HashSet<_> = seats.iter().map(|s| s.session_key).collect();
                prop_assert_eq!(ids.len(), seats.len(), "an identity holds two seats");
                prop_assert_eq!(keys.len(), seats.len(), "a session key names two seats");
                prop_assert!(!keys.contains(&host_key));
                prop_assert!(seats.iter().all(|s| !adm.revoked.contains(&s.id)));

                for (index, s) in adm.seats.iter().enumerate() {
                    let Some(s) = s else { continue };
                    let slot = slot_of(index).unwrap();
                    let first = *named.entry(s.generation).or_insert((s.id, slot));
                    prop_assert_eq!(first, (s.id, slot), "a generation was reused");
                }

                let roster = adm.roster();
                prop_assert!(roster.1.len() <= usize::from(MAX_ROSTER));
                if roster.1 != last_roster.1 {
                    prop_assert!(roster.0 > last_roster.0, "the roster changed under one epoch");
                }
                prop_assert!(roster.0 >= last_roster.0);
                last_roster = roster;
            }
        }
    }
}

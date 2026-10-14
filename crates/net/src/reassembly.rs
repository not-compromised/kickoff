//! Fragment reassembly with its memory charged before it is held (§3.4, §6.3,
//! SI-23): at most `PER_LINK` assemblies per link and `GLOBAL` per endpoint,
//! each at most `MAX_FRAGMENTS` received datagrams, each dropped after
//! `DEADLINE`. The tables are fixed arrays, so a fragment flood cannot grow them.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use kickoff_wire::{FragmentHeader, LanHeader, MAX_FRAGMENTS, MAX_ROSTER, PeerSlot};

use crate::Role;

pub(crate) const PER_LINK: usize = if cfg!(feature = "mutant-si23-no-per-link-reassembly-cap") {
    GLOBAL
} else {
    8
};
pub(crate) const GLOBAL: usize = 32;
pub(crate) const DEADLINE: Duration = Duration::from_millis(50);
const PARTS: usize = MAX_FRAGMENTS as usize;

/// Counts stay charged until the owning assembly actually releases its chunks.
#[derive(Debug)]
pub(crate) struct GlobalBudget {
    counts: Mutex<Counts>,
    reserved: [bool; MAX_ROSTER as usize + 1],
}

#[derive(Debug, Default)]
struct Counts {
    total: usize,
    peers: [usize; MAX_ROSTER as usize + 1],
}

impl Default for GlobalBudget {
    fn default() -> Self {
        Self::new(Role::Host)
    }
}

impl GlobalBudget {
    pub(crate) fn new(role: Role) -> Self {
        let reserved = std::array::from_fn(|slot| match role {
            Role::Host => slot > usize::from(PeerSlot::HOST.get()),
            Role::Guest => slot == usize::from(PeerSlot::HOST.get()),
        });
        Self {
            counts: Mutex::default(),
            reserved,
        }
    }

    fn acquire(self: &Arc<Self>, peer: PeerSlot) -> Option<GlobalSlot> {
        let index = usize::from(peer.get());
        if !self.reserved.get(index).copied().unwrap_or(false) {
            return None;
        }
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        // An idle peer keeps one place. Only the remaining capacity is borrowed.
        let other_idle = self
            .reserved
            .iter()
            .zip(&counts.peers)
            .enumerate()
            .filter(|(slot, (reserved, used))| *slot != index && **reserved && **used == 0)
            .count();
        if !cfg!(feature = "mutant-si23-no-global-reassembly-cap")
            && (counts.total >= GLOBAL
                || (!cfg!(feature = "mutant-si23-reassembly-no-peer-reserve")
                    && counts.total >= GLOBAL.saturating_sub(other_idle)))
        {
            return None;
        }
        let used = counts.peers.get_mut(index)?;
        *used = used.saturating_add(1);
        counts.total = counts.total.saturating_add(1);
        Some(GlobalSlot {
            global: Arc::clone(self),
            peer,
        })
    }

    #[cfg(test)]
    pub(crate) fn in_use(&self) -> usize {
        self.counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .total
    }
}

#[derive(Debug)]
struct GlobalSlot {
    global: Arc<GlobalBudget>,
    peer: PeerSlot,
}

impl Drop for GlobalSlot {
    fn drop(&mut self) {
        let mut counts = self
            .global
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(used) = counts.peers.get_mut(usize::from(self.peer.get())) {
            *used = used.saturating_sub(1);
        }
        counts.total = counts.total.saturating_sub(1);
    }
}

#[derive(Debug)]
struct Assembly {
    frag_id: u16,
    header: LanHeader,
    count: u8,
    parts: [Option<Bytes>; PARTS],
    have: u8,
    started: Instant,
    _slot: GlobalSlot,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Complete(LanHeader, Bytes),
    Pending,
    /// The fragment disagreed with its assembly; the whole assembly is gone.
    Conflict,
    /// No per-link or global slot was free.
    Full,
}

#[derive(Debug)]
pub(crate) struct Reassembler {
    slots: [Option<Assembly>; PER_LINK],
    global: Arc<GlobalBudget>,
    peer: PeerSlot,
}

impl Reassembler {
    pub(crate) fn new(global: Arc<GlobalBudget>, peer: PeerSlot) -> Reassembler {
        Reassembler {
            slots: Default::default(),
            global,
            peer,
        }
    }

    pub(crate) fn accept(
        &mut self,
        now: Instant,
        header: LanHeader,
        frag: FragmentHeader,
        chunk: Bytes,
    ) -> Outcome {
        self.expire(now);
        let idx = usize::from(frag.idx);
        let existing = self
            .slots
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|a| a.frag_id == frag.frag_id));
        let Some(slot) = existing else {
            return self.start(now, header, frag, idx, chunk);
        };
        let Some(asm) = slot.as_mut() else {
            return Outcome::Full;
        };
        let fits = asm.header == header
            && asm.count == frag.count
            && asm.parts.get(idx).is_some_and(Option::is_none);
        if !fits {
            *slot = None;
            return Outcome::Conflict;
        }
        if let Some(part) = asm.parts.get_mut(idx) {
            *part = Some(chunk);
        }
        asm.have = asm.have.saturating_add(1);
        if asm.have < asm.count {
            return Outcome::Pending;
        }
        match slot.take() {
            Some(done) => Outcome::Complete(done.header, concat(done.parts)),
            None => Outcome::Full,
        }
    }

    fn start(
        &mut self,
        now: Instant,
        header: LanHeader,
        frag: FragmentHeader,
        idx: usize,
        chunk: Bytes,
    ) -> Outcome {
        let Some(free) = self.slots.iter_mut().find(|s| s.is_none()) else {
            return Outcome::Full;
        };
        let Some(global) = self.global.acquire(self.peer) else {
            return Outcome::Full;
        };
        let mut parts: [Option<Bytes>; PARTS] = Default::default();
        let Some(part) = parts.get_mut(idx) else {
            return Outcome::Conflict;
        };
        *part = Some(chunk);
        *free = Some(Assembly {
            frag_id: frag.frag_id,
            header,
            count: frag.count,
            parts,
            have: 1,
            started: now,
            _slot: global,
        });
        Outcome::Pending
    }

    /// When the oldest assembly in flight times out, so an idle link still
    /// returns its slots to the global budget on time.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.slots
            .iter()
            .flatten()
            .map(|a| a.started)
            .min()
            .and_then(|t| t.checked_add(DEADLINE))
    }

    pub(crate) fn expire(&mut self, now: Instant) {
        for slot in &mut self.slots {
            if slot
                .as_ref()
                .is_some_and(|a| now.saturating_duration_since(a.started) >= DEADLINE)
            {
                *slot = None;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn in_use(&self) -> usize {
        self.global.in_use()
    }

    #[cfg(test)]
    pub(crate) fn held(&self) -> (usize, usize) {
        let live = self.slots.iter().flatten();
        let bytes = live
            .clone()
            .flat_map(|a| a.parts.iter().flatten())
            .map(Bytes::len)
            .sum();
        (live.count(), bytes)
    }
}

fn concat(parts: [Option<Bytes>; PARTS]) -> Bytes {
    let len = parts
        .iter()
        .flatten()
        .fold(0usize, |n, p| n.saturating_add(p.len()));
    let mut out = BytesMut::with_capacity(len);
    for part in parts.iter().flatten() {
        out.put_slice(part);
    }
    out.freeze()
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use kickoff_wire::DatagramKind;

    fn header(port: u16) -> LanHeader {
        LanHeader {
            kind: DatagramKind::Fragment,
            bcast: false,
            src_port: port,
            dst_port: 7777,
        }
    }

    fn frag(frag_id: u16, idx: u8, count: u8) -> FragmentHeader {
        FragmentHeader {
            frag_id,
            idx,
            count,
        }
    }

    fn chunk(byte: u8, len: usize) -> Bytes {
        vec![byte; len].into()
    }

    #[test]
    fn reassembles_out_of_order() {
        let mut r = Reassembler::new(Arc::default(), PeerSlot::new(2).unwrap());
        let t = Instant::now();
        assert_eq!(
            r.accept(t, header(1), frag(9, 2, 3), chunk(3, 2)),
            Outcome::Pending
        );
        assert_eq!(
            r.accept(t, header(1), frag(9, 0, 3), chunk(1, 2)),
            Outcome::Pending
        );
        let out = r.accept(t, header(1), frag(9, 1, 3), chunk(2, 2));
        assert_eq!(
            out,
            Outcome::Complete(header(1), Bytes::from_static(&[1, 1, 2, 2, 3, 3]))
        );
        assert_eq!(r.held(), (0, 0));
    }

    #[test]
    fn conflict_drops_the_whole_assembly() {
        let t = Instant::now();
        for (h, f) in [
            (header(2), frag(5, 1, 2)),
            (header(1), frag(5, 1, 3)),
            (header(1), frag(5, 0, 2)),
        ] {
            let mut r = Reassembler::new(Arc::default(), PeerSlot::new(2).unwrap());
            assert_eq!(
                r.accept(t, header(1), frag(5, 0, 2), chunk(1, 4)),
                Outcome::Pending
            );
            assert_eq!(r.accept(t, h, f, chunk(1, 4)), Outcome::Conflict);
            assert_eq!(r.held(), (0, 0));
        }
    }

    #[test]
    fn incomplete_assemblies_expire_after_the_deadline() {
        let global = Arc::new(GlobalBudget::default());
        let mut r = Reassembler::new(Arc::clone(&global), PeerSlot::new(2).unwrap());
        let t = Instant::now();
        assert_eq!(
            r.accept(t, header(1), frag(1, 0, 2), chunk(1, 4)),
            Outcome::Pending
        );
        let late = t + DEADLINE;
        assert_eq!(
            r.accept(late, header(1), frag(1, 1, 2), chunk(1, 4)),
            Outcome::Pending
        );
        assert_eq!(r.held().0, 1, "the late fragment starts a fresh assembly");
        assert_eq!(global.in_use(), 1);
    }

    #[test]
    fn every_roster_peer_can_complete_while_other_peers_hold_fragments() {
        let global = Arc::new(GlobalBudget::new(Role::Host));
        let mut peers: Vec<Reassembler> = (2..=MAX_ROSTER)
            .map(|slot| Reassembler::new(Arc::clone(&global), PeerSlot::new(slot).unwrap()))
            .collect();
        let t = Instant::now();
        for peer in peers.iter_mut().skip(1) {
            for id in 0..8 {
                peer.accept(t, header(7777), frag(id, 0, 2), chunk(1, 100));
            }
        }
        assert_eq!(global.in_use(), 31);
        let good = &mut peers[0];
        assert_eq!(
            good.accept(t, header(7777), frag(0, 0, 2), chunk(2, 100)),
            Outcome::Pending
        );
        assert_eq!(global.in_use(), 32);
        assert_eq!(
            good.accept(t, header(7777), frag(0, 1, 2), chunk(3, 100)),
            Outcome::Complete(header(7777), [vec![2; 100], vec![3; 100]].concat().into())
        );
        assert_eq!(global.in_use(), 31);
        peers.clear();
        assert_eq!(global.in_use(), 0, "all physical holders were dropped");
        let mut replacement = Reassembler::new(Arc::clone(&global), PeerSlot::new(2).unwrap());
        for id in 0..8 {
            assert_eq!(
                replacement.accept(t, header(7777), frag(id, 0, 2), chunk(1, 100)),
                Outcome::Pending
            );
        }
        replacement.expire(t + DEADLINE);
        assert_eq!(global.in_use(), 0, "expiry returns the same peer's charges");
    }

    #[test]
    fn guest_budget_has_eight_usable_host_places_and_no_guest_recipient() {
        let global = Arc::new(GlobalBudget::new(Role::Guest));
        let t = Instant::now();
        let mut host = Reassembler::new(Arc::clone(&global), PeerSlot::HOST);
        let mut guest = Reassembler::new(Arc::clone(&global), PeerSlot::new(2).unwrap());
        assert_eq!(
            guest.accept(t, header(7777), frag(0, 0, 2), chunk(1, 100)),
            Outcome::Full
        );
        for id in 0..8 {
            assert_eq!(
                host.accept(t, header(7777), frag(id, 0, 2), chunk(1, 100)),
                Outcome::Pending
            );
        }
        assert_eq!(global.in_use(), 8);
        drop(host);
        assert_eq!(global.in_use(), 0);
    }

    #[test]
    fn si_23_reassembly_memory_cap_holds_under_a_hostile_fragment_flood() {
        let global = Arc::new(GlobalBudget::default());
        let mut links: Vec<Reassembler> = (0..12)
            .map(|i| Reassembler::new(Arc::clone(&global), PeerSlot::new(2 + i % 7).unwrap()))
            .collect();
        let max_chunk = 1414;
        let cap_bytes = PER_LINK * (PARTS - 1) * max_chunk;
        let mut x: u64 = 0xDEAD_BEEF_CAFE_F00D;
        let start = Instant::now();
        let mut full = 0u64;
        for i in 0..300_000u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let link = (x % links.len() as u64) as usize;
            let count = 2 + (x >> 8) as u8 % 3;
            let idx = (x >> 16) as u8 % count;
            let now = start + Duration::from_micros(i);
            let r = &mut links[link];
            if r.accept(
                now,
                header(1),
                frag((x >> 24) as u16, idx, count),
                chunk(0, max_chunk),
            ) == Outcome::Full
            {
                full += 1;
            }
            let (live, bytes) = r.held();
            assert!(live <= PER_LINK, "per-link table grew to {live}");
            assert!(bytes <= cap_bytes, "link holds {bytes} bytes");
            assert!(
                global.in_use() <= GLOBAL,
                "global table grew to {}",
                global.in_use()
            );
            let total: usize = links.iter().map(|l| l.held().0).sum();
            assert_eq!(total, global.in_use(), "budget and tables disagree");
        }
        assert!(
            full > 0,
            "the flood never reached a cap, so the test proved nothing"
        );
        drop(links);
        assert_eq!(global.in_use(), 0, "dropping links returns every slot");
    }
}

//! Fragment reassembly with its memory charged before it is held (§3.4, §6.3,
//! SI-23): at most `PER_LINK` assemblies per link and `GLOBAL` per endpoint,
//! each at most `MAX_FRAGMENTS` received datagrams, each dropped after
//! `DEADLINE`. The tables are fixed arrays, so a fragment flood cannot grow them.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use kickoff_wire::{FragmentHeader, LanHeader, MAX_FRAGMENTS};

pub(crate) const PER_LINK: usize = if cfg!(feature = "mutant-si23-no-per-link-reassembly-cap") {
    GLOBAL
} else {
    8
};
pub(crate) const GLOBAL: usize = 32;
pub(crate) const DEADLINE: Duration = Duration::from_millis(50);
const PARTS: usize = MAX_FRAGMENTS as usize;

/// The endpoint-wide count of assemblies in flight, shared by its links.
#[derive(Debug, Default)]
pub(crate) struct GlobalBudget(AtomicUsize);

impl GlobalBudget {
    fn acquire(self: &Arc<Self>) -> Option<GlobalSlot> {
        self.0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (cfg!(feature = "mutant-si23-no-global-reassembly-cap") || n < GLOBAL)
                    .then(|| n.saturating_add(1))
            })
            .ok()
            .map(|_| GlobalSlot(Arc::clone(self)))
    }

    #[cfg(test)]
    pub(crate) fn in_use(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

/// One unit of `GlobalBudget`, returned when its assembly ends for any reason.
#[derive(Debug)]
struct GlobalSlot(Arc<GlobalBudget>);

impl Drop for GlobalSlot {
    fn drop(&mut self) {
        let _ = self
            .0
            .0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                Some(n.saturating_sub(1))
            });
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
}

impl Reassembler {
    pub(crate) fn new(global: Arc<GlobalBudget>) -> Reassembler {
        Reassembler {
            slots: Default::default(),
            global,
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
        let Some(global) = self.global.acquire() else {
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
    fn held(&self) -> (usize, usize) {
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
        let mut r = Reassembler::new(Arc::default());
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
            let mut r = Reassembler::new(Arc::default());
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
        let mut r = Reassembler::new(Arc::clone(&global));
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
    fn si_23_reassembly_memory_cap_holds_under_a_hostile_fragment_flood() {
        let global = Arc::new(GlobalBudget::default());
        let mut links: Vec<Reassembler> = (0..12)
            .map(|_| Reassembler::new(Arc::clone(&global)))
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

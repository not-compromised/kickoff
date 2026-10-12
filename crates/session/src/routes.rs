//! The pump's only shared state (§2.5): which link carries each slot, and
//! under which generation. Delivery runs under the read lock and every
//! change takes the write lock, so once a change returns, no datagram of the
//! replaced generation is delivered or sent (SI-18).

use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use kickoff_wire::{Generation, MAX_ROSTER, PeerSlot};

const SLOTS: usize = MAX_ROSTER as usize + 1;

pub(crate) struct Route<L, F> {
    pub generation: Generation,
    pub link: L,
    /// Tells the link's task why it was removed, so it can say goodbye.
    pub farewell: F,
}

pub(crate) struct Routes<L, F> {
    table: RwLock<[Option<Route<L, F>>; SLOTS]>,
}

impl<L, F> Routes<L, F> {
    pub(crate) fn new() -> Self {
        Routes {
            table: RwLock::new(std::array::from_fn(|_| None)),
        }
    }

    /// Runs `deliver` only if `slot` is still routed under `generation`, and
    /// holds the routing table steady while it runs.
    pub(crate) fn deliver(
        &self,
        slot: PeerSlot,
        generation: Generation,
        deliver: impl FnOnce(),
    ) -> bool {
        let table = self.read();
        let current = cfg!(feature = "mutant-si18-no-gen-check")
            || table
                .get(index(slot))
                .and_then(Option::as_ref)
                .is_some_and(|r| r.generation == generation);
        if cfg!(feature = "mutant-si18-deliver-outside-lock") {
            drop(table);
        }
        if current {
            deliver();
        }
        current
    }

    /// The link currently routed for `slot`, for a unicast from the local game.
    pub(crate) fn to_slot(&self, slot: PeerSlot, send: impl FnOnce(&L)) {
        if let Some(route) = self.read().get(index(slot)).and_then(Option::as_ref) {
            send(&route.link);
        }
    }

    /// Every routed link, for a broadcast from the host's game.
    pub(crate) fn to_all(&self, mut send: impl FnMut(&L)) {
        for route in self.read().iter().flatten() {
            send(&route.link);
        }
    }

    /// Routes `slot` to a new link, returning whatever it replaces.
    pub(crate) fn install(&self, slot: PeerSlot, route: Route<L, F>) -> Option<Route<L, F>> {
        self.write().get_mut(index(slot))?.replace(route)
    }

    /// Removes `slot`'s route if it still carries `generation`.
    pub(crate) fn remove(&self, slot: PeerSlot, generation: Generation) -> Option<Route<L, F>> {
        let mut table = self.write();
        let entry = table.get_mut(index(slot))?;
        if entry.as_ref().is_some_and(|r| r.generation == generation) {
            entry.take()
        } else {
            None
        }
    }

    pub(crate) fn drain(&self) -> Vec<Route<L, F>> {
        self.write().iter_mut().filter_map(Option::take).collect()
    }

    // A panic never happens while either guard is held (the closures run
    // under the read guard are the pump's non-blocking sends and delivers),
    // and every write leaves the table valid, so a poisoned lock is sound.
    fn read(&self) -> RwLockReadGuard<'_, [Option<Route<L, F>>; SLOTS]> {
        self.table
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, [Option<Route<L, F>>; SLOTS]> {
        self.table
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn index(slot: PeerSlot) -> usize {
    usize::from(slot.get())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    use super::*;

    fn route(generation: u64) -> Route<(), ()> {
        Route {
            generation: Generation::new(generation),
            link: (),
            farewell: (),
        }
    }

    /// A kick racing a delivery already past the generation check: the
    /// removal waits for that delivery, and nothing of the old generation is
    /// delivered once it returns.
    #[test]
    fn si_18_removal_waits_for_in_flight_delivery_then_drops_the_rest() {
        let routes = Arc::new(Routes::new());
        let slot = PeerSlot::new(3).unwrap();
        let old = Generation::new(1);
        routes.install(slot, route(1));
        let delivered = Arc::new(AtomicU64::new(0));
        let inside = Arc::new(Barrier::new(2));

        let deliverer = {
            let (routes, delivered, inside) = (
                Arc::clone(&routes),
                Arc::clone(&delivered),
                Arc::clone(&inside),
            );
            std::thread::spawn(move || {
                routes.deliver(slot, old, || {
                    inside.wait();
                    std::thread::sleep(Duration::from_millis(100));
                    delivered.fetch_add(1, Ordering::SeqCst);
                })
            })
        };
        inside.wait();
        let removed = routes.remove(slot, old);
        assert!(removed.is_some());
        assert_eq!(
            delivered.load(Ordering::SeqCst),
            1,
            "the removal returned while a delivery of the old generation was still running"
        );
        assert!(deliverer.join().unwrap());

        let after = routes.deliver(slot, old, || {
            delivered.fetch_add(1, Ordering::SeqCst);
        });
        assert!(!after);
        routes.install(slot, route(2));
        assert!(!routes.deliver(slot, old, || {
            delivered.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(delivered.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn remove_ignores_a_newer_generation() {
        let routes: Routes<(), ()> = Routes::new();
        let slot = PeerSlot::new(2).unwrap();
        routes.install(slot, route(5));
        assert!(routes.remove(slot, Generation::new(4)).is_none());
        assert!(routes.deliver(slot, Generation::new(5), || {}));
    }
}

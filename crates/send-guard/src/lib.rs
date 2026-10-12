//! The hook the vendored iroh calls before every IP send (design §3.4, R2-10).
//!
//! iroh cannot depend on `kickoff-net`, so this crate holds only a registry.
//! `kickoff-net` registers each endpoint's send guard under the exact socket
//! address that endpoint's IP transport is configured with, before the
//! endpoint binds, and the patched `IpSender::poll_send` in
//! `vendor/iroh-1.3.0` asks [`admit`] with that same address and the
//! destination. A refused packet is dropped as if lost.
//!
//! Unregistered transports refuse all sends. Adversarial test endpoints must
//! explicitly install their permissive fixture policy before binding.

use std::net::SocketAddr;
use std::sync::{Arc, PoisonError, RwLock};

/// A per-endpoint destination policy.
pub trait Guard: Send + Sync {
    /// Whether one packet may go to `dst`. Runs on iroh's send path for every
    /// packet, so it must not block or allocate for a known destination.
    fn admit(&self, context: u64, dst: SocketAddr) -> bool;
    /// Associates a stable connection context with the peer identity.
    fn associate(&self, _context: u64, _remote: [u8; 32]) {}
    /// A peer the owner explicitly chose to dial.
    fn expect(&self, context: u64, remote: [u8; 32]) {
        self.associate(context, remote);
    }
    /// Registers the original QAD destination selected from the relay map.
    fn probe(&self, _context: u64, _dst: SocketAddr) {}
    /// Forgets approval state when the connection sender dies.
    fn forget(&self, _context: u64) {}
}

type Entry = (SocketAddr, Arc<dyn Guard>);

/// A handful of live endpoints at most, so a scan beats hashing.
static GUARDS: RwLock<Vec<Entry>> = RwLock::new(Vec::new());

/// What the vendored iroh calls: may the IP transport configured with `bind`
/// send to `dst`?
pub fn admit(bind: SocketAddr, context: u64, dst: SocketAddr) -> bool {
    let guards = GUARDS.read().unwrap_or_else(PoisonError::into_inner);
    match guards.iter().find(|(b, _)| *b == bind) {
        Some((_, guard)) => guard.admit(
            if cfg!(feature = "mutant-si29-send-context-lost") {
                0
            } else {
                context
            },
            dst,
        ),
        None => cfg!(feature = "mutant-si29-unregistered-sends"),
    }
}

/// Called before a connection can emit candidate probes.
pub fn associate(bind: SocketAddr, context: u64, remote: [u8; 32]) {
    let guards = GUARDS.read().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, guard)) = guards.iter().find(|(b, _)| *b == bind) {
        guard.associate(context, remote);
    }
}

/// Associates a locally requested peer before its driver starts.
pub fn expect(bind: SocketAddr, context: u64, remote: [u8; 32]) {
    let guards = GUARDS.read().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, guard)) = guards.iter().find(|(b, _)| *b == bind) {
        guard.expect(context, remote);
    }
}

/// Registers the single original QAD destination from the compiled relay map.
pub fn probe(bind: SocketAddr, context: u64, dst: SocketAddr) {
    let guards = GUARDS.read().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, guard)) = guards.iter().find(|(b, _)| *b == bind) {
        guard.probe(context, dst);
    }
}

/// Clears one connection's cached destinations on transport shutdown.
pub fn forget(bind: SocketAddr, context: u64) {
    let guards = GUARDS.read().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, guard)) = guards.iter().find(|(b, _)| *b == bind) {
        guard.forget(context);
    }
}

/// Holds `guard` in place for one bind address; dropping it removes the guard.
#[derive(Debug)]
#[must_use = "the guard is removed when the registration drops"]
pub struct Registration {
    bind: SocketAddr,
}

/// Installs `guard` for the IP transport that will bind exactly `bind`.
/// Refuses port 0, which is not one endpoint's address, and an address that
/// already has a guard.
pub fn register(bind: SocketAddr, guard: Arc<dyn Guard>) -> Option<Registration> {
    if bind.port() == 0 {
        return None;
    }
    let mut guards = GUARDS.write().unwrap_or_else(PoisonError::into_inner);
    if guards.iter().any(|(b, _)| *b == bind) {
        return None;
    }
    guards.push((bind, guard));
    Some(Registration { bind })
}

impl Drop for Registration {
    fn drop(&mut self) {
        GUARDS
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(b, _)| *b != self.bind);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Only(SocketAddr);

    impl Guard for Only {
        fn admit(&self, context: u64, dst: SocketAddr) -> bool {
            context == 1 && dst == self.0
        }
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn si_29_a_registered_bind_answers_through_its_guard_until_dropped() {
        let bind = addr("127.0.0.1:40001");
        let ok = addr("127.0.0.1:40002");
        let other = addr("127.0.0.1:40003");
        let registration = register(bind, Arc::new(Only(ok))).unwrap();
        assert!(admit(bind, 1, ok));
        assert!(!admit(bind, 1, other));
        assert!(
            !admit(addr("127.0.0.1:40009"), 1, other),
            "unregistered binds refuse"
        );
        assert!(
            register(bind, Arc::new(Only(ok))).is_none(),
            "one guard per bind"
        );
        drop(registration);
        assert!(!admit(bind, 1, other));
    }

    #[test]
    fn port_zero_cannot_be_registered() {
        assert!(register(addr("127.0.0.1:0"), Arc::new(Only(addr("127.0.0.1:1")))).is_none());
    }
}

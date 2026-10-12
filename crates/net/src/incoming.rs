//! The pre-handshake budget both endpoints share (§3.4, §6.3): at most 16
//! `Incoming`s handshaking at once, `retry` for unvalidated addresses, at most
//! 8 handshakes per second per source and 64 overall, `refuse` beyond. All of
//! it runs before iroh does any TLS work. Rates are charged on validated
//! addresses only, so spoofed sources cannot spend them.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use iroh::EndpointId;
use iroh::endpoint::{Incoming, IncomingAddr};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::PENDING_INCOMING;
use crate::budget::Bucket;
use crate::egress::SendGuard;

/// Handshakes per second from one source, and from everyone (§6.3).
const PER_SOURCE: u64 = 8;
const OVERALL: u64 = 64;
/// Sources whose rate is remembered. A source idle for a second has a full
/// bucket and is forgotten first; if none is, new sources are refused.
const MAX_SOURCES: usize = 256;

/// Where an `Incoming` came from, as far as rates go. A relayed peer is keyed
/// by the endpoint id the relay authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Source {
    Ip(IpAddr),
    Relayed(EndpointId),
    Other,
}

impl Source {
    fn of(addr: &IncomingAddr) -> Source {
        match addr {
            IncomingAddr::Ip(sock) => Source::Ip(sock.ip().to_canonical()),
            IncomingAddr::Relay { endpoint_id, .. } => Source::Relayed(*endpoint_id),
            _ => Source::Other,
        }
    }
}

#[derive(Debug)]
struct Rates {
    overall: Bucket,
    sources: HashMap<Source, Bucket>,
}

impl Rates {
    fn new(now: Instant) -> Rates {
        Rates {
            overall: Bucket::new(now, OVERALL, OVERALL),
            sources: HashMap::new(),
        }
    }

    /// One handshake from `source`: true if both its own and the overall
    /// rate allow it. A refused charge takes nothing.
    fn charge(&mut self, now: Instant, source: Source) -> bool {
        if cfg!(feature = "mutant-si23-no-handshake-rate") {
            return true;
        }
        if !self.sources.contains_key(&source) && self.sources.len() >= MAX_SOURCES {
            self.sources.retain(|_, bucket| !bucket.full(now));
            if self.sources.len() >= MAX_SOURCES {
                return false;
            }
        }
        let own = self
            .sources
            .entry(source)
            .or_insert_with(|| Bucket::new(now, PER_SOURCE, PER_SOURCE));
        if !(own.ready(now, 1) && self.overall.ready(now, 1)) {
            return false;
        }
        own.charge(now, 1) && self.overall.charge(now, 1)
    }
}

#[derive(Debug)]
pub(crate) struct Gate {
    pending: Arc<Semaphore>,
    rates: Mutex<Rates>,
    /// The endpoint's send guard, told which sources it may answer.
    guard: Option<Arc<SendGuard>>,
}

impl Gate {
    pub(crate) fn new(guard: Option<Arc<SendGuard>>) -> Gate {
        Gate {
            pending: Arc::new(Semaphore::new(PENDING_INCOMING)),
            rates: Mutex::new(Rates::new(Instant::now())),
            guard,
        }
    }

    /// Either refuses or retries `incoming` and returns `None`, or hands it
    /// back with a pending slot to hold until its handshake completes.
    pub(crate) fn admit(&self, incoming: Incoming) -> Option<(Incoming, OwnedSemaphorePermit)> {
        let from = incoming.remote_addr();
        self.answering(&from);
        let Ok(permit) = Arc::clone(&self.pending).try_acquire_owned() else {
            incoming.refuse();
            return None;
        };
        if !incoming.remote_addr_validated() {
            if let Err(err) = incoming.retry() {
                err.into_incoming().refuse();
            }
            return None;
        }
        let charged = self
            .rates
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .charge(Instant::now(), Source::of(&from));
        if !charged {
            incoming.refuse();
            return None;
        }
        Some((incoming, permit))
    }

    /// Refuses `incoming` outright: guests accept nothing (SI-21).
    pub(crate) fn refuse(&self, incoming: Incoming) {
        self.answering(&incoming.remote_addr());
        incoming.refuse();
    }

    fn answering(&self, from: &IncomingAddr) {
        if let (Some(guard), IncomingAddr::Ip(src)) = (&self.guard, from) {
            let src = std::net::SocketAddr::new(src.ip().to_canonical(), src.port());
            guard.answer(src, Instant::now());
        }
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use super::*;

    fn from(n: u32) -> Source {
        Source::Ip(IpAddr::V4(Ipv4Addr::from(0xCB00_7200 + n)))
    }

    #[test]
    fn si_23_handshakes_are_rate_limited_per_source_and_overall() {
        let t = Instant::now();
        let mut rates = Rates::new(t);
        let passed =
            |rates: &mut Rates, source, n| (0..n).filter(|_| rates.charge(t, source)).count();
        assert_eq!(passed(&mut rates, from(1), 20), 8, "one source, one second");
        for n in 2..=8 {
            assert_eq!(passed(&mut rates, from(n), 8), 8);
        }
        assert_eq!(
            passed(&mut rates, from(9), 8),
            0,
            "64 overall in one second"
        );

        let later = t + Duration::from_secs(1);
        assert!(rates.charge(later, from(9)), "both rates refill");

        // Remembered sources are bounded; idle ones are forgotten first.
        let mut rates = Rates::new(t);
        let mut admitted = 0;
        for n in 0..(MAX_SOURCES as u32 * 4) {
            let at = t + Duration::from_millis(u64::from(n) * 20);
            admitted += usize::from(rates.charge(at, from(n)));
            assert!(rates.sources.len() <= MAX_SOURCES);
        }
        assert!(admitted > MAX_SOURCES, "idle sources make room");
    }
}

//! Token buckets for ingress charged on attempts, before any work (§6.3).

use std::time::{Duration, Instant};

const NANOS: u128 = 1_000_000_000;

#[derive(Debug, Clone)]
pub(crate) struct Bucket {
    rate_per_sec: u64,
    burst: u64,
    tokens: u64,
    /// Sub-token remainder carried between refills, in token-nanoseconds.
    carry: u128,
    last: Instant,
}

impl Bucket {
    pub(crate) fn new(now: Instant, rate_per_sec: u64, burst: u64) -> Bucket {
        Bucket {
            rate_per_sec,
            burst,
            tokens: burst,
            carry: 0,
            last: now,
        }
    }

    /// Takes `cost` tokens if available. A refused charge takes nothing.
    pub(crate) fn charge(&mut self, now: Instant, cost: u64) -> bool {
        self.refill(now);
        match self.tokens.checked_sub(cost) {
            Some(left) => {
                self.tokens = left;
                true
            }
            None => false,
        }
    }

    /// Whether `cost` tokens are available now, without taking them.
    pub(crate) fn ready(&mut self, now: Instant, cost: u64) -> bool {
        self.refill(now);
        self.tokens >= cost
    }

    /// Whether the bucket has refilled completely: its owner has been idle
    /// long enough that forgetting it loses nothing.
    pub(crate) fn full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens == self.burst
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_nanos();
        self.last = now;
        let earned = elapsed
            .saturating_mul(u128::from(self.rate_per_sec))
            .saturating_add(self.carry);
        let whole = earned.checked_div(NANOS).unwrap_or(0);
        self.carry = earned.checked_rem(NANOS).unwrap_or(0);
        let whole = u64::try_from(whole).unwrap_or(u64::MAX);
        self.tokens = self.tokens.saturating_add(whole).min(self.burst);
        if self.tokens == self.burst {
            self.carry = 0;
        }
    }
}

/// Counts attempts over a fixed window to spot a peer sustaining many times
/// its allowance (§6.3: above 10x for 5 s disconnects).
#[derive(Debug, Clone)]
pub(crate) struct Window {
    len: Duration,
    limit: u64,
    start: Instant,
    seen: u64,
}

impl Window {
    pub(crate) fn new(now: Instant, len: Duration, limit: u64) -> Window {
        Window {
            len,
            limit,
            start: now,
            seen: 0,
        }
    }

    /// Records `n` attempts; true once the window's total exceeds the limit.
    pub(crate) fn exceeded(&mut self, now: Instant, n: u64) -> bool {
        self.roll(now);
        self.seen = self.seen.saturating_add(n);
        self.seen > self.limit
    }

    /// True when one more attempt would exceed the limit.
    pub(crate) fn full(&mut self, now: Instant) -> bool {
        self.roll(now);
        self.seen >= self.limit
    }

    pub(crate) fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.start) >= self.len
    }

    fn roll(&mut self, now: Instant) {
        if self.expired(now) {
            self.start = now;
            self.seen = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_rate() {
        let t = Instant::now();
        let mut b = Bucket::new(t, 3000, 1000);
        assert!((0..1000).all(|_| b.charge(t, 1)));
        assert!(!b.charge(t, 1));
        let later = t + Duration::from_millis(100);
        assert!((0..300).all(|_| b.charge(later, 1)));
        assert!(!b.charge(later, 1));
    }

    #[test]
    fn bucket_never_exceeds_burst_after_idle() {
        let t = Instant::now();
        let mut b = Bucket::new(t, 3000, 1000);
        let later = t + Duration::from_secs(3600);
        assert!((0..1000).all(|_| b.charge(later, 1)));
        assert!(!b.charge(later, 1));
    }

    #[test]
    fn window_trips_only_above_its_limit() {
        let t = Instant::now();
        let mut w = Window::new(t, Duration::from_secs(5), 10);
        assert!(!w.exceeded(t, 10));
        assert!(w.exceeded(t, 1));
        assert!(!w.exceeded(t + Duration::from_secs(5), 1));
    }
}

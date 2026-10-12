//! Shared token arithmetic. Each security layer owns its rates and charge order.

use std::time::Instant;

const NANOS: u128 = 1_000_000_000;

/// A full-starting token bucket with exact fractional refill and strict saturation.
#[derive(Debug, Clone)]
pub struct Bucket {
    rate: u64,
    burst: u64,
    level: u128,
    last: Instant,
}

impl Bucket {
    pub fn new(now: Instant, rate_per_sec: u64, burst: u64) -> Self {
        Self {
            rate: rate_per_sec,
            burst,
            level: scaled(burst),
            last: now,
        }
    }

    /// Charge all of `cost` or none of it, after refilling to `now`.
    #[inline]
    pub fn charge(&mut self, now: Instant, cost: u64) -> bool {
        self.refill(now);
        match self.level.checked_sub(scaled(cost)) {
            Some(left) => {
                self.level = left;
                true
            }
            None => false,
        }
    }

    /// Refill and check availability without charging.
    #[inline]
    pub fn ready(&mut self, now: Instant, cost: u64) -> bool {
        self.refill(now);
        self.level >= scaled(cost)
    }

    /// Refill and check whether forgetting this bucket would lose no credit.
    #[inline]
    pub fn full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.level == scaled(self.burst)
    }

    #[inline]
    fn refill(&mut self, now: Instant) {
        let earned = now
            .saturating_duration_since(self.last)
            .as_nanos()
            .saturating_mul(u128::from(self.rate));
        let level = self.level.saturating_add(earned);
        let capacity = scaled(self.burst);
        self.level = level.min(capacity);
        #[cfg(feature = "mutant-si23-retain-full-credit")]
        if level >= capacity {
            self.level = capacity.saturating_add(level.checked_rem(NANOS).unwrap_or(0));
        }
        self.last = now.max(self.last);
    }
}

#[inline]
fn scaled(tokens: u64) -> u128 {
    u128::from(tokens).saturating_mul(NANOS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn si_23_full_bucket_never_banks_idle_credit() {
        let t = Instant::now();
        let mut b = Bucket::new(t, 1, 1);
        assert!(b.charge(t + Duration::from_millis(900), 1));
        assert!(!b.charge(t + Duration::from_secs(1), 1));
        assert!(b.charge(t + Duration::from_millis(1900), 1));
    }

    #[test]
    fn fractional_refills_accumulate_below_capacity() {
        let t = Instant::now();
        let mut b = Bucket::new(t, 1, 2);
        assert!(b.charge(t, 2));
        for millis in [200, 400, 600, 800] {
            assert!(!b.charge(t + Duration::from_millis(millis), 1));
        }
        assert!(b.charge(t + Duration::from_secs(1), 1));
        assert!(!b.charge(t + Duration::from_secs(1), 1));
    }

    #[test]
    fn refusal_and_readiness_do_not_charge_or_rewind_time() {
        let t = Instant::now();
        let mut b = Bucket::new(t, 1, 2);
        assert!(!b.charge(t, 3));
        assert!(b.ready(t, 2));
        assert!(b.full(t));
        assert!(b.charge(t + Duration::from_secs(1), 2));
        assert!(!b.charge(t, 1));
        assert!(!b.ready(t + Duration::from_secs(1), 1));
        assert!(b.charge(t + Duration::from_secs(2), 1));
    }

    #[test]
    fn zero_and_maximum_rates_and_costs_stay_bounded() {
        let t = Instant::now();
        let later = t + Duration::from_secs(1);
        let mut zero = Bucket::new(t, 0, 0);
        assert!(zero.charge(later, 0));
        assert!(!zero.charge(later, 1));
        let mut no_refill = Bucket::new(t, 0, 1);
        assert!(no_refill.charge(t, 1));
        assert!(!no_refill.charge(later, 1));
        let mut max = Bucket::new(t, u64::MAX, u64::MAX);
        assert!(max.charge(t, u64::MAX));
        assert!(!max.charge(t, 1));
        assert!(max.charge(later, u64::MAX));
        assert!(!max.charge(later, 1));
    }
}

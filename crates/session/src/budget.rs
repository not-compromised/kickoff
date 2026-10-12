//! The host's fan-out egress budget (§6.3), charged per emitted copy before
//! the copy is sent.

use std::time::Instant;

const NANOS_PER_SEC: u128 = 1_000_000_000;

pub(crate) struct Bucket {
    per_sec: u64,
    burst: u64,
    tokens: u64,
    carry: u128,
    last: Instant,
}

impl Bucket {
    pub(crate) fn new(per_sec: u64, burst: u64, now: Instant) -> Bucket {
        Bucket {
            per_sec,
            burst,
            tokens: burst,
            carry: 0,
            last: now,
        }
    }

    /// Takes `cost` if it is all there; a refusal takes nothing.
    pub(crate) fn take(&mut self, cost: u64, now: Instant) -> bool {
        let earned = now
            .saturating_duration_since(self.last)
            .as_nanos()
            .saturating_mul(u128::from(self.per_sec))
            .saturating_add(self.carry);
        self.last = now;
        let whole =
            u64::try_from(earned.checked_div(NANOS_PER_SEC).unwrap_or(0)).unwrap_or(u64::MAX);
        self.carry = earned.checked_rem(NANOS_PER_SEC).unwrap_or(0);
        self.tokens = self.tokens.saturating_add(whole).min(self.burst);
        match self.tokens.checked_sub(cost) {
            Some(left) => {
                self.tokens = left;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn burst_then_rate() {
        let t = Instant::now();
        let mut b = Bucket::new(1000, 100, t);
        assert!((0..100).all(|_| b.take(1, t)));
        assert!(!b.take(1, t));
        let later = t + Duration::from_millis(50);
        assert!((0..50).all(|_| b.take(1, later)));
        assert!(!b.take(1, later));
        assert!(
            !b.take(1000, t + Duration::from_secs(60)),
            "never above burst"
        );
    }
}

//! The host's fan-out egress budget (§6.3), charged per emitted copy before
//! the copy is sent.

use std::time::Instant;

pub(crate) struct Bucket(kickoff_budget::Bucket);

impl Bucket {
    pub(crate) fn new(per_sec: u64, burst: u64, now: Instant) -> Bucket {
        Bucket(kickoff_budget::Bucket::new(now, per_sec, burst))
    }

    #[inline]
    pub(crate) fn take(&mut self, cost: u64, now: Instant) -> bool {
        self.0.charge(now, cost)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn si_23_full_fanout_bucket_discards_idle_fractional_credit() {
        let t = Instant::now();
        let mut b = Bucket::new(1, 1, t);
        assert!(b.take(1, t + Duration::from_millis(900)));
        assert!(!b.take(1, t + Duration::from_secs(1)));
        assert!(b.take(1, t + Duration::from_millis(1900)));
    }

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

use tokio::time::Instant;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Rate {
    pub per_sec: u64,
    pub burst: u64,
}

pub(crate) struct Bucket(kickoff_budget::Bucket);

impl Bucket {
    pub fn new(rate: Rate, now: Instant) -> Bucket {
        Bucket(kickoff_budget::Bucket::new(
            now.into_std(),
            rate.per_sec,
            rate.burst,
        ))
    }

    #[inline]
    pub fn take(&mut self, cost: u64, now: Instant) -> bool {
        self.0.charge(now.into_std(), cost)
    }

    #[inline]
    pub fn has(&mut self, cost: u64, now: Instant) -> bool {
        self.0.ready(now.into_std(), cost)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn si_23_full_lan_bucket_discards_idle_fractional_credit() {
        let t = Instant::now();
        let mut b = Bucket::new(
            Rate {
                per_sec: 1,
                burst: 1,
            },
            t,
        );
        assert!(b.take(1, t + Duration::from_millis(900)));
        assert!(!b.take(1, t + Duration::from_secs(1)));
        assert!(b.take(1, t + Duration::from_millis(1900)));
    }
}

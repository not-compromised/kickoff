use tokio::time::Instant;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Rate {
    pub per_sec: u64,
    pub burst: u64,
}

const NANOS: u128 = 1_000_000_000;

/// A token bucket kept in token-nanoseconds so integer refill loses nothing.
/// Starts full.
pub(crate) struct Bucket {
    rate: Rate,
    level: u128,
    last: Instant,
}

impl Bucket {
    pub fn new(rate: Rate, now: Instant) -> Bucket {
        Bucket {
            rate,
            level: capacity(rate),
            last: now,
        }
    }

    /// Takes `cost` tokens if the bucket holds them; otherwise takes nothing.
    pub fn take(&mut self, cost: u64, now: Instant) -> bool {
        self.refill(now);
        let cost = u128::from(cost).saturating_mul(NANOS);
        match self.level.checked_sub(cost) {
            Some(rest) => {
                self.level = rest;
                true
            }
            None => false,
        }
    }

    /// Whether `cost` would fit now, without taking it.
    pub fn has(&mut self, cost: u64, now: Instant) -> bool {
        self.refill(now);
        self.level >= u128::from(cost).saturating_mul(NANOS)
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_nanos();
        let gained = elapsed.saturating_mul(u128::from(self.rate.per_sec));
        self.level = self.level.saturating_add(gained).min(capacity(self.rate));
        self.last = now.max(self.last);
    }
}

fn capacity(rate: Rate) -> u128 {
    u128::from(rate.burst).saturating_mul(NANOS)
}

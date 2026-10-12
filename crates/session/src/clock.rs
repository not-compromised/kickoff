//! The host's monotonic clock (§4.2): invite validity, the admission window
//! and the reconnect window are measured on it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// `std::time::Instant` plus a forward-only skew. Built on `Instant`, so
/// moving the wall clock changes nothing; `advance` can only move it forward,
/// which can expire an invite or a reconnect window early but never extend one.
#[derive(Debug, Clone, Default)]
pub struct Clock {
    skew_nanos: Arc<AtomicU64>,
}

impl Clock {
    pub fn system() -> Clock {
        Clock::default()
    }

    /// Moves this clock and every clone of it forward by `by`.
    pub fn advance(&self, by: Duration) {
        let nanos = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
        let _ = self
            .skew_nanos
            .try_update(Ordering::AcqRel, Ordering::Acquire, |s| {
                Some(s.saturating_add(nanos))
            });
    }

    pub(crate) fn now(&self) -> Instant {
        let skew = Duration::from_nanos(self.skew_nanos.load(Ordering::Acquire));
        let now = Instant::now();
        now.checked_add(skew).unwrap_or(now)
    }
}

//! The session's monotonic clock (§4.2): invite validity, approval
//! timeouts, the idle close and the admission and reconnect windows are
//! measured on it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// `std::time::Instant` plus a forward-only skew. Built on `Instant`, so
/// moving the wall clock changes nothing; `advance` can only move it forward,
/// which can expire an invite or a reconnect window early but never extend one.
/// How far a wait on this clock can lag an `advance`.
const STEP: Duration = Duration::from_millis(250);

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

    /// Waits until this clock reads `deadline`. Sleeps in short steps, so an
    /// `advance` takes effect within one.
    pub(crate) async fn until(&self, deadline: Instant) {
        loop {
            let left = deadline.saturating_duration_since(self.now());
            if left.is_zero() {
                return;
            }
            tokio::time::sleep(left.min(STEP)).await;
        }
    }
}

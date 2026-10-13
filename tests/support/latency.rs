//! Shared by the design §7 latency tests. The budgets are wall-clock, so a
//! failed measurement also reports how long this process's threads waited for
//! a CPU over the run. That total is diagnostic context, not an explanation:
//! it cannot attribute any single slow datagram to contention.
#![allow(dead_code, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::time::Duration;

pub fn percentile(sorted: &[Duration], p: usize) -> Duration {
    sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
}

/// Total time this process's live threads have spent runnable but waiting
/// for a CPU (Linux schedstat; `None` where the kernel does not report it).
pub fn run_queue_wait() -> Option<Duration> {
    let mut total = 0u64;
    for task in std::fs::read_dir("/proc/self/task").ok()? {
        let Ok(task) = task else { continue };
        // A thread that exits between the listing and the read is skipped.
        let Ok(stat) = std::fs::read_to_string(task.path().join("schedstat")) else {
            continue;
        };
        total += stat.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    }
    Some(Duration::from_nanos(total))
}

/// The CPU contention behind a measurement that started at `before`.
pub fn contention(before: Option<Duration>) -> String {
    match (before, run_queue_wait()) {
        (Some(before), Some(after)) => format!(
            "threads waited {:?} on the run queue during the measurement",
            after.saturating_sub(before)
        ),
        _ => "run-queue wait not reported by this kernel".to_owned(),
    }
}

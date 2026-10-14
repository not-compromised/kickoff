//! Shared by the design §7 latency tests. The budgets are wall-clock, so a
//! failed measurement also reports how long this process's threads waited for
//! a CPU over the run. That total is diagnostic context, not an explanation:
//! it cannot attribute any single slow datagram to contention.
#![allow(dead_code, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::time::Duration;

/// Names the machine a release latency test runs on. Unset, the test asserts
/// the §7 budgets themselves: that is the gate on the reference machine, run
/// before every merge and release. `hosted` names a shared CI runner, several
/// times slower than the reference machine, where the test asserts a ceiling
/// [`HOSTED_FACTOR`] times each budget, so a large regression still fails
/// there. Any other value refuses, so a misspelling cannot loosen a budget.
pub const RUNNER_VAR: &str = "KICKOFF_LATENCY_RUNNER";

/// How far over a §7 budget a hosted runner may measure before it fails.
pub const HOSTED_FACTOR: u32 = 4;

/// The ceiling to assert for the §7 budget `reference` on this runner.
pub fn budget(reference: Duration) -> Duration {
    match std::env::var(RUNNER_VAR) {
        Ok(runner) => budget_for(Some(&runner), reference),
        Err(std::env::VarError::NotPresent) => budget_for(None, reference),
        Err(std::env::VarError::NotUnicode(_)) => budget_for(Some(""), reference),
    }
}

/// [`budget`] for an explicit runner name.
#[allow(clippy::panic)]
pub fn budget_for(runner: Option<&str>, reference: Duration) -> Duration {
    match runner {
        None => reference,
        Some("hosted") => reference * HOSTED_FACTOR,
        Some(other) => panic!("{RUNNER_VAR}={other:?}: only `hosted` or unset is accepted"),
    }
}

/// Which budgets a run asserts, for its report.
pub fn runner_label() -> String {
    if budget(Duration::from_nanos(1)) == Duration::from_nanos(1) {
        "the §7 budget, reference machine".to_owned()
    } else {
        format!("hosted ceiling, {HOSTED_FACTOR}x the §7 budget")
    }
}

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

//! In-process datagram latency (design §7): one-way, `send_lan` on one node
//! to `recv_lan` returning on the other, over loopback with relays disabled.
//! The budget's p50 <= 100 us / p99 <= 500 us covers the whole game-to-game
//! path; this measures net's share, so net alone must fit inside it. Release
//! builds assert that budget (scripts/check.sh runs this with `--release`);
//! debug builds only a loose ceiling. `-- --nocapture` prints the numbers.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::print_stderr
)]

mod common;
#[path = "../../../tests/support/latency.rs"]
mod latency;

use std::time::{Duration, Instant};

use common::*;
use kickoff_net::Role;
use latency::{budget, contention, percentile, run_queue_wait, runner_label};

/// (label, payload length given the path's datagram limit, samples, batch).
/// Each batch stays inside the receiver's datagram and byte burst, and the
/// pause between batches refills it, so no sample is dropped by the budget.
/// One unmeasured batch precedes the samples, so first-use costs stay out of
/// the steady-state figure.
type Case = (&'static str, fn(usize) -> usize, usize, usize);
const CASES: [Case; 2] = [
    ("unfragmented 128 B", |_| 128, 10_000, 500),
    ("3 fragments", |max| 3 * (max - 10), 2_000, 250),
];
const PAUSE: Duration = Duration::from_millis(300);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagram_latency_p50_p99_over_10k() {
    let host = node(Role::Host).await;
    let guest = node(Role::Guest).await;
    let (host_link, guest_link) = pair(&host, &guest, peer(2, 1)).await;
    let max = settled_max(&guest_link).await;

    for (label, len, count, batch) in CASES {
        let len = len(max);
        let mut samples = Vec::with_capacity(count);
        let mut waited = None;
        for i in 0..batch + count {
            if i == batch {
                waited = run_queue_wait();
            }
            let d = lan(len, i as u8);
            let sent = Instant::now();
            guest_link.send_lan(&d);
            let got = tokio::time::timeout(WAIT, host_link.recv_lan())
                .await
                .unwrap()
                .unwrap();
            let took = sent.elapsed();
            assert_eq!(got.payload.len(), len);
            if i >= batch {
                samples.push(took);
            }
            if i % batch == batch - 1 {
                tokio::time::sleep(PAUSE).await;
            }
        }
        let contention = contention(waited);
        samples.sort();
        let (p50, p99) = (percentile(&samples, 50), percentile(&samples, 99));
        eprintln!(
            "{label} ({len} B): p50 {p50:?}, p99 {p99:?}, max {:?} over {count}; {contention}",
            samples[count - 1]
        );
        if cfg!(debug_assertions) {
            assert!(
                p99 < Duration::from_millis(20),
                "{label}: p99 {p99:?}; {contention}"
            );
        } else {
            let (p50_max, p99_max) = (
                budget(Duration::from_micros(100)),
                budget(Duration::from_micros(500)),
            );
            let asserted = runner_label();
            assert!(
                p50 <= p50_max,
                "{label}: p50 {p50:?} over {p50_max:?} ({asserted}); {contention}"
            );
            assert!(
                p99 <= p99_max,
                "{label}: p99 {p99:?} over {p99_max:?} ({asserted}); {contention}"
            );
        }
        let h = host_link.health();
        assert_eq!(
            h.dropped_budget + h.dropped_reassembly + h.dropped_malformed,
            0,
            "{h:?}"
        );
    }
}

#[test]
fn latency_budgets_are_exact_unless_the_runner_is_named_hosted() {
    use latency::{HOSTED_FACTOR, budget_for};
    let budget = Duration::from_micros(100);
    assert_eq!(budget_for(None, budget), budget);
    assert_eq!(budget_for(Some("hosted"), budget), budget * HOSTED_FACTOR);
    for typo in ["", "Hosted", "hosted ", "ci", "reference"] {
        assert!(
            std::panic::catch_unwind(|| budget_for(Some(typo), budget)).is_err(),
            "{typo:?} was accepted as a runner name"
        );
    }
}

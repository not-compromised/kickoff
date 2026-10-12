//! In-process datagram latency (design §7): one-way, `send_lan` on one node
//! to `recv_lan` returning on the other, over loopback with relays disabled.
//! The budget's p50 <= 100 us / p99 <= 500 us covers the whole game-to-game
//! path; this measures net's share. Debug builds only assert a loose ceiling;
//! `cargo test --release -p kickoff-net --test latency -- --nocapture` prints
//! the numbers the report quotes.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::print_stderr
)]

mod common;

use std::time::{Duration, Instant};

use common::*;
use kickoff_net::Role;

/// (label, payload length given the path's datagram limit, samples, batch).
/// Each batch stays inside the receiver's datagram and byte burst, and the
/// pause between batches refills it, so no sample is dropped by the budget.
type Case = (&'static str, fn(usize) -> usize, usize, usize);
const CASES: [Case; 2] = [
    ("unfragmented 128 B", |_| 128, 10_000, 500),
    ("3 fragments", |max| 3 * (max - 10), 2_000, 250),
];
const PAUSE: Duration = Duration::from_millis(300);

fn percentile(sorted: &[Duration], p: usize) -> Duration {
    sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagram_latency_p50_p99_over_10k() {
    let host = node(Role::Host).await;
    let guest = node(Role::Guest).await;
    let (host_link, guest_link) = pair(&host, &guest, peer(2, 1)).await;
    let max = settled_max(&guest_link).await;

    for (label, len, count, batch) in CASES {
        let len = len(max);
        let mut samples = Vec::with_capacity(count);
        for i in 0..count {
            let d = lan(len, i as u8);
            let sent = Instant::now();
            guest_link.send_lan(&d);
            let got = tokio::time::timeout(WAIT, host_link.recv_lan())
                .await
                .unwrap()
                .unwrap();
            samples.push(sent.elapsed());
            assert_eq!(got.payload.len(), len);
            if i % batch == batch - 1 {
                tokio::time::sleep(PAUSE).await;
            }
        }
        samples.sort();
        let (p50, p99) = (percentile(&samples, 50), percentile(&samples, 99));
        eprintln!(
            "{label} ({len} B): p50 {p50:?}, p99 {p99:?}, max {:?} over {count}",
            samples[count - 1]
        );
        assert!(p99 < Duration::from_millis(20), "{label}: p99 {p99:?}");
        let h = host_link.health();
        assert_eq!(
            h.dropped_budget + h.dropped_reassembly + h.dropped_malformed,
            0,
            "{h:?}"
        );
    }
}

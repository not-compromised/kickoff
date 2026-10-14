//! Design §7: the hot path, codec plus filter, costs at most 2 µs per
//! datagram. Measured through the public seam in both directions: frames in
//! at the game end and datagrams out of `Lan::recv`, datagrams into
//! `Lan::deliver` and frames out at the game end, so the figure includes the
//! adapter queues too. Release builds assert the budget (scripts/check.sh
//! runs this with `--release`); debug builds assert a loose ceiling.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::print_stderr
)]

mod common;
#[path = "../../../tests/support/latency.rs"]
mod latency;

use std::time::{Duration, Instant};

use bytes::Bytes;
use common::*;
use kickoff_wire::LanDatagram;

/// Datagrams each way per round: inside the game queue (256) and the
/// per-peer burst (1000), so nothing is dropped and every one is measured.
const BATCH: usize = 200;
const ROUNDS: usize = 200;
const PAYLOAD: usize = 200;

#[tokio::test(start_paused = true)]
async fn hot_path_codec_and_filter_within_2us_per_datagram() {
    let (host, game) = node(1);
    let frame = Bytes::from(
        Udp::unicast(1, 2, 40000, GAME_PORT)
            .payload(&[7; PAYLOAD])
            .frame(),
    );
    // The reply on the flow the outbound frames opened.
    let reply = LanDatagram {
        peer: slot(2),
        bcast: false,
        src_port: GAME_PORT,
        dst_port: 40000,
        payload: Bytes::from(vec![7; PAYLOAD]),
    };

    let mut per_datagram = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let start = Instant::now();
        for _ in 0..BATCH {
            game.send_frame(frame.clone()).unwrap();
        }
        for _ in 0..BATCH {
            host.recv().await.unwrap();
        }
        for _ in 0..BATCH {
            host.deliver(reply.clone());
        }
        for _ in 0..BATCH {
            game.recv_frame().await.unwrap();
        }
        per_datagram.push(start.elapsed() / (2 * BATCH) as u32);
        // Refills every bucket on the paused clock; the std clock above is
        // what is measured.
        tokio::time::advance(Duration::from_secs(1)).await;
    }
    let health = host.health();
    assert_eq!(
        (health.dropped_filter, health.dropped_overload),
        (0, 0),
        "a measured datagram was dropped: {health:?}"
    );

    per_datagram.sort();
    let median = per_datagram[ROUNDS / 2];
    let worst = per_datagram[ROUNDS - 1];
    let (budget, asserted) = if cfg!(debug_assertions) {
        (Duration::from_micros(200), "debug ceiling".to_owned())
    } else {
        (
            latency::budget(Duration::from_micros(2)),
            latency::runner_label(),
        )
    };
    eprintln!(
        "codec plus filter per datagram: median {median:?}, worst round {worst:?}; asserting median <= {budget:?}, {asserted}"
    );
    assert!(
        median <= budget,
        "codec plus filter takes {median:?} per datagram, over {budget:?} ({asserted})"
    );
}

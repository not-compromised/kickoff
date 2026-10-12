//! Budgets (§6.3, SI-23) and the latency budget (§7), through whole nodes:
//! game frames in, game frames out.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::print_stderr
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::*;
use kickoff_wire::{LanDatagram, PeerSlot};

fn percentile(sorted: &[Duration], p: usize) -> Duration {
    sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
}

struct Flood {
    host: kickoff_session::Session,
    flood_link: Arc<kickoff_net::Link>,
    other: GuestNode,
    from_flooder: Arc<AtomicU64>,
    _keep: (
        Identity,
        RawGuest,
        kickoff_net::CtlStream,
        tokio::task::JoinHandle<()>,
    ),
}

/// A host whose game echoes guest B (slot 3) and counts what reaches it from
/// the flooder F (slot 2), played at its link.
async fn flood_setup() -> Flood {
    let HostNode {
        identity,
        session: host,
        game: host_game,
        ..
    } = host().await;
    let (f, b) = (Identity::new().await, Identity::new().await);
    let (tf, tb) = (
        host.invite(kickoff_session::InviteKind::Bound(f.id()))
            .unwrap(),
        host.invite(kickoff_session::InviteKind::Bound(b.id()))
            .unwrap(),
    );
    let flooder = RawGuest::join(f, &tf).await.unwrap();
    let (flood_link, flood_ctl) = flooder.connect().await.unwrap();
    let other = join(b, tb).await.unwrap();
    assert_eq!((flooder.slot().get(), other.slot()), (2, 3));
    let from_flooder = Arc::new(AtomicU64::new(0));
    let echo = {
        let from_flooder = Arc::clone(&from_flooder);
        tokio::spawn(async move {
            while let Ok(frame) = host_game.recv_frame().await {
                let Some(s) = seen(&frame) else { continue };
                if s.from == 3 {
                    let _ =
                        host_game.send_frame(udp(1, Some(3), GAME_PORT, s.src_port, &s.payload));
                } else if s.from == 2 {
                    from_flooder.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
    };
    Flood {
        host,
        flood_link: Arc::new(flood_link),
        other,
        from_flooder,
        _keep: (identity, flooder, flood_ctl, echo),
    }
}

/// Sends `per_tick` datagrams every millisecond (`None`: as fast as the link
/// takes them) until `stop`.
fn flood(
    link: Arc<kickoff_net::Link>,
    per_tick: Option<u32>,
    stop: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<u64> {
    tokio::spawn(async move {
        let d = LanDatagram {
            peer: PeerSlot::HOST,
            bcast: false,
            src_port: 50_000,
            dst_port: GAME_PORT,
            payload: vec![0xee; 64].into(),
        };
        let mut tick = tokio::time::interval(Duration::from_millis(1));
        let mut sent = 0u64;
        while !stop.load(Ordering::Relaxed) {
            match per_tick {
                Some(n) => {
                    tick.tick().await;
                    for _ in 0..n {
                        link.send_lan(&d);
                    }
                    sent += u64::from(n);
                }
                None => {
                    for _ in 0..256 {
                        link.send_lan(&d);
                    }
                    sent += 256;
                    tokio::task::yield_now().await;
                }
            }
        }
        sent
    })
}

/// Round trips from B's game through the host's game and back.
async fn pings(other: &GuestNode, count: u32) -> Vec<Duration> {
    let mut rtts = Vec::new();
    for seq in 0..count {
        let sent_at = Instant::now();
        other
            .game
            .send_frame(udp(3, Some(1), 50_000, GAME_PORT, &seq.to_be_bytes()))
            .unwrap();
        let back = next_udp(&other.game, Duration::from_secs(1)).await;
        if back.is_some_and(|s| s.payload == seq.to_be_bytes()) {
            rtts.push(sent_at.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    rtts.sort();
    rtts
}

/// A guest sending about 7x its datagram budget (under the 10x that
/// disconnects) is cut to the budget, and another guest's round trips stay
/// fast meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_23_peer_over_budget_is_limited_and_another_keeps_its_latency() {
    let f = flood_setup().await;
    let stop = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let flooding = flood(Arc::clone(&f.flood_link), Some(20), Arc::clone(&stop));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let rtts = pings(&f.other, 400).await;
    stop.store(true, Ordering::Relaxed);
    let sent = flooding.await.unwrap();
    let took = started.elapsed();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let delivered = f.from_flooder.load(Ordering::Relaxed);
    let (p50, p99) = (percentile(&rtts, 50), percentile(&rtts, 99));
    eprintln!(
        "flooder sent {sent} in {took:?}, {delivered} reached the game; \
         other guest's RTT: p50 {p50:?} p99 {p99:?} over {}",
        rtts.len()
    );
    // §6.3: 3000/s with a burst of 1000, charged before reassembly; the LAN
    // charges the same per-peer budget again in front of the game.
    let allowance = 1000 + 3000 * (took.as_secs() + 1);
    assert!(
        sent > 3 * allowance,
        "the flood was too slow to test anything: {sent}"
    );
    assert!(
        delivered <= allowance,
        "{delivered} flood datagrams reached the game, budget {allowance}"
    );
    assert!(
        rtts.len() >= 396,
        "the other guest lost {} of 400 pings",
        400 - rtts.len()
    );
    let ceiling = if cfg!(debug_assertions) {
        Duration::from_millis(20)
    } else {
        Duration::from_millis(2)
    };
    assert!(p99 <= ceiling, "the other guest's p99 RTT is {p99:?}");
    assert!(
        f.host.members().iter().any(|m| m.slot.get() == 2),
        "a peer under 10x its budget was disconnected"
    );
}

/// A guest far above its budget is disconnected and loses its seat (§6.3:
/// above 10x for 5 s).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_23_peer_far_over_budget_is_disconnected() {
    let f = flood_setup().await;
    let stop = Arc::new(AtomicBool::new(false));
    let flooding = flood(Arc::clone(&f.flood_link), None, Arc::clone(&stop));
    let evicted = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if !f.host.members().iter().any(|m| m.slot.get() == 2) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    stop.store(true, Ordering::Relaxed);
    let sent = flooding.await.unwrap();
    assert!(evicted.is_ok(), "still seated after {sent} datagrams");
    let rtts = pings(&f.other, 50).await;
    assert_eq!(
        rtts.len(),
        50,
        "the other guest lost pings after the eviction"
    );
}

/// §7: added one-way latency, game socket to peer game socket, two in-process
/// nodes over `Mem`, 10k datagrams. Debug builds assert a loose ceiling;
/// `cargo test --release -p kickoff-session --test budget -- --nocapture`
/// checks the budget itself and prints the numbers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn latency_p50_p99_over_10k_datagrams() {
    let host = host().await;
    let alice = Identity::new().await;
    let ticket = host.bound(alice.id());
    let alice = join(alice, ticket).await.unwrap();

    const COUNT: usize = 10_000;
    // Below both per-peer bursts (1000), refilled by the pause between batches.
    const BATCH: usize = 500;
    let mut samples = Vec::with_capacity(COUNT);
    for i in 0..COUNT {
        let payload = (i as u32).to_be_bytes();
        let frame = udp(2, Some(1), 50_000, GAME_PORT, &payload);
        let sent = Instant::now();
        alice.game.send_frame(frame).unwrap();
        let got = next_udp(&host.game, Duration::from_secs(5)).await.unwrap();
        samples.push(sent.elapsed());
        assert_eq!(got.payload, payload);
        if i % BATCH == BATCH - 1 {
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    }
    samples.sort();
    let (p50, p99) = (percentile(&samples, 50), percentile(&samples, 99));
    eprintln!(
        "game to game, one way, {COUNT} datagrams: p50 {p50:?}, p99 {p99:?}, max {:?}",
        samples[COUNT - 1]
    );
    if cfg!(debug_assertions) {
        assert!(p99 < Duration::from_millis(20), "p99 {p99:?}");
    } else {
        assert!(
            p50 <= Duration::from_micros(100),
            "p50 {p50:?} over the §7 budget"
        );
        assert!(
            p99 <= Duration::from_micros(500),
            "p99 {p99:?} over the §7 budget"
        );
    }
}

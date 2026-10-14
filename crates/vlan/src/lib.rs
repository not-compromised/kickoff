//! The game-facing LAN (design §2.3, §3.1). Hides the L2 frame codec (ARP
//! answered locally, MAC synthesis, IPv4/UDP build and checksums), the filter
//! and adapter I/O. The filter sits in front of every adapter, so Linux,
//! Windows and the in-memory adapter share every line of codec and filter.

mod addr;
mod bucket;
mod codec;
mod filter;
mod mem;
mod ports;
mod verdict;

#[cfg(test)]
extern crate self as kickoff_vlan;
#[cfg(test)]
mod tests;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use bytes::Bytes;
use kickoff_wire::{LanDatagram, PeerSlot};
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::Instant;

use crate::addr::Node;
use crate::codec::FromGame;
use crate::filter::Filter;
use crate::verdict::{Class, Reject};

pub use crate::mem::{MemGame, MemTap, mem_tap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LanError {
    #[error("adapter not supported on this platform or milestone")]
    Unsupported,
    #[error("adapter closed")]
    Closed,
    #[error("adapter queue full")]
    Full,
}

/// Where L2 frames to and from the local game travel.
pub enum Adapter {
    /// In-process frames, for tests and the §7 latency budget.
    Mem(MemTap),
    /// The gamebox tap fd, received from kickoff-gamebox over `SCM_RIGHTS`
    /// (§3.2). Lands in M3.
    #[cfg(target_os = "linux")]
    NsTap(std::os::fd::OwnedFd),
}

/// `GamePorts` and the denylist are compiled in and deliberately absent here:
/// no configuration can widen what peers reach (§3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanConfig {
    /// This node's slot; fixes its MAC `02:4b:4f:00:00:<slot>` and address
    /// `10.75.0.<slot>`. Slot 1 is the host; any other slot is a guest, whose
    /// LAN exchanges traffic with the host only.
    pub slot: PeerSlot,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LanHealth {
    /// Datagrams from the local game that passed the filter.
    pub from_game: u64,
    /// Frames handed to the local game for peers' datagrams.
    pub to_game: u64,
    pub dropped_filter: u64,
    pub dropped_malformed: u64,
    pub dropped_overload: u64,
}

pub struct Lan {
    node: Node,
    filter: Mutex<Filter>,
    io: mem::Io,
    health: Counters,
}

pub fn open(adapter: Adapter, cfg: LanConfig) -> Result<Lan, LanError> {
    let io = match adapter {
        Adapter::Mem(tap) => tap.into_io(),
        #[cfg(target_os = "linux")]
        Adapter::NsTap(_) => return Err(LanError::Unsupported),
    };
    let node = Node { own: cfg.slot };
    Ok(Lan {
        node,
        filter: Mutex::new(Filter::new(node, Instant::now())),
        io,
        health: Counters::default(),
    })
}

impl Lan {
    /// The next datagram from the local game, already decoded and filtered.
    /// A unicast's `peer` is its destination slot. A broadcast's `peer` is the
    /// host: a guest's broadcast goes only to the host, and the host's fans
    /// out to every guest. `Closed` once the adapter is gone (the tap dies
    /// with its gamebox). Cancel-safe.
    pub async fn recv(&self) -> Result<LanDatagram, LanError> {
        let mut from_game = self.io.from_game.lock().await;
        loop {
            let frame = from_game.recv().await.ok_or(LanError::Closed)?;
            match self.take_frame(&frame) {
                Ok(Some(datagram)) => return Ok(datagram),
                Ok(None) => {}
                Err(reject) => self.health.dropped(reject),
            }
        }
    }

    /// To the local game, from the peer in `datagram.peer`, which must be the
    /// slot of the link it arrived on. Filtered; never blocks; drops and
    /// counts on overload.
    pub fn deliver(&self, datagram: LanDatagram) {
        let verdict = self.filter().inbound(&datagram, Instant::now());
        // The frame is built only after the peer has paid for it.
        let outcome = verdict
            .and_then(|()| codec::udp_frame(self.node, &datagram).ok_or(Reject::PayloadTooLarge))
            .and_then(|frame| self.to_game(frame));
        match outcome {
            Ok(true) => {
                self.health.to_game.fetch_add(1, Ordering::Relaxed);
            }
            Ok(false) => {}
            Err(reject) => self.health.dropped(reject),
        }
    }

    /// Forgets every flow the local game opened with `slot`. The admission
    /// owner calls this whenever that slot's generation changes (reconnect,
    /// kick, eviction), before the new generation's datagrams are delivered,
    /// so nothing the old link opened answers the new one (SI-18).
    pub fn reset_peer(&self, slot: PeerSlot) {
        self.filter().reset_peer(slot);
    }

    pub fn health(&self) -> LanHealth {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        LanHealth {
            from_game: get(&self.health.from_game),
            to_game: get(&self.health.to_game),
            dropped_filter: get(&self.health.filter),
            dropped_malformed: get(&self.health.malformed),
            dropped_overload: get(&self.health.overload),
        }
    }

    /// `Ok(None)` for an ARP request answered locally.
    fn take_frame(&self, frame: &Bytes) -> Result<Option<LanDatagram>, Reject> {
        match codec::decode(frame, self.node)? {
            FromGame::ArpFor(peer) => {
                self.to_game(codec::arp_reply(self.node, peer))?;
                Ok(None)
            }
            FromGame::Udp(datagram) => {
                self.filter().outbound(&datagram, Instant::now())?;
                self.health.from_game.fetch_add(1, Ordering::Relaxed);
                Ok(Some(datagram))
            }
        }
    }

    /// `Ok(false)` when the game end is gone; `recv` reports that as `Closed`.
    fn to_game(&self, frame: Bytes) -> Result<bool, Reject> {
        match self.io.to_game.try_send(frame) {
            Ok(()) => Ok(true),
            Err(TrySendError::Full(_)) => Err(Reject::QueueFull),
            Err(TrySendError::Closed(_)) => Ok(false),
        }
    }

    fn filter(&self) -> MutexGuard<'_, Filter> {
        // Nothing panics while holding the lock, and the filter's tables are
        // valid between any two statements, so a poisoned lock is still sound.
        self.filter.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Default)]
struct Counters {
    from_game: AtomicU64,
    to_game: AtomicU64,
    filter: AtomicU64,
    malformed: AtomicU64,
    overload: AtomicU64,
}

impl Counters {
    fn dropped(&self, reject: Reject) {
        let counter = match reject.class() {
            Class::Filter => &self.filter,
            Class::Malformed => &self.malformed,
            Class::Overload => &self.overload,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

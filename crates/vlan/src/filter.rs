//! The filter of §3.1, in front of every adapter. Every table here has a fixed
//! size allocated at `open`, and each datagram pays its peer's budget before
//! any other check (§6.3, SI-23).

use std::time::Duration;

use kickoff_wire::{LanDatagram, MAX_ROSTER, PeerSlot};
use tokio::time::Instant;

use crate::addr::Node;
use crate::bucket::{Bucket, Rate};
use crate::codec::MAX_PAYLOAD;
use crate::ports;
use crate::verdict::Reject;

pub(crate) const FLOW_IDLE: Duration = Duration::from_secs(30);
pub(crate) const FLOWS_PER_PEER: usize = if cfg!(feature = "mutant-si23-flow-table-grows") {
    128
} else {
    64
};
pub(crate) const MAX_BROADCAST_PAYLOAD: usize = 1252;
/// The per-link datagram budget of §6.3, applied again per peer here so one
/// peer cannot fill the game's queue for the others.
pub(crate) const PEER_PACKETS: Rate = Rate {
    per_sec: 3000,
    burst: 1000,
};
pub(crate) const PEER_BYTES: Rate = Rate {
    per_sec: 4_000_000,
    burst: 1_000_000,
};
pub(crate) const BROADCASTS: Rate = Rate {
    per_sec: 10,
    burst: 10,
};

/// Indexed by slot number. Broadcast and unicast permissions share each
/// peer's table so both die at its next generation reset.
const SCOPES: usize = MAX_ROSTER as usize + 1;

pub(crate) struct Filter {
    node: Node,
    flows: Box<[FlowTable; SCOPES]>,
    inbound: [PeerBudget; SCOPES],
    outbound: [PeerBudget; SCOPES],
    broadcast_in: [Bucket; SCOPES],
    broadcast_out: Bucket,
}

impl Filter {
    pub fn new(node: Node, now: Instant) -> Filter {
        Filter {
            node,
            flows: Box::new(std::array::from_fn(|_| FlowTable::EMPTY)),
            inbound: std::array::from_fn(|_| PeerBudget::new(now)),
            outbound: std::array::from_fn(|_| PeerBudget::new(now)),
            broadcast_in: std::array::from_fn(|_| Bucket::new(BROADCASTS, now)),
            broadcast_out: Bucket::new(BROADCASTS, now),
        }
    }

    /// From the local game to `d.peer`, or to the star for a broadcast. The
    /// codec has already checked the frame's addresses.
    pub fn outbound(&mut self, d: &LanDatagram, now: Instant) -> Result<(), Reject> {
        if !d.bcast {
            self.node.check_peer(d.peer)?;
        }
        charge(&mut self.outbound, d, now)?;
        check_ports(d)?;
        let scope = if d.bcast {
            check_broadcast(d, &mut self.broadcast_out, now)?;
            let host = index(PeerSlot::HOST);
            if self.node.is_host() {
                host.saturating_add(1)..SCOPES
            } else {
                host..host.saturating_add(1)
            }
        } else {
            if !ports::game(d.src_port) && !ports::game(d.dst_port) {
                return Err(Reject::NotGamePort);
            }
            let peer = index(d.peer);
            peer..peer.saturating_add(1)
        };
        for table in self.flows.get_mut(scope).into_iter().flatten() {
            table.record(d.src_port, d.dst_port, now);
        }
        Ok(())
    }

    /// From peer `d.peer` (the slot its link was admitted under) to the local
    /// game.
    pub fn inbound(&mut self, d: &LanDatagram, now: Instant) -> Result<(), Reject> {
        self.node.check_peer(d.peer)?;
        if cfg!(feature = "mutant-si23-filter-before-charge") {
            check_ports(d)?;
            if !d.bcast && !ports::game(d.dst_port) && !self.flow_open(d, now) {
                return Err(Reject::NotGamePort);
            }
        }
        charge(&mut self.inbound, d, now)?;
        if d.payload.len() > MAX_PAYLOAD {
            return Err(Reject::PayloadTooLarge);
        }
        check_ports(d)?;
        if d.bcast {
            let bucket = self
                .broadcast_in
                .get_mut(index(d.peer))
                .ok_or(Reject::NotInStar)?;
            return check_broadcast(d, bucket, now);
        }
        if ports::game(d.dst_port) || self.flow_open(d, now) {
            Ok(())
        } else {
            Err(Reject::NotGamePort)
        }
    }

    /// Forgets every flow the local game opened with `slot`. Flows carry no
    /// generation of their own, so this is what keeps a flow opened for one
    /// admission from answering the next holder of the slot (SI-18).
    pub fn reset_peer(&mut self, slot: PeerSlot) {
        if cfg!(feature = "mutant-si18-flows-survive-reset") {
            return;
        }
        if let Some(table) = self.flows.get_mut(index(slot)) {
            *table = FlowTable::EMPTY;
        }
        #[cfg(feature = "mutant-si23-reset-refills-budget")]
        if let Some(budget) = self.inbound.get_mut(index(slot)) {
            *budget = PeerBudget::new(Instant::now());
        }
    }

    fn flow_open(&self, d: &LanDatagram, now: Instant) -> bool {
        self.flows
            .get(index(d.peer))
            .is_some_and(|t| t.live(d.dst_port, d.src_port, now))
    }
}

fn index(slot: PeerSlot) -> usize {
    usize::from(slot.get())
}

fn charge(budgets: &mut [PeerBudget; SCOPES], d: &LanDatagram, now: Instant) -> Result<(), Reject> {
    let budget = budgets.get_mut(index(d.peer)).ok_or(Reject::NotInStar)?;
    let bytes = u64::try_from(d.payload.len()).unwrap_or(u64::MAX);
    if cfg!(feature = "mutant-si23-no-peer-budget") {
        return Ok(());
    }
    let bytes = if cfg!(feature = "mutant-si23-no-byte-budget") {
        0
    } else {
        bytes
    };
    if budget.packets.has(1, now) && budget.bytes.has(bytes, now) {
        budget.packets.take(1, now);
        budget.bytes.take(bytes, now);
        Ok(())
    } else {
        Err(Reject::PeerBudget)
    }
}

fn check_ports(d: &LanDatagram) -> Result<(), Reject> {
    if d.src_port == 0 || d.dst_port == 0 {
        Err(Reject::ZeroPort)
    } else if ports::denied(d.src_port) || ports::denied(d.dst_port) {
        Err(Reject::DeniedPort)
    } else {
        Ok(())
    }
}

fn check_broadcast(d: &LanDatagram, bucket: &mut Bucket, now: Instant) -> Result<(), Reject> {
    if !ports::discovery(d.dst_port) {
        Err(Reject::BroadcastNotDiscovery)
    } else if d.payload.len() > MAX_BROADCAST_PAYLOAD {
        Err(Reject::BroadcastTooLarge)
    } else if !cfg!(feature = "mutant-si23-no-broadcast-budget") && !bucket.take(1, now) {
        Err(Reject::BroadcastBudget)
    } else {
        Ok(())
    }
}

struct PeerBudget {
    packets: Bucket,
    bytes: Bucket,
}

impl PeerBudget {
    fn new(now: Instant) -> PeerBudget {
        PeerBudget {
            packets: Bucket::new(PEER_PACKETS, now),
            bytes: Bucket::new(PEER_BYTES, now),
        }
    }
}

#[derive(Clone, Copy)]
struct Flow {
    local: u16,
    remote: u16,
    last_out: Instant,
}

/// Only the local game's own traffic opens or refreshes a flow, so a peer
/// cannot keep one alive after the game stops using it.
struct FlowTable([Option<Flow>; FLOWS_PER_PEER]);

impl FlowTable {
    const EMPTY: FlowTable = FlowTable([None; FLOWS_PER_PEER]);

    fn record(&mut self, local: u16, remote: u16, now: Instant) {
        if let Some(flow) = self
            .0
            .iter_mut()
            .flatten()
            .find(|f| f.local == local && f.remote == remote)
        {
            flow.last_out = now;
            return;
        }
        // An empty entry first, then the least recently used, which is also
        // the first to expire.
        if let Some(entry) = self.0.iter_mut().min_by_key(|e| e.map(|f| f.last_out)) {
            *entry = Some(Flow {
                local,
                remote,
                last_out: now,
            });
        }
    }

    fn live(&self, local: u16, remote: u16, now: Instant) -> bool {
        self.0.iter().flatten().any(|f| {
            f.local == local
                && f.remote == remote
                && now.saturating_duration_since(f.last_out) < FLOW_IDLE
        })
    }
}

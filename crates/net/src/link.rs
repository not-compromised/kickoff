//! An admitted connection (§2.3, §3.4): LAN datagrams with fragmentation and
//! budgets, the one guest-opened control stream, blob streams, path status.

use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use kickoff_wire::{
    Inbound, LEN_PREFIX_LEN, LanDatagram, PeerRef, PublicWireMessage, WireMessage, decode,
    decode_datagram, encode_datagram, encode_framed, frame_len,
};

use crate::budget::{Bucket, Window};
use crate::reassembly::{GlobalBudget, Outcome, Reassembler};
use crate::session::Shared;
use crate::stream::wire;
use crate::{CONNECT_DEADLINE, NetError, close};

/// Unread datagrams iroh holds per connection before dropping the oldest.
pub(crate) const DATAGRAM_RECEIVE_BUFFER: usize = 256 * 1024;

/// Datagrams per link, charged on every attempt before decoding (§6.3).
const DATAGRAM_RATE: u64 = 3000;
const DATAGRAM_BURST: u64 = 1000;
const BYTE_RATE: u64 = 4_000_000;
const BYTE_BURST: u64 = 1_500_000;
/// A peer sustaining ten times its allowance over this window is disconnected.
const ABUSE_WINDOW: Duration = Duration::from_secs(5);
const ABUSE_FACTOR: u64 = 10;
const ABUSE_SECS: u64 = 5;

/// Control stream (§6.3): messages and bytes per second.
const CTL_MSG_RATE: u64 = 32;
const CTL_BYTE_RATE: u64 = 256 * 1024;
/// How long a throttled control read waits before trying the budget again.
const CTL_BACKOFF: Duration = Duration::from_millis(10);
/// Blob streams the host accepts per second.
const BLOB_OPEN_RATE: u64 = 4;

/// Counters for one link, for health reporting. Never carries payload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkHealth {
    pub sent: u64,
    pub received: u64,
    pub dropped_send: u64,
    pub dropped_budget: u64,
    pub dropped_malformed: u64,
    pub dropped_reassembly: u64,
}

#[derive(Debug, Default)]
struct Counters {
    sent: AtomicU64,
    received: AtomicU64,
    dropped_send: AtomicU64,
    dropped_budget: AtomicU64,
    dropped_malformed: AtomicU64,
    dropped_reassembly: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStatus {
    Relay,
    Direct,
    Unknown,
}

/// Which end of the link this is. Only the host checks the admitted set: a
/// guest's one link lives exactly as long as its connection to the host.
#[derive(Debug)]
enum Side {
    Host {
        shared: Arc<Shared>,
        session_key: EndpointId,
    },
    Guest,
}

/// Datagram ingress state, touched only by `recv_lan`.
#[derive(Debug)]
struct Rx {
    datagrams: Bucket,
    bytes: Bucket,
    abuse_datagrams: Window,
    abuse_bytes: Window,
    frags: Reassembler,
}

enum Charge {
    Pass,
    Drop,
    Abuse,
}

impl Rx {
    fn new(now: Instant, global: Arc<GlobalBudget>) -> Rx {
        let window = |rate: u64| {
            let limit = rate.saturating_mul(ABUSE_FACTOR).saturating_mul(ABUSE_SECS);
            Window::new(now, ABUSE_WINDOW, limit)
        };
        Rx {
            datagrams: Bucket::new(now, DATAGRAM_RATE, DATAGRAM_BURST),
            bytes: Bucket::new(now, BYTE_RATE, BYTE_BURST),
            abuse_datagrams: window(DATAGRAM_RATE),
            abuse_bytes: window(BYTE_RATE),
            frags: Reassembler::new(global),
        }
    }

    fn charge(&mut self, now: Instant, len: usize) -> Charge {
        if cfg!(feature = "mutant-si23-no-datagram-budget") {
            return Charge::Pass;
        }
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        let flood = self.abuse_datagrams.exceeded(now, 1);
        let flood = self.abuse_bytes.exceeded(now, len) || flood;
        if flood {
            return Charge::Abuse;
        }
        if self.datagrams.ready(now, 1) && self.bytes.ready(now, len) {
            self.datagrams.charge(now, 1);
            self.bytes.charge(now, len);
            Charge::Pass
        } else {
            Charge::Drop
        }
    }
}

/// An admitted connection, handed out with its control stream as a separate
/// value so datagrams and control run on their own tasks (§2.5). Everything it
/// yields carries `peer()`'s generation;
/// on the host, once that generation is no longer current the link stops
/// delivering and closes at its next touch (SI-18).
pub struct Link {
    conn: Connection,
    peer: PeerRef,
    side: Side,
    rx: Mutex<Rx>,
    blobs: Mutex<Bucket>,
    next_frag: AtomicU16,
    counters: Counters,
}

impl Link {
    /// Guest: opens the control stream. The host sees it once the guest sends
    /// its first control message.
    pub(crate) async fn dial(
        conn: Connection,
        peer: PeerRef,
        frags: Arc<GlobalBudget>,
    ) -> Result<(Link, CtlStream), NetError> {
        let (send, recv) = conn.open_bi().await.map_err(|_| NetError::Closed)?;
        Ok(Link::new(conn, peer, Side::Guest, (send, recv), frags))
    }

    /// Host: waits for the guest's control stream; the caller bounds the wait.
    pub(crate) async fn accept(
        conn: Connection,
        session_key: EndpointId,
        peer: PeerRef,
        shared: Arc<Shared>,
    ) -> Result<(Link, CtlStream), NetError> {
        let (send, recv) = conn.accept_bi().await.map_err(|_| NetError::Closed)?;
        let frags = Arc::clone(&shared.frags);
        let side = Side::Host {
            shared,
            session_key,
        };
        let (link, ctl) = Link::new(conn, peer, side, (send, recv), frags);
        if !cfg!(feature = "mutant-si18-link-accept-unchecked") && !link.current() {
            link.conn.close(close::STALE, b"");
            return Err(NetError::Closed);
        }
        Ok((link, ctl))
    }

    fn new(
        conn: Connection,
        peer: PeerRef,
        side: Side,
        (send, recv): (SendStream, RecvStream),
        frags: Arc<GlobalBudget>,
    ) -> (Link, CtlStream) {
        let now = Instant::now();
        let ctl = CtlStream::new(conn.clone(), send, recv);
        let link = Link {
            conn,
            peer,
            side,
            rx: Mutex::new(Rx::new(now, frags)),
            blobs: Mutex::new(Bucket::new(now, BLOB_OPEN_RATE, BLOB_OPEN_RATE)),
            next_frag: AtomicU16::new(0),
            counters: Counters::default(),
        };
        (link, ctl)
    }

    /// On the host: the persistent identity, slot and generation the admission
    /// owner published for this session key. On a guest: the host's session
    /// key, `PeerSlot::HOST` and the generation of the guest's pass.
    pub fn peer(&self) -> PeerRef {
        self.peer
    }

    /// The re-check on every datagram and stream the link touches (SI-18).
    fn still_current(&self) -> bool {
        cfg!(feature = "mutant-si18-no-datagram-gen-check") || self.current()
    }

    fn current(&self) -> bool {
        match &self.side {
            Side::Host {
                shared,
                session_key,
            } => shared.is_current(session_key, &self.peer),
            Side::Guest => true,
        }
    }

    /// Fragments into at most `MAX_FRAGMENTS` QUIC datagrams at the path's
    /// current `max_datagram_size`; drop-oldest. Never blocks.
    pub fn send_lan(&self, datagram: &LanDatagram) {
        let Some(max) = self
            .conn
            .max_datagram_size()
            .filter(|_| self.still_current())
        else {
            bump(&self.counters.dropped_send);
            return;
        };
        let frag_id = self.next_frag.fetch_add(1, Ordering::Relaxed);
        let sent = encode_datagram(datagram, frag_id, max)
            .ok()
            .is_some_and(|parts| self.conn.send_many_datagrams(&parts).is_ok());
        bump(if sent {
            &self.counters.sent
        } else {
            &self.counters.dropped_send
        });
    }

    /// The datagram budget is charged on every received datagram before it is
    /// decoded or reassembled (§6.3). A peer far above its budget is
    /// disconnected with `OverBudget`.
    pub async fn recv_lan(&self) -> Result<LanDatagram, NetError> {
        loop {
            let deadline = lock(&self.rx).frags.next_deadline();
            let datagram = match deadline {
                Some(at) => tokio::select! {
                    d = self.conn.read_datagram() => d,
                    () = tokio::time::sleep_until(at.into()) => {
                        lock(&self.rx).frags.expire(Instant::now());
                        continue;
                    }
                },
                None => self.conn.read_datagram().await,
            }
            .map_err(|_| NetError::Closed)?;
            if !self.still_current() {
                self.conn.close(close::STALE, b"");
                return Err(NetError::Closed);
            }
            let now = Instant::now();
            match lock(&self.rx).charge(now, datagram.len()) {
                Charge::Pass => {}
                Charge::Drop => {
                    bump(&self.counters.dropped_budget);
                    continue;
                }
                Charge::Abuse => {
                    self.conn.close(close::OVER_BUDGET, b"");
                    return Err(NetError::OverBudget);
                }
            }
            let (header, fragment, chunk) = match decode_datagram(self.peer.slot, datagram) {
                Ok(Inbound::Lan(lan)) => {
                    bump(&self.counters.received);
                    return Ok(lan);
                }
                Ok(Inbound::Fragment {
                    header,
                    fragment,
                    chunk,
                }) => (header, fragment, chunk),
                Err(_) => {
                    bump(&self.counters.dropped_malformed);
                    continue;
                }
            };
            match lock(&self.rx).frags.accept(now, header, fragment, chunk) {
                Outcome::Complete(header, payload) => {
                    bump(&self.counters.received);
                    return Ok(LanDatagram {
                        peer: self.peer.slot,
                        bcast: header.bcast,
                        src_port: header.src_port,
                        dst_port: header.dst_port,
                        payload,
                    });
                }
                Outcome::Pending => {}
                Outcome::Conflict | Outcome::Full => bump(&self.counters.dropped_reassembly),
            }
        }
    }

    /// Guest: a new bidi stream to the host (map bytes, §5.2). The host allows
    /// four open streams including control.
    pub async fn open_blob(&self) -> Result<(SendStream, RecvStream), NetError> {
        if !matches!(self.side, Side::Guest) {
            return Err(NetError::WrongRole);
        }
        tokio::time::timeout(CONNECT_DEADLINE, self.conn.open_bi())
            .await
            .map_err(|_| NetError::Closed)?
            .map_err(|_| NetError::Closed)
    }

    /// Host: the next blob stream the guest opened. Streams beyond the open
    /// rate are stopped and reset unread.
    pub async fn accept_blob(&self) -> Result<(SendStream, RecvStream), NetError> {
        if matches!(self.side, Side::Guest) {
            return Err(NetError::WrongRole);
        }
        loop {
            let (mut send, mut recv) = self.conn.accept_bi().await.map_err(|_| NetError::Closed)?;
            if !self.still_current() {
                self.conn.close(close::STALE, b"");
                return Err(NetError::Closed);
            }
            if lock(&self.blobs).charge(Instant::now(), 1) {
                return Ok((send, recv));
            }
            let _ = recv.stop(close::OVER_BUDGET);
            let _ = send.reset(close::OVER_BUDGET);
        }
    }

    /// The largest QUIC datagram the path takes now; LAN datagrams up to four
    /// times this (less headers) are fragmented, larger ones dropped.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// Whether the selected path is direct or through a relay, right now.
    pub fn path(&self) -> PathStatus {
        let paths = self.conn.paths();
        let selected = paths.iter().find(|p| p.is_selected());
        match selected {
            Some(p) if p.is_ip() => PathStatus::Direct,
            Some(p) if p.is_relay() => PathStatus::Relay,
            _ => PathStatus::Unknown,
        }
    }

    pub fn health(&self) -> LinkHealth {
        let c = &self.counters;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        LinkHealth {
            sent: get(&c.sent),
            received: get(&c.received),
            dropped_send: get(&c.dropped_send),
            dropped_budget: get(&c.dropped_budget),
            dropped_malformed: get(&c.dropped_malformed),
            dropped_reassembly: get(&c.dropped_reassembly),
        }
    }

    /// Resolves when the connection is closed, by either side.
    pub async fn closed(&self) {
        let _ = self.conn.closed().await;
    }

    pub fn close(&self) {
        self.conn.close(close::DONE, b"");
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The link's one control stream, opened by the guest. `u32` length prefix,
/// each message at most `M::MAX_LEN`, budgeted per §6.3. Both directions are
/// cancel-safe: a dropped `send` or `recv` future leaves its partial frame here
/// and the next call finishes it, so frames never interleave or desync.
pub struct CtlStream {
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    unsent: Option<(kickoff_secret::SecretBuffer, usize)>,
    prefix: [u8; LEN_PREFIX_LEN],
    prefix_have: usize,
    body: Option<(kickoff_secret::SecretBuffer, usize)>,
    msgs: Bucket,
    bytes: Bucket,
    pub(crate) hello_deadline: Option<tokio::time::Instant>,
}

impl CtlStream {
    fn new(conn: Connection, send: SendStream, recv: RecvStream) -> CtlStream {
        let now = Instant::now();
        CtlStream {
            conn,
            send,
            recv,
            unsent: None,
            prefix: [0; LEN_PREFIX_LEN],
            prefix_have: 0,
            body: None,
            msgs: Bucket::new(now, CTL_MSG_RATE, CTL_MSG_RATE),
            bytes: Bucket::new(now, CTL_BYTE_RATE, CTL_BYTE_RATE),
            hello_deadline: None,
        }
    }

    /// Host-side absolute Hello deadline captured by the admission hook at TLS completion.
    pub fn hello_deadline(&self) -> Option<tokio::time::Instant> {
        self.hello_deadline
    }

    pub async fn send<M: PublicWireMessage>(&mut self, msg: &M) -> Result<(), NetError> {
        self.flush().await?;
        self.unsent = Some((encode_framed(msg).map_err(wire)?, 0));
        self.flush().await
    }

    async fn flush(&mut self) -> Result<(), NetError> {
        while let Some((frame, done)) = &mut self.unsent {
            let Some(rest) = frame.get(*done..).filter(|r| !r.is_empty()) else {
                self.unsent = None;
                break;
            };
            let n = self.send.write(rest).await.map_err(|_| NetError::Closed)?;
            *done = done.saturating_add(n);
        }
        Ok(())
    }

    /// Reads the next message. Its length is checked against `M::MAX_LEN`, and
    /// the message and byte budget charged, before the body is allocated; a
    /// sender over budget is throttled and QUIC flow control pushes back. A
    /// message from a newer protocol closes the link with `VERSION` (§4.5).
    pub async fn recv<M: WireMessage>(&mut self) -> Result<M, NetError> {
        while self.body.is_none() {
            if self.prefix_have < LEN_PREFIX_LEN {
                let buf = self
                    .prefix
                    .get_mut(self.prefix_have..)
                    .ok_or(NetError::Protocol)?;
                let n = self.recv.read(buf).await.map_err(|_| NetError::Closed)?;
                let n = n.ok_or(NetError::Closed)?;
                self.prefix_have = self.prefix_have.saturating_add(n);
                continue;
            }
            let len = if cfg!(feature = "mutant-si23-ctl-length-unchecked") {
                usize::try_from(u32::from_be_bytes(self.prefix)).unwrap_or(0)
            } else {
                frame_len::<M>(self.prefix).map_err(wire)?
            };
            self.wait_for_budget(len).await;
            self.body = Some((kickoff_secret::SecretBuffer::zeroed(len), 0));
        }
        while let Some((body, have)) = &mut self.body {
            let Some(buf) = body.get_mut(*have..).filter(|b| !b.is_empty()) else {
                break;
            };
            let n = self.recv.read(buf).await.map_err(|_| NetError::Closed)?;
            *have = have.saturating_add(n.ok_or(NetError::Closed)?);
        }
        let (body, _) = self.body.take().ok_or(NetError::Protocol)?;
        self.prefix_have = 0;
        let msg = decode(&body).map_err(wire);
        if msg.as_ref().err() == Some(&NetError::Version) {
            self.conn.close(close::VERSION, b"");
        }
        msg
    }

    async fn wait_for_budget(&mut self, len: usize) {
        let len = u64::try_from(len).unwrap_or(u64::MAX).min(CTL_BYTE_RATE);
        if cfg!(feature = "mutant-si23-no-ctl-rate") {
            return;
        }
        loop {
            let now = Instant::now();
            if self.msgs.ready(now, 1) && self.bytes.ready(now, len) {
                self.msgs.charge(now, 1);
                self.bytes.charge(now, len);
                return;
            }
            tokio::time::sleep(CTL_BACKOFF).await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    #[test]
    fn si_23_datagram_budget_drops_then_disconnects_a_flooding_peer() {
        let t = Instant::now();
        let mut rx = Rx::new(t, Arc::default());
        let burst = (0..DATAGRAM_BURST).filter(|_| matches!(rx.charge(t, 100), Charge::Pass));
        assert_eq!(burst.count() as u64, DATAGRAM_BURST);
        assert!(
            matches!(rx.charge(t, 100), Charge::Drop),
            "over the burst, at the same instant"
        );

        let mut rx = Rx::new(t, Arc::default());
        let allowance = DATAGRAM_RATE * ABUSE_FACTOR * ABUSE_SECS;
        let mut verdicts = (0..=allowance).map(|i| {
            let now = t + Duration::from_nanos(i * 1_000_000_000 / (DATAGRAM_RATE * 12));
            rx.charge(now, 100)
        });
        let passed_before_abuse = verdicts
            .by_ref()
            .take(allowance as usize)
            .filter(|c| matches!(c, Charge::Pass))
            .count() as u64;
        assert!(
            matches!(verdicts.next(), Some(Charge::Abuse)),
            "above ten times the rate for 5 s disconnects"
        );
        let ceiling = DATAGRAM_BURST + DATAGRAM_RATE * ABUSE_SECS + 1;
        assert!(
            passed_before_abuse <= ceiling,
            "{passed_before_abuse} passed, budget allows {ceiling}"
        );
    }

    #[test]
    fn datagram_byte_budget_is_charged_with_the_count() {
        let t = Instant::now();
        let mut rx = Rx::new(t, Arc::default());
        let big = 1999;
        let fits = (BYTE_BURST / big as u64) as usize;
        assert!((0..fits).all(|_| matches!(rx.charge(t, big), Charge::Pass)));
        assert!(matches!(rx.charge(t, big), Charge::Drop));
        assert!(
            matches!(rx.charge(t, 1), Charge::Pass),
            "a refused charge took nothing"
        );
    }
}

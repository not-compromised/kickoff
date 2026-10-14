//! The send guard (§3.4, R2-10): the policy the vendored iroh hook applies to
//! every IP packet, so destinations iroh chooses itself (NAT-traversal probes
//! to candidates a peer announces, path migration, QAD) obey the same rules as
//! dials.
//!
//! A destination is one of:
//! - **validated**: the remote end of an open IP path of a live connection;
//! - **answered**: the source of an `Incoming` this endpoint chose to reply to
//!   (retry, refusal, handshake), for a short while;
//! - **unvalidated**: anything else, admitted only within the probe budget.
//!
//! Every destination passes `View::allows` first. Known destinations cost one
//! hash lookup per packet; refused packets are dropped and counted.
//!
//! The patched transport preserves a stable connection context across sends
//! and rebinds. Probe budgets belong to remote identities; approved paths
//! belong to connection contexts, even when peers share one destination.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use iroh::TransportAddr;
use iroh::endpoint::{Connection, WeakConnectionHandle};

use super::{IfaceAddr, is_forbidden, is_global};
use crate::budget::Bucket;

/// Destinations sent to but not yet validated, at once (§6.3).
pub(crate) const MAX_UNVALIDATED: usize = 8;
/// New unvalidated destinations per second (§6.3).
const NEW_PER_SEC: u64 = 4;
/// An unvalidated destination is forgotten after this, so it must pass the
/// budget again; path validation takes a few round trips.
const UNVALIDATED_TTL: Duration = Duration::from_secs(10);
/// Incoming sources this endpoint may answer at once, and for how long. When
/// full, the oldest is forgotten.
const MAX_ANSWERED: usize = 64;
const ANSWER_TTL: Duration = Duration::from_secs(10);
/// Connections whose paths count as validated.
const MAX_TRACKED: usize = 256;
const TRUSTED_RESERVED: usize = 16;
const PROBE_RESERVED: usize = 16;

/// The policy's inputs that change with the host's interfaces and routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct View {
    bind: IfaceAddr,
    /// Every address on every interface, plus the public address QAD saw.
    own: Vec<Ipv4Addr>,
    gateways: Vec<Ipv4Addr>,
    resolvers: Vec<Ipv4Addr>,
}

impl View {
    pub(crate) fn new(
        bind: IfaceAddr,
        own: Vec<Ipv4Addr>,
        gateways: Vec<Ipv4Addr>,
        resolvers: Vec<Ipv4Addr>,
    ) -> View {
        View {
            bind,
            own,
            gateways,
            resolvers,
        }
    }

    /// The host as it is now. A loopback bind is the in-process adapter: it
    /// reaches only this host, so its own addresses are not enumerated (they
    /// would include every peer it exists to reach).
    pub(crate) async fn current(bind: IfaceAddr, public: &[Ipv4Addr]) -> View {
        let resolvers = resolvers();
        if bind.ip().is_loopback() {
            return View::new(bind, Vec::new(), Vec::new(), resolvers);
        }
        let state = netwatch::interfaces::State::new().await;
        let mut own: Vec<Ipv4Addr> = state
            .interfaces
            .values()
            .flat_map(|iface| iface.addrs())
            .filter_map(|net| match net {
                netwatch::interfaces::IpNet::V4(v4) => Some(v4.addr()),
                netwatch::interfaces::IpNet::V6 { .. } => None,
            })
            .chain([bind.ip()])
            .chain(public.iter().copied())
            .collect();
        own.sort_unstable();
        own.dedup();
        let gateways = netwatch::interfaces::HomeRouter::new()
            .and_then(|router| match router.gateway {
                std::net::IpAddr::V4(v4) => Some(v4),
                std::net::IpAddr::V6(_) => None,
            })
            .into_iter()
            .collect();
        View::new(bind, own, gateways, resolvers)
    }

    pub(crate) fn bind(&self) -> IfaceAddr {
        self.bind
    }

    /// The stateless half of the policy (§3.4).
    fn allows(&self, dst: SocketAddr) -> bool {
        let SocketAddr::V4(v4) = dst else {
            return false;
        };
        let (ip, port) = (*v4.ip(), v4.port());
        let range = cfg!(feature = "mutant-si29-guard-any-range") || self.in_scope(ip);
        let host = cfg!(feature = "mutant-si29-guard-ignores-host-view")
            || !(self.own.contains(&ip)
                || self.gateways.contains(&ip)
                || self.resolvers.contains(&ip));
        let port = cfg!(feature = "mutant-si29-guard-any-port")
            || kickoff_wire::transport_port_allowed(port);
        range && host && port
    }

    /// Global unicast or on the bound interface's subnet (loopback only for a
    /// loopback bind), and never a range §3.4 forbids or the subnet's own
    /// network or broadcast address.
    fn in_scope(&self, ip: Ipv4Addr) -> bool {
        if is_forbidden(ip) {
            return false;
        }
        if self.bind.ip().is_loopback() {
            return ip.is_loopback();
        }
        if ip.is_loopback() || self.bind.is_subnet_edge(ip) {
            return false;
        }
        is_global(ip) || self.bind.contains(ip)
    }
}

/// Nameservers from the system resolver configuration (Linux). Read at most
/// `RESOLV_MAX` bytes of each file; a missing file contributes nothing.
fn resolvers() -> Vec<Ipv4Addr> {
    const FILES: [&str; 2] = ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"];
    const RESOLV_MAX: u64 = 64 * 1024;
    let mut found = Vec::new();
    for path in FILES {
        let Ok(file) = std::fs::File::open(path) else {
            continue;
        };
        let mut text = String::new();
        if std::io::Read::read_to_string(&mut std::io::Read::take(file, RESOLV_MAX), &mut text)
            .is_err()
        {
            continue;
        }
        found.extend(text.lines().filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver"))
                .then(|| words.next()?.parse::<Ipv4Addr>().ok())
                .flatten()
        }));
    }
    found.sort_unstable();
    found.dedup();
    found
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Known {
    Validated,
    Unvalidated { until: Instant },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Owner {
    Remote([u8; 32]),
    Probe(u64),
}

#[derive(Debug)]
struct RemoteBudget {
    trusted: bool,
    touched: Instant,
    known: HashMap<SocketAddr, Instant>,
    new: Bucket,
}

#[derive(Debug)]
struct ContextState {
    trusted: bool,
    owner: Owner,
    original_probe: Option<SocketAddr>,
    known: HashMap<SocketAddr, Known>,
}

#[derive(Debug)]
struct State {
    view: View,
    approved: HashSet<(u64, SocketAddr)>,
    contexts: HashMap<u64, ContextState>,
    remotes: HashMap<Owner, RemoteBudget>,
    answered: HashMap<SocketAddr, Instant>,
}

impl State {
    fn associate(
        &mut self,
        context: u64,
        owner: Owner,
        probe: Option<SocketAddr>,
        trusted: bool,
        now: Instant,
    ) {
        if context == 0 {
            return;
        }
        if let Some(ctx) = self.contexts.get_mut(&context) {
            if trusted && ctx.owner == owner {
                ctx.trusted = true;
                if let Some(remote) = self.remotes.get_mut(&owner) {
                    remote.trusted = true;
                }
            }
            return;
        }
        self.remotes.retain(|owner, budget| {
            self.contexts.values().any(|ctx| ctx.owner == *owner)
                || now.saturating_duration_since(budget.touched) < UNVALIDATED_TTL
        });
        let trusted = trusted && !cfg!(feature = "mutant-si23-guard-no-trusted-slots");
        let probe_owner = matches!(owner, Owner::Probe(_));
        let capacity = if probe_owner {
            PROBE_RESERVED
        } else if trusted {
            TRUSTED_RESERVED
        } else {
            MAX_TRACKED
        };
        let contexts = self
            .contexts
            .values()
            .filter(|ctx| {
                ctx.trusted == trusted && matches!(ctx.owner, Owner::Probe(_)) == probe_owner
            })
            .count();
        let remotes = self
            .remotes
            .iter()
            .filter(|(key, remote)| {
                remote.trusted == trusted && matches!(key, Owner::Probe(_)) == probe_owner
            })
            .count();
        if contexts >= capacity || (!self.remotes.contains_key(&owner) && remotes >= capacity) {
            return;
        }
        self.remotes
            .entry(owner)
            .and_modify(|budget| budget.trusted |= trusted)
            .or_insert_with(|| RemoteBudget {
                trusted,
                touched: now,
                known: HashMap::new(),
                new: Bucket::new(now, NEW_PER_SEC, NEW_PER_SEC),
            });
        self.contexts.insert(
            context,
            ContextState {
                trusted,
                owner,
                original_probe: probe,
                known: HashMap::new(),
            },
        );
    }
}

#[derive(Debug)]
pub(crate) struct SendGuard {
    state: Mutex<State>,
    conns: Mutex<HashMap<u64, WeakConnectionHandle>>,
    denied: AtomicU64,
    #[cfg(test)]
    track_schedule: Mutex<Option<TrackSchedule>>,
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct TrackSchedule {
    context: u64,
    snapshot_ready: std::sync::mpsc::SyncSender<()>,
    packet_held: std::sync::Arc<std::sync::Barrier>,
    state_held: std::sync::Arc<std::sync::Barrier>,
}

#[cfg(test)]
struct TrackScheduleReset<'a>(&'a Mutex<Option<TrackSchedule>>);

#[cfg(test)]
impl Drop for TrackScheduleReset<'_> {
    fn drop(&mut self) {
        let _ = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
    }
}

impl SendGuard {
    pub(crate) fn new(view: View) -> SendGuard {
        SendGuard {
            state: Mutex::new(State {
                view,
                approved: HashSet::new(),
                contexts: HashMap::new(),
                remotes: HashMap::new(),
                answered: HashMap::new(),
            }),
            conns: Mutex::new(HashMap::new()),
            denied: AtomicU64::new(0),
            #[cfg(test)]
            track_schedule: Mutex::new(None),
        }
    }

    /// Schedule one context against an actual transport admission, never a
    /// process-global hook that could pause unrelated endpoints.
    #[cfg(test)]
    pub(crate) fn schedule_track(
        &self,
        context: u64,
        snapshot_ready: std::sync::mpsc::SyncSender<()>,
        packet_held: std::sync::Arc<std::sync::Barrier>,
        state_held: std::sync::Arc<std::sync::Barrier>,
    ) -> impl Drop + use<'_> {
        let mut schedule = self
            .track_schedule
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert!(schedule.is_none());
        *schedule = Some(TrackSchedule {
            context,
            snapshot_ready,
            packet_held,
            state_held,
        });
        TrackScheduleReset(&self.track_schedule)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One packet to `dst`. `now` is read only when the destination is not
    /// already validated.
    pub(crate) fn decide(
        &self,
        context: u64,
        dst: SocketAddr,
        now: impl FnOnce() -> Instant,
    ) -> bool {
        let mut state = self.state();
        if state.approved.contains(&(context, dst)) {
            return true;
        }
        let now = now();
        if !state.view.allows(dst) {
            self.denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let Some(ctx) = state.contexts.get_mut(&context) else {
            let allowed = state.answered.get(&dst).is_some_and(|until| now < *until);
            if !allowed {
                self.denied.fetch_add(1, Ordering::Relaxed);
            }
            return allowed;
        };
        if !ctx.trusted && state.answered.get(&dst).is_some_and(|until| now < *until) {
            return true;
        }
        let Some(ctx) = state.contexts.get_mut(&context) else {
            return false;
        };
        let owner = ctx.owner;
        let probe_allowed = ctx.original_probe.is_none_or(|original| original == dst);
        if !probe_allowed {
            self.denied.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if ctx
            .known
            .get(&dst)
            .is_some_and(|k| matches!(k, Known::Unvalidated { until } if now < *until))
        {
            return true;
        }
        let validated_elsewhere = state
            .contexts
            .values()
            .any(|ctx| ctx.owner == owner && ctx.known.get(&dst) == Some(&Known::Validated));
        let Some(budget) = state.remotes.get_mut(&owner) else {
            return false;
        };
        budget.touched = now;
        budget.known.retain(|_, until| now < *until);
        let already_probing = budget.known.get(&dst).is_some_and(|until| now < *until);
        let allowed = validated_elsewhere
            || already_probing
            || cfg!(feature = "mutant-si29-guard-no-destination-cap")
            || (budget.known.len() < MAX_UNVALIDATED && budget.new.charge(now, 1));
        if allowed {
            let until = now.checked_add(UNVALIDATED_TTL).unwrap_or(now);
            if !validated_elsewhere {
                budget.known.insert(dst, until);
            }
            if let Some(ctx) = state.contexts.get_mut(&context) {
                ctx.known.retain(|_, k| {
                    *k == Known::Validated
                        || matches!(k, Known::Unvalidated { until } if now < *until)
                });
                if ctx.known.len() < MAX_UNVALIDATED.saturating_add(MAX_UNVALIDATED) {
                    ctx.known.insert(dst, Known::Unvalidated { until });
                }
            }
        } else {
            self.denied.fetch_add(1, Ordering::Relaxed);
        }
        allowed
    }

    pub(crate) fn answer(&self, src: SocketAddr, now: Instant) {
        let mut state = self.state();
        if !state.view.allows(src) {
            return;
        }
        state.answered.retain(|_, until| now < *until);
        if !state.answered.contains_key(&src)
            && state.answered.len() >= MAX_ANSWERED
            && let Some(oldest) = state
                .answered
                .iter()
                .min_by_key(|(_, until)| *until)
                .map(|(addr, _)| *addr)
        {
            state.answered.remove(&oldest);
        }
        state
            .answered
            .insert(src, now.checked_add(ANSWER_TTL).unwrap_or(now));
    }

    /// Counts `conn`'s IP paths as validated from the next `rescan` on.
    pub(crate) fn track(&self, conn: &Connection) {
        // Noq holds its mutex while invoking the guard. Snapshot connections
        // before taking any guard lock, including the tracked-handle lock.
        let context = conn.send_context();
        let owner = Owner::Remote(*conn.remote_id().as_bytes());
        let weak = conn.weak_handle();
        #[cfg(test)]
        let schedule = self
            .track_schedule
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|schedule| schedule.context == context)
            .cloned();
        #[cfg(test)]
        if let Some(schedule) = &schedule {
            assert!(schedule.snapshot_ready.send(()).is_ok());
            schedule.packet_held.wait();
        }
        {
            let mut state = self.state();
            #[cfg(test)]
            if let Some(schedule) = &schedule {
                schedule.state_held.wait();
            }
            if cfg!(feature = "mutant-si23-guard-locks-before-connection") {
                state.associate(conn.send_context(), owner, None, true, Instant::now());
            } else {
                state.associate(context, owner, None, true, Instant::now());
            }
        }
        let full = self
            .conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
            >= MAX_TRACKED;
        if full {
            self.rescan();
        }
        let mut conns = self.conns.lock().unwrap_or_else(PoisonError::into_inner);
        if conns.len() < MAX_TRACKED {
            conns.insert(context, weak);
        }
    }

    /// Validated destinations are exactly the open IP paths of live tracked
    /// connections. Concurrently added handles wait for the next snapshot.
    pub(crate) fn rescan(&self) {
        let snapshot = self
            .conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut dead = Vec::new();
        let mut paths = Vec::new();
        for (context, weak) in snapshot {
            let Some(conn) = weak.upgrade().filter(|c| c.close_reason().is_none()) else {
                dead.push(context);
                continue;
            };
            paths.extend(conn.paths().iter().filter_map(|p| match p.remote_addr() {
                TransportAddr::Ip(sock) => Some((context, *sock)),
                _ => None,
            }));
        }
        self.conns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|context, _| !dead.contains(context));
        self.set_validated(paths);
    }

    fn set_validated(&self, paths: Vec<(u64, SocketAddr)>) {
        let mut state = self.state();
        for (context, ctx) in &mut state.contexts {
            ctx.known
                .retain(|addr, k| *k != Known::Validated || paths.contains(&(*context, *addr)));
        }
        state.approved.clear();
        for (context, addr) in paths {
            let addr = SocketAddr::new(addr.ip().to_canonical(), addr.port());
            if !state.view.allows(addr) {
                continue;
            }
            let Some(ctx) = state.contexts.get_mut(&context) else {
                continue;
            };
            if ctx.known.len() >= MAX_UNVALIDATED.saturating_add(MAX_UNVALIDATED)
                && !ctx.known.contains_key(&addr)
            {
                continue;
            }
            let owner = ctx.owner;
            ctx.known.insert(addr, Known::Validated);
            state.approved.insert((context, addr));
            if let Some(remote) = state.remotes.get_mut(&owner) {
                remote.known.remove(&addr);
            }
        }
    }

    /// The host's interfaces or routes changed: the new view applies to every
    /// destination, including approved ones, so the cache starts empty.
    /// Returns whether anything changed.
    pub(crate) fn refresh(&self, view: View) -> bool {
        let mut state = self.state();
        if state.view == view {
            return false;
        }
        state.view = view;
        if !cfg!(feature = "mutant-si29-guard-keeps-cache") {
            state.approved.clear();
            for ctx in state.contexts.values_mut() {
                ctx.known.clear();
            }
            for remote in state.remotes.values_mut() {
                remote.known.clear();
            }
            state.answered.clear();
        }
        true
    }

    pub(crate) fn view(&self) -> View {
        self.state().view.clone()
    }

    /// Packets refused so far.
    pub(crate) fn denied(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }
}

impl kickoff_send_guard::Guard for SendGuard {
    fn admit(&self, context: u64, dst: SocketAddr) -> bool {
        self.decide(context, dst, Instant::now)
    }
    fn associate(&self, context: u64, remote: [u8; 32]) {
        let owner = if cfg!(feature = "mutant-si29-shared-remote-budget") {
            Owner::Remote([0; 32])
        } else {
            Owner::Remote(remote)
        };
        self.state()
            .associate(context, owner, None, false, Instant::now());
    }
    fn expect(&self, context: u64, remote: [u8; 32]) {
        self.state()
            .associate(context, Owner::Remote(remote), None, true, Instant::now());
    }
    fn probe(&self, context: u64, dst: SocketAddr) {
        self.state().associate(
            context,
            Owner::Probe(context),
            if cfg!(feature = "mutant-si29-probe-any-destination") {
                None
            } else {
                Some(dst)
            },
            true,
            Instant::now(),
        );
    }
    fn forget(&self, context: u64) {
        let mut state = self.state();
        state.contexts.remove(&context);
        state.approved.retain(|(owner, _)| *owner != context);
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A LAN host at 192.168.1.20/24 whose router is also its resolver, with
    /// a Tailscale address, a container bridge and a public address from QAD.
    fn lan_view() -> View {
        View::new(
            IfaceAddr::lan(ip("192.168.1.20"), 24).unwrap(),
            [
                "192.168.1.20",
                "100.101.102.103",
                "172.17.0.1",
                "203.0.120.7",
            ]
            .map(ip)
            .to_vec(),
            vec![ip("192.168.1.1")],
            vec![ip("192.168.1.1"), ip("192.168.1.53")],
        )
    }

    fn guard() -> SendGuard {
        let guard = SendGuard::new(lan_view());
        kickoff_send_guard::Guard::associate(&guard, 1, [1; 32]);
        guard
    }

    /// One packet to `dst` at time `t`.
    fn admits(guard: &SendGuard, dst: SocketAddr, t: Instant) -> bool {
        guard.decide(1, dst, || t)
    }

    #[test]
    fn si_29_send_guard_refuses_own_gateway_and_resolver_addresses() {
        let g = guard();
        let mut t = Instant::now();
        for hostile in [
            "192.168.1.20:40000", // our own bound address, another port
            "192.168.1.1:40000",  // gateway and resolver
            "192.168.1.53:40000", // resolver
            "203.0.120.7:40000",  // our public address as QAD saw it
        ] {
            t += Duration::from_secs(1);
            assert!(!admits(&g, sock(hostile), t), "sent to {hostile}");
        }
        t += Duration::from_secs(1);
        assert!(admits(&g, sock("192.168.1.30:40000"), t), "a LAN peer");
        assert!(admits(&g, sock("203.0.114.9:40000"), t), "a public peer");
        assert_eq!(g.denied(), 4);
    }

    #[test]
    fn si_29_send_guard_refuses_low_and_denylisted_ports() {
        let g = guard();
        let mut t = Instant::now();
        for port in [
            0, 22, 53, 80, 443, 1023, 1900, 5353, 9002, 47990, 49124, 53317,
        ] {
            t += Duration::from_secs(1);
            let dst = SocketAddr::from((ip("203.0.114.9"), port));
            assert!(!admits(&g, dst, t), "sent to port {port}");
        }
        t += Duration::from_secs(1);
        assert!(admits(&g, sock("203.0.114.9:1024"), t));
        assert!(admits(&g, sock("203.0.114.9:7777"), t));
    }

    #[test]
    fn si_29_send_guard_refuses_forbidden_ranges() {
        let g = guard();
        let mut t = Instant::now();
        for hostile in [
            "127.0.0.1:40000",       // loopback
            "169.254.169.254:40000", // link-local, cloud metadata
            "100.64.0.9:40000",      // CGNAT and Tailscale
            "10.75.0.2:40000",       // the Kickoff subnet
            "224.0.0.251:40000",     // multicast
            "255.255.255.255:40000", // broadcast
            "192.168.1.255:40000",   // the bound subnet's broadcast
            "192.168.1.0:40000",     // and its network address
            "192.168.2.30:40000",    // a private subnet we are not on
            "172.17.0.2:40000",      // a container bridge
            "0.0.0.0:40000",
            "[2001:db8::1]:40000", // IPv6: the session binds IPv4 only
        ] {
            t += Duration::from_secs(1);
            assert!(!admits(&g, sock(hostile), t), "sent to {hostile}");
        }
        assert!(admits(&g, sock("192.168.1.30:40000"), t));
    }

    #[test]
    fn si_23_guard_preserves_slots_for_expected_or_admitted_peers() {
        let g = guard();
        let t = Instant::now();
        for n in 1..=MAX_TRACKED {
            let mut remote = [0; 32];
            remote[..8].copy_from_slice(&(n as u64).to_le_bytes());
            kickoff_send_guard::Guard::associate(&g, n as u64, remote);
            for port in 40000..40004 {
                assert!(g.decide(n as u64, SocketAddr::from((ip("203.0.114.9"), port)), || t));
            }
        }
        assert_eq!(g.state().contexts.len(), MAX_TRACKED);
        kickoff_send_guard::Guard::expect(&g, u64::MAX, [254; 32]);
        assert!(
            g.decide(u64::MAX, sock("203.0.114.8:40000"), || t),
            "invalid identities spent a locally expected peer's slots"
        );
        let admitted_context = u64::MAX - 1;
        g.state()
            .associate(admitted_context, Owner::Remote([253; 32]), None, true, t);
        assert!(
            g.decide(admitted_context, sock("203.0.114.7:40000"), || t),
            "invalid identities spent an admitted peer's slots"
        );
    }

    #[test]
    fn si_29_qad_cannot_choose_another_destination() {
        let g = guard();
        let t = Instant::now();
        let relay = sock("203.0.114.9:7842");
        kickoff_send_guard::Guard::probe(&g, 99, relay);
        assert!(g.decide(99, relay, || t));
        assert!(!g.decide(99, sock("203.0.114.8:7842"), || t));
        assert!(!g.decide(99, sock("203.0.114.9:7843"), || t));
    }

    #[test]
    fn si_29_each_remote_keeps_its_probe_budget_and_cache() {
        let g = guard();
        kickoff_send_guard::Guard::associate(&g, 2, [2; 32]);
        kickoff_send_guard::Guard::associate(&g, 3, [1; 32]);
        let t = Instant::now();
        let peer = |n: u32| SocketAddr::from((Ipv4Addr::from(0xCB00_7200 + n), 40000));
        for n in 1..=4 {
            assert!(g.decide(1, peer(n), || t));
        }
        for n in 5..=8 {
            assert!(
                g.decide(2, peer(n), || t),
                "another peer lost its own budget"
            );
        }
        assert!(
            !g.decide(3, peer(9), || t),
            "two connections bypassed one remote's rate"
        );
        let later = t + Duration::from_secs(1);
        for n in 9..=12 {
            assert!(g.decide(1, peer(n), || later));
        }
        assert!(
            !g.decide(3, peer(13), || later),
            "two connections bypassed one remote's destination cap"
        );
        g.set_validated(vec![(1, peer(1))]);
        assert!(
            !g.decide(2, peer(1), || t),
            "one peer inherited another connection's approved cache"
        );
        assert!(g.decide(1, peer(1), || t));
        kickoff_send_guard::Guard::forget(&g, 2);
        kickoff_send_guard::Guard::associate(&g, 4, [2; 32]);
        assert!(
            !g.decide(4, peer(1), || t),
            "reconnecting reset the remote's rate budget"
        );
    }

    #[test]
    fn si_29_send_guard_caps_unvalidated_destinations() {
        let g = guard();
        let t = Instant::now();
        let peer = |n: u32| SocketAddr::from((Ipv4Addr::from(0xCB00_7200 + n), 40000));
        // Four new destinations per second.
        assert!((1..=4).all(|n| admits(&g, peer(n), t)));
        assert!(
            !admits(&g, peer(5), t),
            "a fifth new destination in one second"
        );
        assert!(admits(&g, peer(1), t), "known destinations keep passing");
        let t1 = t + Duration::from_secs(1);
        assert!((5..=8).all(|n| admits(&g, peer(n), t1)));
        // Eight unvalidated at once, whatever the rate allows.
        let t2 = t + Duration::from_secs(3);
        assert!(!admits(&g, peer(9), t2), "a ninth unvalidated destination");
        // Validation frees the slot.
        g.set_validated(vec![(1, peer(1)), (1, peer(2))]);
        assert!(admits(&g, peer(9), t2));
        assert!(admits(&g, peer(10), t2));
        assert!(!admits(&g, peer(11), t2));
        // So does expiry, after which an old destination must pass again.
        let later = t2 + UNVALIDATED_TTL;
        assert!((11..=14).all(|n| admits(&g, peer(n), later)));
        assert!(
            admits(&g, peer(1), later),
            "validated destinations do not expire"
        );
    }

    #[test]
    fn si_29_send_guard_recomputes_on_interface_change() {
        let g = guard();
        let t = Instant::now();
        let peer = sock("192.168.1.30:40000");
        let public = sock("203.0.114.9:40000");
        assert!(admits(&g, peer, t));
        assert!(admits(&g, public, t));
        g.set_validated(vec![(1, peer)]);

        // Moved to another network: the old LAN peer is now off-subnet, and
        // the public peer's address is now our own router.
        let moved = View::new(
            IfaceAddr::lan(ip("10.1.0.5"), 16).unwrap(),
            vec![ip("10.1.0.5")],
            vec![ip("203.0.114.9")],
            Vec::new(),
        );
        assert!(g.refresh(moved.clone()));
        let t1 = t + Duration::from_secs(1);
        assert!(
            !admits(&g, peer, t1),
            "a validated destination outlived the change"
        );
        assert!(
            !admits(&g, public, t1),
            "an approved destination became the gateway"
        );
        assert!(admits(&g, sock("10.1.3.4:40000"), t1));
        assert!(!g.refresh(moved), "an unchanged view keeps the cache");
    }

    #[test]
    fn answered_sources_do_not_spend_the_destination_budget() {
        let g = guard();
        let t = Instant::now();
        for n in 0..(MAX_ANSWERED as u32 + 10) {
            let src = SocketAddr::from((Ipv4Addr::from(0xCB00_7300 + n), 40000));
            g.answer(src, t);
            assert!(g.decide(0, src, || t), "an answered source");
        }
        let state = g.state();
        assert!(state.answered.len() <= MAX_ANSWERED);
        drop(state);
        let peer = |n: u32| SocketAddr::from((Ipv4Addr::from(0xCB00_7200 + n), 40000));
        assert!(
            (1..=4).all(|n| admits(&g, peer(n), t)),
            "the budget is untouched"
        );
        g.answer(sock("192.168.1.1:53"), t);
        assert!(
            !admits(&g, sock("192.168.1.1:53"), t),
            "answers still obey the policy"
        );
    }

    #[test]
    fn loopback_view_reaches_loopback_only() {
        let g = SendGuard::new(View::new(
            IfaceAddr::loopback(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ));
        let t = Instant::now();
        kickoff_send_guard::Guard::associate(&g, 1, [1; 32]);
        assert!(admits(&g, sock("127.0.0.1:40000"), t));
        assert!(!admits(&g, sock("127.0.0.1:53"), t));
        assert!(!admits(&g, sock("192.168.1.30:40000"), t));
        assert!(!admits(&g, sock("203.0.114.9:40000"), t));
    }
}

/// §7: the guard on an approved destination costs at most 50 ns per send,
/// measured through the same entry point the vendored iroh calls. Asserted in
/// release builds (scripts/check.sh runs it there); debug builds only report.
#[cfg(test)]
#[allow(clippy::print_stderr, clippy::cast_possible_truncation)]
mod hot_path {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn send_guard_on_an_approved_destination_within_budget() {
        // Port 1: never an ephemeral port, so no endpoint in this process holds it.
        let bind: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:47002".parse().unwrap();
        let view = View::new(IfaceAddr::loopback(), Vec::new(), Vec::new(), Vec::new());
        let guard = Arc::new(SendGuard::new(view));
        kickoff_send_guard::Guard::associate(guard.as_ref(), 1, [1; 32]);
        guard.set_validated(vec![(1, peer)]);
        let as_hook: Arc<dyn kickoff_send_guard::Guard> = guard.clone();
        let _registration = kickoff_send_guard::register(bind, as_hook).unwrap();
        const SENDS: u32 = 1_000_000;
        let mut best = Duration::MAX;
        for _ in 0..5 {
            let start = Instant::now();
            for _ in 0..SENDS {
                assert!(kickoff_send_guard::admit(
                    std::hint::black_box(bind),
                    std::hint::black_box(1),
                    std::hint::black_box(peer)
                ));
            }
            best = best.min(start.elapsed() / SENDS);
        }
        if cfg!(debug_assertions) {
            eprintln!(
                "send guard, approved destination: {best:?} per send; debug builds only report"
            );
        } else {
            let ceiling = crate::test_latency::budget(Duration::from_nanos(50));
            let asserted = crate::test_latency::runner_label();
            eprintln!(
                "send guard, approved destination: {best:?} per send; asserting <= {ceiling:?}, {asserted}"
            );
            assert!(
                best <= ceiling,
                "{best:?} per send, over {ceiling:?} ({asserted})"
            );
        }
    }
}

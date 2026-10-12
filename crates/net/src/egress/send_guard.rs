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
//! The IP send path carries no remote identity (iroh has already mapped the
//! path to a socket address), so the unvalidated budget is per endpoint, not
//! per remote. On a guest, whose one remote is the host, that is the same.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use iroh::TransportAddr;
use iroh::endpoint::{Connection, WeakConnectionHandle};

use super::{IfaceAddr, denied_port, is_forbidden, is_global};
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
        let port =
            cfg!(feature = "mutant-si29-guard-any-port") || (port >= 1024 && !denied_port(port));
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
    Answered { until: Instant },
    Unvalidated { until: Instant },
}

#[derive(Debug)]
struct State {
    view: View,
    known: HashMap<SocketAddr, Known>,
    new: Bucket,
}

impl State {
    fn forget_expired(&mut self, now: Instant) {
        self.known.retain(|_, k| match k {
            Known::Validated => true,
            Known::Answered { until } | Known::Unvalidated { until } => now < *until,
        });
    }

    fn count(&self, f: impl Fn(&Known) -> bool) -> usize {
        self.known.values().filter(|k| f(k)).count()
    }
}

#[derive(Debug)]
pub(crate) struct SendGuard {
    state: Mutex<State>,
    conns: Mutex<Vec<WeakConnectionHandle>>,
    denied: AtomicU64,
}

impl SendGuard {
    pub(crate) fn new(view: View) -> SendGuard {
        SendGuard {
            state: Mutex::new(State {
                view,
                known: HashMap::new(),
                new: Bucket::new(Instant::now(), NEW_PER_SEC, NEW_PER_SEC),
            }),
            conns: Mutex::new(Vec::new()),
            denied: AtomicU64::new(0),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One packet to `dst`. `now` is read only when the destination is not
    /// already validated.
    pub(crate) fn decide(&self, dst: SocketAddr, now: impl FnOnce() -> Instant) -> bool {
        let mut state = self.state();
        let now = match state.known.get(&dst) {
            Some(Known::Validated) => return true,
            Some(Known::Answered { until } | Known::Unvalidated { until }) => {
                let now = now();
                if now < *until {
                    return true;
                }
                now
            }
            None => now(),
        };
        let admitted = state.view.allows(dst) && {
            state.forget_expired(now);
            let budget = cfg!(feature = "mutant-si29-guard-no-destination-cap")
                || (state.count(|k| matches!(k, Known::Unvalidated { .. })) < MAX_UNVALIDATED
                    && state.new.charge(now, 1));
            if budget {
                let until = now.checked_add(UNVALIDATED_TTL).unwrap_or(now);
                state.known.insert(dst, Known::Unvalidated { until });
            }
            budget
        };
        if !admitted {
            self.denied.fetch_add(1, Ordering::Relaxed);
        }
        admitted
    }

    /// `src` sent this endpoint an `Incoming` that it is about to answer. The
    /// answer still has to pass the policy, but not the probe budget, so a
    /// flood of spoofed sources cannot spend the budget peers' paths need.
    pub(crate) fn answer(&self, src: SocketAddr, now: Instant) {
        let mut state = self.state();
        if !state.view.allows(src) || state.known.get(&src) == Some(&Known::Validated) {
            return;
        }
        state.forget_expired(now);
        let answered = |k: &Known| matches!(k, Known::Answered { .. });
        if !matches!(state.known.get(&src), Some(Known::Answered { .. }))
            && state.count(answered) >= MAX_ANSWERED
        {
            let oldest = state
                .known
                .iter()
                .filter_map(|(addr, k)| match k {
                    Known::Answered { until } => Some((*until, *addr)),
                    _ => None,
                })
                .min();
            if let Some((_, addr)) = oldest {
                state.known.remove(&addr);
            }
        }
        let until = now.checked_add(ANSWER_TTL).unwrap_or(now);
        state.known.insert(src, Known::Answered { until });
    }

    /// Counts `conn`'s IP paths as validated from the next `rescan` on.
    pub(crate) fn track(&self, conn: &Connection) {
        let mut conns = self.conns.lock().unwrap_or_else(PoisonError::into_inner);
        if conns.len() >= MAX_TRACKED {
            conns.retain(|c| c.upgrade().is_some_and(|c| c.close_reason().is_none()));
        }
        if conns.len() < MAX_TRACKED {
            conns.push(conn.weak_handle());
        }
    }

    /// Validated destinations become exactly the open IP paths of the tracked
    /// connections that are still alive.
    pub(crate) fn rescan(&self) {
        let mut paths = Vec::new();
        {
            let mut conns = self.conns.lock().unwrap_or_else(PoisonError::into_inner);
            conns.retain(|weak| {
                let Some(conn) = weak.upgrade().filter(|c| c.close_reason().is_none()) else {
                    return false;
                };
                paths.extend(conn.paths().iter().filter_map(|p| match p.remote_addr() {
                    TransportAddr::Ip(sock) => Some(*sock),
                    _ => None,
                }));
                true
            });
        }
        self.set_validated(paths);
    }

    fn set_validated(&self, paths: Vec<SocketAddr>) {
        let mut state = self.state();
        state
            .known
            .retain(|addr, k| *k != Known::Validated || paths.contains(addr));
        for addr in paths {
            let addr = SocketAddr::new(addr.ip().to_canonical(), addr.port());
            if state.view.allows(addr) {
                state.known.insert(addr, Known::Validated);
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
            state.known.clear();
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
    fn admit(&self, dst: SocketAddr) -> bool {
        self.decide(dst, Instant::now)
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
        SendGuard::new(lan_view())
    }

    /// One packet to `dst` at time `t`.
    fn admits(guard: &SendGuard, dst: SocketAddr, t: Instant) -> bool {
        guard.decide(dst, || t)
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
        g.set_validated(vec![peer(1), peer(2)]);
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
        g.set_validated(vec![peer]);

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
            assert!(admits(&g, src, t), "an answered source");
        }
        let state = g.state();
        assert!(state.count(|k| matches!(k, Known::Answered { .. })) <= MAX_ANSWERED);
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
        guard.set_validated(vec![peer]);
        let as_hook: Arc<dyn kickoff_send_guard::Guard> = guard.clone();
        let _registration = kickoff_send_guard::register(bind, as_hook).unwrap();
        const SENDS: u32 = 1_000_000;
        let mut best = Duration::MAX;
        for _ in 0..5 {
            let start = Instant::now();
            for _ in 0..SENDS {
                assert!(kickoff_send_guard::admit(
                    std::hint::black_box(bind),
                    std::hint::black_box(peer)
                ));
            }
            best = best.min(start.elapsed() / SENDS);
        }
        eprintln!("send guard, approved destination: {best:?} per send");
        if !cfg!(debug_assertions) {
            assert!(best <= Duration::from_nanos(50), "{best:?} per send");
        }
    }
}

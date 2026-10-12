//! Address scoping in both directions. `Egress::scope` is the only place peer
//! data becomes a destination (SI-29); `Egress::publishable` is the only place
//! this node's own addresses are filtered before anyone learns them (SI-31).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use iroh::endpoint::{BeforeConnectOutcome, EndpointHooks};
use iroh::{EndpointAddr, RelayMap, TransportAddr};

use crate::NetError;

/// Tailscale and carrier-grade NAT. Never published, never dialed.
const CGNAT: (Ipv4Addr, u8) = (Ipv4Addr::new(100, 64, 0, 0), 10);
/// The Kickoff virtual subnet is 10.75.0.0/24 (§4.1); §3.4 forbids the whole /16.
const VIRTUAL: (Ipv4Addr, u8) = (Ipv4Addr::new(10, 75, 0, 0), 16);

/// Ranges that are neither global nor ever a peer's direct address.
const NOT_GLOBAL: [(Ipv4Addr, u8); 15] = [
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    CGNAT,
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    (Ipv4Addr::new(192, 88, 99, 0), 24),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

fn in_net(ip: Ipv4Addr, (net, len): (Ipv4Addr, u8)) -> bool {
    let mask = u32::MAX
        .checked_shl(u32::from(32u8.saturating_sub(len)))
        .unwrap_or(0);
    u32::from(ip) & mask == u32::from(net) & mask
}

fn is_global(ip: Ipv4Addr) -> bool {
    !NOT_GLOBAL.iter().any(|&net| in_net(ip, net))
}

/// Never a usable unicast address of ours or a peer's, whatever the scope.
fn is_forbidden(ip: Ipv4Addr) -> bool {
    in_net(ip, CGNAT)
        || in_net(ip, VIRTUAL)
        || ip.is_unspecified()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
}

/// The one local IPv4 address a session endpoint binds. With a specific bind,
/// iroh advertises that address plus the QAD public address and nothing else
/// (§3.4), so Tailscale, Docker and the Kickoff subnet never become candidates.
/// IPv4 only: an IPv6 socket would enumerate every v6 interface address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfaceAddr {
    ip: Ipv4Addr,
    prefix: u8,
}

impl IfaceAddr {
    /// The first usable IPv4 address of the default-route interface.
    pub async fn default_route() -> Result<IfaceAddr, NetError> {
        let state = netwatch::interfaces::State::new().await;
        let name = state.default_route_interface.ok_or(NetError::NoRoute)?;
        let iface = state.interfaces.get(&name).ok_or(NetError::NoRoute)?;
        iface
            .addrs()
            .find_map(|net| match net {
                netwatch::interfaces::IpNet::V4(v4) => Self::lan(v4.addr(), v4.prefix_len()),
                netwatch::interfaces::IpNet::V6 { .. } => None,
            })
            .ok_or(NetError::NoRoute)
    }

    /// 127.0.0.1: the in-process adapter (design §2.3). A loopback endpoint can
    /// only reach and be reached from this host.
    pub fn loopback() -> IfaceAddr {
        IfaceAddr {
            ip: Ipv4Addr::LOCALHOST,
            prefix: 8,
        }
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    /// A LAN or public interface address. Loopback comes only from `loopback()`.
    fn lan(ip: Ipv4Addr, prefix: u8) -> Option<IfaceAddr> {
        (!is_forbidden(ip) && !ip.is_loopback() && prefix <= 32).then_some(IfaceAddr { ip, prefix })
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        in_net(ip, (self.ip, self.prefix))
    }
}

/// What an endpoint may dial and what it may tell others about itself.
#[derive(Debug, Clone)]
pub(crate) struct Egress {
    relays: RelayMap,
    /// `None` for a relay-only endpoint, which dials and publishes no IP address.
    bind: Option<IfaceAddr>,
}

impl Egress {
    pub(crate) fn new(relays: RelayMap, bind: Option<IfaceAddr>) -> Egress {
        Egress { relays, bind }
    }

    /// Keeps only the destinations policy allows: relay URLs equal to an entry
    /// of the compiled map, and IPv4 addresses that are global or on the bound
    /// interface's subnet (loopback only for a loopback bind). Credentials go
    /// only to compiled relays because unlisted URLs never reach iroh.
    pub(crate) fn scope(&self, addr: &EndpointAddr) -> Result<EndpointAddr, NetError> {
        let kept: Vec<TransportAddr> = addr
            .addrs
            .iter()
            .filter(|a| self.may_dial(a))
            .cloned()
            .collect();
        if kept.is_empty() {
            return Err(NetError::Egress);
        }
        Ok(EndpointAddr::from_parts(addr.id, kept))
    }

    fn may_dial(&self, addr: &TransportAddr) -> bool {
        match addr {
            TransportAddr::Relay(url) => self.relays.contains(url),
            TransportAddr::Ip(sock) => self.may_dial_ip(*sock),
            _ => false,
        }
    }

    fn may_dial_ip(&self, sock: SocketAddr) -> bool {
        let (Some(bind), SocketAddr::V4(v4)) = (self.bind, sock) else {
            return false;
        };
        let ip = *v4.ip();
        if sock.port() == 0 || is_forbidden(ip) {
            return false;
        }
        if bind.ip.is_loopback() {
            return ip.is_loopback();
        }
        !ip.is_loopback() && (is_global(ip) || bind.contains(ip))
    }

    /// Our own address as peers may learn it: compiled relays, the bound
    /// address itself, and global (QAD) addresses. Never CGNAT, the virtual
    /// subnet, or any other local interface.
    pub(crate) fn publishable(&self, addr: EndpointAddr) -> EndpointAddr {
        let id = addr.id;
        let kept: Vec<TransportAddr> = addr
            .addrs
            .into_iter()
            .filter(|a| match a {
                TransportAddr::Relay(url) => self.relays.contains(url),
                TransportAddr::Ip(sock) => self.may_publish_ip(*sock),
                _ => false,
            })
            .collect();
        EndpointAddr::from_parts(id, kept)
    }

    fn may_publish_ip(&self, sock: SocketAddr) -> bool {
        let (Some(bind), IpAddr::V4(ip)) = (self.bind, sock.ip()) else {
            return false;
        };
        !is_forbidden(ip) && (ip == bind.ip || is_global(ip))
    }
}

/// Second layer under `Egress::scope`: iroh refuses any connect whose address
/// set holds a destination the policy would have dropped, whichever code path
/// built it.
#[derive(Debug)]
pub(crate) struct EgressGuard(pub(crate) Egress);

impl EndpointHooks for EgressGuard {
    async fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        _alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        if remote_addr.addrs.iter().all(|a| self.0.may_dial(a)) {
            BeforeConnectOutcome::Accept
        } else {
            BeforeConnectOutcome::Reject
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{RelayUrl, SecretKey};

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn lan_bind() -> IfaceAddr {
        IfaceAddr::lan(ip("192.168.1.20"), 24).unwrap()
    }

    fn relay(url: &str) -> RelayUrl {
        url.parse().unwrap()
    }

    fn id() -> iroh::EndpointId {
        SecretKey::from_bytes(&[7; 32]).public()
    }

    /// A deterministic xorshift stream covering the whole IPv4 space.
    fn addresses(n: usize) -> impl Iterator<Item = Ipv4Addr> {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let edges = [
            "100.64.0.0",
            "100.127.255.255",
            "10.75.0.1",
            "10.75.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
        ]
        .map(ip);
        edges.into_iter().chain((0..n).map(move |_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            Ipv4Addr::from((x >> 32) as u32)
        }))
    }

    #[test]
    fn si_31_published_addresses_never_contain_stripped_ranges() {
        let relays = RelayMap::from(relay("https://relay.kickoff.example"));
        for bind in [lan_bind(), IfaceAddr::loopback()] {
            let egress = Egress::new(relays.clone(), Some(bind));
            let candidates: Vec<TransportAddr> = addresses(200_000)
                .map(|a| TransportAddr::Ip(SocketAddr::from((a, 4242))))
                .chain([
                    TransportAddr::Relay(relay("https://relay.kickoff.example")),
                    TransportAddr::Relay(relay("https://evil.example")),
                    TransportAddr::Ip("[fd7a:115c:a1e0::1]:4242".parse().unwrap()),
                    TransportAddr::Ip("[2001:4860::1]:4242".parse().unwrap()),
                ])
                .collect();
            let published = egress.publishable(EndpointAddr::from_parts(id(), candidates));
            assert!(published.relay_urls().all(|u| relays.contains(u)));
            let mut ips = 0;
            for sock in published.ip_addrs() {
                let SocketAddr::V4(v4) = sock else {
                    panic!("published an IPv6 address: {sock}");
                };
                let a = *v4.ip();
                assert!(!in_net(a, CGNAT), "published CGNAT {a}");
                assert!(!in_net(a, VIRTUAL), "published the virtual subnet {a}");
                assert!(a == bind.ip() || is_global(a), "published local {a}");
                ips += 1;
            }
            assert!(
                ips > 0,
                "the filter must keep the bound and global addresses"
            );
        }
    }

    #[test]
    fn iface_addr_refuses_stripped_ranges() {
        for a in [
            "100.100.1.1",
            "10.75.0.3",
            "127.0.0.1",
            "169.254.2.2",
            "0.0.0.0",
            "239.1.1.1",
        ] {
            assert!(
                IfaceAddr::lan(ip(a), 24).is_none(),
                "{a} accepted as a bind"
            );
        }
        assert!(IfaceAddr::lan(ip("192.168.1.20"), 24).is_some());
        assert!(IfaceAddr::lan(ip("192.168.1.20"), 33).is_none());
    }

    #[test]
    fn si_29_egress_keeps_only_compiled_relays_and_scoped_ips() {
        let ours = relay("https://relay.kickoff.example");
        let egress = Egress::new(RelayMap::from(ours.clone()), Some(lan_bind()));
        let hostile = EndpointAddr::from_parts(
            id(),
            [
                TransportAddr::Relay(relay("https://evil.example")),
                TransportAddr::Relay(relay("https://relay.kickoff.example.evil.example")),
                TransportAddr::Ip("127.0.0.1:22".parse().unwrap()),
                TransportAddr::Ip("10.0.0.1:53".parse().unwrap()),
                TransportAddr::Ip("100.100.100.100:41641".parse().unwrap()),
                TransportAddr::Ip("10.75.0.2:7777".parse().unwrap()),
                TransportAddr::Ip("169.254.169.254:80".parse().unwrap()),
                TransportAddr::Ip("224.0.0.251:5353".parse().unwrap()),
                TransportAddr::Ip("[::1]:22".parse().unwrap()),
                TransportAddr::Ip("[::ffff:127.0.0.1]:22".parse().unwrap()),
                TransportAddr::Ip("8.8.8.8:0".parse().unwrap()),
            ],
        );
        assert_eq!(egress.scope(&hostile).err(), Some(NetError::Egress));

        let mixed = EndpointAddr::from_parts(
            id(),
            [
                TransportAddr::Relay(ours.clone()),
                TransportAddr::Relay(relay("https://evil.example")),
                TransportAddr::Ip("192.168.1.30:4000".parse().unwrap()),
                TransportAddr::Ip("192.168.2.30:4000".parse().unwrap()),
                TransportAddr::Ip("203.0.114.9:4000".parse().unwrap()),
                TransportAddr::Ip("127.0.0.1:4000".parse().unwrap()),
            ],
        );
        let kept = egress.scope(&mixed).unwrap();
        assert_eq!(kept.relay_urls().collect::<Vec<_>>(), [&ours]);
        let mut ips: Vec<_> = kept.ip_addrs().map(|s| s.to_string()).collect();
        ips.sort();
        assert_eq!(ips, ["192.168.1.30:4000", "203.0.114.9:4000"]);
    }

    #[test]
    fn relay_only_egress_dials_no_ip() {
        let ours = relay("https://relay.kickoff.example");
        let egress = Egress::new(RelayMap::from(ours.clone()), None);
        let addr = EndpointAddr::from_parts(
            id(),
            [
                TransportAddr::Relay(ours),
                TransportAddr::Ip("8.8.8.8:4000".parse().unwrap()),
            ],
        );
        assert_eq!(egress.scope(&addr).unwrap().ip_addrs().count(), 0);
        let published = egress.publishable(addr);
        assert_eq!(
            published.ip_addrs().count(),
            0,
            "the door publishes no IP address"
        );
        assert_eq!(published.relay_urls().count(), 1);
    }

    #[test]
    fn loopback_bind_dials_loopback_only() {
        let egress = Egress::new(RelayMap::empty(), Some(IfaceAddr::loopback()));
        let local =
            EndpointAddr::from_parts(id(), [TransportAddr::Ip("127.0.0.1:9".parse().unwrap())]);
        assert!(egress.scope(&local).is_ok());
        let public =
            EndpointAddr::from_parts(id(), [TransportAddr::Ip("8.8.8.8:9".parse().unwrap())]);
        assert_eq!(egress.scope(&public).err(), Some(NetError::Egress));
    }
}

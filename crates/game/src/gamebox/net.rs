//! The box's network: pasta with every option explicit (design §3.2.2
//! step 5) and the nft ruleset with the egress deny set (§3.2.4).

use std::fmt;
use std::net::Ipv4Addr;

use super::Refused;
use super::barrier::Fault;

pub(super) const PASTA: &str = "/usr/bin/pasta";
pub(super) const NFT: &str = "/usr/bin/nft";
const PASTA_IF: &str = "gb0";
const LAN_IF: &str = "kick0";

/// pasta's gateway inside the box; with pasta's defaults it would map to
/// the host's loopback.
pub(super) const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// pasta's options. No default is relied on: `-T` and `-U` default to
/// `auto`, which forwards ports bound on the box's loopback to the host's,
/// and the gateway maps to the host's loopback unless told not to. The
/// box's address and gateway are in TEST-NET-1, never a real host.
pub(super) fn pasta_args(fault: Fault) -> Vec<&'static str> {
    let mut args = vec![
        "--config-net",
        "--quiet",
        "--foreground",
        "-I",
        PASTA_IF,
        "-a",
        "192.0.2.2/24",
        "-g",
        "192.0.2.1",
        "-t",
        "none",
        "-u",
        "none",
        "-T",
        "none",
        "-U",
        "none",
    ];
    if fault != Fault::PastaMapsHost {
        args.extend(["--no-map-gw", "--map-host-loopback", "none"]);
    }
    args.extend([
        "--map-guest-addr",
        "none",
        "--ipv4-only",
        "-D",
        "none",
        "--search",
        "none",
        "--no-dhcp",
        "--no-ndp",
        "--no-dhcpv6",
        "--no-ra",
        "--",
    ]);
    args
}

/// Ranges the box never reaches through pasta (design §3.2.4), plus pasta's
/// own TEST-NET-1 subnet.
const FIXED: [([u8; 4], u8); 13] = [
    ([0, 0, 0, 0], 8),
    ([10, 0, 0, 0], 8),
    ([100, 64, 0, 0], 10),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
    ([172, 16, 0, 0], 12),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([192, 168, 0, 0], 16),
    ([198, 18, 0, 0], 15),
    ([224, 0, 0, 0], 4),
    ([240, 0, 0, 0], 4),
    ([255, 255, 255, 255], 32),
];

/// An IPv4 network, its host bits clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Net4 {
    addr: u32,
    len: u8,
}

impl Net4 {
    pub(super) fn new(addr: Ipv4Addr, len: u8) -> Option<Net4> {
        let mask = u32::MAX
            .checked_shl(u32::from(32u8.checked_sub(len)?))
            .unwrap_or(0);
        Some(Net4 {
            addr: u32::from(addr) & mask,
            len,
        })
    }

    fn mask(self) -> u32 {
        u32::MAX
            .checked_shl(u32::from(32u8.saturating_sub(self.len)))
            .unwrap_or(0)
    }

    fn contains(self, other: Net4) -> bool {
        self.len <= other.len && other.addr & self.mask() == self.addr
    }
}

/// As nft lists it: a /32 is the bare address.
impl fmt::Display for Net4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addr = Ipv4Addr::from(self.addr);
        if self.len == 32 {
            write!(f, "{addr}")
        } else {
            write!(f, "{addr}/{}", self.len)
        }
    }
}

/// The deny set: the fixed ranges, every address on every host interface
/// and its connected subnet, every routed subnet and every gateway, as the
/// host's netlink view shows them now. Contained networks are dropped, so
/// the set loads without overlapping intervals.
pub(super) fn deny_set() -> Result<Vec<Net4>, Refused> {
    let mut nets: Vec<Net4> = FIXED
        .iter()
        .filter_map(|(a, len)| Net4::new(Ipv4Addr::from(*a), *len))
        .collect();
    for (addr, len) in interfaces()? {
        nets.extend(Net4::new(addr, 32));
        nets.extend(Net4::new(addr, len));
    }
    nets.extend(routes(&std::fs::read_to_string("/proc/net/route")?)?);
    Ok(minimal(nets))
}

/// Every IPv4 address on a host interface, with its prefix length.
fn interfaces() -> Result<Vec<(Ipv4Addr, u8)>, Refused> {
    let mut found = Vec::new();
    for ifa in nix::ifaddrs::getifaddrs()? {
        let (Some(addr), Some(mask)) = (ifa.address, ifa.netmask) else {
            continue;
        };
        let (Some(addr), Some(mask)) = (addr.as_sockaddr_in(), mask.as_sockaddr_in()) else {
            continue;
        };
        let len = u8::try_from(mask.ip().to_bits().count_ones()).map_err(|_| Refused::Network)?;
        found.push((addr.ip(), len));
    }
    Ok(found)
}

/// The host's own non-loopback IPv4 addresses, which the box must not reach.
pub(super) fn host_addresses() -> Result<Vec<Ipv4Addr>, Refused> {
    Ok(interfaces()?
        .into_iter()
        .map(|(addr, _)| addr)
        .filter(|addr| !addr.is_loopback())
        .collect())
}

/// Destinations and gateways of the main routing table.
fn routes(table: &str) -> Result<Vec<Net4>, Refused> {
    let hex = |s: &str| -> Result<Ipv4Addr, Refused> {
        let n = u32::from_str_radix(s, 16).map_err(|_| Refused::Network)?;
        Ok(Ipv4Addr::from(n.to_ne_bytes()))
    };
    let mut nets = Vec::new();
    for line in table.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let (Some(dest), Some(gateway), Some(mask)) = (cols.get(1), cols.get(2), cols.get(7))
        else {
            return Err(Refused::Network);
        };
        let gateway = hex(gateway)?;
        if !gateway.is_unspecified() {
            nets.extend(Net4::new(gateway, 32));
        }
        let mask = hex(mask)?;
        if !mask.is_unspecified() {
            let len = u8::try_from(mask.to_bits().count_ones()).map_err(|_| Refused::Network)?;
            nets.extend(Net4::new(hex(dest)?, len));
        }
    }
    Ok(nets)
}

fn minimal(mut nets: Vec<Net4>) -> Vec<Net4> {
    nets.sort();
    nets.dedup();
    let all = nets.clone();
    nets.retain(|n| !all.iter().any(|o| o != n && o.contains(*n)));
    nets
}

/// The box's ruleset in the form `nft list ruleset` prints it, so a
/// listing can be compared with it (see [`same_ruleset`]).
pub(super) fn ruleset(deny: &[Net4]) -> String {
    let elements: Vec<String> = deny.iter().map(Net4::to_string).collect();
    let elements = elements.join(", ");
    let deny_rule = if cfg!(feature = "mutant-si14-no-deny-set") {
        String::new()
    } else {
        format!("\t\toifname \"{PASTA_IF}\" ip daddr @deny4 drop\n")
    };
    format!(
        "table inet gamebox {{
\tset deny4 {{
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = {{ {elements} }}
\t}}

\tchain output {{
\t\ttype filter hook output priority filter; policy drop;
\t\toifname \"lo\" accept
\t\tmeta nfproto ipv6 drop
\t\toifname \"{LAN_IF}\" ip daddr {{ 10.75.0.0/24, 255.255.255.255 }} accept
\t\toifname \"{LAN_IF}\" drop
{deny_rule}\t\toifname \"{PASTA_IF}\" accept
\t\tdrop
\t}}

\tchain input {{
\t\ttype filter hook input priority filter; policy drop;
\t\tiifname \"lo\" accept
\t\tmeta nfproto ipv6 drop
\t\tct state invalid drop
\t\tct state established,related accept
\t\tiifname \"{LAN_IF}\" ip saddr 10.75.0.0/24 meta l4proto udp accept
\t\tdrop
\t}}

\tchain forward {{
\t\ttype filter hook forward priority filter; policy drop;
\t}}
}}
"
    )
}

/// Whether an `nft list ruleset` listing is the expected ruleset. nft
/// wraps long element lists by a rule of its own, so runs of whitespace
/// compare equal; every other byte must match.
pub(super) fn same_ruleset(listed: &str, expected: &str) -> bool {
    listed.split_whitespace().eq(expected.split_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Net4 {
        let (a, l) = s.split_once('/').unwrap();
        Net4::new(a.parse().unwrap(), l.parse().unwrap()).unwrap()
    }

    #[test]
    fn deny_set_keeps_only_uncontained_networks_in_address_order() {
        let nets = minimal(vec![
            net("192.168.20.20/32"),
            net("192.168.20.0/22"),
            net("192.168.0.0/16"),
            net("203.0.113.7/32"),
            net("198.51.100.9/24"),
            net("203.0.113.7/32"),
        ]);
        let shown: Vec<String> = nets.iter().map(Net4::to_string).collect();
        assert_eq!(shown, ["192.168.0.0/16", "198.51.100.0/24", "203.0.113.7"]);
    }

    #[test]
    fn route_table_gives_gateways_and_routed_subnets() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     eth0\t00000000\t0164A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                     eth0\t0064A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        let nets = routes(table).unwrap();
        assert_eq!(nets, [net("192.168.100.1/32"), net("192.168.100.0/24")]);
    }

    #[test]
    fn ruleset_comparison_ignores_wrapping_only() {
        let expected = ruleset(&[net("10.0.0.0/8"), net("127.0.0.0/8")]);
        let wrapped = expected.replace("10.0.0.0/8, ", "10.0.0.0/8,\n\t\t\t     ");
        assert!(same_ruleset(&wrapped, &expected));
        let changed = expected.replace("policy drop", "policy accept");
        assert!(!same_ruleset(&changed, &expected));
    }
}

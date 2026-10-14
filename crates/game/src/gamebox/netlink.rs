//! The host's IPv4 network as the kernel holds it, read over rtnetlink:
//! every address, and every route and gateway in every routing table
//! (`/proc/net/route` shows only the main table, while pasta's host-side
//! sockets follow the policy rules into any table), plus a watch that sees
//! any later change (design §3.2.4).

use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkBuffer, NetlinkHeader, NetlinkMessage,
    NetlinkPayload,
};
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{RecvFlags, SendFlags, SocketFlags, SocketType};

use super::Refused;

/// RTMGRP_IPV4_IFADDR, RTMGRP_IPV4_ROUTE and RTMGRP_IPV4_RULE.
const IPV4_GROUPS: u32 = 0x10 | 0x40 | 0x80;
const RT_TABLE_MAIN: u32 = 254;

/// What the deny set is computed from.
#[derive(Debug, Default)]
pub(super) struct HostView {
    /// Every IPv4 address on an interface, with its prefix length.
    pub addresses: Vec<(Ipv4Addr, u8)>,
    /// Every IPv4 route destination other than a default route, any table.
    pub routes: Vec<(Ipv4Addr, u8)>,
    /// Every IPv4 gateway of any route, multipath next hops included.
    pub gateways: Vec<Ipv4Addr>,
}

fn socket(groups: u32, flags: SocketFlags) -> Result<OwnedFd, Refused> {
    // Protocol 0 is NETLINK_ROUTE.
    let fd = rustix::net::socket_with(
        rustix::net::AddressFamily::NETLINK,
        SocketType::RAW,
        flags | SocketFlags::CLOEXEC,
        None,
    )?;
    rustix::net::bind(&fd, &SocketAddrNetlink::new(0, groups))?;
    Ok(fd)
}

/// Reads the host's view in one dump each of addresses and routes. A dump
/// the kernel marks interrupted, an IPv4 route through a nexthop object
/// (whose gateway is not in the route) or an unreadable message refuses.
pub(super) fn host_view() -> Result<HostView, Refused> {
    let sock = socket(0, SocketFlags::empty())?;
    let mut view = HostView::default();
    for message in dump(
        &sock,
        RouteNetlinkMessage::GetAddress(AddressMessage::default()),
    )? {
        if let RouteNetlinkMessage::NewAddress(address) = message {
            add_address(&mut view, &address);
        }
    }
    for message in dump(
        &sock,
        RouteNetlinkMessage::GetRoute(RouteMessage::default()),
    )? {
        if let RouteNetlinkMessage::NewRoute(route) = message {
            add_route(&mut view, &route)?;
        }
    }
    Ok(view)
}

fn add_address(view: &mut HostView, message: &AddressMessage) {
    if message.header.family != AddressFamily::Inet {
        return;
    }
    for attribute in &message.attributes {
        if let AddressAttribute::Address(IpAddr::V4(a)) | AddressAttribute::Local(IpAddr::V4(a)) =
            attribute
        {
            view.addresses.push((*a, message.header.prefix_len));
        }
    }
}

fn add_route(view: &mut HostView, message: &RouteMessage) -> Result<(), Refused> {
    if message.header.address_family != AddressFamily::Inet {
        return Ok(());
    }
    let table = message
        .attributes
        .iter()
        .find_map(|a| match a {
            RouteAttribute::Table(t) => Some(*t),
            _ => None,
        })
        .unwrap_or(u32::from(message.header.table));
    if cfg!(feature = "mutant-si14-main-table-only") && table != RT_TABLE_MAIN {
        return Ok(());
    }
    let len = message.header.destination_prefix_length;
    for attribute in &message.attributes {
        match attribute {
            RouteAttribute::Destination(RouteAddress::Inet(dst)) if len > 0 => {
                view.routes.push((*dst, len));
            }
            RouteAttribute::Gateway(RouteAddress::Inet(gw)) => view.gateways.push(*gw),
            RouteAttribute::MultiPath(hops) => {
                for hop in hops {
                    for a in &hop.attributes {
                        match a {
                            RouteAttribute::Gateway(RouteAddress::Inet(gw)) => {
                                view.gateways.push(*gw);
                            }
                            RouteAttribute::NhId(_) => return Err(Refused::Network),
                            _ => {}
                        }
                    }
                }
            }
            RouteAttribute::NhId(_) => return Err(Refused::Network),
            _ => {}
        }
    }
    Ok(())
}

fn dump(sock: &OwnedFd, request: RouteNetlinkMessage) -> Result<Vec<RouteNetlinkMessage>, Refused> {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    header.sequence_number = 1;
    let mut message = NetlinkMessage::new(header, NetlinkPayload::from(request));
    message.finalize();
    let mut out = vec![0u8; message.buffer_len()];
    message.serialize(&mut out);
    rustix::net::sendto(
        sock,
        &out,
        SendFlags::empty(),
        &SocketAddrNetlink::new(0, 0),
    )?;

    let mut found = Vec::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let (_, len) = rustix::net::recv(sock, &mut buf[..], RecvFlags::empty())?;
        let mut rest = buf.get(..len).ok_or(Refused::Network)?;
        while !rest.is_empty() {
            let size = NetlinkBuffer::new_checked(rest)
                .map_err(|_| Refused::Network)?
                .length();
            let size = usize::try_from(size).map_err(|_| Refused::Network)?;
            let (one, tail) = rest.split_at_checked(size).ok_or(Refused::Network)?;
            rest = tail;
            let parsed = NetlinkMessage::<RouteNetlinkMessage>::deserialize(one)
                .map_err(|_| Refused::Network)?;
            if parsed.header.flags & NLM_F_DUMP_INTR != 0 {
                return Err(Refused::Network);
            }
            match parsed.payload {
                NetlinkPayload::Done(_) => return Ok(found),
                NetlinkPayload::InnerMessage(inner) => found.push(inner),
                NetlinkPayload::Noop => {}
                _ => return Err(Refused::Network),
            }
        }
    }
}

/// A socket subscribed to every IPv4 address, route and rule change. It is
/// opened before the view is read, so no change falls between the two.
pub(super) struct HostWatch(OwnedFd);

impl HostWatch {
    pub(super) fn open() -> Result<HostWatch, Refused> {
        Ok(HostWatch(socket(IPV4_GROUPS, SocketFlags::NONBLOCK)?))
    }

    /// Reads everything queued. Any notification, or a lost one (the socket
    /// overflowed), counts as a change.
    pub(super) fn changed(&self) -> bool {
        let mut buf = [0u8; 8192];
        let mut changed = false;
        loop {
            match rustix::net::recv(&self.0, &mut buf[..], RecvFlags::empty()) {
                Ok((_, 0)) => return changed,
                Ok(_) | Err(rustix::io::Errno::NOBUFS) => changed = true,
                Err(rustix::io::Errno::AGAIN) => return changed,
                Err(_) => return true,
            }
        }
    }
}

impl AsFd for HostWatch {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

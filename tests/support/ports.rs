//! Positive IP transport fixtures select ports their guarded peers can answer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

pub fn bind(ip: std::net::Ipv4Addr) -> std::net::SocketAddr {
    (0..4)
        .find_map(|_| {
            let addr = std::net::UdpSocket::bind((ip, 0))
                .unwrap()
                .local_addr()
                .unwrap();
            kickoff_wire::transport_port_allowed(addr.port()).then_some(addr)
        })
        .expect("no usable fixture port within the bind attempt limit")
}

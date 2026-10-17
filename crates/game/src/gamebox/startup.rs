//! The supervisor's half of the startup probes for pasta behaviour that is
//! not documented as stable (design §3.2.6 requirement 6): canaries on the
//! host's loopback that the box must not reach, and a host port that must
//! not lead into the box. The setup link's half runs before the ruleset
//! loads, so the ruleset cannot hide the answer.

use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

use super::Refused;

const PROBE_TIMEOUT: Duration = Duration::from_millis(300);
/// Where to look for a free host port for the inbound probe: below the
/// usual ephemeral range, where pasta's `all` forwarding would bind.
const INBOUND: std::ops::Range<u16> = 29500..29530;

pub(super) struct Canaries {
    /// Reached only through pasta's gateway mapping or `-T` forwarding.
    tcp: TcpListener,
    /// Reached only through `-U` forwarding.
    udp: UdpSocket,
    /// Free on the host now; bound later only by pasta's `-t`/`-u`.
    inbound: u16,
}

impl Canaries {
    pub(super) fn open() -> Result<Canaries, Refused> {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        tcp.set_nonblocking(true)?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        udp.set_nonblocking(true)?;
        let inbound = INBOUND
            .clone()
            .find(|port| {
                TcpListener::bind((Ipv4Addr::LOCALHOST, *port)).is_ok()
                    && UdpSocket::bind((Ipv4Addr::LOCALHOST, *port)).is_ok()
            })
            .ok_or(Refused::PastaForwards)?;
        Ok(Canaries { tcp, udp, inbound })
    }

    pub(super) fn tcp_port(&self) -> Result<u16, Refused> {
        Ok(self.tcp.local_addr()?.port())
    }

    pub(super) fn udp_port(&self) -> Result<u16, Refused> {
        Ok(self.udp.local_addr()?.port())
    }

    pub(super) fn inbound_port(&self) -> u16 {
        self.inbound
    }

    /// After the setup link probed: nothing reached the loopback canaries,
    /// and the inbound port is still closed on the host for TCP and UDP.
    pub(super) fn held(&self) -> Result<(), Refused> {
        if cfg!(feature = "mutant-si14-no-startup-probe") {
            return Ok(());
        }
        let quiet = |e: &std::io::Error| e.kind() == std::io::ErrorKind::WouldBlock;
        if !self.tcp.accept().is_err_and(|e| quiet(&e)) {
            return Err(Refused::PastaMapsHost);
        }
        let mut buf = [0u8; 64];
        if !self.udp.recv(&mut buf).is_err_and(|e| quiet(&e)) {
            return Err(Refused::PastaForwards);
        }
        let inbound = SocketAddr::from((Ipv4Addr::LOCALHOST, self.inbound));
        let refused = |e: &std::io::Error| e.kind() == std::io::ErrorKind::ConnectionRefused;
        if !TcpStream::connect_timeout(&inbound, PROBE_TIMEOUT).is_err_and(|e| refused(&e)) {
            return Err(Refused::PastaForwards);
        }
        // A connected UDP socket learns of a closed port from the ICMP
        // port-unreachable reply; a bound one stays silent.
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        socket.set_read_timeout(Some(PROBE_TIMEOUT))?;
        socket.connect(inbound)?;
        socket.send(b"kickoff probe")?;
        if !socket.recv(&mut buf).is_err_and(|e| refused(&e)) {
            return Err(Refused::PastaForwards);
        }
        Ok(())
    }
}

//! SI-31: what a peer learns about the host's session endpoint, before and
//! after admission. The endpoint binds the default-route address when this
//! machine has one, so other local interfaces (Tailscale, Docker, a Kickoff
//! subnet) exist alongside and iroh's own candidate exchange is exercised;
//! without a default route it binds loopback. On a machine running Tailscale the unfixed endpoint
//! (bound to 0.0.0.0) hands an admitted peer its Tailscale 100.x address.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

mod common;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use common::*;
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointId, RelayMap, RelayMode, TransportAddr};
use kickoff_net::{AdmittedSet, IfaceAddr, Role, SESSION_ALPN, session};

fn stripped(ip: IpAddr) -> bool {
    let IpAddr::V4(v4) = ip else { return true };
    let [a, b, ..] = v4.octets();
    (a == 100 && (64..128).contains(&b)) || (a == 10 && b == 75)
}

async fn learned(observer: &Endpoint, host: EndpointId) -> Vec<TransportAddr> {
    observer
        .remote_info(host)
        .await
        .map(|info| info.into_addrs().map(|a| a.into_addr()).collect())
        .unwrap_or_default()
}

fn assert_only(bind: IfaceAddr, addrs: &[TransportAddr], who: &str) {
    for addr in addrs {
        let TransportAddr::Ip(sock) = addr else {
            panic!("{who} learned a non-IP address {addr:?}");
        };
        assert!(
            !stripped(sock.ip()),
            "{who} learned a stripped address {sock}"
        );
        assert_eq!(
            sock.ip(),
            IpAddr::V4(bind.ip()),
            "{who} learned {sock} beyond the bind"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_31_peers_learn_only_the_bound_address() {
    let bind = IfaceAddr::default_route()
        .await
        .unwrap_or_else(|_| IfaceAddr::loopback());
    eprintln!("session bound to {}", bind.ip());
    let host = session(&RelayMap::empty(), bind, Role::Host).await.unwrap();

    let published = host.addr();
    let ips: Vec<SocketAddr> = published.ip_addrs().copied().collect();
    assert!(!ips.is_empty());
    assert_eq!(published.relay_urls().count(), 0);
    for ip in &ips {
        assert_eq!(
            ip.ip(),
            IpAddr::V4(bind.ip()),
            "published a second address {ip}"
        );
    }

    let observer = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr((bind.ip(), 0))
        .unwrap()
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let refused = raw_dial(&observer, published.clone(), SESSION_ALPN).await;
    assert!(refused.is_err(), "unadmitted dial got through");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_only(
        bind,
        &learned(&observer, host.id()).await,
        "an unadmitted peer",
    );

    host.set_admitted(
        [(observer.id(), peer(2, 1))]
            .into_iter()
            .collect::<AdmittedSet>(),
    );
    let conn = raw_dial(&observer, published, SESSION_ALPN).await;
    assert!(conn.is_ok(), "admitted dial refused: {:?}", conn.err());
    // Long enough for iroh's candidate exchange on the live connection.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_only(
        bind,
        &learned(&observer, host.id()).await,
        "an admitted peer",
    );
}

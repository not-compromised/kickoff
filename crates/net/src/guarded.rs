//! The only way Kickoff gives an endpoint an IP transport (§3.4). The send
//! guard is registered for the exact address before iroh binds it, so no
//! packet leaves unguarded, and a task keeps the guard's view of the host and
//! of validated paths current for as long as the endpoint lives.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::Builder;
use iroh::{Endpoint, Watcher};

use crate::egress::{Egress, EgressGuard, SendGuard, View, is_global};
use crate::{AbortOnDrop, NetError};

/// How often validated paths are re-read from the live connections.
const RESCAN: Duration = Duration::from_secs(1);
/// Without a route monitor, how many rescans between re-reading the host.
const VIEW_POLL_TICKS: u32 = 5;
/// Unusable candidates and ports taken before binding share this retry bound.
const BIND_ATTEMPTS: usize = 4;

/// The endpoint's send guard and the task maintaining it.
#[derive(Debug)]
pub(crate) struct Guarded {
    pub(crate) guard: Arc<SendGuard>,
    _task: AbortOnDrop,
}

#[derive(Debug)]
struct Unfiltered;

impl kickoff_send_guard::Guard for Unfiltered {
    fn admit(&self, _: u64, _: SocketAddr) -> bool {
        true
    }
}

/// Binds `make()` with an IP transport on `ip` and a port chosen here, with
/// the guard for `view` installed first. `ip` is the view's bind address
/// except under `mutant-si31-unbound`.
pub(crate) async fn bind(
    make: impl Fn() -> Builder,
    ip: Ipv4Addr,
    egress: &Egress,
    view: View,
) -> Result<(Endpoint, Guarded), NetError> {
    bind_with(make, |builder| builder.bind(), free_port, ip, egress, view).await
}

pub(crate) async fn bind_key(
    key: &kickoff_secret::key::IdentityKey,
    make: impl Fn() -> Builder,
    ip: Ipv4Addr,
    egress: &Egress,
    view: View,
) -> Result<(kickoff_secret::key::KeyEndpoint, Guarded), NetError> {
    bind_with(
        make,
        |builder| key.bind(builder),
        free_port,
        ip,
        egress,
        view,
    )
    .await
}

async fn bind_with<E, F, Fut>(
    make: impl Fn() -> Builder,
    attach: F,
    mut choose: impl FnMut(Ipv4Addr) -> Result<u16, NetError>,
    ip: Ipv4Addr,
    egress: &Egress,
    view: View,
) -> Result<(E, Guarded), NetError>
where
    E: EndpointAddress + Clone + 'static,
    F: Fn(Builder) -> Fut,
    Fut: std::future::Future<Output = Result<E, iroh::endpoint::BindError>>,
{
    let guard = Arc::new(SendGuard::new(view));
    for _ in 0..BIND_ATTEMPTS {
        let port = choose(ip)?;
        if !cfg!(feature = "mutant-si29-bind-any-port")
            && !kickoff_wire::transport_port_allowed(port)
        {
            continue;
        }
        let addr = SocketAddr::from((ip, port));
        let as_hook: Arc<dyn kickoff_send_guard::Guard> =
            if cfg!(feature = "mutant-si29-no-send-guard") {
                Arc::new(Unfiltered)
            } else {
                guard.clone()
            };
        let Some(registration) = kickoff_send_guard::register(addr, as_hook) else {
            continue;
        };
        let hooks = EgressGuard::with_send_guard(egress.clone(), registration);
        let builder = make()
            .bind_addr(addr)
            .map_err(|_| NetError::Bind)?
            .hooks(hooks);
        if let Ok(ep) = attach(builder).await {
            let task = tokio::spawn(maintain(ep.clone(), Arc::clone(&guard)));
            return Ok((
                ep,
                Guarded {
                    guard,
                    _task: AbortOnDrop(task),
                },
            ));
        }
    }
    Err(NetError::Bind)
}

/// A port the OS considers free on `ip` right now.
fn free_port(ip: Ipv4Addr) -> Result<u16, NetError> {
    std::net::UdpSocket::bind((ip, 0))
        .and_then(|s| s.local_addr())
        .map(|a| a.port())
        .map_err(|_| NetError::Bind)
}

/// Re-reads validated paths every `RESCAN`, and the host's addresses, routes
/// and resolvers whenever they change or QAD reports a new public address.
/// A loopback bind is the in-process adapter and keeps its view.
trait EndpointAddress: Send {
    fn address(&self) -> iroh::EndpointAddr;
}
impl EndpointAddress for Endpoint {
    fn address(&self) -> iroh::EndpointAddr {
        self.addr()
    }
}
impl EndpointAddress for kickoff_secret::key::KeyEndpoint {
    fn address(&self) -> iroh::EndpointAddr {
        self.addr()
    }
}

async fn maintain(ep: impl EndpointAddress, guard: Arc<SendGuard>) {
    let bind = guard.view().bind();
    let fixed = bind.ip().is_loopback();
    let monitor = if fixed {
        None
    } else {
        netwatch::netmon::Monitor::new().await.ok()
    };
    let mut changes = monitor.as_ref().map(|m| m.interface_state());
    let mut tick = tokio::time::interval(RESCAN);
    let mut ticks: u32 = 0;
    let mut public: Vec<Ipv4Addr> = Vec::new();
    loop {
        let mut changed = false;
        let mut monitor_gone = false;
        tokio::select! {
            _ = tick.tick() => {}
            updated = async {
                match changes.as_mut() {
                    Some(watch) => watch.updated().await.is_ok(),
                    None => std::future::pending().await,
                }
            } => {
                changed = true;
                monitor_gone = !updated;
            }
        }
        if monitor_gone {
            changes = None;
        }
        if !fixed {
            ticks = ticks.wrapping_add(1);
            let polled = changes.is_none() && ticks.is_multiple_of(VIEW_POLL_TICKS);
            let seen = public_addrs(&ep);
            if changed || polled || seen != public {
                public = seen;
                guard.refresh(View::current(bind, &public).await);
            }
        }
        guard.rescan();
    }
}

/// The public addresses this endpoint currently advertises (QAD's view).
fn public_addrs(ep: &impl EndpointAddress) -> Vec<Ipv4Addr> {
    let mut found: Vec<Ipv4Addr> = ep
        .address()
        .ip_addrs()
        .filter_map(|sock| match sock {
            SocketAddr::V4(v4) if is_global(*v4.ip()) => Some(*v4.ip()),
            _ => None,
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use crate::egress::IfaceAddr;
    use iroh::{RelayMode, endpoint::presets};
    use std::time::Instant;

    #[derive(Debug)]
    struct Registered {
        _registration: kickoff_send_guard::Registration,
    }
    impl iroh::endpoint::EndpointHooks for Registered {}

    #[tokio::test]
    async fn unusable_candidates_exhaust_the_existing_bound_without_binding() {
        let ip = Ipv4Addr::LOCALHOST;
        let iface = IfaceAddr::loopback();
        let calls = std::cell::Cell::new(0);
        let makers = std::cell::Cell::new(0);
        let result: Result<(Endpoint, Guarded), NetError> = bind_with(
            || {
                makers.set(makers.get() + 1);
                Endpoint::builder(presets::Minimal).clear_ip_transports()
            },
            |builder| builder.bind(),
            |_| {
                calls.set(calls.get() + 1);
                Ok(47984)
            },
            ip,
            &Egress::new(iroh::RelayMap::empty(), Some(iface)),
            View::new(iface, Vec::new(), Vec::new(), Vec::new()),
        )
        .await;
        assert!(matches!(result, Err(NetError::Bind)));
        assert_eq!(calls.get(), BIND_ATTEMPTS);
        assert_eq!(makers.get(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn si_29_binding_skips_unusable_ports_before_publishing_a_reachable_endpoint() {
        let ip = Ipv4Addr::LOCALHOST;
        let iface = IfaceAddr::loopback();
        let allowed = crate::test_ports::bind(ip).port();
        let mut ports = [47984, allowed].into_iter();
        let (host, guarded) = bind_with(
            || {
                Endpoint::builder(presets::Minimal)
                    .clear_ip_transports()
                    .relay_mode(RelayMode::Disabled)
                    .alpns(vec![b"bind-test".to_vec()])
            },
            |builder| builder.bind(),
            |_| Ok(ports.next().expect("candidate sequence exhausted")),
            ip,
            &Egress::new(iroh::RelayMap::empty(), Some(iface)),
            View::new(iface, Vec::new(), Vec::new(), Vec::new()),
        )
        .await
        .unwrap();
        assert!(
            host.addr().ip_addrs().all(|a| a.port() == allowed),
            "binding published a denylisted candidate instead of the usable candidate"
        );
        assert!(host.addr().ip_addrs().next().is_some());

        let client_ip = Ipv4Addr::new(127, 0, 0, 2);
        let client_addr = crate::test_ports::bind(client_ip);
        let registration = kickoff_send_guard::register(client_addr, Arc::new(Unfiltered)).unwrap();
        let client = Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .bind_addr(client_addr)
            .unwrap()
            .relay_mode(RelayMode::Disabled)
            .hooks(Registered {
                _registration: registration,
            })
            .bind()
            .await
            .unwrap();
        guarded.guard.answer(client_addr, Instant::now());
        let (dialed, accepted) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(client.connect(host.addr(), b"bind-test"), async {
                host.accept().await.unwrap().await
            })
        })
        .await
        .unwrap();
        let dialed = dialed.unwrap();
        let accepted = accepted.unwrap();
        dialed
            .send_datagram(bytes::Bytes::from_static(b"reachable"))
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), accepted.read_datagram())
                .await
                .unwrap()
                .unwrap()
                .as_ref(),
            b"reachable"
        );
        client.close().await;
        host.close().await;
    }
}

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
/// The chosen port can be taken between choosing and binding; try again.
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
    let guard = Arc::new(SendGuard::new(view));
    for _ in 0..BIND_ATTEMPTS {
        let addr = SocketAddr::from((ip, free_port(ip)?));
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
        if let Ok(ep) = builder.bind().await {
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
async fn maintain(ep: Endpoint, guard: Arc<SendGuard>) {
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
fn public_addrs(ep: &Endpoint) -> Vec<Ipv4Addr> {
    let mut found: Vec<Ipv4Addr> = ep
        .addr()
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

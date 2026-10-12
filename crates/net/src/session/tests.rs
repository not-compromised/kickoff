//! SI-18 holds an unknown or stale session key back in several layers.
//! Each test here drives one layer alone, by hand, so removing just that
//! layer (its `mutant-si18-*` feature) fails its test even though the
//! other layers would still refuse the key end to end.
//!
//! The SI-29 and SI-31 tests here need what the public API does not offer: a
//! second loopback host, a synthetic view of the host, and the endpoint's
//! sockets.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use iroh::{SecretKey, TransportAddr};
use kickoff_wire::{Generation, GuestMsg, LanDatagram};

use super::*;

const WAIT: Duration = Duration::from_secs(5);

fn peer(generation: u64) -> PeerRef {
    PeerRef {
        id: SecretKey::generate().public(),
        slot: PeerSlot::new(2).unwrap(),
        generation: Generation::new(generation),
    }
}

#[derive(Debug)]
struct FixtureGuard {
    _registration: kickoff_send_guard::Registration,
}
impl EndpointHooks for FixtureGuard {}
struct Unfiltered;
impl kickoff_send_guard::Guard for Unfiltered {
    fn admit(&self, _: u64, _: SocketAddr) -> bool {
        true
    }
}

async fn endpoint(serve: bool, hook: Option<AdmissionHook>) -> Endpoint {
    let alpns = if serve {
        vec![SESSION_ALPN.to_vec()]
    } else {
        Vec::new()
    };
    let bind = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap();
    let registered = kickoff_send_guard::register(bind, Arc::new(Unfiltered)).unwrap();
    let builder = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr(bind)
        .unwrap()
        .hooks(FixtureGuard {
            _registration: registered,
        })
        .relay_mode(RelayMode::Disabled)
        .alpns(alpns)
        .transport_config(transport(HOST_BIDI, true));
    match hook {
        Some(hook) => builder.hooks(hook),
        None => builder,
    }
    .bind()
    .await
    .unwrap()
}

/// `client` dials `host`; the host's side comes back unaccepted, so the
/// test applies a layer to it by hand.
async fn dial(
    host: &Endpoint,
    client: &Endpoint,
) -> (Incoming, tokio::task::JoinHandle<Option<Connection>>) {
    let (to, client) = (host.addr(), client.clone());
    let dialing = tokio::spawn(async move { client.connect(to, SESSION_ALPN).await.ok() });
    let incoming = tokio::time::timeout(WAIT, host.accept())
        .await
        .unwrap()
        .unwrap();
    (incoming, dialing)
}

fn admitted(entries: &[(EndpointId, PeerRef)]) -> Arc<AdmittedSet> {
    Arc::new(entries.iter().copied().collect())
}

/// Layer 1: the handshake hook refuses a key outside the admitted set
/// before iroh hands the connection out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_18_handshake_hook_rejects_an_unadmitted_key() {
    let shared = Arc::new(Shared::default());
    let hook = AdmissionHook {
        shared: Arc::clone(&shared),
        role: Role::Host,
    };
    let host = endpoint(true, Some(hook)).await;
    let stranger = endpoint(false, None).await;
    let (incoming, _dialing) = dial(&host, &stranger).await;
    let handshake = tokio::time::timeout(WAIT, incoming.accept().unwrap())
        .await
        .unwrap();
    assert!(
        handshake.is_err(),
        "an unadmitted key got through the handshake hook"
    );
    assert!(shared.live().is_empty());
}

/// Layer 2: the key the hook admitted is looked up again once the
/// connection is accepted. Here the owner removed it in between.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_18_admission_is_rechecked_after_the_handshake() {
    let shared = Arc::new(Shared::default());
    let host = endpoint(true, None).await;
    let guest = endpoint(false, None).await;
    // What the hook recorded when it admitted the key.
    let (first, _dialing) = dial(&host, &guest).await;
    let recorded = first.accept().unwrap().await.unwrap();
    shared.live().insert(
        guest.id(),
        Live {
            peer: peer(1),
            conn: recorded.weak_handle(),
            hello_deadline: tokio::time::Instant::now()
                .checked_add(HELLO_WINDOW)
                .unwrap(),
        },
    );
    // The owner has since published a set without it.
    let (incoming, _dialing) = dial(&host, &guest).await;
    let pending = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let established = tokio::time::timeout(WAIT, establish(incoming, pending, shared, None)).await;
    assert!(
        matches!(established, Ok(Err(NetError::Closed))),
        "a key removed after the handshake was not refused"
    );
}

/// Layer 3: a link is handed out only if its generation is still current
/// when the guest's control stream arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_18_link_refused_when_its_generation_moved_before_the_stream() {
    let shared = Arc::new(Shared::default());
    let host = endpoint(true, None).await;
    let guest = endpoint(false, None).await;
    let read_as = peer(1);
    let now = PeerRef {
        generation: Generation::new(2),
        ..read_as
    };
    shared.admitted.store(admitted(&[(guest.id(), now)]));
    let (incoming, dialing) = dial(&host, &guest).await;
    let conn = incoming.accept().unwrap().await.unwrap();
    let client = dialing.await.unwrap().unwrap();
    let (mut send, _recv) = client.open_bi().await.unwrap();
    send.write_all(&[0]).await.unwrap();
    let link = tokio::time::timeout(
        WAIT,
        Link::accept(conn, guest.id(), read_as, Arc::clone(&shared)),
    )
    .await
    .unwrap();
    assert!(
        link.is_err(),
        "a link was handed out under a generation that is no longer current"
    );
}

/// Layer 4: every datagram re-checks the generation, so a stale link
/// whose connection is somehow still open delivers nothing. The set is
/// swapped here without `set_admitted`, which would also close it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_18_each_datagram_rechecks_the_generation() {
    let host = session(&RelayMap::empty(), IfaceAddr::loopback(), Role::Host)
        .await
        .unwrap();
    let guest = session(&RelayMap::empty(), IfaceAddr::loopback(), Role::Guest)
        .await
        .unwrap();
    let p = peer(1);
    host.set_admitted([(guest.id(), p)].into_iter().collect());
    let pass = AdmitPass {
        slot: p.slot,
        generation: p.generation,
    };
    let (guest_link, mut ctl) = guest.dial(host.addr(), pass).await.unwrap();
    ctl.send(&GuestMsg::Hello {
        generation: p.generation,
    })
    .await
    .unwrap();
    let (host_link, _host_ctl) = tokio::time::timeout(WAIT, host.accept())
        .await
        .unwrap()
        .unwrap();

    let bumped = PeerRef {
        generation: Generation::new(2),
        ..p
    };
    host.shared
        .admitted
        .store(admitted(&[(guest.id(), bumped)]));
    guest_link.send_lan(&LanDatagram {
        peer: PeerSlot::HOST,
        bcast: false,
        src_port: 7777,
        dst_port: 7777,
        payload: bytes::Bytes::from_static(b"stale"),
    });
    let got = tokio::time::timeout(WAIT, host_link.recv_lan())
        .await
        .unwrap();
    assert_eq!(got.err(), Some(NetError::Closed), "a stale link delivered");
}

/// A bare iroh endpoint on `ip`, with no Kickoff policy.
async fn raw(ip: Ipv4Addr) -> Endpoint {
    let bind = std::net::UdpSocket::bind((ip, 0))
        .unwrap()
        .local_addr()
        .unwrap();
    let registered = kickoff_send_guard::register(bind, Arc::new(Unfiltered)).unwrap();
    Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr(bind)
        .unwrap()
        .hooks(FixtureGuard {
            _registration: registered,
        })
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap()
}

/// A relay map whose one relay is a closed loopback port: relay-only
/// endpoints need a relay to exist, and this one keeps every test on the host.
fn dead_relay() -> RelayMap {
    RelayMap::from("http://127.0.0.1:9".parse::<iroh::RelayUrl>().unwrap())
}

/// Every address `observer` has recorded for `id`, however it learned it.
async fn learned(observer: &Endpoint, id: EndpointId) -> Vec<TransportAddr> {
    observer
        .remote_info(id)
        .await
        .map(|info| info.into_addrs().map(|a| a.into_addr()).collect())
        .unwrap_or_default()
}

/// SI-31, the leaked-endpoint test. An admitted peer hands the host's session
/// endpoint to an outsider, whose handshake completes and is then rejected.
/// Both record every candidate iroh shows them, and both see exactly the bound
/// address. The interface change is the owner's response to one: the endpoint
/// is recreated on the new address, and the same holds there. A relay-only
/// endpoint shows nothing at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_31_leaked_endpoint_shows_only_the_bound_address() {
    for ip in [Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2)] {
        let bind = IfaceAddr::loopback_at(ip);
        let host = session(&RelayMap::empty(), bind, Role::Host).await.unwrap();
        let leaked = host.addr();
        let allowed: Vec<SocketAddr> = leaked.ip_addrs().copied().collect();
        assert_eq!(allowed.len(), 1, "published {allowed:?}");
        assert!(allowed.iter().all(|a| a.ip() == IpAddr::V4(ip)));

        let admitted = raw(ip).await;
        host.set_admitted([(admitted.id(), peer(1))].into_iter().collect());
        let conn = tokio::time::timeout(WAIT, admitted.connect(leaked.clone(), SESSION_ALPN))
            .await
            .unwrap()
            .unwrap();
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        send.write_all(&[0, 0, 0, 1, 0]).await.unwrap();

        let outsider = raw(ip).await;
        let rejected = tokio::time::timeout(WAIT, async {
            let conn = outsider.connect(leaked.clone(), SESSION_ALPN).await.ok()?;
            Some(conn.closed().await)
        })
        .await
        .unwrap();
        assert!(
            rejected.is_some(),
            "the outsider's handshake never completed"
        );
        // Long enough for iroh's candidate exchange on the live connection.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        for (who, observer) in [("the admitted peer", &admitted), ("an outsider", &outsider)] {
            let seen = learned(observer, host.id()).await;
            assert!(!seen.is_empty(), "{who} recorded nothing");
            for addr in &seen {
                assert!(
                    matches!(addr, TransportAddr::Ip(sock) if allowed.contains(sock)),
                    "{who} learned {addr:?} beyond {allowed:?}"
                );
            }
        }
        host.close().await;
    }

    let host = session(&dead_relay(), SessionBind::RelayOnly, Role::Host)
        .await
        .unwrap();
    let leaked = host.addr();
    assert_eq!(
        leaked.ip_addrs().count(),
        0,
        "relay-only published {leaked:?}"
    );
    let outsider = raw(Ipv4Addr::LOCALHOST).await;
    let dialed = tokio::time::timeout(WAIT, outsider.connect(leaked, SESSION_ALPN)).await;
    assert!(!matches!(dialed, Ok(Ok(_))));
    let seen = learned(&outsider, host.id()).await;
    assert!(
        seen.iter().all(|a| !matches!(a, TransportAddr::Ip(_))),
        "an outsider learned {seen:?} from a relay-only endpoint"
    );
}

/// SI-31 and SI-29: a relay-only endpoint has no IP transport, so it owns no
/// UDP socket. It cannot open or publish an IP path, runs no QAD probe, and
/// its dials keep no IP destination.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_31_relay_only_endpoint_owns_no_socket_and_publishes_no_address() {
    for role in [Role::Host, Role::Guest] {
        let net = session(&dead_relay(), SessionBind::RelayOnly, role)
            .await
            .unwrap();
        assert!(
            net.ep.bound_sockets().is_empty(),
            "a relay-only endpoint bound {:?}",
            net.ep.bound_sockets()
        );
        assert_eq!(net.addr().ip_addrs().count(), 0);
        assert!(net.guarded.is_none());
    }
    let host = session(&RelayMap::empty(), IfaceAddr::loopback(), Role::Host)
        .await
        .unwrap();
    let guest = session(&dead_relay(), SessionBind::RelayOnly, Role::Guest)
        .await
        .unwrap();
    let p = peer(1);
    host.set_admitted([(guest.id(), p)].into_iter().collect());
    let pass = AdmitPass {
        slot: p.slot,
        generation: p.generation,
    };
    let dialed = guest.dial(host.addr(), pass).await;
    assert_eq!(dialed.err(), Some(NetError::Egress), "dialed an IP address");
}

/// SI-29, the hook itself: a guest whose view names the host's address as its
/// DNS resolver. `scope` and the connect guard allow loopback, so only the
/// send guard in the vendored iroh stands between them, and nothing iroh
/// sends there leaves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_29_send_guard_drops_what_iroh_sends_to_a_refused_destination() {
    let host = session(&RelayMap::empty(), IfaceAddr::loopback(), Role::Host)
        .await
        .unwrap();
    let bind = IfaceAddr::loopback_at(Ipv4Addr::new(127, 0, 0, 2));
    let view = View::new(bind, Vec::new(), Vec::new(), vec![Ipv4Addr::LOCALHOST]);
    let guest = bind_session(&RelayMap::empty(), Some(view), Role::Guest)
        .await
        .unwrap();
    let p = peer(1);
    host.set_admitted([(guest.id(), p)].into_iter().collect());
    let pass = AdmitPass {
        slot: p.slot,
        generation: p.generation,
    };
    let dialed = tokio::time::timeout(Duration::from_secs(3), guest.dial(host.addr(), pass)).await;
    assert!(
        !matches!(dialed, Ok(Ok(_))),
        "the guest reached a destination its send guard refuses"
    );
    assert!(
        guest.egress_denied() > 0,
        "no packet was refused at the send path"
    );
}

#[derive(Default)]
struct ContextRecorder(std::sync::Mutex<std::collections::HashSet<u64>>);
impl kickoff_send_guard::Guard for ContextRecorder {
    fn admit(&self, context: u64, _: SocketAddr) -> bool {
        self.0.lock().unwrap().insert(context);
        true
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_29_transport_carries_distinct_connection_contexts() {
    let bind = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap();
    let recorded = Arc::new(ContextRecorder::default());
    let registered = kickoff_send_guard::register(bind, recorded.clone()).unwrap();
    let client = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr(bind)
        .unwrap()
        .hooks(FixtureGuard {
            _registration: registered,
        })
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let host_one = endpoint(true, None).await;
    let host_two = endpoint(true, None).await;
    let first_client = client.clone();
    let to = host_one.addr();
    let (first, accepted) = tokio::join!(
        async move { first_client.connect(to, SESSION_ALPN).await.unwrap() },
        async { host_one.accept().await.unwrap().await.unwrap() }
    );
    let second_client = client.clone();
    let to = host_two.addr();
    let (second, accepted_two) = tokio::join!(
        async move { second_client.connect(to, SESSION_ALPN).await.unwrap() },
        async { host_two.accept().await.unwrap().await.unwrap() }
    );
    let first_context = first.send_context();
    let second_context = second.send_context();
    assert_ne!(first_context, second_context);
    assert_ne!(accepted.send_context(), first_context);
    assert_ne!(accepted_two.send_context(), second_context);
    let contexts = recorded.0.lock().unwrap();
    assert!(
        contexts.contains(&first_context),
        "first connection lost its context on the IP send path"
    );
    assert!(
        contexts.contains(&second_context),
        "second connection lost its context on the IP send path"
    );
}

#[test]
#[allow(clippy::panic)]
fn si_23_guard_connection_snapshots_do_not_block_packets() {
    struct SupervisedChild(Option<std::process::Child>);
    impl Drop for SupervisedChild {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "session::tests::guard_connection_snapshot_worker",
            "--nocapture",
        ])
        .env("KICKOFF_GUARD_STRESS", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = SupervisedChild(Some(child));
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
            let output = child.0.take().unwrap().wait_with_output().unwrap();
            let diagnostics = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            eprintln!("{diagnostics}");
            assert!(status.success(), "{}", diagnostics);
            break;
        }
        if started.elapsed() >= Duration::from_secs(15) {
            child.0.as_mut().unwrap().kill().unwrap();
            let output = child.0.take().unwrap().wait_with_output().unwrap();
            panic!(
                "concurrent admission and game packets deadlocked\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn guard_connection_snapshot_worker() {
    if std::env::var_os("KICKOFF_GUARD_STRESS").is_none() {
        return;
    }
    // Noq's real driver holds the connection mutex throughout this callback.
    // Rendezvous after snapshots, then after state acquisition, so tracking
    // and packet admission must attempt the competing locks in that order.
    struct ScheduledGuard {
        guard: Arc<SendGuard>,
        armed: std::sync::atomic::AtomicU64,
        packet_held: Arc<std::sync::Barrier>,
        state_held: Arc<std::sync::Barrier>,
        completed: std::sync::mpsc::SyncSender<bool>,
    }
    impl kickoff_send_guard::Guard for ScheduledGuard {
        fn admit(&self, context: u64, dst: SocketAddr) -> bool {
            use std::sync::atomic::Ordering;
            let selected = context != 0
                && self
                    .armed
                    .compare_exchange(context, 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok();
            if selected {
                eprintln!("guard proof: target packet holds transport connection");
                self.packet_held.wait();
                self.state_held.wait();
                eprintln!("guard proof: tracking holds state, invoking real packet guard");
            }
            let admitted = kickoff_send_guard::Guard::admit(self.guard.as_ref(), context, dst);
            if selected {
                self.completed.send(admitted).unwrap();
            }
            admitted
        }
        fn associate(&self, context: u64, remote: [u8; 32]) {
            kickoff_send_guard::Guard::associate(self.guard.as_ref(), context, remote);
        }
        fn expect(&self, context: u64, remote: [u8; 32]) {
            kickoff_send_guard::Guard::expect(self.guard.as_ref(), context, remote);
        }
        fn probe(&self, context: u64, dst: SocketAddr) {
            kickoff_send_guard::Guard::probe(self.guard.as_ref(), context, dst);
        }
        fn forget(&self, context: u64) {
            kickoff_send_guard::Guard::forget(self.guard.as_ref(), context);
        }
    }

    let bind = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap();
    let guard = Arc::new(SendGuard::new(View::new(
        IfaceAddr::loopback(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )));
    let packet_held = Arc::new(std::sync::Barrier::new(2));
    let state_held = Arc::new(std::sync::Barrier::new(2));
    let (packet_completed, admitted_packet) = std::sync::mpsc::sync_channel(1);
    let scheduled = Arc::new(ScheduledGuard {
        guard: Arc::clone(&guard),
        armed: std::sync::atomic::AtomicU64::new(0),
        packet_held: Arc::clone(&packet_held),
        state_held: Arc::clone(&state_held),
        completed: packet_completed,
    });
    let registered = kickoff_send_guard::register(bind, scheduled.clone()).unwrap();
    let server = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr(bind)
        .unwrap()
        .hooks(FixtureGuard {
            _registration: registered,
        })
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![SESSION_ALPN.to_vec()])
        .transport_config(transport(HOST_BIDI, true))
        .bind()
        .await
        .unwrap();
    let client = endpoint(false, None).await;
    let client_addr = client.addr();
    let peer_addr = *client_addr.ip_addrs().next().unwrap();
    guard.answer(peer_addr, std::time::Instant::now());
    let (receiving, sending) = tokio::join!(
        async { client.connect(server.addr(), SESSION_ALPN).await.unwrap() },
        async { server.accept().await.unwrap().await.unwrap() },
    );
    // Accepted IP connections start with the peer's real socket address;
    // the client's initial mapped route can send through an actor instead.
    assert!(
        sending
            .paths()
            .iter()
            .any(|path| path.remote_addr() == &TransportAddr::Ip(peer_addr))
    );
    let context = sending.send_context();
    assert_ne!(context, 0);
    let (snapshot_ready, snapshot_reached) = std::sync::mpsc::sync_channel(1);
    let schedule = guard.schedule_track(context, snapshot_ready, packet_held, state_held);
    let (track_completed, tracked) = std::sync::mpsc::sync_channel(1);
    let tracking_guard = Arc::clone(&guard);
    let tracking_conn = sending.clone();
    let tracking = std::thread::spawn(move || {
        tracking_guard.track(&tracking_conn);
        track_completed.send(()).unwrap();
    });
    snapshot_reached.recv_timeout(WAIT).unwrap();
    eprintln!("guard proof: target connection snapshots complete, arming packet rendezvous");
    scheduled
        .armed
        .store(context, std::sync::atomic::Ordering::SeqCst);
    let payload = bytes::Bytes::from_static(b"guard-lock-order-progress");
    sending.send_datagram(payload.clone()).unwrap();
    tracked.recv_timeout(WAIT).unwrap();
    assert!(
        admitted_packet.recv_timeout(WAIT).unwrap(),
        "real guard refused target packet"
    );
    assert_eq!(
        tokio::time::timeout(WAIT, receiving.read_datagram())
            .await
            .unwrap()
            .unwrap(),
        payload
    );
    tracking.join().unwrap();
    drop(schedule);
    eprintln!("guard proof: tracking and real packet admission completed, datagram received");
    client.close().await;
    server.close().await;

    for _ in 0..3 {
        let host = Arc::new(
            session(&RelayMap::empty(), IfaceAddr::loopback(), Role::Host)
                .await
                .unwrap(),
        );
        let mut guests = Vec::new();
        let mut admitted = AdmittedSet::new();
        for slot in 2..=7 {
            let guest = session(&RelayMap::empty(), IfaceAddr::loopback(), Role::Guest)
                .await
                .unwrap();
            let mut p = peer(1);
            p.slot = PeerSlot::new(slot).unwrap();
            admitted.insert(guest.id(), p);
            guests.push((guest, p));
        }
        host.set_admitted(admitted);
        let mut tasks = Vec::new();
        for (guest, p) in guests {
            let accepting = Arc::clone(&host);
            let to = host.addr();
            tasks.push(tokio::spawn(async move {
                let (link, mut ctl) = guest
                    .dial(
                        to,
                        AdmitPass {
                            slot: p.slot,
                            generation: p.generation,
                        },
                    )
                    .await
                    .unwrap();
                ctl.send(&GuestMsg::Hello {
                    generation: p.generation,
                })
                .await
                .unwrap();
                for _ in 0..64 {
                    tokio::time::timeout(WAIT, link.recv_lan())
                        .await
                        .unwrap()
                        .unwrap();
                }
            }));
            tasks.push(tokio::spawn(async move {
                let (link, _ctl) = accepting.accept().await.unwrap();
                for _ in 0..64 {
                    link.send_lan(&LanDatagram {
                        peer: PeerSlot::HOST,
                        bcast: false,
                        src_port: 7777,
                        dst_port: 7777,
                        payload: bytes::Bytes::from_static(b"game"),
                    });
                    tokio::task::yield_now().await;
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
    }
}

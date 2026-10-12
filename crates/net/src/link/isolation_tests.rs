//! Real authenticated transport composition, with bounded receive witnesses.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::net::{Ipv4Addr, SocketAddr};

use bytes::Bytes;
use kickoff_vlan::{Lan, LanConfig, MemGame, mem_tap};

use iroh::endpoint::{EndpointHooks, presets};
use iroh::{Endpoint, RelayMap, RelayMode, SecretKey};
use kickoff_wire::{AdmitPass, Generation, GuestMsg, LanDatagram, PeerSlot};
use tokio::sync::mpsc;

use super::*;
use crate::reassembly::DEADLINE;
use crate::{AbortOnDrop, AdmittedSet, IfaceAddr, Role, SessionNet, session};

const WAIT: Duration = Duration::from_secs(5);

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

fn peer(slot: u8) -> PeerRef {
    PeerRef {
        id: SecretKey::generate().public(),
        slot: PeerSlot::new(slot).unwrap(),
        generation: Generation::new(1),
    }
}

fn lan(payload: Bytes) -> LanDatagram {
    LanDatagram {
        peer: PeerSlot::HOST,
        bcast: false,
        src_port: 7777,
        dst_port: 14001,
        payload,
    }
}

async fn receive(link: &Link) -> LanDatagram {
    tokio::time::timeout(WAIT, link.recv_lan())
        .await
        .unwrap()
        .unwrap()
}

struct Attacker {
    ep: Endpoint,
    conn: Connection,
    _send: SendStream,
    _recv: RecvStream,
    link: Arc<Link>,
    _ctl: CtlStream,
    seen: mpsc::Receiver<FragmentSeen>,
    _drain: AbortOnDrop,
}

impl Drop for Attacker {
    fn drop(&mut self) {
        self.conn.close(crate::close::DONE, b"");
    }
}

struct Fixture {
    host: SessionNet,
    guest: SessionNet,
    good: Link,
    host_good: Arc<Link>,
    _guest_ctl: CtlStream,
    _host_ctl: CtlStream,
    attacks: Vec<Attacker>,
    big: LanDatagram,
    chunk_limit: usize,
    game_lan: Lan,
    game: MemGame,
}

impl Fixture {
    async fn new(attackers: u8) -> Self {
        let host = session(&RelayMap::empty(), IfaceAddr::loopback(), Role::Host)
            .await
            .unwrap();
        let guest = session(&RelayMap::empty(), IfaceAddr::loopback(), Role::Guest)
            .await
            .unwrap();
        let good_peer = peer(attackers + 2);
        let mut endpoints = Vec::new();
        let mut entries = vec![(guest.id(), good_peer)];
        for i in 0..attackers {
            let ep = raw(Ipv4Addr::new(127, 0, 0, i + 2)).await;
            let p = peer(i + 2);
            entries.push((ep.id(), p));
            endpoints.push((ep, p));
        }
        host.set_admitted(entries.into_iter().collect::<AdmittedSet>());
        let (good, mut guest_ctl) = guest
            .dial(
                host.addr(),
                AdmitPass {
                    slot: good_peer.slot,
                    generation: good_peer.generation,
                },
            )
            .await
            .unwrap();
        guest_ctl
            .send(&GuestMsg::Hello {
                generation: good_peer.generation,
            })
            .await
            .unwrap();
        let (host_good, mut host_ctl) = host.accept().await.unwrap();
        assert_eq!(host_good.peer(), good_peer);
        assert_eq!(
            host_ctl.recv::<GuestMsg>().await.unwrap(),
            GuestMsg::Hello {
                generation: good_peer.generation,
            }
        );
        let mut attacks = Vec::new();
        for (ep, p) in endpoints {
            let conn = ep.connect(host.addr(), crate::SESSION_ALPN).await.unwrap();
            let (mut send, recv) = conn.open_bi().await.unwrap();
            let hello = encode_framed(&GuestMsg::Hello {
                generation: p.generation,
            })
            .unwrap();
            send.write_all(&hello).await.unwrap();
            let (mut link, mut ctl) = host.accept().await.unwrap();
            assert_eq!(link.peer(), p);
            assert_eq!(
                ctl.recv::<GuestMsg>().await.unwrap(),
                GuestMsg::Hello {
                    generation: p.generation,
                }
            );
            let (tx, seen) = mpsc::channel(16);
            link.reassembly_observer = Some(tx);
            let link = Arc::new(link);
            let draining = Arc::clone(&link);
            let drain = tokio::spawn(async move { while draining.recv_lan().await.is_ok() {} });
            attacks.push(Attacker {
                ep,
                conn,
                _send: send,
                _recv: recv,
                link,
                _ctl: ctl,
                seen,
                _drain: AbortOnDrop(drain),
            });
        }
        let last = tokio::time::timeout(WAIT, async {
            let mut last = 0;
            let mut stable = 0;
            while stable < 5 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let now = good.max_datagram_size().unwrap();
                stable = if now == last { stable + 1 } else { 0 };
                last = now;
            }
            last
        })
        .await
        .expect("the fixture path MTU did not settle");
        let chunk_limit = last.min(1000);
        let big = lan(vec![0x5A; 1472].into());
        assert_eq!(encode_datagram(&big, 0, chunk_limit).unwrap().len(), 2);
        let (adapter, game) = mem_tap();
        let game_lan = kickoff_vlan::open(
            adapter,
            LanConfig {
                slot: PeerSlot::HOST,
            },
        )
        .unwrap();
        let fixture = Self {
            host,
            guest,
            good,
            host_good: Arc::new(host_good),
            _guest_ctl: guest_ctl,
            _host_ctl: host_ctl,
            attacks,
            big,
            chunk_limit,
            game_lan,
            game,
        };
        let small = lan(Bytes::from_static(b"live before occupancy"));
        fixture.good.send_lan(&small);
        let received = receive(&fixture.host_good).await;
        let frame = fixture.deliver(received).await;
        assert!(frame.ends_with(&small.payload));
        fixture.send_big();
        let received = receive(&fixture.host_good).await;
        let frame = fixture.deliver(received).await;
        assert!(frame.ends_with(&fixture.big.payload));
        fixture
    }

    // A legal smaller packet size exercises a fragmented game-sized payload
    // even when this loopback path can carry it in one packet.
    fn send_big(&self) -> u16 {
        let id = self.good.next_frag.fetch_add(1, Ordering::Relaxed);
        let parts = encode_datagram(&self.big, id, self.chunk_limit).unwrap();
        self.good.conn.send_many_datagrams(&parts).unwrap();
        id
    }

    async fn deliver(&self, datagram: LanDatagram) -> Bytes {
        self.game_lan.deliver(datagram);
        tokio::time::timeout(WAIT, self.game.recv_frame())
            .await
            .unwrap()
            .unwrap()
    }

    fn live(&self) {
        assert!(self.host_good.current());
        assert!(self.good.conn.close_reason().is_none());
        for attack in &self.attacks {
            assert!(attack.link.current());
            assert!(attack.conn.close_reason().is_none());
            assert_eq!(attack.link.health().dropped_budget, 0);
            assert_eq!(attack.link.health().dropped_malformed, 0);
        }
    }

    async fn close(self) {
        for attack in &self.attacks {
            attack.conn.close(crate::close::DONE, b"");
            attack.ep.close().await;
        }
        self.host.close().await;
        self.guest.close().await;
    }
}

fn first_fragment(id: u16, ports: (u16, u16)) -> Bytes {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[2, 0]);
    frame.extend_from_slice(&ports.0.to_be_bytes());
    frame.extend_from_slice(&ports.1.to_be_bytes());
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(&[4, 0]);
    frame.extend_from_slice(&[0xAA; 1000]);
    frame.into()
}

async fn witness(seen: &mut mpsc::Receiver<FragmentSeen>) -> FragmentSeen {
    tokio::time::timeout(WAIT, seen.recv())
        .await
        .unwrap()
        .unwrap()
}

async fn colluding_fragments(ports: (u16, u16)) {
    let mut f = Fixture::new(4).await;
    let (tx, mut good_seen) = mpsc::channel(8);
    Arc::get_mut(&mut f.host_good).unwrap().reassembly_observer = Some(tx);
    let mut earliest = None;
    let mut accepted = 0;
    let mut refused = 0;
    let mut occupied = 0;
    for attack in &mut f.attacks {
        for id in 0..8 {
            attack
                .conn
                .send_datagram(first_fragment(id, ports))
                .unwrap();
        }
        for _ in 0..8 {
            let seen = witness(&mut attack.seen).await;
            assert!(seen.id < 8 && seen.idx == 0);
            assert!(seen.pending || seen.full, "{seen:?}");
            if seen.pending {
                earliest.get_or_insert(seen.at);
                accepted += 1;
            } else {
                refused += 1;
            }
            occupied = seen.total;
        }
    }
    assert_eq!(accepted + refused, 32);
    assert!(accepted >= 8, "no meaningful attacker occupancy");
    assert_eq!(
        occupied, accepted,
        "physical occupancy was already released"
    );
    f.live();
    let deadline = earliest.unwrap().checked_add(DEADLINE).unwrap();
    assert!(
        Instant::now() < deadline,
        "attack setup outlived its assemblies"
    );
    let id = f.good.next_frag.load(Ordering::Relaxed);
    let reading = Arc::clone(&f.host_good);
    let (finished, receiving) = tokio::sync::oneshot::channel();
    let _receiver = AbortOnDrop(tokio::spawn(async move {
        let _ = finished.send(reading.recv_lan().await);
    }));
    assert_eq!(f.send_big(), id);
    let mut completed = false;
    let mut full = 0;
    for _ in 0..2 {
        let seen = tokio::time::timeout_at(deadline.into(), good_seen.recv())
            .await
            .expect("legitimate fragments not consumed within original assembly lifetime")
            .unwrap();
        assert_eq!(seen.id, id);
        assert!(seen.idx < 2);
        assert!(seen.at < deadline);
        completed |= seen.complete;
        if seen.full {
            full += 1;
            assert_eq!(
                seen.total, 32,
                "Full was not caused by occupied shared pool"
            );
            assert_eq!(seen.held, 0, "legitimate local table was not empty");
        }
    }
    if !completed {
        assert_eq!(full, 2, "loss was not the shared-capacity counterexample");
        f.good.send_lan(&lan(Bytes::from_static(
            b"marker after discarded fragments",
        )));
    }
    let got = tokio::time::timeout_at(deadline.into(), receiving)
        .await
        .expect("result exceeded the unchanged assembly lifetime")
        .unwrap();
    f.live();
    assert!(Instant::now() < deadline);
    eprintln!(
        "ports={ports:?}, accepted={accepted}, refused={refused}, occupied={occupied}, legitimate_full={full}, complete={completed}, elapsed={:?}",
        earliest.unwrap().elapsed()
    );
    let frame = f.deliver(got.unwrap()).await;
    assert!(
        frame.ends_with(&f.big.payload),
        "the fragmented game payload did not reach Mem while other assemblies were held"
    );
    assert!(
        Instant::now() < deadline,
        "Mem delivery outlived the held assemblies"
    );
    assert_eq!(
        lock(&f.host_good.rx).frags.in_use(),
        accepted,
        "attacker occupancy expired before Mem delivery"
    );
    f.live();
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_23_denied_port_colluding_fragments_leave_peer_capacity() {
    colluding_fragments((22, 53)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_23_allowed_port_colluding_fragments_leave_peer_capacity() {
    colluding_fragments((7777, 14001)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn si_23_one_link_holds_eight_assemblies_and_refuses_the_ninth() {
    let mut f = Fixture::new(1).await;
    let attack = &mut f.attacks[0];
    let mut earliest = None;
    for id in 0..9 {
        attack
            .conn
            .send_datagram(first_fragment(id, (7777, 14001)))
            .unwrap();
        let seen = witness(&mut attack.seen).await;
        assert_eq!(seen.id, id);
        if id < 8 {
            assert!(seen.pending && !seen.full, "eight usable places: {seen:?}");
            earliest.get_or_insert(seen.at);
        } else {
            assert!(seen.full, "ninth assembly was accepted: {seen:?}");
            assert_eq!(seen.held, 8);
            assert_eq!(seen.total, 8, "global pool must retain ample headroom");
        }
    }
    assert!(earliest.unwrap().elapsed() < DEADLINE);
    let big = f.big.clone();
    f.send_big();
    assert_eq!(receive(&f.host_good).await.payload, big.payload);
    f.live();
    f.close().await;
}

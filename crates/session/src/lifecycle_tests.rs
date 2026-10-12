//! Ending rejects late operations while the actual cleared endpoint is open.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::any::Any;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Poll;

use common::*;
use iroh::{RelayMap, RelayUrl, SecretKey};
use kickoff_net::{NetError, Role, SessionBind, SessionNet};
use kickoff_secret::key::IdentityKey;
use kickoff_vlan::mem_tap;
use kickoff_wire::{GuestMsg, HostMsg, JoinRefused, LanDatagram, PeerRef, PeerSlot};
use tokio::sync::oneshot;

use crate::{Command, EndReason, HostOpts, SessionError, SessionEvent};

#[derive(Default)]
pub(super) struct Hooks {
    drain: Mutex<Option<Drain>>,
    hello: Mutex<Option<(PeerRef, oneshot::Sender<()>)>>,
}

struct Drain {
    reached: oneshot::Sender<()>,
    resume: oneshot::Receiver<()>,
}

impl Hooks {
    fn hold_end(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached, at_drain) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        let previous = self
            .drain
            .lock()
            .unwrap()
            .replace(Drain { reached, resume });
        assert!(previous.is_none(), "end hold was already armed");
        (at_drain, release)
    }

    pub(super) async fn after_drain(&self) {
        let drain = self
            .drain
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(Drain { reached, resume }) = drain {
            let _ = reached.send(());
            // Dropping the fixture's sender also releases teardown on panic.
            let _ = resume.await;
        }
    }

    fn observe_hello(&self, peer: PeerRef) -> oneshot::Receiver<()> {
        let (seen, received) = oneshot::channel();
        let previous = self.hello.lock().unwrap().replace((peer, seen));
        assert!(previous.is_none(), "Hello observation was already armed");
        received
    }

    pub(super) fn hello_seen(&self, peer: PeerRef) {
        let mut hello = self.hello.lock().unwrap_or_else(PoisonError::into_inner);
        if hello
            .as_ref()
            .is_some_and(|(expected, _)| *expected == peer)
            && let Some((_, seen)) = hello.take()
        {
            let _ = seen.send(());
        }
    }
}

fn hooks(host: &HostNode) -> &Hooks {
    match &host.session.role {
        crate::Role::Host(host) => &host.lifecycle,
        crate::Role::Guest(_) => panic!("expected a host"),
    }
}

struct Fixture {
    host: HostNode,
    relay: Option<iroh_relay::server::Server>,
    relay_url: Option<RelayUrl>,
    relays: kickoff_net::Relays,
}

impl Fixture {
    async fn new(relay_only: bool) -> Self {
        let (relay, relay_url, relays) = if relay_only {
            let (certs, server_config) =
                iroh_relay::server::testing::self_signed_tls_certs_and_config();
            let mut relay =
                iroh_relay::server::RelayConfig::new((std::net::Ipv4Addr::LOCALHOST, 0));
            relay.tls = Some(iroh_relay::server::TlsConfig::new(
                (std::net::Ipv4Addr::LOCALHOST, 0),
                iroh_relay::server::CertConfig::Manual { server_config },
            ));
            let mut config = iroh_relay::server::ServerConfig::default();
            config.relay = Some(relay);
            let server = iroh_relay::server::Server::spawn(config).await.unwrap();
            let url: RelayUrl = format!("https://{}", server.https_addr().unwrap())
                .parse()
                .unwrap();
            let relays = kickoff_net::Relays::with_ca(
                RelayMap::from(url.clone()),
                iroh::tls::CaTlsConfig::custom_roots(certs),
            );
            (Some(server), Some(url), relays)
        } else {
            (None, None, (&RelayMap::empty()).into())
        };
        let identity = Self::identity().await;
        let net = kickoff_net::session(
            relays.clone(),
            if relay_only {
                SessionBind::RelayOnly
            } else {
                kickoff_net::IfaceAddr::loopback().into()
            },
            Role::Host,
        )
        .await
        .unwrap();
        let (adapter, game) = mem_tap();
        let session = crate::host(
            Arc::clone(&identity.door),
            &identity.key,
            net,
            adapter,
            HostOpts::new(name("host")),
        )
        .await
        .unwrap();
        let events = session.events();
        Self {
            host: HostNode {
                identity,
                session,
                game,
                events,
            },
            relay,
            relay_url,
            relays,
        }
    }

    async fn identity() -> Identity {
        let key = IdentityKey::new(SecretKey::generate());
        let door = Arc::new(kickoff_net::door_loopback(&key).await.unwrap());
        Identity { key, door }
    }

    async fn guest_net(&self) -> SessionNet {
        kickoff_net::session(
            self.relays.clone(),
            if self.relay_url.is_some() {
                SessionBind::RelayOnly
            } else {
                kickoff_net::IfaceAddr::loopback().into()
            },
            Role::Guest,
        )
        .await
        .unwrap()
    }

    async fn bound_guest(&self) -> RawGuest {
        let identity = Self::identity().await;
        let ticket = self.host.bound(identity.id());
        let net = self.guest_net().await;
        let mut admitted = request_join(&identity, &net, &ticket).await.unwrap();
        // Known fixture relay addressing avoids polling endpoint discovery.
        if let Some(url) = &self.relay_url {
            admitted.session_addr = admitted.session_addr.with_relay_url(url.clone());
        }
        RawGuest {
            identity,
            net,
            admitted,
        }
    }

    async fn close(mut self) {
        self.host.session._tasks.abort_all();
        while self.host.session._tasks.join_next().await.is_some() {}
        match &self.host.session.role {
            crate::Role::Host(host) => host.net.close().await,
            crate::Role::Guest(_) => panic!("expected a host fixture"),
        }
        self.host.identity.door.close().await;
        drop(self.host);
        if let Some(relay) = self.relay {
            relay.shutdown().await.unwrap();
        }
    }
}

// Reap the scoped Session and relay before propagating an assertion panic.
async fn catch_scenario(future: impl Future<Output = ()>) -> Result<(), Box<dyn Any + Send>> {
    let mut future = Box::pin(future);
    std::future::poll_fn(
        |cx| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(Poll::Ready(())) => Poll::Ready(Ok(())),
            Ok(Poll::Pending) => Poll::Pending,
            Err(panic) => Poll::Ready(Err(panic)),
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_41_end_refuses_bearer_join_after_final_clear() {
    let mut fixture = Fixture::new(true).await;
    let result = catch_scenario(async {
        let holding = fixture.bound_guest().await;
        let (holding_link, mut holding_ctl) = holding.connect().await.unwrap();
        let late = Fixture::identity().await;
        let late_net = fixture.guest_net().await;
        let ticket = fixture.host.bearer();
        let pending_identity = Fixture::identity().await;
        let pending_net = fixture.guest_net().await;
        let pending_ticket = fixture.host.bearer();
        let pending_join = request_join(&pending_identity, &pending_net, &pending_ticket);
        tokio::pin!(pending_join);
        let old = tokio::select! {
            reply = &mut pending_join => panic!("bearer answered without approval: {reply:?}"),
            approval = approval(&mut fixture.host) => approval,
        };
        let mut approvals = fixture.host.session.approvals();
        assert_eq!(approvals.borrow().len(), 1);
        let (at_drain, release) = hooks(&fixture.host).hold_end();
        let leave = fixture.host.session.command(Command::Leave);
        tokio::pin!(leave);
        tokio::select! {
            result = &mut leave => panic!("Leave escaped the held drain: {result:?}"),
            reached = tokio::time::timeout(WAIT, at_drain) => reached.unwrap().unwrap(),
        }
        assert!(
            approvals.borrow().is_empty(),
            "the existing prompt survived end"
        );
        assert_eq!(
            fixture
                .host
                .session
                .command(Command::Decide {
                    approval: old.id,
                    allow: true,
                })
                .await,
            Err(SessionError::Ended)
        );

        let late_join = request_join(&late, &late_net, &ticket);
        tokio::pin!(late_join);
        let reply = tokio::time::timeout(WAIT, async {
            tokio::select! {
                reply = &mut late_join => reply,
                changed = approvals.wait_for(|pending| !pending.is_empty()) => {
                    panic!("a join recreated approval state after the final clear: {changed:?}")
                }
                result = &mut leave => panic!("endpoint teardown escaped its hold: {result:?}"),
            }
        })
        .await
        .expect("the late join was not refused");
        assert_eq!(reply.err(), Some(NetError::Refused(JoinRefused::Declined)));
        assert!(approvals.borrow().is_empty());
        assert!(
            tokio::time::timeout(WAIT, &mut pending_join)
                .await
                .unwrap()
                .is_err()
        );
        release.send(()).unwrap();
        tokio::time::timeout(WAIT, async {
            loop {
                if holding_ctl.recv::<HostMsg>().await.unwrap() == HostMsg::End {
                    break;
                }
            }
        })
        .await
        .unwrap();
        holding_link.close();
        tokio::time::timeout(WAIT, &mut leave)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            event(&mut fixture.host.events, |event| match event {
                SessionEvent::Ended(reason) => Some(*reason),
                _ => None,
            })
            .await,
            EndReason::Left
        );
    })
    .await;
    fixture.close().await;
    if let Err(panic) = result {
        resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_18_end_refuses_delayed_hello_after_route_drain() {
    let fixture = Fixture::new(false).await;
    let result = catch_scenario(async {
        let holding = fixture.bound_guest().await;
        let (holding_link, mut holding_ctl) = holding.connect().await.unwrap();
        let delayed = fixture.bound_guest().await;
        let (delayed_link, mut delayed_ctl) = delayed
            .net
            .dial(delayed.admitted.session_addr.clone(), delayed.admitted.pass)
            .await
            .unwrap();
        let packet = LanDatagram {
            peer: PeerSlot::HOST,
            bcast: false,
            src_port: 50_000,
            dst_port: GAME_PORT,
            payload: b"live game frame".to_vec().into(),
        };
        holding_link.send_lan(&packet);
        assert_eq!(
            next_udp(&fixture.host.game, WAIT).await.unwrap().payload,
            b"live game frame"
        );
        let seen = hooks(&fixture.host).observe_hello(PeerRef {
            id: delayed.identity.id(),
            slot: delayed.admitted.pass.slot,
            generation: delayed.admitted.pass.generation,
        });
        let (at_drain, release) = hooks(&fixture.host).hold_end();
        let leave = fixture.host.session.command(Command::Leave);
        tokio::pin!(leave);
        tokio::select! {
            result = &mut leave => panic!("Leave escaped the held drain: {result:?}"),
            reached = tokio::time::timeout(WAIT, at_drain) => reached.unwrap().unwrap(),
        }
        delayed_ctl
            .send(&GuestMsg::Hello {
                generation: delayed.admitted.pass.generation,
            })
            .await
            .expect("Hello could not be written at the held open endpoint");
        tokio::time::timeout(WAIT, seen)
            .await
            .expect("Hello never reached admission processing at the held drain")
            .unwrap();
        let response = tokio::time::timeout(WAIT, delayed_ctl.recv::<HostMsg>())
            .await
            .unwrap();
        assert!(
            response.is_err(),
            "a delayed Hello activated a route after drain: {response:?}"
        );
        tokio::time::timeout(WAIT, delayed_link.closed())
            .await
            .unwrap();
        release.send(()).unwrap();
        tokio::time::timeout(WAIT, async {
            loop {
                if holding_ctl.recv::<HostMsg>().await.unwrap() == HostMsg::End {
                    break;
                }
            }
        })
        .await
        .unwrap();
        holding_link.close();
        tokio::time::timeout(WAIT, &mut leave)
            .await
            .unwrap()
            .unwrap();
        assert!(fixture.host.session.approvals().borrow().is_empty());
    })
    .await;
    fixture.close().await;
    if let Err(panic) = result {
        resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_rendezvous_is_scoped_to_one_session() {
    let held = Fixture::new(false).await;
    let independent = Fixture::new(false).await;
    let result = catch_scenario(async {
        let (at_drain, release) = hooks(&held.host).hold_end();
        let leave = held.host.session.command(Command::Leave);
        tokio::pin!(leave);
        tokio::select! {
            result = &mut leave => panic!("Leave escaped the held drain: {result:?}"),
            reached = tokio::time::timeout(WAIT, at_drain) => reached.unwrap().unwrap(),
        }
        tokio::time::timeout(WAIT, independent.host.session.command(Command::Leave))
            .await
            .unwrap()
            .unwrap();
        // Dropping the hold, including on unwind, must release its own worker.
        drop(release);
        tokio::time::timeout(WAIT, &mut leave)
            .await
            .unwrap()
            .unwrap();
    })
    .await;
    held.close().await;
    independent.close().await;
    if let Err(panic) = result {
        resume_unwind(panic);
    }
}

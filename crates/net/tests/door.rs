//! The door (§4.3, §6.3): join exchange, refusals, egress policy on tickets
//! and the post-handshake invalid-request budget.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use common::*;
use iroh::endpoint::ConnectionError;
use iroh::{EndpointAddr, RelayUrl, SecretKey, TransportAddr};
use kickoff_net::{Door, JOIN_ALPN, NetError, Role, SESSION_ALPN, door_loopback};
use kickoff_secret::Secret;
use kickoff_wire::{
    AdmitPass, Admitted, BuildId, Cap, Generation, JoinRefused, JoinRequest, KickoffVersion, Name,
    Nonce, PeerSlot, Platform, SessionId, Ticket,
};

const BUSY: u32 = 7;
const PROTOCOL: u32 = 6;

async fn door() -> Door {
    door_loopback(&Secret::new(SecretKey::generate()))
        .await
        .unwrap()
}

fn ticket(to: EndpointAddr, invitee: Option<iroh::EndpointId>) -> Secret<Ticket> {
    let signer = SecretKey::generate();
    Secret::new(Ticket {
        door: to,
        cap: Cap {
            session_id: SessionId([1; 16]),
            invitee,
            nonce: Nonce([2; 16]),
            sig: signer.sign(b"fixture"),
        },
    })
}

fn request(session_key: iroh::EndpointId) -> JoinRequest {
    JoinRequest {
        cap: Cap {
            session_id: SessionId([1; 16]),
            invitee: None,
            nonce: Nonce([2; 16]),
            sig: SecretKey::generate().sign(b"fixture"),
        },
        session_key,
        name: Name::new("guest").unwrap(),
        platform: Platform::Linux,
        game_build: BuildId::new("build-1").unwrap(),
        kickoff_version: KickoffVersion {
            major: 0,
            minor: 1,
            patch: 0,
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn join_exchange_carries_the_authenticated_id_and_the_answer() {
    let host_door = door().await;
    let guest_door = door().await;
    let host_session = node(Role::Host).await;
    let guest_session = node(Role::Guest).await;
    let admitted = Admitted {
        session_addr: host_session.addr(),
        pass: AdmitPass {
            slot: PeerSlot::new(2).unwrap(),
            generation: Generation::new(1),
        },
    };

    let t = ticket(host_door.addr(), Some(guest_door.id()));
    let guest = guest_door.request_join(&t, request(guest_session.id()));
    let host = async {
        let attempt = tokio::time::timeout(WAIT, host_door.next_join())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(attempt.id(), guest_door.id(), "the id is TLS-authenticated");
        assert_eq!(attempt.request().session_key, guest_session.id());
        assert_eq!(attempt.request().name.as_str(), "guest");
        attempt.answer(Ok(admitted.clone())).await
    };
    let (got, answered) = tokio::join!(guest, host);
    answered.unwrap();
    assert_eq!(got.unwrap(), admitted);

    let t = ticket(host_door.addr(), None);
    let guest = guest_door.request_join(&t, request(guest_session.id()));
    let host = async {
        let attempt = host_door.next_join().await.unwrap();
        attempt.answer(Err(JoinRefused::Declined)).await
    };
    let (got, _) = tokio::join!(guest, host);
    assert_eq!(got.err(), Some(NetError::Refused(JoinRefused::Declined)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_29_ticket_destinations_outside_the_policy_are_never_dialed() {
    let host_door = door().await;
    let guest_door = door().await;
    let id = host_door.id();
    let real_port = host_door.addr().ip_addrs().next().unwrap().port();
    let hostile = [
        vec![TransportAddr::Relay(
            "https://evil.example".parse::<RelayUrl>().unwrap(),
        )],
        vec![TransportAddr::Ip(
            format!("8.8.8.8:{real_port}").parse().unwrap(),
        )],
        vec![TransportAddr::Ip(
            format!("10.75.0.1:{real_port}").parse().unwrap(),
        )],
        vec![TransportAddr::Ip(
            format!("100.64.0.1:{real_port}").parse().unwrap(),
        )],
        vec![TransportAddr::Ip(
            format!("[::1]:{real_port}").parse().unwrap(),
        )],
        vec![TransportAddr::Ip("127.0.0.1:0".parse().unwrap())],
    ];
    for addrs in hostile {
        let t = ticket(EndpointAddr::from_parts(id, addrs), None);
        let start = Instant::now();
        let got = guest_door
            .request_join(&t, request(SecretKey::generate().public()))
            .await;
        assert_eq!(got.err(), Some(NetError::Egress));
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "refused only after trying"
        );
    }
    let nothing = tokio::time::timeout(Duration::from_millis(300), host_door.next_join()).await;
    assert!(nothing.is_err(), "a refused ticket still reached the door");
}

async fn close_code(conn: &iroh::endpoint::Connection) -> Option<u32> {
    match tokio::time::timeout(WAIT, conn.closed()).await.ok()? {
        ConnectionError::ApplicationClosed(close) => {
            u32::try_from(close.error_code.into_inner()).ok()
        }
        _ => None,
    }
}

/// Sends one join frame whose body is not a `JoinRequest`.
async fn invalid_join(ep: &iroh::Endpoint, door: &Door) -> Option<u32> {
    let conn = ep.connect(door.addr(), JOIN_ALPN).await.ok()?;
    if let Ok((mut send, _recv)) = conn.open_bi().await {
        let _ = send.write_all(&[0, 0, 0, 3, 0xff, 0xff, 0xff]).await;
        let _ = send.finish();
    }
    close_code(&conn).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_23_invalid_join_requests_exhaust_only_their_own_identity() {
    let host_door = door().await;
    let flooder = raw_endpoint().await;
    for n in 0..10 {
        assert_eq!(
            invalid_join(&flooder, &host_door).await,
            Some(PROTOCOL),
            "attempt {n} is read and refused"
        );
    }
    assert_eq!(
        invalid_join(&flooder, &host_door).await,
        Some(BUSY),
        "the 11th is turned away unread"
    );

    let friend = raw_endpoint().await;
    assert_eq!(
        invalid_join(&friend, &host_door).await,
        Some(PROTOCOL),
        "another identity is still read"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn door_speaks_only_the_join_alpn() {
    let host_door = door().await;
    let ep = raw_endpoint().await;
    assert!(raw_dial(&ep, host_door.addr(), SESSION_ALPN).await.is_err());
}

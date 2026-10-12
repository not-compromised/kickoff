//! The door (§4.3, §6.3): join exchange, refusals, egress policy on tickets
//! and the post-handshake invalid-request budget.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use kickoff_secret::key::IdentityKey;
use std::net::Ipv4Addr;
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
/// Slower than the per-source handshake rate (8/s), so a test about another
/// limit is never refused by that one.
const HANDSHAKE_SPACING: Duration = Duration::from_millis(150);
const PROTOCOL: u32 = 6;

async fn door() -> Door {
    door_loopback(&IdentityKey::new(SecretKey::generate()))
        .await
        .unwrap()
}

fn ticket(to: EndpointAddr, invitee: Option<iroh::EndpointId>) -> Secret<Ticket> {
    let signer = SecretKey::generate();
    let issuer = to.id;
    Secret::new(Ticket {
        door: to,
        cap: Cap::new_for_door(
            issuer,
            SessionId([1; 16]),
            invitee,
            Nonce([2; 16]),
            signer.sign(b"fixture"),
        ),
    })
}

fn request(session_key: iroh::EndpointId, issuer: iroh::EndpointId) -> JoinRequest {
    JoinRequest {
        cap: Cap::new_for_door(
            issuer,
            SessionId([1; 16]),
            None,
            Nonce([2; 16]),
            SecretKey::generate().sign(b"fixture"),
        ),
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
    let guest = guest_door.request_join(&t, request(guest_session.id(), host_door.id()));
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
    let guest = guest_door.request_join(&t, request(guest_session.id(), host_door.id()));
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
            .request_join(&t, request(SecretKey::generate().public(), host_door.id()))
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

/// The flooder paces its attempts below the per-source handshake rate (8/s)
/// and its friend has its own loopback address, so that rate never decides
/// an attempt here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_23_invalid_join_requests_exhaust_only_their_own_identity() {
    let host_door = door().await;
    let flooder = raw_endpoint().await;
    for n in 0..10 {
        if n >= 4 {
            tokio::time::sleep(HANDSHAKE_SPACING).await;
        }
        assert_eq!(
            invalid_join(&flooder, &host_door).await,
            Some(PROTOCOL),
            "attempt {n} is read and refused"
        );
    }
    tokio::time::sleep(HANDSHAKE_SPACING).await;
    assert_eq!(
        invalid_join(&flooder, &host_door).await,
        Some(BUSY),
        "the 11th is turned away unread"
    );

    let friend = raw_endpoint_at(Ipv4Addr::new(127, 0, 2, 1)).await;
    assert_eq!(
        invalid_join(&friend, &host_door).await,
        Some(PROTOCOL),
        "another identity is still read"
    );
}

/// SI-23: completed handshakes that never send a `JoinRequest`. One identity
/// holds at most two such connections; the third is closed at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_23_door_holds_two_silent_connections_per_identity() {
    let host_door = door().await;
    let silent = raw_endpoint().await;
    let mut held = Vec::new();
    for _ in 0..2 {
        held.push(silent.connect(host_door.addr(), JOIN_ALPN).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let third = silent.connect(host_door.addr(), JOIN_ALPN).await.unwrap();
    assert_eq!(
        close_code(&third).await,
        Some(BUSY),
        "a third silent connection"
    );
    assert!(held.iter().all(|c| c.close_reason().is_none()));

    let other = raw_endpoint().await;
    let theirs = other.connect(host_door.addr(), JOIN_ALPN).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), theirs.closed())
            .await
            .is_err(),
        "another identity was turned away"
    );
}

/// SI-23: at most 16 connections await a `JoinRequest` at once, whoever
/// holds them. Each silent connection here comes from its own address and
/// identity, so only that cap can turn the seventeenth away.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_23_door_caps_connections_awaiting_a_join_request() {
    let host_door = door().await;
    let mut held = Vec::new();
    for n in 0..16u8 {
        let ep = raw_endpoint_at(Ipv4Addr::new(127, 0, 1, n.wrapping_add(1))).await;
        let conn = ep.connect(host_door.addr(), JOIN_ALPN).await.unwrap();
        held.push((ep, conn));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let late = raw_endpoint_at(Ipv4Addr::new(127, 0, 1, 100)).await;
    let conn = late.connect(host_door.addr(), JOIN_ALPN).await.unwrap();
    assert_eq!(
        close_code(&conn).await,
        Some(BUSY),
        "a seventeenth awaiting connection"
    );
    assert!(held.iter().all(|(_, c)| c.close_reason().is_none()));
}

/// SI-23: a silent connection is closed at the 5 s join deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_23_door_closes_silent_connections_at_the_join_deadline() {
    let host_door = door().await;
    let silent = raw_endpoint().await;
    let conn = silent.connect(host_door.addr(), JOIN_ALPN).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(8), conn.closed()).await;
    assert!(
        closed.is_ok(),
        "a silent connection outlived the join deadline"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn door_speaks_only_the_join_alpn() {
    let host_door = door().await;
    let ep = raw_endpoint().await;
    assert!(raw_dial(&ep, host_door.addr(), SESSION_ALPN).await.is_err());
}

/// Real QUIC receive credit is zero, while client-to-server writes remain usable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_23_door_reply_write_and_linger_share_one_deadline() {
    let host = door().await;
    let guest = raw_endpoint_with_window(Ipv4Addr::LOCALHOST, 0).await;
    let conn = guest.connect(host.addr(), JOIN_ALPN).await.unwrap();
    let _recv = kickoff_wire::prepare_message(&request(guest.id(), host.id()))
        .unwrap()
        .transmit_quic(&conn)
        .await
        .unwrap();
    let attempt = tokio::time::timeout(WAIT, host.next_join())
        .await
        .unwrap()
        .unwrap();
    let answer = attempt.answer(Err(JoinRefused::InvalidCap));
    tokio::pin!(answer);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut answer)
            .await
            .is_err(),
        "the zero-credit write did not block"
    );
    assert!(conn.close_reason().is_none());
    assert!(
        tokio::time::timeout(Duration::from_secs(6), &mut answer)
            .await
            .is_ok(),
        "zero reply credit held the answer beyond its complete lifetime"
    );
    assert!(tokio::time::timeout(WAIT, conn.closed()).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn si_30_join_transmission_requires_its_issuing_door_before_opening_a_stream() {
    let issuer_key = SecretKey::generate();
    let issuer = receiving_endpoint(issuer_key.clone()).await;
    let attacker = receiving_endpoint(SecretKey::generate()).await;
    let guest = raw_endpoint().await;
    let (dialed, accepted) = tokio::join!(guest.connect(attacker.addr(), JOIN_ALPN), async {
        attacker.accept().await.unwrap().await.unwrap()
    });
    let wrong = dialed.unwrap();
    let identity = IdentityKey::new(issuer_key.clone());
    let mut invites = kickoff_wire::Invites::new(&identity).unwrap();
    let mut outbound = request(guest.id(), issuer.id());
    outbound.cap = invites.issue(&identity, None, Instant::now()).unwrap();
    assert!(
        kickoff_wire::prepare_message(&outbound)
            .unwrap()
            .transmit_quic(&wrong)
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), accepted.accept_bi())
            .await
            .is_err(),
        "wrong door observed an opened secret stream"
    );
    wrong.close(iroh::endpoint::VarInt::from_u32(0), b"");
    let (dialed, accepted) = tokio::join!(guest.connect(issuer.addr(), JOIN_ALPN), async {
        issuer.accept().await.unwrap().await.unwrap()
    });
    let right = dialed.unwrap();
    let (sent, received) = tokio::join!(
        kickoff_wire::prepare_message(&outbound)
            .unwrap()
            .transmit_quic(&right),
        async {
            let (_send, mut recv) = accepted.accept_bi().await.unwrap();
            let mut prefix = [0; 4];
            recv.read_exact(&mut prefix).await.unwrap();
            let mut body = kickoff_secret::SecretBuffer::zeroed(
                kickoff_wire::frame_len::<JoinRequest>(prefix).unwrap(),
            );
            recv.read_exact(&mut body).await.unwrap();
            kickoff_wire::decode::<JoinRequest>(&body).unwrap()
        }
    );
    let _reply = sent.unwrap();
    assert_eq!(received.name.as_str(), outbound.name.as_str());
    assert!(
        kickoff_wire::prepare_message(&received)
            .unwrap()
            .transmit_quic(&right)
            .await
            .is_err(),
        "receiving a raw join minted retransmission authority"
    );
    // Receiving the valid capability cannot regain export authority by
    // wrapping it in a Ticket and round-tripping through the text encoder.
    let address =
        EndpointAddr::new(issuer.id()).with_relay_url("https://relay.example./".parse().unwrap());
    let original = Secret::new(Ticket {
        door: address.clone(),
        cap: outbound.cap.copy_for_join(),
    });
    let text = kickoff_wire::encode_ticket(&original).unwrap();
    assert!(kickoff_wire::TicketTextValue::parse(&text).is_ok());
    let received_ticket = Secret::new(Ticket {
        door: address,
        cap: received.cap.copy_for_join(),
    });
    assert!(
        kickoff_wire::encode_ticket(&received_ticket).is_err(),
        "a received capability regained export authority through a Ticket"
    );
    right.close(iroh::endpoint::VarInt::from_u32(0), b"");
    guest.close().await;
    attacker.close().await;
    issuer.close().await;
}

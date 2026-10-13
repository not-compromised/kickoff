//! Compile real downstream crates: successful controls keep missing dependencies
//! and compiler errors unrelated to ownership from counting as a boundary proof.

#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;

fn configured_features() -> Vec<&'static str> {
    let mut features = Vec::new();
    macro_rules! feature {
        ($name:literal) => {
            if cfg!(feature = $name) {
                features.push($name);
            }
        };
    }
    feature!("mutant-si3-path-field");
    feature!("mutant-si20-nonatomic-nonce");
    feature!("mutant-si20-bearer-never-expires");
    feature!("mutant-si20-any-session");
    feature!("mutant-si20-bound-any-requester");
    feature!("mutant-si23-trust-declared-length");
    feature!("mutant-si23-unbounded-lists");
    feature!("mutant-si23-no-message-cap");
    feature!("mutant-si23-no-frame-cap");
    feature!("mutant-si29-door-with-ip");
    feature!("mutant-si30-cap-debug");
    feature!("mutant-si30-open-owner");
    feature!("mutant-si30-cap-repr-no-wipe");
    feature!("mutant-si30-readable-transmission");
    feature!("mutant-si30-public-join-encoder");
    feature!("mutant-si30-ticket-transport");
    feature!("mutant-si30-recipient-unbound");
    feature!("mutant-si30-ticket-issuer-unchecked");
    features
}

fn compile(source: &str) -> std::process::Output {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let _serial = SERIAL.lock().unwrap();
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let wire = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = wire.parent().unwrap().parent().unwrap();
    let temp = std::env::temp_dir().join(format!(
        "kickoff-secret-owner-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir_all(temp.join("src")).unwrap();
    let features = configured_features()
        .iter()
        .map(|f| format!("{f:?}"))
        .collect::<Vec<_>>()
        .join(",");
    // Every probe shares one target directory, and as its own workspace root
    // each has the same path identity, so one package name would make every
    // probe the same Cargo unit. A probe written while another process held
    // the target lock then predates that build's output, and Cargo reports the
    // other probe's result as fresh. Naming the package after its source
    // makes a reused result always the result of this same program.
    let name = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::hash::DefaultHasher::new();
        source.hash(&mut hasher);
        format!("secret-owner-consumer-{:016x}", hasher.finish())
    };
    let manifest = format!(
        r#"
[package]
name = "{name}"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
kickoff-wire = {{ path = {wire:?}, features = [{features}] }}
kickoff-secret = {{ path = {secret:?} }}
kickoff-local = {{ path = {local:?} }}
iroh = {{ version = "=1.3.0", default-features = false, features = ["tls-ring"] }}
tokio = {{ version = "=1.53.2", default-features = false, features = ["net"] }}
[patch.crates-io]
iroh = {{ path = {iroh:?} }}
noq = {{ path = {noq:?} }}
"#,
        secret = root.join("crates/secret"),
        local = root.join("crates/local"),
        iroh = root.join("vendor/iroh-1.3.0"),
        noq = root.join("vendor/noq-1.3.0")
    );
    std::fs::write(temp.join("Cargo.toml"), manifest).unwrap();
    std::fs::copy(root.join("Cargo.lock"), temp.join("Cargo.lock")).unwrap();
    std::fs::write(temp.join("src/lib.rs"), source).unwrap();
    // A separate target avoids the outer Cargo test's target lock. Cargo
    // resolves the actual path dependencies and this test's enabled features;
    // no artifact is selected by whether its owner policy passes the test.
    let executable = std::env::current_exe().unwrap();
    let target = executable
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("owner-probe");
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .arg("check")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(temp.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_BUILD_JOBS", "2")
        .output()
        .unwrap();
    std::fs::remove_dir_all(temp).unwrap();
    output
}

#[test]
fn si_30_unrelated_consumers_cannot_expose_or_replace_secret_owners() {
    let control = compile(
        r#"
        use kickoff_secret::Secret;
        use kickoff_wire::Ticket;
        fn consume(ticket: &Secret<Ticket>) { let _ = ticket; }
    "#,
    );
    assert!(
        control.status.success(),
        "{}",
        String::from_utf8_lossy(&control.stderr)
    );
    let operations = compile(
        r#"
        use kickoff_secret::{Secret, key::{IdentityKey, KeyEndpoint}};
        use kickoff_wire::{Cap, Ticket};
        fn use_operations(ticket: &Secret<Ticket>, cap: &Cap, key: &IdentityKey, ep: &KeyEndpoint) {
            let _ = Ticket::is_bearer(ticket); let _ = Ticket::join_cap(ticket);
            let _ = cap.invitee(); let _ = key.public(); let _ = ep.id();
        }
    "#,
    );
    assert!(
        operations.status.success(),
        "{}",
        String::from_utf8_lossy(&operations.stderr)
    );
    let original = compile(
        r#"
        use kickoff_secret::Secret;
        use kickoff_wire::Ticket;
        fn steal(ticket: &Secret<Ticket>) { ticket.expose(|raw: &Ticket| { let _ = raw.cap; }); }
    "#,
    );
    assert!(
        !original.status.success(),
        "an unrelated consumer can expose a ticket"
    );
    assert!(
        String::from_utf8_lossy(&original.stderr).contains("E0061"),
        "{}",
        String::from_utf8_lossy(&original.stderr)
    );
    let substitute = compile(
        r#"
        use kickoff_secret::{Secret, OwnedSecret};
        use kickoff_wire::Ticket;
        fn steal(ticket: &Secret<Ticket>) { ticket.expose(&(), |raw| { let _ = raw.door.clone(); }); }
    "#,
    );
    assert!(
        !substitute.status.success(),
        "a substitute token grants raw access"
    );
    assert!(
        String::from_utf8_lossy(&substitute.stderr).contains("E0308"),
        "{}",
        String::from_utf8_lossy(&substitute.stderr)
    );
    let default_owner = compile(
        r#"
        use kickoff_secret::{Secret, OwnedSecret};
        use kickoff_wire::Ticket;
        fn steal(ticket: &Secret<Ticket>) {
            let owner: <Ticket as OwnedSecret>::Consumer = Default::default();
            ticket.expose(&owner, |raw| { let _ = raw.door.clone(); });
        }
    "#,
    );
    assert!(
        !default_owner.status.success(),
        "an unrelated consumer manufactured the owner through Default"
    );
    assert!(String::from_utf8_lossy(&default_owner.stderr).contains("E0277"));
    let constructor = compile(
        r#"
        use kickoff_secret::{Secret, OwnedSecret};
        use kickoff_wire::Ticket;
        type Owner = <Ticket as OwnedSecret>::Consumer;
        fn steal(ticket: &Secret<Ticket>) {
            let owner = Owner { _private: () };
            ticket.expose(&owner, |raw| { let _ = raw.door.clone(); });
        }
    "#,
    );
    assert!(
        !constructor.status.success(),
        "an unrelated consumer constructed the private owner"
    );
    assert!(
        String::from_utf8_lossy(&constructor.stderr).contains("E0451"),
        "{}",
        String::from_utf8_lossy(&constructor.stderr)
    );
    let replaced = compile(
        r#"
        use kickoff_secret::OwnedSecret;
        use kickoff_wire::Ticket;
        impl OwnedSecret for Ticket { type Consumer = (); }
    "#,
    );
    assert!(
        !replaced.status.success(),
        "another crate replaced the existing secret's owner"
    );
    assert!(
        String::from_utf8_lossy(&replaced.stderr).contains("E0117"),
        "{}",
        String::from_utf8_lossy(&replaced.stderr)
    );
    let raw_cap = compile(
        r#"
        use kickoff_wire::Cap;
        fn steal(cap: &Cap) { let _ = cap.sig; }
    "#,
    );
    assert!(
        !raw_cap.status.success(),
        "the protected capability still exposes raw fields"
    );
    assert!(
        String::from_utf8_lossy(&raw_cap.stderr).contains("E0609"),
        "{}",
        String::from_utf8_lossy(&raw_cap.stderr)
    );
    let key = compile(
        r#"
        use kickoff_secret::key::IdentityKey;
        fn steal(key: &IdentityKey) { let _ = key.expose(|raw| raw.clone()); }
    "#,
    );
    assert!(
        !key.status.success(),
        "the identity adapter returns its raw key"
    );
    assert!(
        String::from_utf8_lossy(&key.stderr).contains("E0599"),
        "{}",
        String::from_utf8_lossy(&key.stderr)
    );
    let endpoint = compile(
        r#"
        use kickoff_secret::key::KeyEndpoint;
        fn steal(ep: &KeyEndpoint) { let _ = ep.secret_key(); }
    "#,
    );
    assert!(
        !endpoint.status.success(),
        "the endpoint adapter returns its raw key"
    );
    assert!(
        String::from_utf8_lossy(&endpoint.stderr).contains("E0599"),
        "{}",
        String::from_utf8_lossy(&endpoint.stderr)
    );
    let deref = compile(
        r#"
        use kickoff_secret::key::KeyEndpoint;
        fn steal(ep: &KeyEndpoint) { let _ = std::ops::Deref::deref(ep); }
    "#,
    );
    assert!(
        !deref.status.success(),
        "the endpoint adapter dereferences to a raw endpoint"
    );
    assert!(
        String::from_utf8_lossy(&deref.stderr).contains("E0277"),
        "{}",
        String::from_utf8_lossy(&deref.stderr)
    );
    let identity_owner = compile(
        r#"
        use kickoff_secret::{OwnedSecret, key::IdentityKey};
        impl OwnedSecret for IdentityKey { type Consumer = (); }
    "#,
    );
    assert!(
        !identity_owner.status.success(),
        "another consumer replaced the identity owner"
    );
    assert!(
        String::from_utf8_lossy(&identity_owner.stderr).contains("E0117"),
        "{}",
        String::from_utf8_lossy(&identity_owner.stderr)
    );
}

#[test]
fn si_30_unrelated_holders_cannot_copy_serialized_secrets() {
    let controls = compile(
        r#"
        use kickoff_secret::Secret;
        use kickoff_wire::{Ticket, TicketTextValue, JoinRequest, HostMsg, WireError};
        fn ordinary(msg: &HostMsg) { let _ = kickoff_wire::encode(msg).unwrap().to_vec(); }
        async fn authorized(ticket: &Secret<Ticket>, request: &JoinRequest,
            local: &mut kickoff_local::InstalledPeer<'_>, quic: &iroh::endpoint::Connection)
            -> Result<(), Box<dyn std::error::Error>> {
            let text = kickoff_wire::encode_ticket(ticket)?;
            TicketTextValue::postcard_frame(&text, 2)?.transmit_local(local).await?;
            kickoff_wire::prepare_message(request)?.transmit_quic(quic).await?;
            Ok(())
        }
    "#,
    );
    assert!(
        controls.status.success(),
        "{}",
        String::from_utf8_lossy(&controls.stderr)
    );
    for (source, diagnostic) in [
        (
            r#"
            use kickoff_secret::Secret;
            use kickoff_wire::{Ticket, TicketTextValue, WireError, encode_ticket};
            fn copy(ticket: &Secret<Ticket>) -> Result<Vec<u8>, WireError> {
                let text = encode_ticket(ticket)?;
                Ok(TicketTextValue::transport(&text).to_vec())
            }
        "#,
            "transport",
        ),
        (
            r#"
            use kickoff_wire::JoinRequest;
            fn copy(request: &JoinRequest) -> Vec<u8> {
                kickoff_wire::encode(request).unwrap().to_vec()
            }
        "#,
            "PublicWireMessage",
        ),
        (
            r#"
            use kickoff_wire::JoinRequest;
            fn copy(request: &JoinRequest) -> Vec<u8> {
                kickoff_wire::encode_framed(request).unwrap().to_vec()
            }
        "#,
            "PublicWireMessage",
        ),
        (
            r#"
            use kickoff_wire::JoinRequest;
            fn copy(request: &JoinRequest) -> Vec<u8> {
                kickoff_wire::prepare_message(request).unwrap().to_vec()
            }
        "#,
            "to_vec",
        ),
        (
            r#"
            use kickoff_wire::WireMessage;
            fn copy<M: WireMessage>(request: &M) -> Vec<u8> {
                request.write().unwrap().to_vec()
            }
        "#,
            "to_vec",
        ),
        (
            r#"
            use kickoff_wire::JoinRequest;
            fn copy(request: &JoinRequest) {
                let frame = kickoff_wire::prepare_message(request).unwrap();
                let _ = std::ops::Deref::deref(&frame);
            }
        "#,
            "Deref",
        ),
        (
            r#"
            use kickoff_wire::JoinRequest;
            fn copy(request: &JoinRequest) {
                let frame = kickoff_wire::prepare_message(request).unwrap();
                let _ = frame.body;
            }
        "#,
            "private",
        ),
        (
            r#"
            use kickoff_wire::JoinRequest;
            impl kickoff_wire::PublicWireMessage for JoinRequest {}
        "#,
            "E0117",
        ),
        (
            r#"
            use kickoff_local::{InstalledPeer, DataOnly};
            fn fake(stream: &mut DataOnly) {
                let _ = InstalledPeer { transport: stream, _pidfd: None };
            }
        "#,
            "private",
        ),
        (
            r#"
            use kickoff_local::InstalledPeer;
            fn raw(peer: &InstalledPeer<'_>) { let _ = std::ops::Deref::deref(peer); }
        "#,
            "Deref",
        ),
        (
            r#"
            use kickoff_local::DataOnly;
            fn raw(peer: &mut DataOnly) { let _ = peer.unix_mut(); }
        "#,
            "unix_mut",
        ),
        (
            r#"
            use kickoff_secret::Secret;
            use kickoff_wire::TicketTextValue;
            fn callback(text: &Secret<TicketTextValue>) {
                let _ = TicketTextValue::postcard_frame(text, |raw: &str| raw.to_owned());
            }
        "#,
            "u32",
        ),
        (
            r#"
            use kickoff_wire::JoinRequest;
            async fn copy(request: &JoinRequest) {
                let mut raw = Vec::new();
                kickoff_wire::prepare_message(request).unwrap().transmit_local(&mut raw).await.unwrap();
            }
        "#,
            "InstalledPeer",
        ),
    ] {
        let output = compile(source);
        assert!(
            !output.status.success(),
            "an unrelated holder can copy serialized secrets: {source}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(diagnostic),
            "wrong compiler boundary: {stderr}"
        );
    }
}

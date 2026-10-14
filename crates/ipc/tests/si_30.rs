//! SI-30 for the local channels: a ticket crossing the socket is a secret
//! the whole way, and no type that holds one prints it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

mod common;

use common::*;
use kickoff_ipc::role::{Cli, UiMain};
use kickoff_ipc::{
    CliCommand, InviteFor, IpcError, Reply, Request, TicketText, UiCommand, connect,
};

const CANARY: &str = "kickoff1CANARYQ7XZ3T2WVB";

/// True if any 8-character window of the canary's distinctive part appears
/// in `text`, in any case: catches partial, re-cased and chunked leaks.
fn leaks(text: &str) -> bool {
    let needle = CANARY["kickoff1".len()..].to_ascii_lowercase();
    let hay = text.to_ascii_lowercase();
    let bytes = needle.as_bytes();
    bytes
        .windows(8)
        .any(|w| hay.contains(std::str::from_utf8(w).unwrap()))
}

fn ticket() -> TicketText {
    canary_ticket(CANARY)
}

fn assert_quiet(what: &str, text: String) {
    assert!(!leaks(&text), "{what} printed the canary: {text}");
}

#[test]
fn si_30_leak_check_sees_a_leak() {
    // The scanner itself must fire, or every check below proves nothing.
    assert!(leaks(CANARY));
    assert!(leaks(&CANARY.to_lowercase()));
    assert!(leaks(&format!("x={}", &CANARY[10..20])));
}

#[test]
fn si_30_every_ipc_type_holding_a_ticket_redacts_it() {
    let values: Vec<(&str, Box<dyn std::fmt::Debug>)> = vec![
        ("TicketText", Box::new(ticket())),
        ("CliCommand::Join", Box::new(CliCommand::Join(ticket()))),
        ("UiCommand::Join", Box::new(UiCommand::Join(ticket()))),
        (
            "Request::Cli",
            Box::new(Request::Cli(CliCommand::Join(ticket()))),
        ),
        (
            "Request::UiMain",
            Box::new(Request::UiMain(UiCommand::Join(ticket()))),
        ),
        ("Reply::Invite", Box::new(Reply::Invite(ticket()))),
        (
            "Result<Reply>",
            Box::new(Ok::<Reply, IpcError>(Reply::Invite(ticket()))),
        ),
    ];
    for (what, value) in values {
        assert_quiet(what, format!("{value:?}"));
        assert_quiet(what, format!("{value:#?}"));
    }
}

/// A rejected ticket's error carries nothing of it either.
#[test]
fn si_30_rejected_ticket_error_is_silent() {
    let bad = format!("{CANARY}/../x");
    let err = TicketText::new(kickoff_wire::TicketTextValue::protect(bad)).unwrap_err();
    assert_quiet("IpcError", format!("{err} {err:?}"));
}

/// End to end: the ticket arrives intact at the daemon, which can use it,
/// while everything either side can print stays clean.
#[tokio::test]
async fn si_30_ticket_crosses_the_socket_without_being_printed() {
    if !installed_fixture("si_30_ticket_crosses_the_socket_without_being_printed") {
        return;
    }
    let base = TempBase::new();
    let dir = base.dir();
    let daemon = InstalledDaemon::start(&base, "join");

    let mut client = connect::<Cli>(&dir, &trust_me()).await.unwrap();
    let reply = client.call(CliCommand::Join(ticket())).await.unwrap();
    assert_quiet("Client", format!("{client:?} {reply:?}"));
    for printed in daemon.finish().await {
        assert_quiet("daemon side", printed);
    }
}

#[tokio::test]
async fn si_30_invite_reply_is_redacted_on_the_client() {
    if !installed_fixture("si_30_invite_reply_is_redacted_on_the_client") {
        return;
    }
    let base = TempBase::new();
    let dir = base.dir();
    let daemon = InstalledDaemon::start(&base, "invite");
    let mut client = connect::<UiMain>(&dir, &trust_me()).await.unwrap();
    let reply = client
        .call(UiCommand::Invite(InviteFor::Bearer))
        .await
        .unwrap();
    assert_quiet("Reply", format!("{reply:?}"));
    let Reply::Invite(t) = reply else {
        panic!("expected Invite")
    };
    assert!(t.secret().ct_eq(CANARY.as_bytes()));
    for printed in daemon.finish().await {
        assert_quiet("daemon side", printed);
    }
}

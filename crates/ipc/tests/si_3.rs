//! SI-3: no IPC command can express "EAC on", a game path, a URL, launch
//! arguments or a write outside the copy.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use kickoff_ipc::{CliCommand, InviteFor, OverlayCommand, Reply, Server, TicketText, UiCommand};

use tokio::io::AsyncWriteExt;

/// What a command argument can be. Everything here is either fixed-size
/// binary or a ticket in a closed alphabet.
#[derive(Debug, PartialEq, Eq)]
enum Arg {
    Ticket,
    Invitee,
    Identity,
    Map,
    Approval,
}

// These matches have no wildcard arm on purpose: a new command variant does
// not compile until it is classified here, and the classification is checked
// against the denylist below.
fn cli_args(c: &CliCommand) -> Vec<Arg> {
    match c {
        CliCommand::Status
        | CliCommand::Host
        | CliCommand::Leave
        | CliCommand::Doctor
        | CliCommand::ToggleOverlay => vec![],
        CliCommand::Join(_) => vec![Arg::Ticket],
        CliCommand::Invite(_) => vec![Arg::Invitee],
    }
}

fn ui_args(c: &UiCommand) -> Vec<Arg> {
    match c {
        UiCommand::Status | UiCommand::Host | UiCommand::Leave | UiCommand::Doctor => vec![],
        UiCommand::Join(_) => vec![Arg::Ticket],
        UiCommand::Invite(_) => vec![Arg::Invitee],
        UiCommand::Kick(_) => vec![Arg::Identity],
        UiCommand::Decide { .. } => vec![Arg::Approval],
        UiCommand::PickMap(_) => vec![Arg::Map],
    }
}

fn overlay_args(c: &OverlayCommand) -> Vec<Arg> {
    match c {
        OverlayCommand::Status => vec![],
    }
}

fn reply_args(r: &Reply) -> Vec<Arg> {
    match r {
        Reply::Done | Reply::Refused(_) | Reply::Report(_) => vec![],
        Reply::Invite(_) => vec![Arg::Ticket],
    }
}

fn ticket(text: &str) -> TicketText {
    TicketText::new(kickoff_wire::TicketTextValue::protect(text.to_owned())).unwrap()
}

fn id() -> iroh_base::EndpointId {
    iroh_base::SecretKey::from_bytes(&[7; 32]).public()
}

#[test]
fn si_3_no_command_carries_a_path_url_eac_mode_or_launch_args() {
    let allowed = [
        Arg::Ticket,
        Arg::Invitee,
        Arg::Identity,
        Arg::Map,
        Arg::Approval,
    ];
    let cli = [
        CliCommand::Status,
        CliCommand::Host,
        CliCommand::Join(ticket("kickoff1AB")),
        CliCommand::Invite(InviteFor::Bearer),
        CliCommand::Leave,
        CliCommand::Doctor,
        CliCommand::ToggleOverlay,
    ];
    let ui = [
        UiCommand::Status,
        UiCommand::Host,
        UiCommand::Join(ticket("kickoff1AB")),
        UiCommand::Invite(InviteFor::Friend(id())),
        UiCommand::Kick(id()),
        UiCommand::Decide {
            approval: kickoff_ipc::ApprovalId::from_bytes([1; 16]),
            allow: true,
        },
        UiCommand::PickMap(kickoff_wire::MapId([0; 32])),
        UiCommand::Leave,
        UiCommand::Doctor,
    ];
    let args = cli
        .iter()
        .flat_map(cli_args)
        .chain(ui.iter().flat_map(ui_args))
        .chain(overlay_args(&OverlayCommand::Status))
        .chain(reply_args(&Reply::Invite(ticket("kickoff1AB"))));
    for arg in args {
        assert!(allowed.contains(&arg), "{arg:?}");
    }
}

/// The one text argument cannot hold anything path-, URL-, option- or
/// escape-shaped.
#[test]
fn si_3_ticket_text_cannot_hold_path_url_or_option() {
    for hostile in [
        "/home/user/.steam/steamapps/common/rocketleague",
        "../../../../etc/passwd",
        "C:\\Program Files\\Epic Games\\rocketleague",
        "https://evil.example/x",
        "file:///etc/shadow",
        "kickoff://join/ABC",
        "-noeac",
        "--eac=on",
        "kickoff1ABC -AUTH_PASSWORD=x",
        "kickoff1ABC\n-EpicPortal",
        "kickoff1%2Fetc",
        "kickoff1ABC;rm",
        "kickoff1ÄBC",
        "",
    ] {
        assert!(
            TicketText::new(kickoff_wire::TicketTextValue::protect(hostile.to_owned())).is_err(),
            "{hostile:?}"
        );
    }
    let longest = "A".repeat(kickoff_wire::MAX_TICKET_LEN);
    assert!(TicketText::new(kickoff_wire::TicketTextValue::protect(longest.clone())).is_ok());
    assert!(
        TicketText::new(kickoff_wire::TicketTextValue::protect(format!(
            "{longest}A"
        )))
        .is_err()
    );
}

/// The same rule holds on the socket: a `Join` frame whose ticket is a path
/// is answered `Refused(Unknown)` and never reaches the daemon.
#[tokio::test]
async fn si_3_path_shaped_join_on_the_wire_never_reaches_the_daemon() {
    let base = TempBase::new();
    let dir = base.dir();
    let server = Arc::new(Server::bind(&dir, trust_me()).unwrap());
    let (_task, mut seen) = serve(server);
    let mut stream = raw_channel(&dir, CLI).await;
    let path = b"../../etc/passwd";
    let mut join = vec![2u8];
    join.push(u8::try_from(path.len()).unwrap());
    join.extend_from_slice(path);
    stream.write_all(&frame(&join)).await.unwrap();
    assert_eq!(read_frame(&mut stream).await.unwrap(), [1, 0]);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(seen.try_recv().is_err());
}

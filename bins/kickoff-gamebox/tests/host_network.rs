//! SI-14 against a host network the test owns. The supervisor runs in its
//! own user and network namespace (never the machine's), holds before it
//! reads the host's view, and the test gives that namespace globally
//! addressed LANs: a connected subnet and a gateway route in the main
//! table, and a subnet reached only through a policy table.
//!
//! What these tests prove: the deny set taken at launch covers every one of
//! those LANs, and a host network change during a session ends the box
//! within the teardown deadline. What they do not prove: that no packet
//! reaches a LAN the host adds mid-session. Between the change and the box's
//! end the loaded deny set still permits it (see the crate README).

#![allow(clippy::unwrap_used, clippy::panic)]

mod support;

use support::{DEADLINE, Options, Supervisor, within};

fn start_in_own_network(payload: &str) -> Supervisor {
    let options = Options {
        env: vec![("KICKOFF_TEST_GATE", "host-view".to_owned())],
        // The supervisor keeps the user's uid; uid 0 is mapped too (from the
        // user's subordinate ids), so the test can configure the namespace.
        wrapper: vec![
            "/usr/bin/unshare".to_owned(),
            "--user".to_owned(),
            "--map-auto".to_owned(),
            format!("--map-user={}", id("-u")),
            format!("--map-group={}", id("-g")),
            "--net".to_owned(),
            "--".to_owned(),
        ],
        ..Options::default()
    };
    let supervisor = Supervisor::start_with(options, &["probe", payload]);
    supervisor.wait_gate("host-view");
    supervisor
}

fn id(flag: &str) -> String {
    let out = std::process::Command::new("id").arg(flag).output().unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// Runs `ip` as root of the supervisor's user namespace, in its network
/// namespace.
fn ip(supervisor: &Supervisor, args: &str) {
    let status = std::process::Command::new("nsenter")
        .arg(format!("--target={}", supervisor.main_pid()))
        .args(["--user", "--net", "--", "/usr/bin/ip"])
        .args(args.split_whitespace())
        .status()
        .unwrap();
    assert!(status.success(), "ip {args} failed in the test namespace");
}

fn give_lans(supervisor: &Supervisor) {
    for step in [
        "link set lo up",
        "link add d0 type dummy",
        "addr add 203.0.113.1/24 dev d0",
        "link set d0 up",
        "route add default via 203.0.113.254 dev d0",
        "route add 192.88.99.0/24 via 203.0.113.254 dev d0",
        "link add d1 type dummy",
        "link set d1 up",
        "route add 198.51.100.0/24 dev d1 table 100",
        "rule add lookup 100 pref 100",
    ] {
        ip(supervisor, step);
    }
}

#[test]
fn si_14_startup_deny_set_covers_lans_in_every_routing_table() {
    let supervisor = start_in_own_network("lans");
    give_lans(&supervisor);
    supervisor.release_gate("host-view");
    supervisor.wait_exit();
    let report = supervisor.report();
    assert!(
        report.contains("barrier: released") && report.contains("box exited: exit status: 0"),
        "a LAN of the host left the box (70: main-table subnet; 71: main-table \
         gateway route; 72: policy-table subnet; 73: public destination dropped): {report}"
    );
}

#[test]
fn si_14_host_network_change_ends_the_box_within_the_deadline() {
    let supervisor = start_in_own_network("inventory");
    give_lans(&supervisor);
    supervisor.release_gate("host-view");
    let dir = supervisor.scope_dir();
    let snapshot = supervisor.wait_procs("kickoff-box-probe", 1);
    // A new LAN appears while the box runs: its deny set is now stale.
    ip(&supervisor, "addr add 192.0.0.200/32 dev d0");
    ip(&supervisor, "route add 192.31.196.0/24 dev d1 table 100");
    assert!(
        within(DEADLINE, || !dir.exists()
            && !snapshot.iter().any(|p| support::alive(*p))
            && supervisor.exited_within(std::time::Duration::ZERO)),
        "the box kept running with a stale deny set: {}",
        supervisor.report()
    );
    assert!(
        supervisor
            .report()
            .contains("refused: the host network changed")
    );
}

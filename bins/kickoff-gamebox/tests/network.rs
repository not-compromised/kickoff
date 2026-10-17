//! SI-14: the box's egress reaches the internet and nothing of the host,
//! its LAN or the private and special ranges, and the game cannot change
//! its own network (design §3.2.2 step 5, §3.2.4, §3.2.6 requirement 6).

mod support;

use support::{DEADLINE, Supervisor, within};

#[test]
fn si_14_box_reaches_the_internet_and_no_host_or_private_destination() {
    // The probe exits 0 only if every forbidden destination, including each
    // of this host's own addresses, is dropped by the ruleset, a public
    // resolver answers, and link, route and ruleset changes are refused.
    let supervisor = Supervisor::start(&["probe", "network"]);
    supervisor.wait_exit();
    let report = supervisor.report();
    assert!(
        report.contains("barrier: released") && report.contains("box exited: exit status: 0"),
        "the box's network is not internet-only (20+n: forbidden destination n \
         left the box; 40: no internet; 41-43: a network change went through): {report}"
    );
}

#[test]
fn si_14_startup_probes_refuse_a_pasta_linking_box_and_host() {
    // Each fault is a pasta that links the box and the host: the default
    // gateway mapping to the host's loopback, the box's loopback forwarded
    // to the host's (-T/-U), and a host port forwarded into the box
    // (-t/-u). The ruleset would still drop the first two and the input
    // chain the third; the startup probes must refuse each on their own.
    let cases = [
        (
            "pasta-maps-host",
            "the box ended before the launch barrier, status 77",
        ),
        (
            "pasta-forwards-loopback",
            "the box ended before the launch barrier, status 88",
        ),
        (
            "pasta-forwards-inbound",
            "refused: pasta forwards ports between the box and the host",
        ),
    ];
    for (fault, refusal) in cases {
        let supervisor = Supervisor::start(&["probe", "inventory", "--fault", fault]);
        let dir = supervisor.scope_dir();
        assert!(
            supervisor.exited_within(std::time::Duration::from_secs(10)),
            "{fault}: a pasta linking the box and the host was launched: {}",
            supervisor.report()
        );
        let report = supervisor.report();
        assert!(
            !report.contains("barrier: released") && report.contains(refusal),
            "{fault}: not refused with `{refusal}`: {report}"
        );
        assert!(within(DEADLINE, || !dir.exists()));
    }
}

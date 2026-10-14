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
fn si_14_startup_probe_refuses_a_pasta_that_maps_the_host() {
    // With pasta's default gateway mapping the gateway leads to the host's
    // loopback. The ruleset would still drop it; the startup probe must
    // refuse the launch on its own.
    let supervisor = Supervisor::start(&["probe", "inventory", "--fault", "pasta-maps-host"]);
    let dir = supervisor.scope_dir();
    assert!(
        supervisor.exited_within(std::time::Duration::from_secs(10)),
        "a pasta that maps the host was launched: {}",
        supervisor.report()
    );
    let report = supervisor.report();
    assert!(
        !report.contains("barrier: released")
            && report.contains("the box ended before the launch barrier, status 77"),
        "a pasta that maps the host was not refused: {report}"
    );
    assert!(within(DEADLINE, || !dir.exists()));
}

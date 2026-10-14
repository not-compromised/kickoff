//! SI-34 and the direct half of SI-35, from a probe run exactly where the
//! game runs: the copy cannot be changed, no launcher or Kickoff state of
//! the host is visible, and no host display or bus socket is reachable.
//! gamescope, WlFilter and the security context (the rest of SI-35) are
//! not in this box yet.

mod support;

use support::Supervisor;

fn run_probe(payload: &str) -> String {
    let supervisor = Supervisor::start(&["probe", payload]);
    supervisor.wait_exit();
    supervisor.report()
}

#[test]
fn si_34_game_cannot_change_its_copy_or_see_launcher_state() {
    let report = run_probe("files");
    assert!(
        report.contains("barrier: released") && report.contains("box exited: exit status: 0"),
        "the box let the game change its copy or see host state (60-64: a change \
         to the copy went through; 65-66: a positive control failed; 67-71: a \
         launcher or Kickoff path is visible): {report}"
    );
}

#[test]
fn si_35_no_host_display_or_bus_socket_in_the_box() {
    let report = run_probe("display");
    assert!(
        report.contains("barrier: released") && report.contains("box exited: exit status: 0"),
        "a host display or bus socket is reachable from the box (50: X11 \
         directory; 51: runtime directory; 52: system bus; 53: abstract X11; \
         54: the positive control failed): {report}"
    );
}

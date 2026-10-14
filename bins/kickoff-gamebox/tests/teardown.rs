//! SI-38: each teardown path of design §3.2.6, tested alone with a stand-in
//! that ignores SIGTERM and whose double-forked descendant arms no
//! parent-death signal, so no fast path can mask a removed one.

mod support;

use support::{DEADLINE, Supervisor, alive, within};

#[test]
fn si_38_normal_stop_kills_the_cgroup_before_asking_the_manager() {
    let supervisor = Supervisor::start(&["probe", "standin"]);
    let dir = supervisor.scope_dir();
    let probes = supervisor.wait_procs("kickoff-box-probe", 2);

    supervisor.signal("SIGTERM");
    assert!(
        within(DEADLINE, || !dir.exists()
            && !probes.iter().any(|p| alive(*p))),
        "the box outlived the teardown deadline after a normal stop: {}",
        supervisor.report()
    );
    supervisor.wait_exit();
    let report = supervisor.report();
    assert!(
        report.contains("teardown: stop request with the scope populated=0"),
        "the manager was asked to stop a scope that still had processes: {report}"
    );
    assert!(report.contains("box stopped"), "{report}");
}

#[test]
fn si_38_owner_death_ends_the_box_without_a_normal_stop() {
    let supervisor = Supervisor::start(&["probe", "standin"]);
    let dir = supervisor.scope_dir();
    let probes = supervisor.wait_procs("kickoff-box-probe", 2);

    supervisor.signal("SIGKILL");
    assert!(
        within(DEADLINE, || !probes.iter().any(|p| alive(*p))),
        "a stand-in survived its supervisor's death past the deadline"
    );
    assert!(
        within(DEADLINE, || !dir.exists()),
        "the scope survived its supervisor's death"
    );
}

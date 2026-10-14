//! SI-38: each teardown path of design §3.2.6, tested alone with a stand-in
//! that ignores SIGTERM and whose double-forked descendant arms no
//! parent-death signal, so no fast path can mask a removed one.

#![allow(clippy::unwrap_used)]

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

#[test]
fn si_38_scope_carries_the_box_limits() {
    let supervisor = Supervisor::start(&["probe", "standin"]);
    let dir = supervisor.scope_dir();
    supervisor.wait_procs("kickoff-box-probe", 2);
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
    assert_eq!(read("memory.max").trim(), (12u64 << 30).to_string());
    assert_eq!(read("memory.swap.max").trim(), "0");
    assert_eq!(read("pids.max").trim(), "512");
    assert_eq!(read("cpu.weight").trim(), "100");
}

#[test]
fn si_38_supervisor_killed_during_or_after_a_launch_leaves_nothing() {
    // Through the whole chain: killed as soon as the scope exists (pasta,
    // the links and bwrap still starting), and again with the payload
    // running behind a released barrier.
    for after_release in [false, true] {
        let supervisor = Supervisor::start(&["probe", "inventory"]);
        let dir = supervisor.scope_dir();
        if after_release {
            supervisor.wait_procs("kickoff-box-probe", 1);
        }
        let snapshot: Vec<i32> = std::fs::read_to_string(dir.join("cgroup.procs"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.parse().ok())
            .collect();
        supervisor.signal("SIGKILL");
        assert!(
            within(DEADLINE, || !dir.exists()
                && !snapshot.iter().any(|p| alive(*p))),
            "after_release={after_release}: the launch outlived its supervisor"
        );
    }
}

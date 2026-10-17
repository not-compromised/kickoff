//! SI-38: each teardown path of design §3.2.6, tested alone with a stand-in
//! that ignores SIGTERM and whose double-forked descendant arms no
//! parent-death signal, so no fast path can mask a removed one.

#![allow(clippy::unwrap_used)]

mod support;

use support::{DEADLINE, Options, Supervisor, alive, within};

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

/// Waits for the supervisor to exit and the box to be gone, from `start`.
fn gone_within_deadline(supervisor: &Supervisor, dir: &std::path::Path, snapshot: &[i32]) -> bool {
    within(DEADLINE, || {
        !dir.exists()
            && !snapshot.iter().any(|p| alive(*p))
            && supervisor.exited_within(std::time::Duration::ZERO)
    })
}

#[test]
fn si_38_stop_during_a_stalled_helper_ends_the_box_within_the_deadline() {
    // The outside nft listing is replaced by a helper that never finishes.
    let options = Options {
        env: vec![
            ("KICKOFF_TEST_STALL_HELPER", "1".to_owned()),
            ("KICKOFF_TEST_GATE", "helper".to_owned()),
        ],
        ..Options::default()
    };
    let supervisor = Supervisor::start_with(options, &["probe", "inventory"]);
    let dir = supervisor.scope_dir();
    supervisor.wait_gate("helper");
    let snapshot = supervisor.scope_procs();
    supervisor.signal("SIGTERM");
    assert!(
        gone_within_deadline(&supervisor, &dir, &snapshot),
        "a stop during a stalled helper did not end the box and the supervisor in time: {}",
        supervisor.report()
    );
    let report = supervisor.report();
    assert!(
        report.contains("box stopped") && !report.contains("barrier: released"),
        "{report}"
    );
}

#[test]
fn si_38_stop_during_scope_registration_ends_within_the_deadline() {
    // The supervisor never sees the scope registered and keeps waiting.
    let options = Options {
        env: vec![("KICKOFF_TEST_SLOW_REGISTRATION", "1".to_owned())],
        ..Options::default()
    };
    let supervisor = Supervisor::start_with(options, &["probe", "standin"]);
    let dir = supervisor.scope_dir();
    let snapshot = supervisor.wait_procs("kickoff-box-probe", 2);
    supervisor.signal("SIGTERM");
    assert!(
        gone_within_deadline(&supervisor, &dir, &snapshot),
        "a stop during registration did not end the box and the supervisor in time: {}",
        supervisor.report()
    );
    assert!(supervisor.report().contains("box stopped"));
}

/// Which processes a kill at a hold point targets.
#[derive(Clone, Copy, Debug)]
enum Victim {
    Supervisor,
    /// The one trusted link alive at that phase (the others have exec'd).
    Link,
}

#[test]
fn si_38_kill_at_each_startup_phase_leaves_nothing() {
    use Victim::{Link, Supervisor as Sup};
    // Each hold point stops the supervisor or a link at an exact phase:
    // before and after registration, before and after each link arms its
    // parent-death signal (pasta started for `inner`), after the nft helper
    // fork, at the barrier and during the outside helper. Every process the
    // launch started must be gone within the deadline.
    let cases: [(&str, &[Victim]); 9] = [
        ("before-registration", &[Sup]),
        ("scope-registered", &[Sup]),
        ("enter-before-pdeathsig", &[Sup, Link]),
        ("enter-after-pdeathsig", &[Sup, Link]),
        ("inner-before-pdeathsig", &[Sup, Link]),
        ("inner-after-pdeathsig", &[Sup, Link]),
        ("inner-after-nft", &[Sup, Link]),
        ("barrier", &[Sup, Link]),
        ("helper", &[Sup]),
    ];
    for (phase, victims) in cases {
        for victim in victims {
            let mut options = Options {
                env: vec![("KICKOFF_TEST_GATE", phase.to_owned())],
                ..Options::default()
            };
            if phase == "helper" {
                options
                    .env
                    .push(("KICKOFF_TEST_STALL_HELPER", "1".to_owned()));
            }
            let supervisor = Supervisor::start_with(options, &["probe", "inventory"]);
            supervisor.wait_gate(phase);
            if phase == "before-registration" {
                supervisor.signal("SIGKILL");
                assert!(supervisor.exited_within(DEADLINE));
                std::thread::sleep(DEADLINE);
                assert!(
                    supervisor.scope_absent(),
                    "{phase}: a scope appeared after the supervisor died"
                );
                continue;
            }
            let dir = supervisor.scope_dir();
            let snapshot = supervisor.scope_procs();
            match victim {
                Sup => supervisor.signal("SIGKILL"),
                Link => {
                    let link = supervisor.wait_procs_named("kickoff-box-link", 1);
                    let [pid] = link[..] else {
                        panic!("{phase}: expected one live trusted link, found {link:?}");
                    };
                    std::process::Command::new("kill")
                        .args(["-KILL", &pid.to_string()])
                        .status()
                        .unwrap();
                    // A link killed while the supervisor holds: let the
                    // supervisor go on and find it dead.
                    if phase == "barrier" {
                        supervisor.release_gate(phase);
                    }
                }
            }
            assert!(
                within(DEADLINE, || !dir.exists()
                    && !snapshot.iter().any(|p| alive(*p))),
                "{phase}, {victim:?} killed: the launch outlived the deadline: {}",
                supervisor.report()
            );
        }
    }
}

#[test]
fn si_38_box_limits_are_enforced() {
    // Under the probe's small limits (16 MiB prefix, 64 tasks, 64 MiB): a
    // prefix fill stops with ENOSPC within its size, forking stops below the
    // task limit, and a child that keeps allocating is killed.
    let supervisor = Supervisor::start(&["probe", "limits"]);
    supervisor.wait_exit();
    let report = supervisor.report();
    assert!(
        report.contains("barrier: released") && report.contains("box exited: exit status: 0"),
        "a limit did not hold (80: prefix fill; 81: forks; 82: memory): {report}"
    );
}

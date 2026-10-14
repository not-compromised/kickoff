//! SI-36: authority is enumerated, not inherited. The box's payload holds
//! stdio on /dev/null and nothing else, the supervisor drops what its
//! service was started with, and the launch barrier refuses a setup with
//! any one barrier property wrong (design §3.2.6).

#![allow(clippy::unwrap_used)]

mod support;

use std::path::{Path, PathBuf};

use support::{DEADLINE, Supervisor, descriptors, identity, within};

const PROBE: &str = "kickoff-box-probe";

fn null() -> (u64, u64) {
    identity(Path::new("/dev/null"))
}

#[test]
fn si_36_game_holds_only_stdio_on_dev_null() {
    let supervisor = Supervisor::start(&["probe", "inventory"]);
    let [probe] = supervisor.wait_procs(PROBE, 1)[..] else {
        panic!("expected one probe in the box");
    };
    let held = descriptors(probe);
    assert_eq!(
        held,
        [(0, null()), (1, null()), (2, null())],
        "the game holds more than stdio on /dev/null"
    );
    assert!(supervisor.report().contains("barrier: released"));
}

#[test]
fn si_36_supervisor_never_holds_a_descriptor_leaked_to_its_service() {
    let canary = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("si36-canary-{}", std::process::id()));
    std::fs::write(&canary, b"canary\n").unwrap();
    let supervisor = Supervisor::start_with(
        &[format!("OpenFile={}:canary", canary.display())],
        &["probe", "inventory"],
    );
    supervisor.wait_procs(PROBE, 1);
    let leaked = identity(&canary);
    let held = descriptors(supervisor.main_pid());
    assert!(
        !held.iter().any(|(_, id)| *id == leaked),
        "the supervisor kept the descriptor its service was started with: {held:?}"
    );
    supervisor.signal("SIGTERM");
    supervisor.wait_exit();
    assert_eq!(std::fs::read(&canary).unwrap(), b"canary\n");
    std::fs::remove_file(&canary).unwrap();
}

#[test]
fn si_36_launch_barrier_refuses_each_faulted_property() {
    // Each fault leaves one barrier property wrong; the refusal names the
    // check that caught it, from inside the box (a link's exit status) or
    // from the supervisor's outside check.
    let cases = [
        (
            "namespaces",
            "the box ended before the launch barrier, status 80",
        ),
        ("nft", "refused: launch barrier: nft ruleset"),
        (
            "rlimits",
            "the box ended before the launch barrier, status 83",
        ),
        (
            "capabilities",
            "the box ended before the launch barrier, status 84",
        ),
        (
            "descriptors",
            "refused: launch barrier: descriptor inventory",
        ),
    ];
    for (fault, refusal) in cases {
        let supervisor = Supervisor::start(&["probe", "inventory", "--fault", fault]);
        let dir = supervisor.scope_dir();
        supervisor.wait_exit();
        let report = supervisor.report();
        assert!(
            !report.contains("barrier: released") && report.contains(refusal),
            "fault {fault}: the barrier did not refuse with `{refusal}`: {report}"
        );
        assert!(
            within(DEADLINE, || !dir.exists()),
            "fault {fault}: the scope survived the refused launch"
        );
    }
}

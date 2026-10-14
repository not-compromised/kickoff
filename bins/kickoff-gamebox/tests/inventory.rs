//! SI-36: authority is enumerated, not inherited. The box's payload holds
//! stdio on /dev/null and nothing else, the supervisor drops what its
//! service was started with, and the launch barrier refuses a setup with
//! any one barrier property wrong (design §3.2.6).

#![allow(clippy::unwrap_used)]

mod support;

use std::path::{Path, PathBuf};

use support::{DEADLINE, Options, Supervisor, descriptors, identity, within};

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
    let options = Options {
        properties: vec![format!("OpenFile={}:canary", canary.display())],
        ..Options::default()
    };
    let supervisor = Supervisor::start_with(options, &["probe", "inventory"]);
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

/// Launches the inventory probe with `fault` and, if `side` names one,
/// only that barrier side checking. Returns the supervisor's report, after
/// asserting the scope is gone and the payload never started: the probe
/// writes a witness file first thing, which must not exist.
fn refused_launch(fault: &str, side: Option<&str>) -> String {
    let witness = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "witness-{}-{fault}-{}",
        std::process::id(),
        side.unwrap_or("both")
    ));
    let _ = std::fs::remove_dir_all(&witness);
    std::fs::create_dir_all(&witness).unwrap();
    let mut env = vec![("KICKOFF_TEST_WITNESS_DIR", witness.display().to_string())];
    if let Some(side) = side {
        env.push(("KICKOFF_TEST_BARRIER", side.to_owned()));
    }
    let options = Options {
        env,
        ..Options::default()
    };
    let supervisor = Supervisor::start_with(options, &["probe", "inventory", "--fault", fault]);
    let dir = supervisor.scope_dir();
    let exited = supervisor.exited_within(std::time::Duration::from_secs(10));
    let report = supervisor.report();
    let entered = witness.join("entered").exists();
    std::fs::remove_dir_all(&witness).unwrap();
    assert!(
        exited && !entered,
        "fault {fault}, side {side:?}: the payload started (witness {entered}, \
         supervisor exited {exited}): {report}"
    );
    assert!(
        within(DEADLINE, || !dir.exists()),
        "fault {fault}: the scope survived the refused launch"
    );
    report
}

/// The witness, checked in `refused_launch`, shows the payload never ran;
/// the refusal names which check stopped it.
fn assert_refusals(side: Option<&str>, cases: &[(&str, &str)]) {
    for (fault, refusal) in cases {
        let report = refused_launch(fault, side);
        assert!(
            report.contains(refusal),
            "fault {fault}, side {side:?}: not refused with `{refusal}`: {report}"
        );
    }
}

#[test]
fn si_36_launch_barrier_refuses_each_faulted_property() {
    // Each fault leaves one barrier property wrong; the refusal names the
    // check that caught it first, from inside the box (a link's exit
    // status) or from the supervisor's outside check.
    assert_refusals(
        None,
        &[
            (
                "namespaces",
                "the box ended before the launch barrier, status 80",
            ),
            ("nft", "refused: launch barrier: nft ruleset"),
            ("cgroup", "refused: launch barrier: cgroup"),
            (
                "cgroup-namespace",
                "the box ended before the launch barrier, status 82",
            ),
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
            (
                "prefix-unsized",
                "the box ended before the launch barrier, status 87",
            ),
        ],
    );
}

#[test]
fn si_36_inside_barrier_refuses_each_fault_alone() {
    // The supervisor's outside check is off: the barrier link alone must
    // refuse every property it can see from inside.
    assert_refusals(
        Some("inside"),
        &[
            (
                "namespaces",
                "the box ended before the launch barrier, status 80",
            ),
            (
                "cgroup-namespace",
                "the box ended before the launch barrier, status 82",
            ),
            (
                "rlimits",
                "the box ended before the launch barrier, status 83",
            ),
            (
                "capabilities",
                "the box ended before the launch barrier, status 84",
            ),
            // Caught by the final inventory, after the release byte.
            ("descriptors", "box exited: exit status: 86"),
            (
                "prefix-unsized",
                "the box ended before the launch barrier, status 87",
            ),
        ],
    );
}

#[test]
fn si_36_outside_barrier_refuses_each_fault_alone() {
    // The barrier link's own checks are off: the supervisor's outside check
    // alone must refuse every property.
    assert_refusals(
        Some("outside"),
        &[
            ("namespaces", "refused: launch barrier: namespaces"),
            ("nft", "refused: launch barrier: nft ruleset"),
            ("cgroup", "refused: launch barrier: cgroup"),
            ("rlimits", "refused: launch barrier: rlimits"),
            ("capabilities", "refused: launch barrier: capability sets"),
            (
                "descriptors",
                "refused: launch barrier: descriptor inventory",
            ),
            ("prefix-unsized", "refused: launch barrier: prefix size"),
        ],
    );
}

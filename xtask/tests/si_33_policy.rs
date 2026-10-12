//! SI-33: the release-policy test. Parses docs/SECURITY-INVARIANTS.md and
//! /mutants.toml and checks them against the workspace: every row held in M2
//! names tests that exist and has registered mutants, and every mutant points
//! at a declared feature and a real test. `xtask mutants` (run by
//! scripts/check.sh) then proves each mutant fails its test.

use std::collections::BTreeMap;
use std::path::PathBuf;

use kickoff_xtask::invariants;
use kickoff_xtask::policy::{self, Finding};
use kickoff_xtask::registry;
use kickoff_xtask::workspace::{Package, Workspace};
use kickoff_xtask::{MILESTONE, load, root};

#[test]
fn si_33_every_m2_row_has_existing_tests_and_registered_mutants() {
    let (registry, rows, ws) = load(&root()).unwrap();
    let held: Vec<&str> = rows
        .iter()
        .filter(|r| r.held_in(MILESTONE))
        .map(|r| r.id.as_str())
        .collect();
    // A parser that silently found nothing would pass everything.
    for si in ["SI-3", "SI-7", "SI-18", "SI-23", "SI-31", "SI-33"] {
        assert!(
            held.contains(&si),
            "{si} not read as held in {MILESTONE}: {held:?}"
        );
    }

    let report = policy::check(&rows, &registry, &ws, MILESTONE);
    for gap in &report.pending {
        eprintln!("pending (mutants.toml [[pending]]): {gap}");
    }
    let failures: Vec<String> = report.failures.iter().map(ToString::to_string).collect();
    assert!(
        failures.is_empty(),
        "SI-33 policy: {} rows or mutants are missing or wrong:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

const DOC: &str = "\
| # | Rule | Enforced by | Mutant | Born from | Scope | Held |
|---|---|---|---|---|---|---|
| SI-1 | r | **Test** | `mutant-si1-gone` | X | all | M2 |
| SI-2 | r | **Test** `named_but_absent` | `mutant-si2-named`; a prose mutant | X | all | M2, M7 |
| SI-3 | r | **Test** | `mutant-si3-later` | X | all | M5 |
";

fn fixture(fns: &[(&str, &str)]) -> Workspace {
    let dir = PathBuf::from("/w/crates/a");
    let mut map: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for (name, file) in fns {
        map.entry((*name).to_owned())
            .or_default()
            .push(dir.join(file));
    }
    Workspace {
        root: PathBuf::from("/w"),
        packages: vec![Package {
            name: "kickoff-a".to_owned(),
            dir,
            mutant_features: Vec::new(),
            build: None,
        }],
        fns: map,
    }
}

#[test]
fn si_33_policy_reports_rows_without_tests_or_mutants() {
    let rows = invariants::parse(DOC).unwrap();
    let ws = fixture(&[("si_2_holds", "tests/si.rs")]);
    let report = policy::check(&rows, &registry::Registry::default(), &ws, "M2");
    let si = |s: &str| s.to_owned();
    assert_eq!(
        report.failures,
        vec![
            Finding::NoTest { si: si("SI-1") },
            Finding::NamedTestMissing {
                si: si("SI-2"),
                test: si("named_but_absent")
            },
            Finding::NoMutant { si: si("SI-1") },
            Finding::NoMutant { si: si("SI-2") },
            Finding::NamedMutantUnregistered {
                si: si("SI-1"),
                feature: si("mutant-si1-gone")
            },
            Finding::NamedMutantUnregistered {
                si: si("SI-2"),
                feature: si("mutant-si2-named")
            },
            Finding::TestUnaccounted {
                test: si("si_2_holds")
            },
        ],
        "SI-3 is held in M5 and must be ignored"
    );
}

#[test]
fn si_33_registered_mutants_must_point_at_declared_features_and_real_tests() {
    let rows = invariants::parse(DOC).unwrap();
    let mut ws = fixture(&[("si_2_holds", "tests/si.rs")]);
    ws.packages[0].mutant_features =
        vec!["mutant-si2-named".to_owned(), "mutant-si2-spare".to_owned()];
    let registry = registry::parse(
        "[[mutant]] si = \"SI-2\", crate = \"kickoff-a\", feature = \"mutant-si2-named\", test = \"si_2_holds\", note = \"n\"\n\
         [[mutant]] si = \"SI-2\", crate = \"kickoff-a\", feature = \"mutant-si1-gone\", test = \"si_2_nowhere\", note = \"n\"\n\
         [[mutant]] si = \"SI-2\", crate = \"kickoff-b\", feature = \"mutant-si2-x\", test = \"si_2_holds\", note = \"n\"\n\
         [[pending]] si = \"SI-1\", item = \"test\", reason = \"r\"\n\
         [[pending]] si = \"SI-2\", item = \"mutant\", reason = \"r\"\n",
    )
    .unwrap();
    let report = policy::check(&rows, &registry, &ws, "M2");
    let has = |f: &Finding| report.failures.contains(f);
    let s = |s: &str| s.to_owned();
    assert!(has(&Finding::FeatureUndeclared {
        package: s("kickoff-a"),
        feature: s("mutant-si1-gone")
    }));
    assert!(has(&Finding::FeatureNameMismatch {
        si: s("SI-2"),
        feature: s("mutant-si1-gone")
    }));
    assert!(has(&Finding::MutantTestMissing {
        feature: s("mutant-si1-gone"),
        test: s("si_2_nowhere")
    }));
    assert!(has(&Finding::UnknownPackage {
        feature: s("mutant-si2-x"),
        package: s("kickoff-b")
    }));
    assert!(has(&Finding::FeatureUnregistered {
        package: s("kickoff-a"),
        feature: s("mutant-si2-spare")
    }));
    assert!(has(&Finding::NoReleaseGuard {
        package: s("kickoff-a")
    }));
    // A pending gap is reported apart from failures; one that is no longer a
    // gap (SI-2 has a mutant now) fails as stale.
    assert!(report.pending.contains(&Finding::NoTest { si: s("SI-1") }));
    assert!(!has(&Finding::NoTest { si: s("SI-1") }));
    assert!(has(&Finding::StalePending {
        si: s("SI-2"),
        item: s("mutant")
    }));
}

//! SI-33's static half: every row held in a milestone names tests that exist
//! and has registered mutants, every registered mutant points at a real
//! feature and test, and no mutant feature exists outside the registry or
//! without the release guard. `xtask mutants` is the dynamic half: it runs
//! each mutant and requires its test to fail.

use std::collections::BTreeSet;
use std::fmt;

use crate::invariants::Row;
use crate::registry::Registry;
use crate::workspace::Workspace;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Finding {
    /// The row has no `si_<n>_` test and names none.
    NoTest { si: String },
    /// The Enforced-by column names a test function nobody defines.
    NamedTestMissing { si: String, test: String },
    /// No registered mutant carries this row's id.
    NoMutant { si: String },
    /// The Mutant column names a build mutant the registry lacks.
    NamedMutantUnregistered { si: String, feature: String },
    /// A registry entry names a package that is not in the workspace.
    UnknownPackage { feature: String, package: String },
    /// A registry entry's feature is not declared by its package.
    FeatureUndeclared { package: String, feature: String },
    /// A registry entry's feature is not `mutant-si<n>-...` for its row.
    FeatureNameMismatch { si: String, feature: String },
    /// A registry entry's test is not defined in its test package.
    MutantTestMissing { feature: String, test: String },
    /// A package declares a mutant feature that no registry entry runs.
    FeatureUnregistered { package: String, feature: String },
    /// A package declares mutant features but its build script is not the
    /// release guard.
    NoReleaseGuard { package: String },
    /// An `si_<n>_` test of a held row has no mutant and no recorded reason.
    TestUnaccounted { test: String },
    /// An `[[unmutated]]` entry names a missing test or one that has a mutant.
    StaleUnmutated { test: String },
    /// A `[[pending]]` entry is no longer missing.
    StalePending { si: String, item: String },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::NoTest { si } => write!(f, "{si}: no si_<n>_ test exists"),
            Finding::NamedTestMissing { si, test } => {
                write!(f, "{si}: named test `{test}` is not defined")
            }
            Finding::NoMutant { si } => write!(f, "{si}: no registered mutant"),
            Finding::NamedMutantUnregistered { si, feature } => {
                write!(f, "{si}: named mutant `{feature}` is not registered")
            }
            Finding::UnknownPackage { feature, package } => {
                write!(f, "`{feature}`: no workspace package {package}")
            }
            Finding::FeatureUndeclared { package, feature } => {
                write!(f, "`{feature}` is not a feature of {package}")
            }
            Finding::FeatureNameMismatch { si, feature } => {
                write!(
                    f,
                    "`{feature}` is registered under {si}; its name must match"
                )
            }
            Finding::MutantTestMissing { feature, test } => {
                write!(f, "`{feature}`: test `{test}` is not in its test package")
            }
            Finding::FeatureUnregistered { package, feature } => {
                write!(
                    f,
                    "{package} declares `{feature}` but mutants.toml never runs it"
                )
            }
            Finding::NoReleaseGuard { package } => write!(
                f,
                "{package} declares mutant features without the release guard build script"
            ),
            Finding::TestUnaccounted { test } => write!(
                f,
                "`{test}` has no registered mutant and no [[unmutated]] reason"
            ),
            Finding::StaleUnmutated { test } => write!(
                f,
                "[[unmutated]] `{test}` is missing or has a mutant now; remove the entry"
            ),
            Finding::StalePending { si, item } => {
                write!(f, "[[pending]] {si} `{item}` is done; remove the entry")
            }
        }
    }
}

impl Finding {
    /// The `[[pending]]` (si, item) that excuses this finding, if any can.
    fn pending_key(&self) -> Option<(&str, &str)> {
        match self {
            Finding::NoTest { si } => Some((si, "test")),
            Finding::NoMutant { si } => Some((si, "mutant")),
            Finding::NamedTestMissing { si, test } => Some((si, test)),
            Finding::NamedMutantUnregistered { si, feature } => Some((si, feature)),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Report {
    /// Fail the gate.
    pub failures: Vec<Finding>,
    /// Known gaps recorded in `[[pending]]`; shown, not failed.
    pub pending: Vec<Finding>,
}

/// Checks every row held in `milestone` and the whole registry.
pub fn check(rows: &[Row], registry: &Registry, ws: &Workspace, milestone: &str) -> Report {
    let mut found = BTreeSet::new();
    let held: Vec<&Row> = rows.iter().filter(|r| r.held_in(milestone)).collect();

    for row in &held {
        let prefix = row.test_prefix();
        let named = row.named_tests();
        if ws.fns_with_prefix(&prefix).next().is_none() && named.is_empty() {
            found.insert(Finding::NoTest { si: row.id.clone() });
        }
        for test in named {
            if !ws.fns.contains_key(&test) {
                found.insert(Finding::NamedTestMissing {
                    si: row.id.clone(),
                    test,
                });
            }
        }
        check_row_mutants(row, registry, &mut found);
    }

    for m in &registry.mutants {
        let Some(package) = ws.package(&m.krate) else {
            found.insert(Finding::UnknownPackage {
                feature: m.feature.clone(),
                package: m.krate.clone(),
            });
            continue;
        };
        if !package.mutant_features.contains(&m.feature) {
            found.insert(Finding::FeatureUndeclared {
                package: m.krate.clone(),
                feature: m.feature.clone(),
            });
        }
        let number = m.si.strip_prefix("SI-").unwrap_or("?");
        if !m.feature.starts_with(&format!("mutant-si{number}-")) {
            found.insert(Finding::FeatureNameMismatch {
                si: m.si.clone(),
                feature: m.feature.clone(),
            });
        }
        if ws.target_of(&m.test_crate, &m.test).is_err() {
            found.insert(Finding::MutantTestMissing {
                feature: m.feature.clone(),
                test: m.test.clone(),
            });
        }
    }

    for package in &ws.packages {
        for feature in &package.mutant_features {
            if !registry
                .mutants
                .iter()
                .any(|m| m.krate == package.name && m.feature == *feature)
            {
                found.insert(Finding::FeatureUnregistered {
                    package: package.name.clone(),
                    feature: feature.clone(),
                });
            }
        }
        if !cfg!(feature = "mutant-si33-no-release-guard-check")
            && !package.mutant_features.is_empty()
            && !package.guarded(&ws.root)
        {
            found.insert(Finding::NoReleaseGuard {
                package: package.name.clone(),
            });
        }
    }

    let mutated: BTreeSet<&str> = registry.mutants.iter().map(|m| m.test.as_str()).collect();
    let excused: BTreeSet<&str> = registry.unmutated.iter().map(|u| u.test.as_str()).collect();
    for row in &held {
        for test in ws.fns_with_prefix(&row.test_prefix()) {
            if !mutated.contains(test) && !excused.contains(test) {
                found.insert(Finding::TestUnaccounted {
                    test: test.to_owned(),
                });
            }
        }
    }
    for u in &registry.unmutated {
        if mutated.contains(u.test.as_str()) || !ws.fns.contains_key(&u.test) {
            found.insert(Finding::StaleUnmutated {
                test: u.test.clone(),
            });
        }
    }

    let mut report = Report::default();
    for finding in found {
        let pending = finding.pending_key().is_some_and(|(si, item)| {
            registry
                .pending
                .iter()
                .any(|p| p.si == si && p.item == item)
        });
        if pending {
            report.pending.push(finding);
        } else {
            report.failures.push(finding);
        }
    }
    for p in &registry.pending {
        let still = report
            .pending
            .iter()
            .any(|f| f.pending_key() == Some((p.si.as_str(), p.item.as_str())));
        if !still {
            report.failures.push(Finding::StalePending {
                si: p.si.clone(),
                item: p.item.clone(),
            });
        }
    }
    report
}

#[cfg(not(feature = "mutant-si33-tests-only"))]
fn check_row_mutants(row: &Row, registry: &Registry, found: &mut BTreeSet<Finding>) {
    if !registry.mutants.iter().any(|m| m.si == row.id) {
        found.insert(Finding::NoMutant { si: row.id.clone() });
    }
    for feature in row.named_mutants() {
        if !registry.mutants.iter().any(|m| m.feature == feature) {
            found.insert(Finding::NamedMutantUnregistered {
                si: row.id.clone(),
                feature,
            });
        }
    }
}

/// The mutant: the policy checks only that tests exist, SI-33's own example
/// of a policy that proves nothing.
#[cfg(feature = "mutant-si33-tests-only")]
fn check_row_mutants(_: &Row, _: &Registry, _: &mut BTreeSet<Finding>) {}

//! What the policy and the runner need from the workspace on disk: each
//! package's name, directory, mutant features and build script, and where
//! every function is defined.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Where workspace packages live, relative to the root (`Cargo.toml`'s
/// `members`).
const MEMBER_DIRS: [&str; 2] = ["crates", "bins"];
const MEMBER_PACKAGES: [&str; 1] = ["xtask"];

/// The build script that refuses mutant features in release builds, as a
/// package manifest names it.
pub const GUARD_FILE: &str = "scripts/mutant-guard.rs";

#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub dir: PathBuf,
    /// Declared features named `mutant-*`.
    pub mutant_features: Vec<String>,
    /// `[package] build`, as written.
    pub build: Option<String>,
}

impl Package {
    /// Whether this package's build script is the release guard.
    pub fn guarded(&self, root: &Path) -> bool {
        self.build
            .as_ref()
            .and_then(|b| self.dir.join(b).canonicalize().ok())
            .is_some_and(|b| root.join(GUARD_FILE).canonicalize().is_ok_and(|g| g == b))
    }
}

/// Where a test function is compiled: the library's unit tests, or one
/// integration test target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Lib,
    Test(String),
}

#[derive(Debug)]
pub struct Workspace {
    pub root: PathBuf,
    pub packages: Vec<Package>,
    /// Function name to every file that defines one by that name.
    pub fns: BTreeMap<String, Vec<PathBuf>>,
}

impl Workspace {
    pub fn load(root: &Path) -> io::Result<Workspace> {
        let mut dirs = Vec::new();
        for group in MEMBER_DIRS {
            for entry in fs::read_dir(root.join(group))? {
                dirs.push(entry?.path());
            }
        }
        dirs.extend(MEMBER_PACKAGES.iter().map(|p| root.join(p)));
        dirs.sort();

        let mut packages = Vec::new();
        let mut fns: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
        for dir in dirs {
            let Ok(manifest) = fs::read_to_string(dir.join("Cargo.toml")) else {
                continue;
            };
            for file in rust_files(&dir)? {
                for name in fn_names(&fs::read_to_string(&file)?) {
                    fns.entry(name).or_default().push(file.clone());
                }
            }
            packages.push(package(&manifest, dir));
        }
        Ok(Workspace {
            root: root.to_path_buf(),
            packages,
            fns,
        })
    }

    pub fn package(&self, name: &str) -> Option<&Package> {
        self.packages.iter().find(|p| p.name == name)
    }

    /// Every function whose name starts with `prefix`.
    pub fn fns_with_prefix<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = &'a str> {
        self.fns
            .range(prefix.to_owned()..)
            .map(|(name, _)| name.as_str())
            .take_while(move |name| name.starts_with(prefix))
    }

    /// The one target of `package` that defines the test function `test`.
    pub fn target_of(&self, package: &str, test: &str) -> Result<Target, String> {
        let pkg = self
            .package(package)
            .ok_or_else(|| format!("no package {package}"))?;
        let files: Vec<&PathBuf> = self
            .fns
            .get(test)
            .into_iter()
            .flatten()
            .filter(|f| f.starts_with(&pkg.dir))
            .collect();
        let [file] = files.as_slice() else {
            return Err(format!(
                "{package} defines `fn {test}` in {} files, not exactly one",
                files.len()
            ));
        };
        let rel = file.strip_prefix(&pkg.dir).map_err(|e| e.to_string())?;
        let parts: Vec<&str> = rel.iter().filter_map(|p| p.to_str()).collect();
        match parts.as_slice() {
            ["src", ..] => Ok(Target::Lib),
            ["tests", file] => file
                .strip_suffix(".rs")
                .map(|stem| Target::Test(stem.to_owned()))
                .ok_or_else(|| format!("{} is not a test target", rel.display())),
            _ => Err(format!(
                "`fn {test}` is in {}, which is not a lib or test target root",
                rel.display()
            )),
        }
    }
}

fn package(manifest: &str, dir: PathBuf) -> Package {
    let mut section = "";
    let mut name = String::new();
    let mut build = None;
    let mut mutant_features = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim().trim_matches('"'));
        match section {
            "[package]" if key == "name" => value.clone_into(&mut name),
            "[package]" if key == "build" => build = Some(value.to_owned()),
            "[features]" if key.starts_with("mutant-") => mutant_features.push(key.to_owned()),
            _ => {}
        }
    }
    Package {
        name,
        dir,
        mutant_features,
        build,
    }
}

fn rust_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                if path.file_name().is_none_or(|n| n != "target") {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    Ok(out)
}

/// Names following `fn ` at a token boundary.
pub fn fn_names(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find("fn ") {
        let boundary = rest
            .get(..at)
            .and_then(|before| before.chars().next_back())
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        let after = rest.get(at.saturating_add(3)..).unwrap_or("");
        if boundary {
            let name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                names.push(name);
            }
        }
        rest = after;
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fn_names_finds_async_and_generic_functions_only_at_boundaries() {
        let src = "async fn si_1_a() {}\npub(crate) fn b<T>() {}\nlet cfn = 1; // fn\nfn  c";
        assert_eq!(fn_names(src), ["si_1_a", "b"]);
    }

    #[test]
    fn manifests_yield_name_build_and_mutant_features() {
        let p = package(
            "[package]\nname = \"kickoff-x\"\nbuild = \"../../scripts/mutant-guard.rs\"\n\
             [features]\nmutant-si3-a = []\nother = []\n[dependencies]\nmutant-like = \"1\"\n",
            PathBuf::from("/w/crates/x"),
        );
        assert_eq!(p.name, "kickoff-x");
        assert_eq!(p.build.as_deref(), Some("../../scripts/mutant-guard.rs"));
        assert_eq!(p.mutant_features, ["mutant-si3-a"]);
    }
}

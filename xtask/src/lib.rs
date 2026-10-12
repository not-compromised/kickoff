//! The SI-33 harness: the mutant registry (`/mutants.toml`), the invariant
//! table (`docs/SECURITY-INVARIANTS.md`), the policy tying them to the
//! workspace, and the runner behind `cargo run -p kickoff-xtask -- mutants`.

use std::path::{Path, PathBuf};

pub mod invariants;
pub mod policy;
pub mod registry;
pub mod scope;
pub mod workspace;

pub const REGISTRY_FILE: &str = "mutants.toml";
pub const INVARIANTS_FILE: &str = "docs/SECURITY-INVARIANTS.md";
/// The milestone whose rows the gate holds today.
pub const MILESTONE: &str = "M2";

/// The workspace root: this package's parent directory.
pub fn root() -> PathBuf {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    here.parent().unwrap_or(here).to_path_buf()
}

/// The registry, the invariant rows and the workspace, read from `root`.
pub fn load(
    root: &Path,
) -> Result<
    (
        registry::Registry,
        Vec<invariants::Row>,
        workspace::Workspace,
    ),
    String,
> {
    let read =
        |file: &str| std::fs::read_to_string(root.join(file)).map_err(|e| format!("{file}: {e}"));
    let registry = registry::parse(&read(REGISTRY_FILE)?).map_err(|e| e.to_string())?;
    let rows = invariants::parse(&read(INVARIANTS_FILE)?).map_err(|e| e.to_string())?;
    scope::check_claims(&read("docs/design.md")?, &rows)?;
    let ws = workspace::Workspace::load(root).map_err(|e| format!("workspace: {e}"))?;
    Ok((registry, rows, ws))
}

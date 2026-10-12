//! Build script shared by every crate that defines mutant features (SI-33).
//!
//! A mutant feature compiles a security protection out so its test can prove
//! it notices. A release build must never carry one, so this refuses to build
//! a crate with any `mutant-*` feature enabled when debug assertions are off
//! or the profile is `release`. It reads Cargo's feature variables, so a
//! mutant added later is covered without editing a list.

use std::env;

fn main() -> Result<(), String> {
    let mut enabled: Vec<String> = env::vars_os()
        .filter_map(|(key, _)| {
            key.to_str()?
                .strip_prefix("CARGO_FEATURE_MUTANT_")
                .map(|rest| format!("mutant_{}", rest.to_ascii_lowercase()))
        })
        .collect();
    enabled.sort();
    let release = env::var_os("CARGO_CFG_DEBUG_ASSERTIONS").is_none()
        || env::var("PROFILE").is_ok_and(|profile| profile == "release");
    if release && !enabled.is_empty() {
        return Err(format!(
            "refusing a release build with mutant features enabled ({}): \
             a mutant compiles a security protection out",
            enabled.join(", ")
        ));
    }
    Ok(())
}

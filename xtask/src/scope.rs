//! Claim/platform bindings live beside the numbered claims, not in a second registry.
use crate::invariants::Row;

#[derive(Clone, Copy)]
enum Platform {
    Linux,
    WindowsContained,
    WindowsSameUser,
    Relay,
}

fn platforms(scope: &str) -> Result<Vec<Platform>, String> {
    use Platform::{Linux, Relay, WindowsContained, WindowsSameUser};
    match scope {
        "all" => Ok(vec![Linux, WindowsContained, WindowsSameUser, Relay]),
        "Linux" => Ok(vec![Linux]),
        "Windows" => Ok(vec![WindowsContained, WindowsSameUser]),
        "Linux, Windows" | "Linux+Windows" => Ok(vec![Linux, WindowsContained, WindowsSameUser]),
        "relay" => Ok(vec![Relay]),
        "Linux, Windows-contained" => Ok(vec![Linux, WindowsContained]),
        _ => Err(format!("unknown invariant scope: {scope}")),
    }
}

fn permits(scope: &str, platform: Platform) -> Result<bool, String> {
    let tag = |p: Platform| match p {
        Platform::Linux => 0,
        Platform::WindowsContained => 1,
        Platform::WindowsSameUser => 2,
        Platform::Relay => 3,
    };
    Ok(platforms(scope)?.iter().any(|p| tag(*p) == tag(platform)))
}

pub fn check_rows(rows: &[Row], milestone: &str) -> Vec<String> {
    if cfg!(feature = "mutant-si33-no-scope-check") {
        return Vec::new();
    }
    let mut failures = Vec::new();
    for row in rows {
        if let Err(error) = platforms(&row.scope) {
            failures.push(format!("{}: {error}", row.id));
        } else if milestone == "M2"
            && row.held_in(milestone)
            && !permits(&row.scope, Platform::Linux).unwrap_or(false)
        {
            failures.push(format!("{}: scope excludes Linux M2", row.id));
        }
    }
    failures
}

pub fn check_claims(design: &str, rows: &[Row]) -> Result<(), String> {
    if cfg!(feature = "mutant-si33-no-scope-check") {
        return Ok(());
    }
    let section = design
        .split_once("### 1.2 Claims, and the design choice behind each")
        .and_then(|(_, rest)| rest.split_once("### 1.3"))
        .map(|(claims, _)| claims)
        .ok_or("missing design §1.2 claims")?;
    let mut seen = std::collections::BTreeSet::new();
    let mut header_seen = false;
    for line in section.lines().filter(|l| l.starts_with("| ")) {
        let cells: Vec<_> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.first() == Some(&"#") {
            if cells
                != [
                    "#",
                    "Claim",
                    "Design choice that delivers it",
                    "Invariants Linux",
                    "Invariants Windows contained",
                    "Invariants Windows same-user",
                ]
            {
                return Err("malformed claim mapping header".to_owned());
            }
            header_seen = true;
            continue;
        }
        let number = cells
            .first()
            .ok_or("missing claim id")?
            .parse::<u32>()
            .map_err(|_| "malformed claim id")?;
        if !(1..=15).contains(&number) || !seen.insert(number) || cells.len() != 6 {
            return Err(format!("malformed or duplicate claim {number}"));
        }
        if cells.iter().skip(3).all(|cell| *cell == "—") {
            return Err(format!("claim {number}: no mapped invariants"));
        }
        let platforms = [
            Platform::Linux,
            Platform::WindowsContained,
            Platform::WindowsSameUser,
        ];
        for (cell, platform) in cells.iter().skip(3).zip(platforms) {
            if *cell == "—" {
                continue;
            }
            for id in cell.split(", ") {
                let row = rows
                    .iter()
                    .find(|row| row.id == id)
                    .ok_or_else(|| format!("claim {number}: missing mapped invariant {id}"))?;
                if !permits(&row.scope, platform)? {
                    return Err(format!(
                        "claim {number}: {id} scope excludes mapped platform"
                    ));
                }
            }
        }
    }
    if !header_seen || seen.len() != 15 {
        return Err("missing numbered claim mapping".to_owned());
    }
    Ok(())
}

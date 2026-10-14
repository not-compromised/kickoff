//! The synthetic payload that stands in for the game in containment probes.

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    return kickoff_game::gamebox::probe_main();
    #[cfg(not(target_os = "linux"))]
    std::process::ExitCode::FAILURE
}

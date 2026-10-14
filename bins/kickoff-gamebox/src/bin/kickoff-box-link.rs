//! A trusted link of the gamebox chain (design §3.2.6).

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    return kickoff_game::gamebox::link_main();
    #[cfg(not(target_os = "linux"))]
    std::process::ExitCode::FAILURE
}

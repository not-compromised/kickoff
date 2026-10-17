//! The gamebox supervisor (design §2.1, §3.2.6).

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    return kickoff_game::gamebox::supervisor_main();
    #[cfg(not(target_os = "linux"))]
    std::process::ExitCode::FAILURE
}

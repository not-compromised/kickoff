//! `cargo run -p kickoff-xtask -- <command>`
//!
//! - `mutants [FILTER...]`: runs every registered mutant, or those whose SI
//!   or package equals a FILTER or whose feature or test contains one. Each test must pass without its
//!   feature and fail with it; a mutant that does not compile is an error,
//!   not a pass.
//! - `release-guard`: a release build of each package that has mutants, with
//!   one of them enabled, must be refused.
//! - `policy`: prints the SI-33 policy report (`tests/si_33_policy.rs`
//!   enforces it).

#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::ffi::OsString;
use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use kickoff_xtask::registry::Mutant;
use kickoff_xtask::workspace::{Target, Workspace};
use kickoff_xtask::{MILESTONE, load, policy, root};

/// The first build of a package's tests with a new feature set compiles its
/// dependents again; running one test never needs this long.
const BUILD_TIMEOUT: Duration = Duration::from_secs(1800);
const RUN_TIMEOUT: Duration = Duration::from_secs(300);
const GUARD_MESSAGE: &str = "refusing a release build with mutant features enabled";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((cmd, filters)) if cmd == "mutants" => mutants(filters),
        Some((cmd, [])) if cmd == "release-guard" => release_guard(),
        Some((cmd, [])) if cmd == "policy" => print_policy(),
        _ => Err("usage: xtask mutants [FILTER...] | release-guard | policy".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_policy() -> Result<(), String> {
    let root = root();
    let (registry, rows, ws) = load(&root)?;
    let report = policy::check(&rows, &registry, &ws, MILESTONE);
    for p in &report.pending {
        println!("pending: {p}");
    }
    for f in &report.failures {
        println!("FAIL: {f}");
    }
    if report.failures.is_empty() {
        Ok(())
    } else {
        Err(format!("{} policy failures", report.failures.len()))
    }
}

fn mutants(filters: &[String]) -> Result<(), String> {
    let root = root();
    let (registry, _, ws) = load(&root)?;
    let chosen: Vec<&Mutant> = registry
        .mutants
        .iter()
        .filter(|m| {
            filters.is_empty()
                || filters.iter().any(|f| {
                    m.si == *f
                        || m.krate == *f
                        || m.test_crate == *f
                        || m.feature.contains(f.as_str())
                        || m.test.contains(f.as_str())
                })
        })
        .collect();
    if chosen.is_empty() {
        return Err("no registered mutant matches".to_owned());
    }
    for (i, m) in chosen.iter().enumerate() {
        let started = Instant::now();
        let verdict = run_mutant(&ws, m);
        let secs = started.elapsed().as_secs();
        let label = format!(
            "[{}/{}] {} {} -> {}::{}",
            i.saturating_add(1),
            chosen.len(),
            m.si,
            m.feature,
            m.test_crate,
            m.test
        );
        match verdict {
            Ok(note) => println!("killed   {label} ({secs}s{note})"),
            Err(why) => {
                println!("FAILED   {label}: {why}");
                return Err(format!("mutant not killed: {label}"));
            }
        }
    }
    println!("all {} mutants killed", chosen.len());
    Ok(())
}

/// `Ok` when the test passes on the plain build and fails on the mutant.
fn run_mutant(ws: &Workspace, m: &Mutant) -> Result<&'static str, String> {
    let target = ws.target_of(&m.test_crate, &m.test)?;
    let mut base = vec![
        "test".to_owned(),
        "--locked".to_owned(),
        "-p".to_owned(),
        m.test_crate.clone(),
    ];
    match target {
        Target::Lib => base.push("--lib".to_owned()),
        Target::Test(name) => base.extend(["--test".to_owned(), name]),
    }
    let mut with_feature = base.clone();
    with_feature.extend([
        "--features".to_owned(),
        format!("{}/{}", m.krate, m.feature),
    ]);

    let plain = run_test(&base, &m.test)?;
    if !plain.passed {
        return Err(format!(
            "the test does not pass without the mutant\n{}",
            plain.output
        ));
    }

    let mut build = with_feature.clone();
    build.push("--no-run".to_owned());
    let built = cargo(&build, BUILD_TIMEOUT)?;
    if !built.success {
        return Err(format!(
            "the mutant does not compile\n{}",
            tail(&built.stderr)
        ));
    }
    let mutated = run_test(&with_feature, &m.test)?;
    if mutated.passed {
        return Err("the test PASSES with the protection removed".to_owned());
    }
    Ok(if mutated.timed_out {
        ", hung until the timeout"
    } else {
        ""
    })
}

struct TestRun {
    passed: bool,
    timed_out: bool,
    output: String,
}

/// Runs exactly the test function `name` (found through `--list`, so a test
/// whose name merely contains it does not count).
fn run_test(args: &[String], name: &str) -> Result<TestRun, String> {
    let mut list = args.to_vec();
    list.extend(["--".to_owned(), "--list".to_owned()]);
    let listed = cargo(&list, BUILD_TIMEOUT)?;
    if !listed.success {
        return Err(format!("listing tests failed\n{}", tail(&listed.stderr)));
    }
    let paths: Vec<&str> = listed
        .stdout
        .lines()
        .filter_map(|l| l.strip_suffix(": test"))
        .filter(|path| path.rsplit("::").next() == Some(name))
        .collect();
    let [path] = paths.as_slice() else {
        return Err(format!(
            "expected one test named {name}, found {}",
            paths.len()
        ));
    };
    let mut run = args.to_vec();
    run.extend(["--".to_owned(), "--exact".to_owned(), (*path).to_owned()]);
    let ran = cargo(&run, RUN_TIMEOUT)?;
    let ok_line = format!("test {path} ... ok");
    Ok(TestRun {
        passed: ran.success && ran.stdout.lines().any(|l| l == ok_line),
        timed_out: ran.timed_out,
        output: tail(&format!("{}{}", ran.stdout, ran.stderr)),
    })
}

fn release_guard() -> Result<(), String> {
    let root = root();
    let (registry, _, _) = load(&root)?;
    let mut seen: Vec<&str> = Vec::new();
    let mut bad = Vec::new();
    for m in &registry.mutants {
        if seen.contains(&m.krate.as_str()) {
            continue;
        }
        seen.push(&m.krate);
        let args: Vec<String> = [
            "check",
            "--release",
            "--locked",
            "-p",
            &m.krate,
            "--features",
            &format!("{}/{}", m.krate, m.feature),
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        let out = cargo(&args, BUILD_TIMEOUT)?;
        if !out.success && out.stderr.contains(GUARD_MESSAGE) {
            println!("refused  {} with {} in release", m.krate, m.feature);
        } else {
            println!("FAILED   {} built in release with {}", m.krate, m.feature);
            bad.push(m.krate.clone());
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "release builds accepted mutants: {}",
            bad.join(", ")
        ))
    }
}

struct Output {
    success: bool,
    timed_out: bool,
    stdout: String,
    stderr: String,
}

/// Runs cargo in its own process group, so a timeout kills the test binary
/// it started too.
fn cargo(args: &[String], timeout: Duration) -> Result<Output, String> {
    let program = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut child = Command::new(program)
        .args(args)
        .current_dir(root())
        // A mutant fails proptest suites on purpose; the counterexample must
        // not be written into the source tree as a regression file.
        .env("PROPTEST_DISABLE_FAILURE_PERSISTENCE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("cargo {}: {e}", args.join(" ")))?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let (status, timed_out) = wait(&mut child, timeout).map_err(|e| e.to_string())?;
    Ok(Output {
        success: status.is_some_and(|s| s.success()),
        timed_out,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

fn drain(pipe: Option<impl Read + Send + 'static>) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut text = String::new();
        if let Some(mut pipe) = pipe {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            text = String::from_utf8_lossy(&bytes).into_owned();
        }
        text
    })
}

fn wait(
    child: &mut Child,
    timeout: Duration,
) -> io::Result<(Option<std::process::ExitStatus>, bool)> {
    let deadline = Instant::now().checked_add(timeout);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok((Some(status), false));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            // The group id is the child's pid (`process_group(0)`).
            let _ = Command::new("kill")
                .args(["-KILL", "--", &format!("-{}", child.id())])
                .status();
            child.wait()?;
            return Ok((None, true));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// The last lines of a long output, which is where cargo and libtest say why.
fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let from = lines.len().saturating_sub(40);
    lines.get(from..).unwrap_or_default().join("\n")
}

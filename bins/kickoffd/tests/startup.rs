//! The installed executable's two modes use the same seam as the IPC tests.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#[path = "../../../tests/support/exec.rs"]
mod exec;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn client_helper() {
    let Some(base) = std::env::var_os("KIPC_STARTUP_CLIENT") else {
        return;
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let dir = kickoff_ipc::RuntimeDir::open_in(std::path::Path::new(&base)).unwrap();
        let mut client = kickoff_ipc::connect::<kickoff_ipc::role::Cli>(
            &dir,
            &kickoff_ipc::Trust::kickoffd().unwrap(),
        )
        .await
        .unwrap();
        assert!(matches!(
            client.call(kickoff_ipc::CliCommand::Status).await,
            Ok(kickoff_ipc::Reply::Refused(kickoff_ipc::Refusal::Failed))
        ));
        let identity =
            kickoff_secret::key::IdentityKey::new(iroh_base::SecretKey::from_bytes(&[7; 32]));
        let mut invites = kickoff_wire::Invites::new(&identity).unwrap();
        let ticket = kickoff_secret::Secret::new(kickoff_wire::Ticket {
            door: iroh_base::EndpointAddr::new(identity.public())
                .with_relay_url("https://relay.example./".parse().unwrap()),
            cap: invites.issue(&identity, None, Instant::now()).unwrap(),
        });
        let text =
            kickoff_ipc::TicketText::new(kickoff_wire::encode_ticket(&ticket).unwrap()).unwrap();
        assert!(
            matches!(
                client.call(kickoff_ipc::CliCommand::Join(text)).await,
                Ok(kickoff_ipc::Reply::Refused(kickoff_ipc::Refusal::Failed))
            ),
            "the installed facade/worker must receive a genuine protected ticket command"
        );
    });
}

#[test]
fn si_7_installed_daemon_modes_authenticate_with_hardening() {
    use std::os::unix::fs::PermissionsExt;
    let base = Temp(std::env::temp_dir().join(format!("kickoff-startup-{}", std::process::id())));
    std::fs::create_dir(&base.0).unwrap();
    std::fs::set_permissions(&base.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let installed = base.0.join("install");
    std::fs::create_dir(&installed).unwrap();
    let daemon = installed.join("kickoffd");
    let client = installed.join("kickoff");
    exec::copy_executable(env!("CARGO_BIN_EXE_kickoffd"), &daemon);
    exec::copy_executable(std::env::current_exe().unwrap(), &client);
    let dir = kickoff_ipc::RuntimeDir::open_in(&base.0).unwrap();
    let mut running = Daemon(
        Command::new(&daemon)
            .env("XDG_RUNTIME_DIR", &base.0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while !dir.socket_path().exists() {
        assert!(
            Instant::now() < deadline,
            "daemon did not create the real IPC socket"
        );
        assert!(
            running.0.try_wait().unwrap().is_none(),
            "daemon startup failed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = Command::new(&client)
        .args([
            "--exact",
            "client_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("KIPC_STARTUP_CLIENT", &base.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "installed daemon refused the authenticated client: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(running.0.try_wait().unwrap().is_none());
    // Worker mode alone, without an inherited facade pair, must fail closed.
    assert!(
        !Command::new(&daemon)
            .arg("--ipc-worker")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
}

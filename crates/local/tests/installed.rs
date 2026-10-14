#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "../../../tests/support/exec.rs"]
mod exec;
use kickoff_local::{DataOnly, PeerKind, Trust};
use tokio::io::AsyncReadExt;

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Temp(std::path::PathBuf);
impl Temp {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("kickoff-local-{}-{n}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn untrusted_process_helper() {
    let Some(path) = std::env::var_os("KLOCAL_UNTRUSTED_SOCKET") else {
        return;
    };
    let mut socket = tokio::net::UnixStream::connect(path).await.unwrap();
    let mut received = Vec::new();
    socket.read_to_end(&mut received).await.unwrap();
    assert!(received.is_empty(), "an unrelated recipient received bytes");
}

#[tokio::test]
async fn si_30_custom_trust_cannot_authorize_a_secret_recipient() {
    let base = Temp::new();
    let path = base.0.join("socket");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "untrusted_process_helper", "--test-threads=1"])
            .env("KLOCAL_UNTRUSTED_SOCKET", &path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let (sender, _) = tokio::time::timeout(std::time::Duration::from_secs(3), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let custom = Trust::same_user(&[&std::env::current_exe().unwrap()]).unwrap();
    let peer = custom.check(&sender).unwrap();
    assert_ne!(
        u32::try_from(peer.pid).unwrap(),
        std::process::id(),
        "wrong-exe case must not hit self-recipient guard"
    );
    let mut sender = DataOnly::new(sender);
    assert!(
        sender.installed_peer(PeerKind::Daemon).is_err(),
        "custom caller became installed daemon"
    );
    assert!(
        sender.installed_peer(PeerKind::Client).is_err(),
        "custom caller became installed client"
    );
    drop(sender);
    assert!(child.0.wait().unwrap().success());
}

#[tokio::test]
async fn si_30_installed_self_recipient_is_refused_before_sending_bytes() {
    if std::env::var_os("KLOCAL_SELF_INSTALL").is_none() {
        let base = Temp::new();
        let program = base.0.join("kickoff");
        exec::copy_executable(std::env::current_exe().unwrap(), &program);
        std::fs::hard_link(&program, base.0.join("kickoffd")).unwrap();
        let output = std::process::Command::new(&program)
            .args([
                "--exact",
                "si_30_installed_self_recipient_is_refused_before_sending_bytes",
                "--test-threads=1",
            ])
            .env("KLOCAL_SELF_INSTALL", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let (sender, mut receiver) = tokio::net::UnixStream::pair().unwrap();
    assert!(
        Trust::kickoffd().unwrap().check(&sender).is_ok(),
        "positive canonical installed binary control"
    );
    let mut sender = DataOnly::new(sender);
    assert!(
        sender.installed_peer(PeerKind::Daemon).is_err(),
        "installed holder minted a self-recipient authority"
    );
    assert!(
        sender.installed_peer(PeerKind::Client).is_err(),
        "installed holder minted a self-recipient authority"
    );
    drop(sender);
    let mut bytes = Vec::new();
    receiver.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty(), "self recipient received bytes");
}

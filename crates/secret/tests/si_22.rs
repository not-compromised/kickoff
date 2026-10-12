//! SI-22 (local half): the identity key is readable only by its user, and a
//! reset revokes every trust entry that named the old key. The signed
//! revocation notice for friends' clients is M10.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::indexing_slicing
)]

use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use iroh_base::SecretKey;
use kickoff_secret::identity::{IdentityStore, StoreError, TrustState};

/// A private stand-in for `$XDG_DATA_HOME`, removed on drop.
struct TempBase(PathBuf);

impl TempBase {
    fn new() -> TempBase {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!("/tmp/ksec-id-{}-{n}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        chmod(&path, 0o700);
        TempBase(path)
    }

    fn state(&self) -> PathBuf {
        self.0.join("kickoff").join("state")
    }

    fn identity(&self) -> PathBuf {
        self.state().join("identity")
    }

    fn store(&self) -> IdentityStore {
        IdentityStore::open_in(&self.0).unwrap()
    }
}

impl Drop for TempBase {
    fn drop(&mut self) {
        for dir in [self.0.clone(), self.0.join("kickoff"), self.state()] {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn public(store: &IdentityStore) -> iroh_base::EndpointId {
    store.load_or_create().unwrap().expose(SecretKey::public)
}

#[test]
fn si_22_identity_key_created_0600_in_a_0700_dir() {
    let base = TempBase::new();
    let first = public(&base.store());

    let state = std::fs::symlink_metadata(base.state()).unwrap();
    assert!(state.is_dir());
    assert_eq!(state.mode() & 0o7777, 0o700);
    let file = std::fs::symlink_metadata(base.identity()).unwrap();
    assert!(file.file_type().is_file());
    assert_eq!(file.mode() & 0o7777, 0o600);
    assert_eq!(file.uid(), state.uid());
    let names: Vec<_> = std::fs::read_dir(base.state())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["identity"], "no staging file left behind");

    // Persistent: the next start loads the same key.
    assert_eq!(public(&base.store()), first);
}

/// Each wrong `identity` is refused and left exactly as it was: never
/// followed, read, chmodded or replaced.
#[test]
fn si_22_identity_key_with_wrong_mode_type_or_link_refused() {
    let good = TempBase::new();
    public(&good.store());
    let valid = std::fs::read(good.identity()).unwrap();

    // Readable by group and other, with a valid key inside.
    let base = TempBase::new();
    let store = base.store();
    std::fs::write(base.identity(), &valid).unwrap();
    chmod(&base.identity(), 0o644);
    assert_eq!(store.load_or_create().err(), Some(StoreError::UnsafePath));
    assert_eq!(mode(&base.identity()), 0o644);
    assert_eq!(std::fs::read(base.identity()).unwrap(), valid);

    // A symlink to a valid 0600 key file elsewhere.
    let base = TempBase::new();
    let store = base.store();
    std::os::unix::fs::symlink(good.identity(), base.identity()).unwrap();
    assert_eq!(store.load_or_create().err(), Some(StoreError::UnsafePath));
    assert!(
        std::fs::symlink_metadata(base.identity())
            .unwrap()
            .is_symlink()
    );

    // A FIFO: refused without blocking on it.
    let base = TempBase::new();
    let store = base.store();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        base.identity(),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    assert_eq!(store.load_or_create().err(), Some(StoreError::UnsafePath));
    assert!(
        std::fs::symlink_metadata(base.identity())
            .unwrap()
            .file_type()
            .is_fifo()
    );

    // A directory.
    let base = TempBase::new();
    let store = base.store();
    std::fs::create_dir(base.identity()).unwrap();
    chmod(&base.identity(), 0o600);
    assert_eq!(store.load_or_create().err(), Some(StoreError::UnsafePath));
    assert!(base.identity().is_dir());
}

#[test]
fn si_22_state_dir_with_wrong_mode_type_or_link_refused() {
    // Group- and other-readable.
    let base = TempBase::new();
    std::fs::create_dir_all(base.state()).unwrap();
    chmod(&base.state(), 0o755);
    assert_eq!(
        IdentityStore::open_in(&base.0).err(),
        Some(StoreError::UnsafePath)
    );
    assert_eq!(mode(&base.state()), 0o755, "refusal must not touch it");

    // A symlink to a private directory elsewhere.
    let base = TempBase::new();
    let elsewhere = TempBase::new();
    std::fs::create_dir(base.0.join("kickoff")).unwrap();
    chmod(&base.0.join("kickoff"), 0o700);
    std::os::unix::fs::symlink(&elsewhere.0, base.state()).unwrap();
    assert_eq!(
        IdentityStore::open_in(&base.0).err(),
        Some(StoreError::UnsafePath)
    );
    assert_eq!(std::fs::read_dir(&elsewhere.0).unwrap().count(), 0);

    // A file.
    let base = TempBase::new();
    std::fs::create_dir(base.0.join("kickoff")).unwrap();
    chmod(&base.0.join("kickoff"), 0o700);
    std::fs::write(base.state(), b"squatter").unwrap();
    assert_eq!(
        IdentityStore::open_in(&base.0).err(),
        Some(StoreError::UnsafePath)
    );
    assert_eq!(std::fs::read(base.state()).unwrap(), b"squatter");
}

#[test]
fn data_dir_writable_by_others_or_relative_refused() {
    let base = TempBase::new();
    chmod(&base.0, 0o777);
    assert_eq!(
        IdentityStore::open_in(&base.0).err(),
        Some(StoreError::UnsafePath)
    );
    assert!(!base.0.join("kickoff").exists());
    assert_eq!(
        IdentityStore::open_in(Path::new("relative/share")).err(),
        Some(StoreError::UnsafePath)
    );
}

/// A damaged key file is an error, not a reason to mint a new identity over
/// it: that would silently drop every friendship the old key had.
#[test]
fn si_22_damaged_identity_file_is_refused_not_replaced() {
    let base = TempBase::new();
    let store = base.store();
    public(&store);
    std::fs::write(base.identity(), b"KOID\0\x01short").unwrap();
    assert_eq!(store.load_or_create().err(), Some(StoreError::Damaged));
    assert_eq!(std::fs::read(base.identity()).unwrap(), b"KOID\0\x01short");
}

#[test]
fn si_22_reset_revokes_every_trust_entry_for_the_old_key() {
    let base = TempBase::new();
    let store = base.store();
    let old = public(&store);
    let friend = SecretKey::from_bytes(&[5; 32]).public();
    let mut trust = store.trust_list().unwrap();
    trust.trust(old).unwrap();
    trust.trust(friend).unwrap();
    store.save_trust(&trust).unwrap();

    let new = store.reset().unwrap().expose(SecretKey::public);
    assert_ne!(new, old);

    // As the next start sees it.
    let store = base.store();
    assert_eq!(public(&store), new);
    let trust = store.trust_list().unwrap();
    assert_eq!(trust.state(&old), Some(TrustState::Revoked));
    assert_eq!(trust.state(&friend), Some(TrustState::Trusted));
    // What kickoffd hands the admission owner: the old key's rejoin would
    // need a ticket.
    assert_eq!(trust.trusted().collect::<Vec<_>>(), [friend]);

    // A key no entry named is still marked revoked after its reset.
    store.reset().unwrap();
    assert_eq!(
        store.trust_list().unwrap().state(&new),
        Some(TrustState::Revoked)
    );
}

const READER_ENV: &str = "KSEC_READ_IDENTITY";

/// Runs only inside `si_22_another_user_cannot_read_the_identity_key`, as a
/// subordinate uid or as us: try to read the key file and report.
#[test]
fn identity_reader() {
    let Some(path) = std::env::var_os(READER_ENV) else {
        return;
    };
    let report = match std::fs::File::open(&path) {
        Err(e) => format!("open-error:{:?}", e.kind()),
        Ok(mut f) => {
            let mut buf = Vec::new();
            match f.read_to_end(&mut buf) {
                Ok(n) => format!("read:{n}"),
                Err(e) => format!("read-error:{:?}", e.kind()),
            }
        }
    };
    println!("KSEC {report}");
}

fn read_as(reader: &Path, identity: &Path, second_uid: bool) -> String {
    let mut cmd = if second_uid {
        let mut cmd = std::process::Command::new("unshare");
        cmd.args(["--map-auto", "--setuid", "0", "--setgid", "0"])
            .arg(reader);
        cmd
    } else {
        std::process::Command::new(reader)
    };
    let out = cmd
        .args([
            "--exact",
            "identity_reader",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(READER_ENV, identity)
        .output()
        .expect("the reader must run");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    stdout
        .lines()
        .find_map(|l| l.split_once("KSEC ").map(|(_, r)| r.trim().to_owned()))
        .unwrap_or_else(|| {
            panic!(
                "the reader did not run; the second-uid case needs util-linux \
                 unshare, newuidmap and a /etc/subuid entry for this user. \
                 stdout: {stdout} stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            )
        })
}

/// A real second uid (the first subordinate uid, through `unshare
/// --map-auto`; no root) cannot read the key even with every directory above
/// the state directory open to it. The same reader as our own uid can, so
/// the refusal is the state directory's and the file's mode.
#[test]
fn si_22_another_user_cannot_read_the_identity_key() {
    let base = TempBase::new();
    public(&base.store());
    chmod(&base.0, 0o711);
    chmod(&base.0.join("kickoff"), 0o711);

    let shared = TempBase::new();
    chmod(&shared.0, 0o755);
    let reader = shared.0.join("reader");
    std::fs::copy(std::env::current_exe().unwrap(), &reader).unwrap();
    chmod(&reader, 0o755);

    assert_eq!(read_as(&reader, &base.identity(), false), "read:38");
    assert_eq!(
        read_as(&reader, &base.identity(), true),
        "open-error:PermissionDenied"
    );
}

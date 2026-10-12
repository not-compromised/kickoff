//! The persistent identity key at rest, and the local trust list that a
//! reset revokes (design §3.4 "Identity key", SI-22).
//!
//! ```text
//! $XDG_DATA_HOME/kickoff/state/      0700, ours, not a symlink
//!                         identity   0600, ours, regular: "KOID" v1 + 32-byte key
//!                         trust      0600, ours, regular: "KOTR" v1 + entries
//! ```
//!
//! Every file is opened relative to the state directory's handle with
//! `O_NOFOLLOW`, checked on that handle, and written by creating a staging
//! file exclusively, syncing it and renaming it into place, so no reader
//! ever sees a partial key and no name we do not own is followed.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use iroh_base::{EndpointId, SecretKey};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
use rustix::io::Errno;
use zeroize::Zeroizing;

use crate::Secret;

const APP_DIR: &str = "kickoff";
const STATE_DIR: &str = "state";
const IDENTITY: &str = "identity";
const IDENTITY_STAGING: &str = "identity.new";
const TRUST: &str = "trust";
const TRUST_STAGING: &str = "trust.new";
const STATE_LOCK: &str = "state.lock";

const DIR_MODE: u32 = if cfg!(feature = "mutant-si22-world-readable") {
    0o755
} else {
    0o700
};
const FILE_MODE: u32 = if cfg!(feature = "mutant-si22-world-readable") {
    0o644
} else {
    0o600
};

// Persisted state carries a version (SI-10); another version is `Damaged`.
const IDENTITY_MAGIC: [u8; 4] = *b"KOID";
const TRUST_MAGIC: [u8; 4] = *b"KOTR";
const FORMAT_VERSION: u16 = 1;
const HEADER_LEN: usize = 6;
const KEY_LEN: usize = 32;
const IDENTITY_LEN: usize = HEADER_LEN + KEY_LEN;
const TRUST_ENTRY_LEN: usize = KEY_LEN + 1;
/// Entries in the trust list; the file is refused beyond this.
pub const MAX_TRUST_ENTRIES: usize = 4096;
const TRUST_MAX_LEN: usize = HEADER_LEN + 2 + MAX_TRUST_ENTRIES * TRUST_ENTRY_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreError {
    /// Neither `$XDG_DATA_HOME` nor `$HOME` is an absolute path.
    NoDataDir,
    /// A directory or file has the wrong owner, type or mode, or is a
    /// symlink. Nothing was changed.
    UnsafePath,
    /// A file has the wrong length, header, version or content. It is left
    /// as it is: a damaged identity is never silently replaced by a new one.
    Damaged,
    /// The trust list already holds `MAX_TRUST_ENTRIES`.
    Full,
    /// The identity file appeared while it was being created.
    Raced,
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NoDataDir => f.write_str("no absolute XDG_DATA_HOME or HOME"),
            StoreError::UnsafePath => {
                f.write_str("identity directory or file has the wrong owner, type or mode")
            }
            StoreError::Damaged => f.write_str("identity or trust file is damaged"),
            StoreError::Full => f.write_str("trust list is full"),
            StoreError::Raced => f.write_str("identity file appeared while being created"),
            StoreError::Io(kind) => write!(f, "i/o error: {kind:?}"),
        }
    }
}

impl std::error::Error for StoreError {}

fn io(e: Errno) -> StoreError {
    StoreError::Io(std::io::Error::from(e).kind())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    /// May join without a ticket (§4.4 "Trusted friends").
    Trusted,
    /// Refused as trusted until the user trusts it again explicitly.
    Revoked,
}

/// The local trust list. kickoffd hands `trusted()` to the session's
/// admission owner; a revoked entry stays, so the identity is not trusted
/// again by accident.
#[derive(Debug, Clone, Default)]
pub struct TrustList {
    entries: Vec<(EndpointId, TrustState)>,
    baseline: Vec<(EndpointId, TrustState)>,
}

impl PartialEq for TrustList {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}
impl Eq for TrustList {}

impl TrustList {
    pub fn state(&self, id: &EndpointId) -> Option<TrustState> {
        self.entries
            .iter()
            .find(|(known, _)| known == id)
            .map(|(_, state)| *state)
    }

    pub fn trusted(&self) -> impl Iterator<Item = EndpointId> + '_ {
        self.entries
            .iter()
            .filter(|(_, state)| *state == TrustState::Trusted)
            .map(|(id, _)| *id)
    }

    /// An explicit user action; it also re-trusts a revoked identity.
    pub fn trust(&mut self, id: EndpointId) -> Result<(), StoreError> {
        self.set(id, TrustState::Trusted)
    }

    pub fn revoke(&mut self, id: EndpointId) -> Result<(), StoreError> {
        self.set(id, TrustState::Revoked)
    }

    fn set(&mut self, id: EndpointId, state: TrustState) -> Result<(), StoreError> {
        if let Some(entry) = self.entries.iter_mut().find(|(known, _)| *known == id) {
            entry.1 = state;
            return Ok(());
        }
        if self.entries.len() >= MAX_TRUST_ENTRIES {
            return Err(StoreError::Full);
        }
        self.entries.push((id, state));
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let count = u16::try_from(self.entries.len()).map_err(|_| StoreError::Full)?;
        let mut out = header(TRUST_MAGIC).to_vec();
        out.extend_from_slice(&count.to_be_bytes());
        for (id, state) in &self.entries {
            out.extend_from_slice(id.as_bytes());
            out.push(match state {
                TrustState::Trusted => 1,
                TrustState::Revoked => 2,
            });
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<TrustList, StoreError> {
        let body = strip_header(bytes, TRUST_MAGIC)?;
        let (count, mut rest) = body.split_first_chunk::<2>().ok_or(StoreError::Damaged)?;
        let count = usize::from(u16::from_be_bytes(*count));
        if count > MAX_TRUST_ENTRIES || rest.len() != count.saturating_mul(TRUST_ENTRY_LEN) {
            return Err(StoreError::Damaged);
        }
        let mut list = TrustList::default();
        while let Some((key, tail)) = rest.split_first_chunk::<KEY_LEN>() {
            let (state, tail) = tail.split_first().ok_or(StoreError::Damaged)?;
            let id = EndpointId::from_bytes(key).map_err(|_| StoreError::Damaged)?;
            let state = match state {
                1 => TrustState::Trusted,
                2 => TrustState::Revoked,
                _ => return Err(StoreError::Damaged),
            };
            if list.state(&id).is_some() {
                return Err(StoreError::Damaged);
            }
            list.entries.push((id, state));
            rest = tail;
        }
        list.baseline = list.entries.clone();
        Ok(list)
    }
}

/// The state directory, held open: every file operation is relative to this
/// handle, so renaming or replacing a parent directory later changes nothing.
#[derive(Debug)]
pub struct IdentityStore {
    dir: OwnedFd,
    uid: u32,
    state_lock: OwnedFd,
    local_lock: Mutex<()>,
    #[cfg(test)]
    before_publish: Option<std::sync::Arc<(std::sync::Barrier, std::sync::Barrier)>>,
}

struct Transaction<'a> {
    fd: &'a OwnedFd,
    _local: MutexGuard<'a, ()>,
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !cfg!(feature = "mutant-si22-no-state-lock") {
            let _ = rustix::fs::flock(self.fd, rustix::fs::FlockOperation::Unlock);
        }
    }
}

impl IdentityStore {
    /// `$XDG_DATA_HOME/kickoff/state`, or `$HOME/.local/share/kickoff/state`.
    pub fn open() -> Result<IdentityStore, StoreError> {
        IdentityStore::open_in(&data_home()?)
    }

    /// `base` stands in for the XDG data directory: absolute, a directory we
    /// own that no one else can write. `kickoff` inside it is created 0700 or
    /// accepted if ours and not writable by others; `state` inside that is
    /// created 0700 or accepted only if ours, a real directory and 0700.
    pub fn open_in(base: &Path) -> Result<IdentityStore, StoreError> {
        if !base.is_absolute() {
            return Err(StoreError::UnsafePath);
        }
        let uid = rustix::process::geteuid().as_raw();
        // The base itself may be reached through a symlink (a home directory
        // often is); everything we create below it may not.
        let base_fd = rustix::fs::openat(
            rustix::fs::CWD,
            base,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StoreError::UnsafePath)?;
        check_dir(&base_fd, uid, |mode| mode & 0o022 == 0)?;
        let app = subdir(&base_fd, APP_DIR, uid, |mode| mode & 0o022 == 0)?;
        let state = subdir(&app, STATE_DIR, uid, |mode| {
            cfg!(feature = "mutant-si22-dir-unchecked") || mode == DIR_MODE
        })?;
        let state_lock = match rustix::fs::openat(
            &state,
            STATE_LOCK,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => {
                rustix::fs::fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(io)?;
                fd
            }
            Err(Errno::EXIST) => rustix::fs::openat(
                &state,
                STATE_LOCK,
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| StoreError::UnsafePath)?,
            Err(_) => return Err(StoreError::UnsafePath),
        };
        let metadata = rustix::fs::fstat(&state_lock).map_err(io)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_uid != uid
            || metadata.st_mode & 0o7777 != 0o600
            || metadata.st_nlink != 1
        {
            return Err(StoreError::UnsafePath);
        }
        Ok(IdentityStore {
            dir: state,
            uid,
            state_lock,
            local_lock: Mutex::new(()),
            #[cfg(test)]
            before_publish: None,
        })
    }

    /// The identity key, created on first use. An existing file must be a
    /// regular file we own with mode 0600 holding exactly one key; anything
    /// else is refused and left alone.
    pub fn load_or_create(&self) -> Result<Secret<SecretKey>, StoreError> {
        let _transaction = self.transaction()?;
        match self.read(IDENTITY, IDENTITY_LEN)? {
            Some(bytes) => match decode_identity(&bytes) {
                Err(StoreError::Damaged) if cfg!(feature = "mutant-si22-replace-damaged") => {
                    let _ = rustix::fs::unlinkat(&self.dir, IDENTITY, AtFlags::empty());
                    self.create_identity()
                }
                decoded => decoded,
            },
            None => self.create_identity(),
        }
    }

    /// Replaces the identity key with a new one. First, every trust entry
    /// naming the old key is marked revoked (and one is added if none did),
    /// so whoever holds the old key is no longer trusted here; then the new
    /// key replaces the old one. A crash in between leaves the old key with
    /// its trust revoked, which fails closed.
    pub fn reset(&self) -> Result<Secret<SecretKey>, StoreError> {
        let _transaction = self.transaction()?;
        if let Some(bytes) = self.read(IDENTITY, IDENTITY_LEN)? {
            let old = decode_identity(&bytes)?.expose(SecretKey::public);
            let mut trust = self.read_trust()?;
            if !cfg!(feature = "mutant-si22-reset-keeps-trust") {
                trust.revoke(old)?;
            }
            self.save_trust_locked(&trust)?;
        }
        let key = new_key()?;
        self.publish(
            IDENTITY,
            IDENTITY_STAGING,
            &encode_identity(&key),
            Publish::Replace,
        )?;
        Ok(key)
    }

    /// The trust list; empty if none was saved yet.
    pub fn trust_list(&self) -> Result<TrustList, StoreError> {
        let _transaction = self.transaction()?;
        self.read_trust()
    }

    fn read_trust(&self) -> Result<TrustList, StoreError> {
        match self.read(TRUST, TRUST_MAX_LEN)? {
            Some(bytes) => TrustList::decode(&bytes),
            None => Ok(TrustList::default()),
        }
    }

    /// Saves only against the snapshot this list was loaded from. Reload the
    /// list after a successful save or a `Raced` error before another edit.
    pub fn save_trust(&self, list: &TrustList) -> Result<(), StoreError> {
        let _transaction = self.transaction()?;
        self.save_trust_locked(list)
    }

    fn save_trust_locked(&self, list: &TrustList) -> Result<(), StoreError> {
        if !cfg!(feature = "mutant-si22-stale-trust-save")
            && list.baseline != self.read_trust()?.entries
        {
            return Err(StoreError::Raced);
        }
        self.publish(TRUST, TRUST_STAGING, &list.encode()?, Publish::Replace)
    }

    fn transaction(&self) -> Result<Transaction<'_>, StoreError> {
        let local = self
            .local_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !cfg!(feature = "mutant-si22-no-state-lock") {
            rustix::fs::flock(&self.state_lock, rustix::fs::FlockOperation::LockExclusive)
                .map_err(io)?;
        }
        Ok(Transaction {
            fd: &self.state_lock,
            _local: local,
        })
    }

    fn create_identity(&self) -> Result<Secret<SecretKey>, StoreError> {
        let key = new_key()?;
        self.publish(
            IDENTITY,
            IDENTITY_STAGING,
            &encode_identity(&key),
            Publish::Exclusive,
        )?;
        Ok(key)
    }

    /// `None` if `name` does not exist. Opened without following a symlink
    /// and without blocking on a FIFO, then checked on the open handle.
    fn read(&self, name: &str, max_len: usize) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        let unchecked = cfg!(feature = "mutant-si22-file-unchecked");
        let follow = if unchecked {
            OFlags::empty()
        } else {
            OFlags::NOFOLLOW
        };
        let fd = match rustix::fs::openat(
            &self.dir,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | follow,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(StoreError::UnsafePath),
        };
        let stat = rustix::fs::fstat(&fd).map_err(io)?;
        if !unchecked
            && (FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_uid != self.uid
                || stat.st_mode & 0o7777 != FILE_MODE)
        {
            return Err(StoreError::UnsafePath);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(max_len));
        let limit = u64::try_from(max_len).map_err(|_| StoreError::Damaged)?;
        File::from(fd)
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| StoreError::Io(e.kind()))?;
        if bytes.len() > max_len {
            return Err(StoreError::Damaged);
        }
        Ok(Some(bytes))
    }

    /// Writes `bytes` to a staging file created exclusively with `FILE_MODE`,
    /// syncs it, and renames it to `name`. A staging file left by an
    /// interrupted write is ours (nobody else can enter this directory) and
    /// is removed first.
    fn publish(
        &self,
        name: &str,
        staging: &str,
        bytes: &[u8],
        how: Publish,
    ) -> Result<(), StoreError> {
        let create = || {
            rustix::fs::openat(
                &self.dir,
                staging,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(FILE_MODE),
            )
        };
        let fd = match create() {
            Err(Errno::EXIST) => {
                rustix::fs::unlinkat(&self.dir, staging, AtFlags::empty()).map_err(io)?;
                create().map_err(io)?
            }
            other => other.map_err(io)?,
        };
        // The umask can only have narrowed the mode; set it exactly.
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(FILE_MODE)).map_err(io)?;
        let mut file = File::from(fd);
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| StoreError::Io(e.kind()))?;
        #[cfg(test)]
        if let Some(barriers) = &self.before_publish {
            barriers.0.wait();
            barriers.1.wait();
        }
        let renamed = match how {
            Publish::Exclusive => rustix::fs::renameat_with(
                &self.dir,
                staging,
                &self.dir,
                name,
                RenameFlags::NOREPLACE,
            ),
            Publish::Replace => rustix::fs::renameat(&self.dir, staging, &self.dir, name),
        };
        if let Err(e) = renamed {
            let _ = rustix::fs::unlinkat(&self.dir, staging, AtFlags::empty());
            return Err(if e == Errno::EXIST {
                StoreError::Raced
            } else {
                io(e)
            });
        }
        rustix::fs::fsync(&self.dir).map_err(io)
    }
}

#[derive(Clone, Copy)]
enum Publish {
    /// Never replaces an existing file: a first key is created exclusively.
    Exclusive,
    Replace,
}

fn data_home() -> Result<PathBuf, StoreError> {
    let absolute = |var| {
        std::env::var_os(var)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    absolute("XDG_DATA_HOME")
        .or_else(|| absolute("HOME").map(|home| home.join(".local").join("share")))
        .ok_or(StoreError::NoDataDir)
}

/// Opens `name` inside `parent`, creating it with `DIR_MODE` if absent, and
/// accepts it only if it is a real directory we own whose mode passes `ok`.
fn subdir(
    parent: &OwnedFd,
    name: &str,
    uid: u32,
    ok: impl Fn(u32) -> bool,
) -> Result<OwnedFd, StoreError> {
    let created = match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(DIR_MODE)) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(e) => return Err(io(e)),
    };
    let follow = if cfg!(feature = "mutant-si22-dir-unchecked") {
        OFlags::empty()
    } else {
        OFlags::NOFOLLOW
    };
    let fd = rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | follow,
        Mode::empty(),
    )
    .map_err(|_| StoreError::UnsafePath)?;
    if created {
        rustix::fs::fchmod(&fd, Mode::from_raw_mode(DIR_MODE)).map_err(io)?;
    }
    if !cfg!(feature = "mutant-si22-dir-unchecked") {
        check_dir(&fd, uid, ok)?;
    }
    Ok(fd)
}

fn check_dir(fd: &OwnedFd, uid: u32, ok: impl Fn(u32) -> bool) -> Result<(), StoreError> {
    let stat = rustix::fs::fstat(fd).map_err(io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != uid
        || !ok(stat.st_mode & 0o7777)
    {
        return Err(StoreError::UnsafePath);
    }
    Ok(())
}

fn header(magic: [u8; 4]) -> [u8; HEADER_LEN] {
    let [m0, m1, m2, m3] = magic;
    let [v0, v1] = FORMAT_VERSION.to_be_bytes();
    [m0, m1, m2, m3, v0, v1]
}

fn strip_header(bytes: &[u8], magic: [u8; 4]) -> Result<&[u8], StoreError> {
    match bytes.split_first_chunk::<HEADER_LEN>() {
        Some((head, rest)) if *head == header(magic) => Ok(rest),
        _ => Err(StoreError::Damaged),
    }
}

fn new_key() -> Result<Secret<SecretKey>, StoreError> {
    let mut seed = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(seed.as_mut_slice()).map_err(|_| StoreError::Io(std::io::ErrorKind::Other))?;
    Ok(Secret::new(SecretKey::from_bytes(&seed)))
}

fn encode_identity(key: &Secret<SecretKey>) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(IDENTITY_LEN));
    out.extend_from_slice(&header(IDENTITY_MAGIC));
    let raw = Zeroizing::new(key.expose(SecretKey::to_bytes));
    out.extend_from_slice(raw.as_slice());
    out
}

fn decode_identity(bytes: &[u8]) -> Result<Secret<SecretKey>, StoreError> {
    let body = strip_header(bytes, IDENTITY_MAGIC)?;
    let raw: Zeroizing<[u8; KEY_LEN]> =
        Zeroizing::new(body.try_into().map_err(|_| StoreError::Damaged)?);
    Ok(Secret::new(SecretKey::from_bytes(&raw)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    #[test]
    fn si_22_concurrent_creators_return_the_published_identity() {
        use std::sync::{Arc, Barrier, mpsc};
        use std::time::Duration;
        let base = std::env::temp_dir().join(format!("ksec-overlap-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        rustix::fs::chmod(&base, Mode::from_raw_mode(0o700)).unwrap();
        let mut first = IdentityStore::open_in(&base).unwrap();
        let second = IdentityStore::open_in(&base).unwrap();
        let barriers = Arc::new((Barrier::new(2), Barrier::new(2)));
        first.before_publish = Some(Arc::clone(&barriers));
        let creator = std::thread::spawn(move || {
            first
                .load_or_create()
                .map(|key| key.expose(SecretKey::public))
        });
        barriers.0.wait();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let contender = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = second
                .load_or_create()
                .map(|key| key.expose(SecretKey::public));
            done_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        let early = done_rx.recv_timeout(Duration::from_millis(100)).ok();
        barriers.1.wait();
        let published = creator.join().unwrap();
        let other = early.or_else(|| done_rx.recv_timeout(Duration::from_secs(2)).ok());
        contender.join().unwrap();
        let on_disk = IdentityStore::open_in(&base)
            .unwrap()
            .load_or_create()
            .map(|key| key.expose(SecretKey::public));
        std::fs::remove_dir_all(base).unwrap();
        assert!(
            early.is_none(),
            "a second writer took the first writer's staging file"
        );
        assert!(published.is_ok(), "the creator lost its staging file");
        assert_eq!(other, Some(published));
        assert_eq!(on_disk, published);
    }

    #[test]
    fn trust_list_round_trips_and_rejects_damage() {
        let mut list = TrustList::default();
        list.trust(id(1)).unwrap();
        list.revoke(id(2)).unwrap();
        let bytes = list.encode().unwrap();
        assert_eq!(TrustList::decode(&bytes).unwrap(), list);
        for cut in 0..bytes.len() {
            assert_eq!(TrustList::decode(&bytes[..cut]), Err(StoreError::Damaged));
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(TrustList::decode(&longer), Err(StoreError::Damaged));
        let mut bad_state = bytes.clone();
        *bad_state.last_mut().unwrap() = 3;
        assert_eq!(TrustList::decode(&bad_state), Err(StoreError::Damaged));
        let mut other_version = bytes.clone();
        other_version[5] = 2;
        assert_eq!(TrustList::decode(&other_version), Err(StoreError::Damaged));
    }

    #[test]
    fn duplicate_entries_are_damage() {
        let mut list = TrustList::default();
        list.trust(id(1)).unwrap();
        let mut bytes = list.encode().unwrap();
        bytes[7] = 2;
        bytes.extend_from_slice(id(1).as_bytes());
        bytes.push(2);
        assert_eq!(TrustList::decode(&bytes), Err(StoreError::Damaged));
    }

    #[test]
    fn identity_round_trips_and_rejects_damage() {
        let key = new_key().unwrap();
        let bytes = encode_identity(&key);
        let back = decode_identity(&bytes).unwrap();
        assert_eq!(
            back.expose(SecretKey::public),
            key.expose(SecretKey::public)
        );
        for cut in 0..bytes.len() {
            assert!(decode_identity(&bytes[..cut]).is_err());
        }
    }
}

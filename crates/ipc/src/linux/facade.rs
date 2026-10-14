//! The listener stays dumpable and holds no payload buffers. Only the worker
//! reads external bytes. Descriptor passing is confined to this inherited pair;
//! it never changes the DataOnly protocol used on external connections.

use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString};
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream as StdStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SocketAddrUnix, SocketType,
};
use rustix::process::{Resource, Rlimit};
use tokio::io::{Interest, unix::AsyncFd};
use tokio::net::UnixStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{interval, timeout};

use super::server::{Counters, admit_stream};
use super::{Channel, RuntimeDir, Server, Trust};
use crate::{HANDSHAKE_DEADLINE, IpcError, MAX_CHANNELS};

const READY: u8 = 1;
const CONNECTION: u8 = 2;

/// Secret-free listener owner. A direct child receives only the private pair
/// on stdin. Drop, worker exit, or a failed control protocol kills and reaps it.
pub struct Facade {
    server: Server,
    control: UnixStream,
    child: Spawned,
}

/// The worker the facade execs: the installed daemon's worker mode, or
/// another mode of a test's own executable. It inherits the facade's
/// environment with these overrides. Its stdin is the control pair, stdout
/// and stderr are `/dev/null`, and it receives no other descriptor (SI-36).
#[derive(Debug, Clone)]
pub struct WorkerLaunch {
    program: PathBuf,
    args: Vec<OsString>,
    envs: Vec<(OsString, OsString)>,
}

impl WorkerLaunch {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            envs: Vec::new(),
        }
    }

    pub fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    pub fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        let key = key.as_ref().to_owned();
        self.envs.retain(|(existing, _)| *existing != key);
        self.envs.push((key, value.as_ref().to_owned()));
        self
    }

    fn environment(&self) -> Vec<(OsString, OsString)> {
        let mut env: Vec<_> = std::env::vars_os()
            .filter(|(key, _)| key != WORKER_ENV && self.envs.iter().all(|(set, _)| set != key))
            .collect();
        env.extend(self.envs.iter().cloned());
        env.push((WORKER_ENV.into(), "1".into()));
        env
    }
}

impl Facade {
    /// `worker` must exec the worker mode of the installed daemon. No
    /// secrets may exist in this process, its argv, or its environment.
    pub async fn spawn(
        dir: &RuntimeDir,
        clients: Trust,
        worker_launch: WorkerLaunch,
    ) -> Result<Self, IpcError> {
        harden_facade()?;
        let ours = std::fs::metadata(std::env::current_exe()?)?;
        let worker = std::fs::metadata(&worker_launch.program)?;
        if !cfg!(feature = "mutant-si7-worker-exe-unchecked")
            && (ours.dev(), ours.ino()) != (worker.dev(), worker.ino())
        {
            return Err(IpcError::PeerRejected);
        }
        if !cfg!(feature = "mutant-si30-facade-no-probe") {
            probe_core_suppression(dir, &worker_launch).await?;
        }
        let mut server = Server::bind(dir, clients)?;
        server.slots = Arc::new(Semaphore::new(connection_limit()));
        let (parent, child) = StdStream::pair()?;
        let mut child = spawn_clean(
            &worker_launch.program,
            &worker_launch.args,
            &worker_launch.environment(),
            Some(OwnedFd::from(child)),
            // The worker closes them itself at entry: a parent-side list
            // races any thread opening a descriptor before the fork.
            false,
        )?;
        let control = into_async(parent)?;
        let (tag, fds) = timeout(HANDSHAKE_DEADLINE, receive(&control))
            .await
            .map_err(|_| IpcError::Timeout)??;
        if tag != READY || !fds.is_empty() || child.try_exit()?.is_some() {
            return Err(IpcError::Malformed);
        }
        Ok(Self {
            server,
            control,
            child,
        })
    }

    /// Holds a slot until the worker drops that connection's private lease.
    /// Neither the control reader nor the lease readers can see client data.
    pub async fn run(mut self) -> Result<(), IpcError> {
        let mut leases = JoinSet::new();
        let mut child_tick = interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                result = receive(&self.control) => {
                    // READY is the worker's only message. Afterwards EOF or
                    // any byte/control data means the worker is unusable.
                    let _ = result?;
                    return Err(IpcError::Malformed);
                }
                _ = child_tick.tick() => {
                    if self.child.try_exit()?.is_some() {
                        return Err(IpcError::Closed);
                    }
                }
                result = leases.join_next(), if !leases.is_empty() => {
                    match result {
                        Some(Ok(Ok(()))) => {},
                        _ => return Err(IpcError::Malformed),
                    }
                }
                result = self.server.listener.accept(), if leases.len() < connection_limit() => {
                    let (stream, _) = result?;
                    if self.server.trust.check(&stream).is_err() {
                        Counters::bump(&self.server.health.peers_rejected);
                        continue;
                    }
                    let slot = Arc::clone(&self.server.slots).try_acquire_owned().map_err(|_| IpcError::OverBudget)?;
                    let (lease, worker_lease) = StdStream::pair()?;
                    let lease = into_async(lease)?;
                    let fds = [stream.as_fd(), worker_lease.as_fd()];
                    timeout(HANDSHAKE_DEADLINE, send(&self.control, CONNECTION, &fds)).await.map_err(|_| IpcError::Timeout)??;
                    // The only accepted socket descriptor in the facade is
                    // gone before another connection is accepted.
                    drop(stream);
                    drop(worker_lease);
                    leases.spawn(async move {
                        let _slot = slot;
                        match receive(&lease).await {
                            Err(IpcError::Closed) => Ok(()),
                            _ => Err(IpcError::Malformed),
                        }
                    });
                }
            }
        }
    }
}

/// Authenticated control receiver in the nondumpable worker. The background
/// task watches the facade's kernel pidfd and control EOF even while callers
/// are idle. Either closes every transferred socket and ends accept.
pub struct Worker {
    incoming: mpsc::Receiver<Transferred>,
    monitor: JoinHandle<()>,
    registry: Arc<Registry>,
    slots: Arc<Semaphore>,
    clients: Trust,
    health: Arc<Counters>,
}

struct Transferred {
    stream: UnixStream,
    lease: Lease,
}

struct Registry {
    sockets: Mutex<BTreeMap<u64, StdStream>>,
}

impl Registry {
    fn close_all(&self) {
        if let Ok(mut sockets) = self.sockets.lock() {
            for stream in sockets.values() {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            sockets.clear();
        }
    }
}

pub(super) struct Lease {
    _socket: OwnedFd,
    id: u64,
    registry: Arc<Registry>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut sockets) = self.registry.sockets.lock() {
            sockets.remove(&self.id);
        }
    }
}

struct CloseOnExit(Arc<Registry>, Arc<Semaphore>);
impl Drop for CloseOnExit {
    fn drop(&mut self) {
        self.0.close_all();
        self.1.close();
    }
}

impl Worker {
    /// Duplicate stdin with safe rustix, preserving descriptor ownership.
    /// The inherited fd must be an unnamed AF_UNIX stream pair created by
    /// our still-live, allowlisted direct parent. A pathname listener or a
    /// peer-supplied executable fd is never an identity proof.
    pub async fn inherit(facade: Trust, clients: Trust) -> Result<Self, IpcError> {
        let fd = rustix::io::fcntl_dupfd_cloexec(std::io::stdin(), 3).map_err(io::Error::from)?;
        let null = std::fs::File::open("/dev/null")?;
        rustix::stdio::dup2_stdin(&null).map_err(io::Error::from)?;
        drop(null);
        Self::from_control(fd, facade, clients).await
    }

    pub async fn from_control(
        fd: OwnedFd,
        facade: Trust,
        clients: Trust,
    ) -> Result<Self, IpcError> {
        kickoff_secret::harden_process().map_err(|_| IpcError::PeerRejected)?;
        validate_pair(&fd)?;
        let control = into_async(StdStream::from(fd))?;
        let (peer, pinned) = if cfg!(feature = "mutant-si7-control-unchecked") {
            let cred = control.peer_cred()?;
            (
                crate::PeerCred {
                    uid: cred.uid(),
                    pid: cred.pid().ok_or(IpcError::PeerRejected)?,
                },
                Some(
                    nix::sys::socket::getsockopt(&control, nix::sys::socket::sockopt::PeerPidfd)
                        .map_err(|_| IpcError::PeerRejected)?,
                ),
            )
        } else {
            facade.pin(&control)?
        };
        if !cfg!(feature = "mutant-si7-control-unchecked")
            && rustix::process::getppid().map(|pid| pid.as_raw_nonzero().get()) != Some(peer.pid)
        {
            return Err(IpcError::PeerRejected);
        }
        let pinned = pinned.ok_or(IpcError::PeerRejected)?;
        let parent = AsyncFd::new(pinned)?;
        let registry = Arc::new(Registry {
            sockets: Mutex::new(BTreeMap::new()),
        });
        let (tx, incoming) = mpsc::channel(connection_limit());
        let slots = Arc::new(Semaphore::new(connection_limit()));
        let close = CloseOnExit(Arc::clone(&registry), Arc::clone(&slots));
        send(&control, READY, &[]).await?;
        let monitor = tokio::spawn(async move {
            let _close = close;
            let mut next_id = 0u64;
            loop {
                let message = if cfg!(feature = "mutant-si7-facade-lifetime-unchecked") {
                    receive(&control).await
                } else {
                    tokio::select! {
                        result = receive(&control) => result,
                        _ = parent.readable() => break,
                    }
                };
                if cfg!(feature = "mutant-si7-facade-lifetime-unchecked")
                    && matches!(message, Err(IpcError::Closed))
                {
                    std::future::pending::<()>().await;
                }
                let Ok((CONNECTION, mut fds)) = message else {
                    break;
                };
                if !cfg!(feature = "mutant-si7-control-count-unchecked") && fds.len() != 2 {
                    break;
                }
                let Some(lease) = fds.pop() else {
                    break;
                };
                let Some(socket) = fds.pop() else {
                    break;
                };
                if validate_stream(&socket).is_err() || validate_pair(&lease).is_err() {
                    break;
                }
                let Ok(lease_stream) = into_async(StdStream::from(lease)) else {
                    break;
                };
                // Lease endpoints were created by the same facade; another
                // process's socketpair cannot release a connection slot.
                let Ok(lease_peer) = facade.check(&lease_stream) else {
                    break;
                };
                if lease_peer != peer {
                    break;
                }
                let Ok(lease) = lease_stream.into_std() else {
                    break;
                };
                let socket = StdStream::from(socket);
                let Ok(shutdown) = socket.try_clone() else {
                    break;
                };
                let Ok(stream) = into_async(socket) else {
                    break;
                };
                let Ok(mut sockets) = _close.0.sockets.lock() else {
                    break;
                };
                if sockets.len() >= connection_limit() {
                    break;
                }
                let id = next_id;
                next_id = match next_id.checked_add(1) {
                    Some(id) => id,
                    None => break,
                };
                sockets.insert(id, shutdown);
                drop(sockets);
                let lease = Lease {
                    _socket: lease.into(),
                    id,
                    registry: Arc::clone(&_close.0),
                };
                if tx.try_send(Transferred { stream, lease }).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            incoming,
            monitor,
            registry,
            slots,
            clients,
            health: Arc::default(),
        })
    }

    /// Same version, role, budget and ancillary checks as a direct Server.
    /// Client identity is rechecked from the transferred socket's kernel
    /// credentials; the facade sends no caller identity claims.
    pub async fn accept(&mut self) -> Result<Channel, IpcError> {
        loop {
            let slot: OwnedSemaphorePermit = Arc::clone(&self.slots)
                .acquire_owned()
                .await
                .map_err(|_| IpcError::Closed)?;
            let transferred = self.incoming.recv().await.ok_or(IpcError::Closed)?;
            still_nondumpable()?;
            if let Ok(channel) = admit_stream(
                &self.clients,
                Arc::clone(&self.health),
                transferred.stream,
                slot,
                Some(transferred.lease),
            )
            .await
            {
                return Ok(channel);
            }
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.registry.close_all();
        self.slots.close();
        self.monitor.abort();
    }
}

/// A credential change (uid, gid, fsuid, capabilities) resets "dumpable" to
/// `fs.suid_dumpable`, which may be 2. The worker hardens once at startup, so
/// it re-checks before reading any client bytes, which may carry secrets.
pub(super) fn still_nondumpable() -> Result<(), IpcError> {
    if cfg!(feature = "mutant-si30-worker-dumpable-unchecked") {
        return Ok(());
    }
    match rustix::process::dumpable_behavior() {
        Ok(rustix::process::DumpableBehavior::NotDumpable) => Ok(()),
        _ => Err(IpcError::Hardening),
    }
}

fn into_async(stream: StdStream) -> Result<UnixStream, IpcError> {
    stream.set_nonblocking(true)?;
    Ok(UnixStream::from_std(stream)?)
}

fn validate_stream(fd: &OwnedFd) -> io::Result<()> {
    if cfg!(feature = "mutant-si7-control-fd-unchecked") {
        return Ok(());
    }
    if rustix::net::sockopt::socket_domain(fd)? != AddressFamily::UNIX
        || rustix::net::sockopt::socket_type(fd)? != SocketType::STREAM
        || rustix::net::sockopt::socket_acceptconn(fd)?
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let _ = rustix::net::getpeername(fd)?;
    Ok(())
}

fn validate_pair(fd: &OwnedFd) -> io::Result<()> {
    validate_stream(fd)?;
    if cfg!(feature = "mutant-si7-control-fd-unchecked") {
        return Ok(());
    }
    // Check the kernel address length before conversion: rustix 1.1.5
    // converts an unnamed address to an empty pathname with a terminator.
    let unnamed = rustix::net::SocketAddrAny::from(SocketAddrUnix::new_unnamed());
    let local = rustix::net::getsockname(fd)?;
    let remote = rustix::net::getpeername(fd)?;
    if local.addr_len() != unnamed.addr_len()
        || remote.is_some_and(|addr| addr.addr_len() != unnamed.addr_len())
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}

async fn send(
    socket: &UnixStream,
    tag: u8,
    fds: &[std::os::fd::BorrowedFd<'_>],
) -> Result<(), IpcError> {
    loop {
        socket.writable().await?;
        let result = socket.try_io(Interest::WRITABLE, || {
            let mut space = [MaybeUninit::uninit(); 128];
            let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut space);
            if !fds.is_empty() && !ancillary.push(rustix::net::SendAncillaryMessage::ScmRights(fds))
            {
                return Err(io::Error::other("control descriptor overflow"));
            }
            let [high, low] = crate::PROTOCOL_VERSION.to_be_bytes();
            let packet = [high, low, tag];
            let sent = rustix::net::sendmsg(
                socket,
                &[IoSlice::new(&packet)],
                &mut ancillary,
                rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
            )?;
            if sent == 3 {
                Ok(())
            } else {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        });
        match result {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            result => return result.map_err(Into::into),
        }
    }
}

async fn receive(socket: &UnixStream) -> Result<(u8, Vec<OwnedFd>), IpcError> {
    loop {
        socket.readable().await?;
        let result = socket.try_io(Interest::READABLE, || {
            let mut byte = [0u8; 3];
            let mut space = [MaybeUninit::uninit(); 128];
            let mut ancillary = RecvAncillaryBuffer::new(&mut space);
            let got = rustix::net::recvmsg(
                socket,
                &mut [IoSliceMut::new(&mut byte)],
                &mut ancillary,
                RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
            )?;
            let mut fds = Vec::new();
            let mut invalid = got.flags.contains(ReturnFlags::CTRUNC);
            for message in ancillary.drain() {
                match message {
                    RecvAncillaryMessage::ScmRights(rights) => fds.extend(rights),
                    _ => invalid = true,
                }
            }
            if got.bytes != 3 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if invalid {
                return Err(io::Error::other(super::stream::AncillaryRefused));
            }
            Ok((byte, fds))
        });
        match result {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
            Ok(([high, low, tag], fds)) => {
                if !cfg!(feature = "mutant-si10-control-skips-version")
                    && u16::from_be_bytes([high, low]) != crate::PROTOCOL_VERSION
                {
                    return Err(IpcError::Version);
                }
                return Ok((tag, fds));
            }
        }
    }
}

fn connection_limit() -> usize {
    if cfg!(feature = "mutant-si23-facade-unbounded") {
        1024
    } else {
        MAX_CHANNELS
    }
}

const CORE_PROBE_ENV: &str = "KICKOFF_IPC_CORE_PROBE";
/// Set by the facade for its worker, which then closes every descriptor
/// above stdio at entry (SI-36). Descendants that inherit it do the same.
const WORKER_ENV: &str = "KICKOFF_IPC_WORKER";

fn harden_facade() -> Result<(), IpcError> {
    // Linux skips piped core handlers only for the recursion sentinel 1, and
    // writes no core file below the ELF minimum dump size. An inherited hard
    // limit of 0 cannot be raised; it still suppresses file dumps, and the
    // startup probe refuses it for piped handlers.
    let ceiling = rustix::process::getrlimit(Resource::Core).maximum;
    let limit = if cfg!(feature = "mutant-si30-facade-core-zero") {
        0
    } else {
        ceiling.map_or(1, |hard| hard.min(1))
    };
    rustix::process::setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(limit),
            maximum: Some(limit),
        },
    )
    .map_err(io::Error::from)?;
    Ok(())
}

/// Call first at normal executable entry, before arguments or runtime setup.
/// It applies the facade policy before checking the probe marker. The worker
/// subsequently makes itself nondumpable and lowers both limits to zero.
/// A facade launches the genuine exec probe with only its marker, which names
/// the private scratch directory the probe crashes in, null stdio and no other
/// descriptor, and checks kernel wait status. No secrets may exist yet.
pub fn run_core_probe_if_requested() -> Result<(), IpcError> {
    if std::env::var_os(WORKER_ENV).as_deref() == Some(OsStr::new("1")) {
        close_inherited()?;
    }
    if !cfg!(feature = "mutant-si30-late-facade-core") {
        harden_facade()?;
    }
    let Some(scratch) = std::env::var_os(CORE_PROBE_ENV) else {
        return Ok(());
    };
    harden_facade()?;
    if rustix::process::dumpable_behavior().map_err(io::Error::from)?
        != rustix::process::DumpableBehavior::Dumpable
        || std::env::vars_os().count() != 1
        || !std::path::Path::new(&scratch).is_absolute()
    {
        return Err(IpcError::Hardening);
    }
    // A relative file core_pattern writes into the cwd, where the facade
    // looks for it after the crash.
    std::env::set_current_dir(&scratch)?;
    let expected = std::fs::metadata("/dev/null")?;
    for stat in [
        rustix::fs::fstat(std::io::stdin()),
        rustix::fs::fstat(std::io::stdout()),
        rustix::fs::fstat(std::io::stderr()),
    ] {
        let stat = stat.map_err(io::Error::from)?;
        if stat.st_dev != expected.dev() || stat.st_ino != expected.ino() {
            return Err(IpcError::Hardening);
        }
    }
    for fd in open_descriptors()? {
        if !cfg!(feature = "mutant-si30-probe-fd-unchecked") && fd >= 3 {
            return Err(IpcError::Hardening);
        }
    }
    std::process::abort();
}

/// Closes every descriptor above stdio, before this process has created any
/// of its own: at entry, everything there was inherited across exec. This
/// runs in the child, so no other thread of the launcher can add one later.
fn close_inherited() -> Result<(), IpcError> {
    if cfg!(feature = "mutant-si36-worker-inherits-fds") {
        return Ok(());
    }
    for fd in open_descriptors()? {
        if fd >= 3 {
            nix::unistd::close(fd).map_err(io::Error::from)?;
        }
    }
    Ok(())
}

/// Descriptor numbers open in this process. Collecting closes the enumeration
/// fd before the caller acts, so it cannot be confused with inherited
/// authority.
fn open_descriptors() -> Result<Vec<i32>, IpcError> {
    let entries: Vec<_> = std::fs::read_dir("/proc/self/fd")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<_, _>>()?;
    let mut open = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(fd) = entry.to_str().and_then(|name| name.parse::<i32>().ok()) else {
            return Err(IpcError::Hardening);
        };
        if std::fs::symlink_metadata(std::path::Path::new("/proc/self/fd").join(&entry)).is_ok() {
            open.push(fd);
        }
    }
    Ok(open)
}

struct Scratch {
    path: std::path::PathBuf,
    inode: (u64, u64),
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if let Ok(meta) = std::fs::symlink_metadata(&self.path)
            && (meta.dev(), meta.ino()) == self.inode
        {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// A direct child, killed and reaped on drop unless its exit status was
/// already collected, so its pid cannot be recycled under the handle.
struct Spawned(Option<rustix::process::Pid>);

impl Spawned {
    fn try_exit(&mut self) -> io::Result<Option<rustix::process::WaitStatus>> {
        let Some(pid) = self.0 else {
            return Err(io::ErrorKind::NotFound.into());
        };
        let status = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)?;
        if status.is_some() {
            self.0 = None;
        }
        Ok(status.map(|(_, status)| status))
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        if let Some(pid) = self.0.take() {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
            let _ = rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty());
        }
    }
}

/// posix_spawn rather than `Command`: its file actions close, by number, the
/// descriptors this process inherited without close-on-exec from whatever
/// launched it. Safe Rust cannot own those to mark them close-on-exec. The
/// child gets exactly `stdin` (or `/dev/null`) on 0, `/dev/null` on 1 and 2,
/// and with `sweep` nothing else.
fn spawn_clean(
    program: &Path,
    args: &[OsString],
    env: &[(OsString, OsString)],
    stdin: Option<OwnedFd>,
    sweep: bool,
) -> Result<Spawned, IpcError> {
    use nix::spawn::{PosixSpawnAttr, PosixSpawnFileActions, posix_spawn};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let cstring = |bytes: &[u8]| {
        CString::new(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    };
    let program = cstring(program.as_os_str().as_bytes())?;
    let mut argv = vec![program.clone()];
    for arg in args {
        argv.push(cstring(arg.as_bytes())?);
    }
    let mut envp = Vec::with_capacity(env.len());
    for (key, value) in env {
        let mut pair = key.as_bytes().to_vec();
        pair.push(b'=');
        pair.extend_from_slice(value.as_bytes());
        envp.push(cstring(&pair)?);
    }
    let null = std::fs::File::options()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let input = stdin.as_ref().map_or(null.as_raw_fd(), AsRawFd::as_raw_fd);
    let mut actions = PosixSpawnFileActions::init().map_err(io::Error::from)?;
    actions.add_dup2(input, 0).map_err(io::Error::from)?;
    for target in 1..3 {
        actions
            .add_dup2(null.as_raw_fd(), target)
            .map_err(io::Error::from)?;
    }
    if sweep {
        for fd in open_descriptors()? {
            if fd >= 3 {
                actions.add_close(fd).map_err(io::Error::from)?;
            }
        }
    }
    let attr = PosixSpawnAttr::init().map_err(io::Error::from)?;
    let pid =
        posix_spawn(program.as_c_str(), &actions, &attr, &argv, &envp).map_err(io::Error::from)?;
    let pid = rustix::process::Pid::from_raw(pid.as_raw())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok(Spawned(Some(pid)))
}

async fn probe_core_suppression(dir: &RuntimeDir, worker: &WorkerLaunch) -> Result<(), IpcError> {
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    // A pipe handler ignores a zero limit, so the probe would only hand its
    // crash to the handler before the same refusal.
    if rustix::process::getrlimit(Resource::Core).maximum == Some(0)
        && std::fs::read("/proc/sys/kernel/core_pattern")
            .is_ok_and(|pattern| pattern.first() == Some(&b'|'))
    {
        return Err(IpcError::CoreDumpsEnabled);
    }
    let parent = dir.socket_path().parent().ok_or(IpcError::UnsafeDir)?;
    let path = parent.join(format!(
        ".core-probe-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&path)?;
    let meta = std::fs::symlink_metadata(&path)?;
    let scratch = Scratch {
        path,
        inode: (meta.dev(), meta.ino()),
    };
    let mut probe = spawn_clean(
        &worker.program,
        &worker.args,
        &[(
            OsString::from(CORE_PROBE_ENV),
            scratch.path.clone().into_os_string(),
        )],
        None,
        !cfg!(feature = "mutant-si30-probe-inherits-fds"),
    )?;
    timeout(Duration::from_secs(3), async {
        let mut tick = interval(Duration::from_millis(5));
        loop {
            tick.tick().await;
            let Some(status) = probe.try_exit()? else {
                continue;
            };
            // WCOREDUMP: the kernel wrote a core to a file, a pipe or a
            // socket handler. A file left in the cwd is a dump whatever the
            // status says.
            let dumped = (status.signaled() && status.as_raw() & 0x80 != 0)
                || (!cfg!(feature = "mutant-si30-probe-scratch-unchecked")
                    && std::fs::read_dir(&scratch.path)?.next().is_some());
            if dumped {
                return Err(IpcError::CoreDumpsEnabled);
            }
            if status.terminating_signal() != Some(6) {
                return Err(IpcError::Hardening);
            }
            return Ok(());
        }
    })
    .await
    .map_err(|_| IpcError::Timeout)?
}

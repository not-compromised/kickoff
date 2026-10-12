use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, timeout};

use super::{RuntimeDir, Trust};
use crate::codec::{self, Welcome};
use crate::command::{Refusal, Reply, Request};
use crate::frame::{read_body, read_frame, read_header, write_frame};
use crate::{
    ChannelRole, HANDSHAKE_DEADLINE, IpcError, IpcHealth, MAX_CHANNELS, MAX_REPLY_FRAME,
    MAX_REQUEST_FRAME, PeerCred, REQUEST_RATE,
};

/// kickoffd's listening socket.
pub struct Server {
    listener: UnixListener,
    trust: Trust,
    slots: Arc<Semaphore>,
    health: Arc<Counters>,
    path: PathBuf,
    inode: (u64, u64),
}

#[derive(Default)]
struct Counters {
    peers_rejected: AtomicU64,
    frames_refused: AtomicU64,
}

impl Counters {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

impl Server {
    /// Creates the socket with `bind`, which fails if the name exists. The
    /// one name we replace is a dead socket we own, left by a kickoffd that
    /// was killed; anything else at that name (a live server, a file, a
    /// symlink, another owner's socket) fails closed as `Squatted`.
    ///
    /// Must be called inside a tokio runtime.
    pub fn bind(dir: &RuntimeDir, trust: Trust) -> Result<Server, IpcError> {
        tokio::runtime::Handle::try_current().map_err(|_| IpcError::Io(ErrorKind::Other))?;
        let path = dir.socket_path();
        let std_listener = match std::os::unix::net::UnixListener::bind(path) {
            Ok(listener) => listener,
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                reclaim_dead_socket(path, dir.uid())?;
                std::os::unix::net::UnixListener::bind(path).map_err(|_| IpcError::Squatted)?
            }
            Err(e) => return Err(e.into()),
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.file_type().is_socket() || meta.uid() != dir.uid() || meta.mode() & 0o7777 != 0o600
        {
            return Err(IpcError::Squatted);
        }
        std_listener.set_nonblocking(true)?;
        Ok(Server {
            listener: UnixListener::from_std(std_listener)?,
            trust,
            slots: Arc::new(Semaphore::new(MAX_CHANNELS)),
            health: Arc::default(),
            path: path.to_path_buf(),
            inode: (meta.dev(), meta.ino()),
        })
    }

    /// The next caller that passed the credential check and the version
    /// handshake. Refused callers are dropped here and counted in `health`;
    /// they never reach the daemon. A channel slot is held before the
    /// connection is accepted, so at most `MAX_CHANNELS` exist at once.
    pub async fn accept(&self) -> Result<Channel, IpcError> {
        loop {
            let slot = Arc::clone(&self.slots)
                .acquire_owned()
                .await
                .map_err(|_| IpcError::Closed)?;
            let (stream, _) = self.listener.accept().await?;
            if let Ok(channel) = self.admit(stream, slot).await {
                return Ok(channel);
            }
        }
    }

    pub fn health(&self) -> IpcHealth {
        IpcHealth {
            peers_rejected: self.health.peers_rejected.load(Ordering::Relaxed),
            frames_refused: self.health.frames_refused.load(Ordering::Relaxed),
        }
    }

    async fn admit(
        &self,
        mut stream: UnixStream,
        slot: OwnedSemaphorePermit,
    ) -> Result<Channel, IpcError> {
        // Nothing has been read or written yet, so a refused caller learns
        // only that the connection closed.
        let peer = match self.trust.check(stream.peer_cred()?) {
            Ok(peer) => peer,
            Err(e) => {
                Counters::bump(&self.health.peers_rejected);
                return Err(e);
            }
        };
        let role = timeout(HANDSHAKE_DEADLINE, async {
            let hello = read_frame(&mut stream, codec::HELLO_LEN).await?;
            let (welcome, role) = match codec::decode_hello(&hello) {
                Ok(role) => (Welcome::Ok, Ok(role)),
                Err(refusal) => (refusal, Err(refusal)),
            };
            write_frame(&mut stream, &codec::encode_welcome(welcome)).await?;
            Ok::<_, IpcError>(role)
        })
        .await
        .map_err(|_| IpcError::Timeout)
        .and_then(|r| r);
        let role = match role {
            Ok(Ok(role)) => role,
            Ok(Err(refusal)) => {
                Counters::bump(&self.health.frames_refused);
                return Err(match refusal {
                    Welcome::Role => IpcError::Role,
                    Welcome::Ok | Welcome::Version => IpcError::Version,
                });
            }
            Err(e) => {
                Counters::bump(&self.health.frames_refused);
                return Err(e);
            }
        };
        Ok(Channel {
            stream,
            role,
            peer,
            budget: RateBudget::new(),
            pending: false,
            dead: false,
            health: Arc::clone(&self.health),
            _slot: slot,
        })
    }
}

impl Drop for Server {
    /// Removes the socket only if it is still the one this server created.
    fn drop(&mut self) {
        if let Ok(meta) = std::fs::symlink_metadata(&self.path)
            && (meta.dev(), meta.ino()) == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Lets kickoffd start after it was killed. The directory is ours and 0700,
/// so only our uid could have put anything here; we still remove only a
/// socket we own that nobody is listening on.
fn reclaim_dead_socket(path: &Path, uid: u32) -> Result<(), IpcError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| IpcError::Squatted)?;
    if !meta.file_type().is_socket() || meta.uid() != uid {
        return Err(IpcError::Squatted);
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
            std::fs::remove_file(path)?;
            Ok(())
        }
        Ok(_) | Err(_) => Err(IpcError::Squatted),
    }
}

/// One authenticated caller. Requests and replies alternate: every request
/// `recv` returns gets exactly one reply.
///
/// `recv` is not cancel-safe: dropping it mid-frame leaves the stream
/// unaligned, and the next frame is then refused or closes the channel.
pub struct Channel {
    stream: UnixStream,
    role: ChannelRole,
    peer: PeerCred,
    budget: RateBudget,
    pending: bool,
    dead: bool,
    health: Arc<Counters>,
    _slot: OwnedSemaphorePermit,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("role", &self.role)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl Channel {
    pub fn role(&self) -> ChannelRole {
        self.role
    }

    pub fn peer(&self) -> PeerCred {
        self.peer
    }

    /// The next command this channel's role may send. A command outside the
    /// role, an unknown tag or a malformed body is answered `Refused(Unknown)`
    /// here and never returned. An oversize frame, a stalled frame or a
    /// caller over its request rate closes the channel.
    pub async fn recv(&mut self) -> Result<Request, IpcError> {
        if self.pending {
            self.reply(Reply::Refused(Refusal::Failed)).await?;
        }
        loop {
            if self.dead {
                return Err(IpcError::Closed);
            }
            match self.next_request().await {
                Ok(Some(request)) => {
                    self.pending = true;
                    return Ok(request);
                }
                Ok(None) => {}
                Err(e) => {
                    self.dead = true;
                    return Err(e);
                }
            }
        }
    }

    /// Answers the request `recv` returned last. A reply the role may not
    /// receive (a ticket to the overlay) is replaced by `Refused(Failed)`.
    pub async fn reply(&mut self, reply: Reply) -> Result<(), IpcError> {
        if self.dead {
            return Err(IpcError::Closed);
        }
        if !self.pending {
            return Err(IpcError::Unrequested);
        }
        self.pending = false;
        if !reply.allowed_for(self.role) {
            self.send(&Reply::Refused(Refusal::Failed)).await?;
            return Err(IpcError::Role);
        }
        self.send(&reply).await
    }

    async fn next_request(&mut self) -> Result<Option<Request>, IpcError> {
        let (len, deadline) = match read_header(&mut self.stream, MAX_REQUEST_FRAME).await {
            Ok(header) => header,
            Err(e) => {
                if matches!(e, IpcError::TooLarge { .. }) {
                    Counters::bump(&self.health.frames_refused);
                }
                return Err(e);
            }
        };
        // Charged on the header, before the body is allocated or read.
        self.budget.charge()?;
        let body = read_body(&mut self.stream, len, deadline).await?;
        match codec::decode_op(&body)
            .ok()
            .and_then(|op| op.for_role(self.role))
        {
            Some(request) => Ok(Some(request)),
            None => {
                Counters::bump(&self.health.frames_refused);
                self.send(&Reply::Refused(Refusal::Unknown)).await?;
                Ok(None)
            }
        }
    }

    async fn send(&mut self, reply: &Reply) -> Result<(), IpcError> {
        let result = async {
            let bytes = codec::encode_reply(reply)?;
            if bytes.len() > MAX_REPLY_FRAME {
                return Err(IpcError::TooLarge {
                    max: MAX_REPLY_FRAME,
                });
            }
            write_frame(&mut self.stream, &bytes).await
        }
        .await;
        if result.is_err() {
            self.dead = true;
        }
        result
    }
}

/// `REQUEST_RATE` requests per one-second window.
struct RateBudget {
    window: Instant,
    used: u32,
}

impl RateBudget {
    fn new() -> RateBudget {
        RateBudget {
            window: Instant::now(),
            used: 0,
        }
    }

    fn charge(&mut self) -> Result<(), IpcError> {
        let now = Instant::now();
        if now.saturating_duration_since(self.window) >= std::time::Duration::from_secs(1) {
            self.window = now;
            self.used = 0;
        }
        if self.used >= REQUEST_RATE {
            return Err(IpcError::OverBudget);
        }
        self.used = self.used.saturating_add(1);
        Ok(())
    }
}

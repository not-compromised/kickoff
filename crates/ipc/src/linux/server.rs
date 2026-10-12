use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, timeout};
use zeroize::Zeroizing;

use super::stream::DataOnly;
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
    pub(super) listener: UnixListener,
    pub(super) trust: Trust,
    pub(super) slots: Arc<Semaphore>,
    pub(super) health: Arc<Counters>,
    path: PathBuf,
    inode: (u64, u64),
}

#[derive(Default)]
pub(super) struct Counters {
    pub(super) peers_rejected: AtomicU64,
    frames_refused: AtomicU64,
}

impl Counters {
    pub(super) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

impl Server {
    /// Creates a new socket exclusively. Every existing name fails closed.
    ///
    /// Must be called inside a tokio runtime.
    pub fn bind(dir: &RuntimeDir, trust: Trust) -> Result<Server, IpcError> {
        tokio::runtime::Handle::try_current().map_err(|_| IpcError::Io(ErrorKind::Other))?;
        let path = dir.socket_path();
        let std_listener = match std::os::unix::net::UnixListener::bind(path) {
            Ok(listener) => listener,
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                if !cfg!(feature = "mutant-si7-reclaim-any") {
                    return Err(IpcError::Squatted);
                }
                std::fs::remove_file(path)?;
                std::os::unix::net::UnixListener::bind(path).map_err(|_| IpcError::Squatted)?
            }
            Err(e) => return Err(e.into()),
        };
        let private = !cfg!(feature = "mutant-si7-socket-mode");
        if private {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.file_type().is_socket()
            || meta.uid() != dir.uid()
            || (private && meta.mode() & 0o7777 != 0o600)
        {
            return Err(IpcError::Squatted);
        }
        std_listener.set_nonblocking(true)?;
        Ok(Server {
            listener: UnixListener::from_std(std_listener)?,
            trust,
            slots: Arc::new(Semaphore::new(
                if cfg!(feature = "mutant-si23-ipc-unbounded-channels") {
                    Semaphore::MAX_PERMITS
                } else {
                    MAX_CHANNELS
                },
            )),
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
        stream: UnixStream,
        slot: OwnedSemaphorePermit,
    ) -> Result<Channel, IpcError> {
        admit_stream(&self.trust, Arc::clone(&self.health), stream, slot, None).await
    }
}

pub(super) async fn admit_stream(
    trust: &Trust,
    health: Arc<Counters>,
    stream: UnixStream,
    slot: OwnedSemaphorePermit,
    lease: Option<super::facade::Lease>,
) -> Result<Channel, IpcError> {
    // Nothing has been read or written yet, so a refused caller learns
    // only that the connection closed.
    let peer = match trust.check(&stream) {
        Ok(peer) => peer,
        Err(e) => {
            Counters::bump(&health.peers_rejected);
            return Err(e.into());
        }
    };
    let mut stream = DataOnly::new(stream);
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
            Counters::bump(&health.frames_refused);
            return Err(match refusal {
                Welcome::Role => IpcError::Role,
                Welcome::Ok | Welcome::Version => IpcError::Version,
            });
        }
        Err(e) => {
            Counters::bump(&health.frames_refused);
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
        health,
        _slot: slot,
        _lease: lease,
    })
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

/// One authenticated caller. Requests and replies alternate: every request
/// `recv` returns gets exactly one reply.
///
/// Dropping a polled `recv` or `reply` before completion permanently closes
/// the channel. An interrupted frame or reply is never reused.
pub struct Channel {
    stream: DataOnly,
    role: ChannelRole,
    peer: PeerCred,
    budget: RateBudget,
    pending: bool,
    dead: bool,
    health: Arc<Counters>,
    _slot: OwnedSemaphorePermit,
    _lease: Option<super::facade::Lease>,
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
            // Cancellation may consume a partial frame, so only completion
            // permits another receive.
            self.dead = !cfg!(feature = "mutant-si10-ipc-recv-cancel-reuse");
            match self.next_request().await {
                Ok(Some(request)) => {
                    self.dead = false;
                    self.pending = true;
                    return Ok(request);
                }
                Ok(None) => {
                    self.dead = false;
                }
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
        let body = match self.next_frame().await {
            Ok(body) => body,
            Err(e) => {
                if matches!(e, IpcError::TooLarge { .. } | IpcError::Ancillary) {
                    Counters::bump(&self.health.frames_refused);
                }
                return Err(e);
            }
        };
        match codec::decode_op(self.role, &body)
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

    async fn next_frame(&mut self) -> Result<Zeroizing<Vec<u8>>, IpcError> {
        let (len, deadline) = read_header(&mut self.stream, MAX_REQUEST_FRAME).await?;
        // Charged on the header, before the body is allocated or read.
        self.budget.charge()?;
        read_body(&mut self.stream, len, deadline).await
    }

    async fn send(&mut self, reply: &Reply) -> Result<(), IpcError> {
        // The peer may have read any prefix of a cancelled reply.
        self.dead = !cfg!(feature = "mutant-si10-ipc-reply-cancel-reuse");
        let result = async {
            let bytes = codec::encode_reply(reply)?;
            if bytes.len() > MAX_REPLY_FRAME {
                return Err(IpcError::TooLarge {
                    max: MAX_REPLY_FRAME,
                });
            }
            bytes
                .send(&mut self.stream, kickoff_local::PeerKind::Client)
                .await
        }
        .await;
        self.dead = result.is_err();
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
        if !cfg!(feature = "mutant-si23-ipc-no-rate-limit") && self.used >= REQUEST_RATE {
            return Err(IpcError::OverBudget);
        }
        self.used = self.used.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests;

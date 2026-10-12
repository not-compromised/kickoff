use std::marker::PhantomData;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use tokio::net::UnixStream;
use tokio::time::timeout;

use super::{RuntimeDir, Trust};
use crate::codec::{self, WELCOME_LEN};
use crate::command::Reply;
use crate::frame::{read_frame, write_frame};
use crate::role::Role;
use crate::{HANDSHAKE_DEADLINE, IpcError, MAX_REPLY_FRAME, MAX_REQUEST_FRAME, PeerCred};

/// A channel to kickoffd in role `R`; it can only send `R::Command`.
pub struct Client<R: Role> {
    stream: UnixStream,
    server: PeerCred,
    dead: bool,
    role: PhantomData<R>,
}

impl<R: Role> std::fmt::Debug for Client<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("role", &R::ROLE)
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

/// Connects in role `R`. The server must pass `trust` (kernel uid and
/// executable) before the client sends anything, so a squatter or a fake
/// server never sees the hello, let alone a command or ticket.
pub async fn connect<R: Role>(dir: &RuntimeDir, trust: &Trust) -> Result<Client<R>, IpcError> {
    let path = dir.socket_path();
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_socket() || meta.uid() != dir.uid() {
        return Err(IpcError::Squatted);
    }
    let mut stream = UnixStream::connect(path).await?;
    let server = trust.check(stream.peer_cred()?)?;
    timeout(HANDSHAKE_DEADLINE, async {
        write_frame(
            &mut stream,
            &codec::encode_hello(crate::PROTOCOL_VERSION, R::ROLE),
        )
        .await?;
        let welcome = read_frame(&mut stream, WELCOME_LEN).await?;
        codec::decode_welcome(&welcome)
    })
    .await
    .map_err(|_| IpcError::Timeout)??;
    Ok(Client {
        stream,
        server,
        dead: false,
        role: PhantomData,
    })
}

impl<R: Role> Client<R> {
    pub fn server(&self) -> PeerCred {
        self.server
    }

    /// Sends one command and waits for its reply. Waiting for the reply's
    /// first byte has no deadline (a command such as `Host` takes as long as
    /// it takes); the rest of the frame must follow promptly.
    pub async fn call(&mut self, command: R::Command) -> Result<Reply, IpcError> {
        if self.dead {
            return Err(IpcError::Closed);
        }
        let result = self.exchange(command).await;
        if result.is_err() {
            self.dead = true;
        }
        result
    }

    async fn exchange(&mut self, command: R::Command) -> Result<Reply, IpcError> {
        let bytes = codec::encode_op(&command.into())?;
        if bytes.len() > MAX_REQUEST_FRAME {
            return Err(IpcError::TooLarge {
                max: MAX_REQUEST_FRAME,
            });
        }
        write_frame(&mut self.stream, &bytes).await?;
        let frame = read_frame(&mut self.stream, MAX_REPLY_FRAME).await?;
        let reply = codec::decode_reply(&frame)?;
        if !reply.allowed_for(R::ROLE) {
            return Err(IpcError::Malformed);
        }
        Ok(reply)
    }
}

//! A Unix stream that carries bytes and nothing else (§2.7, SI-7). Every read
//! is a `recvmsg` with no room for control data, so a descriptor or credential
//! sent alongside the bytes never enters this process: the kernel closes the
//! descriptors itself and reports `MSG_CTRUNC`, and that flag closes the
//! channel. Credentials reach a reader only through `SO_PASSCRED` or
//! `SO_PASSPIDFD`, which these sockets never enable; if one ever were, every
//! message would carry them and every channel would refuse, which fails closed.

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use rustix::net::{RecvAncillaryBuffer, RecvFlags, ReturnFlags};
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::UnixStream;

pub struct DataOnly {
    stream: UnixStream,
}

/// Marks the `io::Error` a read returns for control data, so it maps to
/// `IpcError::Ancillary` rather than to a generic I/O failure.
#[derive(Debug)]
pub struct AncillaryRefused;

impl std::fmt::Display for AncillaryRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ancillary data on a local channel")
    }
}

impl std::error::Error for AncillaryRefused {}

impl DataOnly {
    pub fn new(stream: UnixStream) -> DataOnly {
        DataOnly { stream }
    }

    #[cfg(test)]
    fn socket(&self) -> &UnixStream {
        &self.stream
    }
}

/// One `recvmsg` into `dst` with a zero-length control buffer.
fn recv_bytes(socket: impl AsFd, dst: &mut [u8]) -> io::Result<usize> {
    let mut no_room: [MaybeUninit<u8>; 0] = [];
    let mut control = RecvAncillaryBuffer::from(&mut no_room[..]);
    let got = rustix::net::recvmsg(
        socket,
        &mut [io::IoSliceMut::new(dst)],
        &mut control,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    )?;
    if !cfg!(feature = "mutant-si7-accept-ancillary") && got.flags.contains(ReturnFlags::CTRUNC) {
        return Err(io::Error::other(AncillaryRefused));
    }
    Ok(got.bytes)
}

impl AsyncRead for DataOnly {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let stream = &self.get_mut().stream;
        loop {
            ready!(stream.poll_read_ready(cx))?;
            let dst = buf.initialize_unfilled();
            match stream.try_io(Interest::READABLE, || recv_bytes(stream, dst)) {
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncWrite for DataOnly {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use tokio::io::AsyncReadExt;

    fn pair() -> (std::os::unix::net::UnixStream, DataOnly) {
        let (tx, rx) = std::os::unix::net::UnixStream::pair().unwrap();
        rx.set_nonblocking(true).unwrap();
        (tx, DataOnly::new(UnixStream::from_std(rx).unwrap()))
    }

    fn send_with(
        tx: &std::os::unix::net::UnixStream,
        bytes: &[u8],
        msg: rustix::net::SendAncillaryMessage<'_, '_>,
    ) {
        let mut space = [MaybeUninit::uninit(); 64];
        let mut control = rustix::net::SendAncillaryBuffer::new(&mut space);
        assert!(control.push(msg));
        rustix::net::sendmsg(
            tx,
            &[io::IoSlice::new(bytes)],
            &mut control,
            rustix::net::SendFlags::empty(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn plain_bytes_pass() {
        let (mut tx, mut rx) = pair();
        std::io::Write::write_all(&mut tx, b"hello").unwrap();
        let mut got = [0u8; 5];
        rx.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
    }

    /// The reader never asks for credentials, so to see what it does with
    /// them this socket opts in to `SO_PASSCRED`, as a misconfigured or future
    /// socket might: the kernel then attaches credentials to every message,
    /// and the read must refuse rather than drop them silently.
    #[tokio::test]
    async fn si_7_credentials_close_the_channel() {
        let (tx, mut rx) = pair();
        rustix::net::sockopt::set_socket_passcred(rx.socket(), true).unwrap();
        let me = rustix::net::UCred {
            pid: rustix::process::getpid(),
            uid: rustix::process::getuid(),
            gid: rustix::process::getgid(),
        };
        send_with(
            &tx,
            b"x",
            rustix::net::SendAncillaryMessage::ScmCredentials(me),
        );
        let mut byte = [0u8; 1];
        let err = rx.read(&mut byte).await.unwrap_err();
        assert_eq!(Error::from(err), Error::Ancillary);
    }

    #[tokio::test]
    async fn si_7_descriptors_close_the_channel_and_are_closed() {
        let (tx, mut rx) = pair();
        let (pipe_r, pipe_w) = rustix::pipe::pipe().unwrap();
        send_with(
            &tx,
            b"x",
            rustix::net::SendAncillaryMessage::ScmRights(&[pipe_w.as_fd()]),
        );
        drop(pipe_w);
        rustix::io::ioctl_fionbio(&pipe_r, true).unwrap();
        let mut byte = [0u8; 1];
        let err = rx.read(&mut byte).await.unwrap_err();
        assert_eq!(Error::from(err), Error::Ancillary);
        // Our write end is gone and the received copy never entered this
        // process, so the pipe has no writer left: EOF, not a block.
        let mut sink = [0u8; 1];
        assert_eq!(rustix::io::read(&pipe_r, &mut sink).unwrap(), 0);
    }
}

/// Which fixed installed executable set may receive the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerKind {
    Daemon,
    Client,
}

/// Borrowed transmission authority for a different, canonically authenticated
/// installed process. The source process cannot be its own secret recipient.
pub struct InstalledPeer<'a> {
    transport: &'a mut DataOnly,
    _pidfd: Option<std::os::fd::OwnedFd>,
}

impl DataOnly {
    pub fn installed_peer(&mut self, kind: PeerKind) -> Result<InstalledPeer<'_>, crate::Error> {
        let trust = match kind {
            PeerKind::Daemon => crate::Trust::kickoffd()?,
            PeerKind::Client => crate::Trust::clients()?,
        };
        let (peer, pidfd) = trust.pin(&self.stream)?;
        if !cfg!(feature = "mutant-si30-local-self-recipient")
            && u32::try_from(peer.pid).ok() == Some(std::process::id())
        {
            return Err(crate::Error::PeerRejected);
        }
        Ok(InstalledPeer {
            transport: self,
            _pidfd: pidfd,
        })
    }
}

impl AsyncWrite for InstalledPeer<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().transport).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().transport).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().transport).poll_shutdown(cx)
    }
}

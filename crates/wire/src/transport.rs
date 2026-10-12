//! Secret-bearing frames leave their owner only through concrete transports.

use iroh::endpoint::{Connection, RecvStream};
use kickoff_secret::{OwnedSecret, Secret, SecretBuffer, Wipe};
use std::pin::Pin;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

use crate::WireError;

/// An outgoing frame. Its protected body is accessible only to the wire owner.
/// Consuming a transmission makes successful, failed and cancelled writes drop
/// the same wiping allocation.
pub struct Transmission {
    body: Secret<FrameBody>,
    prefix: [u8; 4],
    recipient: Recipient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("transport closed")]
pub struct TransmissionError;

struct FrameBody(Vec<u8>);
impl OwnedSecret for FrameBody {
    type Consumer = crate::ticket::WireConsumer;
}
impl AsRef<[u8]> for FrameBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl Wipe for FrameBody {
    fn wipe(&mut self) {
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        WIPE_AUDIT.with(|audit| {
            audit
                .borrow_mut()
                .push(!self.0.is_empty() && self.0.iter().all(|b| *b == 0))
        });
        self.0.zeroize();
    }
}
#[cfg(test)]
thread_local! { static WIPE_AUDIT: std::cell::RefCell<Vec<bool>> = const { std::cell::RefCell::new(Vec::new()) }; }

enum Recipient {
    Public,
    Local,
    Door(Option<iroh::EndpointId>),
}

impl Transmission {
    pub(crate) fn new(body: SecretBuffer) -> Result<Self, WireError> {
        let len = u32::try_from(body.len()).map_err(|_| WireError::TooLong {
            max: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
        })?;
        Ok(Self {
            body: Secret::new(FrameBody(body.to_vec())),
            prefix: len.to_be_bytes(),
            recipient: Recipient::Public,
        })
    }

    pub fn body_len(&self) -> usize {
        self.body.expose(&crate::ticket::OWNER, |body| body.0.len())
    }

    pub(crate) fn matches(&self, bytes: &[u8]) -> bool {
        self.body.ct_eq(bytes)
    }
    #[cfg(test)]
    pub(crate) fn copy_body(&self) -> SecretBuffer {
        self.body.expose(&crate::ticket::OWNER, |body| {
            SecretBuffer::copy_from(&body.0)
        })
    }
    async fn write_body<W: AsyncWrite + Unpin>(
        &self,
        send: &mut W,
    ) -> Result<(), TransmissionError> {
        let mut done = 0usize;
        while done < self.body_len() {
            let count = std::future::poll_fn(|cx| {
                self.body.expose(&crate::ticket::OWNER, |body| {
                    let Some(rest) = body.0.get(done..) else {
                        return std::task::Poll::Ready(Err(std::io::Error::from(
                            std::io::ErrorKind::InvalidData,
                        )));
                    };
                    Pin::new(&mut *send).poll_write(cx, rest)
                })
            })
            .await
            .map_err(|_| TransmissionError)?;
            if count == 0 {
                return Err(TransmissionError);
            }
            done = done.saturating_add(count);
        }
        Ok(())
    }

    pub(crate) fn local(body: SecretBuffer) -> Result<Self, WireError> {
        let mut out = Self::new(body)?;
        out.recipient = Recipient::Local;
        Ok(out)
    }

    pub(crate) fn join(
        body: SecretBuffer,
        issuer: Option<iroh::EndpointId>,
    ) -> Result<Self, WireError> {
        let mut out = Self::new(body)?;
        out.recipient = Recipient::Door(issuer);
        Ok(out)
    }

    /// Opens its own stream only after verifying the designated door.
    pub async fn transmit_quic(self, conn: &Connection) -> Result<RecvStream, TransmissionError> {
        match self.recipient {
            Recipient::Public => {}
            Recipient::Door(Some(id))
                if cfg!(feature = "mutant-si30-recipient-unbound") || id == conn.remote_id() => {}
            Recipient::Local | Recipient::Door(_) => return Err(TransmissionError),
        }
        let (mut send, recv) = conn.open_bi().await.map_err(|_| TransmissionError)?;
        send.write_all(&self.prefix)
            .await
            .map_err(|_| TransmissionError)?;
        self.write_body(&mut send).await?;
        send.finish().map_err(|_| TransmissionError)?;
        Ok(recv)
    }

    #[cfg(target_os = "linux")]
    pub async fn transmit_local(
        self,
        send: &mut kickoff_local::InstalledPeer<'_>,
    ) -> Result<(), TransmissionError> {
        if !matches!(self.recipient, Recipient::Local | Recipient::Public) {
            return Err(TransmissionError);
        }
        send.write_all(&self.prefix)
            .await
            .map_err(|_| TransmissionError)?;
        self.write_body(send).await?;
        send.flush().await.map_err(|_| TransmissionError)
    }
}

#[cfg(feature = "mutant-si30-readable-transmission")]
impl Transmission {
    pub fn to_vec(&self) -> Vec<u8> {
        self.body
            .expose(&crate::ticket::OWNER, |body| body.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, task::Poll};

    struct Allow;
    impl kickoff_send_guard::Guard for Allow {
        fn admit(&self, _: u64, _: std::net::SocketAddr) -> bool {
            true
        }
    }
    #[derive(Debug)]
    struct Registered {
        _registration: kickoff_send_guard::Registration,
    }
    impl iroh::endpoint::EndpointHooks for Registered {}

    async fn endpoint(window: u32) -> iroh::Endpoint {
        let bind = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap();
        let registered = kickoff_send_guard::register(bind, std::sync::Arc::new(Allow)).unwrap();
        iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .clear_ip_transports()
            .bind_addr(bind)
            .unwrap()
            .hooks(Registered {
                _registration: registered,
            })
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(vec![b"wipe-test".to_vec()])
            .transport_config(
                iroh::endpoint::QuicTransportConfig::builder()
                    .stream_receive_window(iroh::endpoint::VarInt::from_u32(window))
                    .receive_window(iroh::endpoint::VarInt::from_u32(window))
                    .build(),
            )
            .bind()
            .await
            .unwrap()
    }
    async fn connect(client: &iroh::Endpoint, server: &iroh::Endpoint) -> (Connection, Connection) {
        let (dialed, accepted) = tokio::join!(client.connect(server.addr(), b"wipe-test"), async {
            server.accept().await.unwrap().await.unwrap()
        });
        (dialed.unwrap(), accepted)
    }

    #[tokio::test]
    async fn si_30_designated_transmission_wipes_owned_bytes_on_success_error_and_cancel() {
        WIPE_AUDIT.with(|audit| audit.borrow_mut().clear());
        let client = endpoint(8192).await;
        let server = endpoint(8192).await;
        let (outbound, inbound) = connect(&client, &server).await;
        let frame = |id| Transmission::join(SecretBuffer::copy_from(&[9; 4096]), Some(id)).unwrap();
        let (written, ()) = tokio::join!(frame(server.id()).transmit_quic(&outbound), async {
            let (_send, mut recv) = inbound.accept_bi().await.unwrap();
            let mut prefix = [0; 4];
            recv.read_exact(&mut prefix).await.unwrap();
            assert_eq!(u32::from_be_bytes(prefix), 4096);
            let mut body = SecretBuffer::zeroed(4096);
            recv.read_exact(&mut body).await.unwrap();
            assert!(body.iter().all(|b| *b == 9));
        });
        let _reply = written.unwrap();
        outbound.close(iroh::endpoint::VarInt::from_u32(0), b"");
        let _ = outbound.closed().await;
        assert!(frame(server.id()).transmit_quic(&outbound).await.is_err());

        let blocked = endpoint(0).await;
        let (outbound, _inbound) = connect(&client, &blocked).await;
        let mut pending = Box::pin(frame(blocked.id()).transmit_quic(&outbound));
        std::future::poll_fn(|cx| {
            assert!(
                pending.as_mut().poll(cx).is_pending(),
                "zero receive credit must stop the real transmission"
            );
            Poll::Ready(())
        })
        .await;
        drop(pending);
        WIPE_AUDIT.with(|audit| {
            let observed = audit.borrow();
            assert_eq!(
                observed.len(),
                3,
                "each owned secret frame must reach its real wipe before release"
            );
            assert!(
                observed.iter().all(|wiped| *wiped),
                "a live outgoing allocation retained bytes after wiping"
            );
        });
        outbound.close(iroh::endpoint::VarInt::from_u32(0), b"");
        client.close().await;
        server.close().await;
        blocked.close().await;
    }
}

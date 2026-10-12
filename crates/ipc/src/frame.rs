//! Length-prefixed frames: a big-endian `u32` length, then the payload.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout, timeout_at};
use zeroize::Zeroizing;

use crate::{FRAME_DEADLINE, IpcError, WRITE_DEADLINE};

/// A length already checked against its channel's maximum. `check` is the
/// only constructor and `read_body` takes nothing else, so no buffer is ever
/// sized from an unchecked header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrameLen(usize);

impl FrameLen {
    pub(crate) fn check(header: [u8; 4], max: usize) -> Result<FrameLen, IpcError> {
        let len =
            usize::try_from(u32::from_be_bytes(header)).map_err(|_| IpcError::TooLarge { max })?;
        if len > max {
            return Err(IpcError::TooLarge { max });
        }
        Ok(FrameLen(len))
    }
}

/// Waits as long as it takes for the first byte, so an idle channel costs
/// nothing; from then on the whole frame shares one `FRAME_DEADLINE`.
pub(crate) async fn read_header<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<(FrameLen, Instant), IpcError> {
    let first = r.read_u8().await?;
    let deadline = Instant::now()
        .checked_add(FRAME_DEADLINE)
        .ok_or(IpcError::Timeout)?;
    let mut rest = [0u8; 3];
    timeout_at(deadline, r.read_exact(&mut rest))
        .await
        .map_err(|_| IpcError::Timeout)??;
    let [b1, b2, b3] = rest;
    Ok((FrameLen::check([first, b1, b2, b3], max)?, deadline))
}

/// Zeroized on drop: a frame may carry a ticket.
pub(crate) async fn read_body<R: AsyncRead + Unpin>(
    r: &mut R,
    len: FrameLen,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    let mut buf = Zeroizing::new(vec![0u8; len.0]);
    timeout_at(deadline, r.read_exact(&mut buf))
        .await
        .map_err(|_| IpcError::Timeout)??;
    Ok(buf)
}

pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    let (len, deadline) = read_header(r, max).await?;
    read_body(r, len, deadline).await
}

/// A peer that stops reading cannot hold the writer past `WRITE_DEADLINE`.
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    payload: &[u8],
) -> Result<(), IpcError> {
    let len = u32::try_from(payload.len()).map_err(|_| IpcError::TooLarge {
        max: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
    })?;
    timeout(WRITE_DEADLINE, async {
        w.write_all(&len.to_be_bytes()).await?;
        w.write_all(payload).await?;
        w.flush().await
    })
    .await
    .map_err(|_| IpcError::Timeout)??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_is_checked_against_the_channel_maximum() {
        assert_eq!(FrameLen::check([0, 0, 0, 0], 16), Ok(FrameLen(0)));
        assert_eq!(FrameLen::check([0, 0, 0, 16], 16), Ok(FrameLen(16)));
        assert_eq!(
            FrameLen::check([0, 0, 0, 17], 16),
            Err(IpcError::TooLarge { max: 16 })
        );
        assert_eq!(
            FrameLen::check([0xff; 4], 4096),
            Err(IpcError::TooLarge { max: 4096 })
        );
    }

    /// The refusal comes from the header alone: the body is never awaited, so
    /// nothing is allocated for it.
    #[tokio::test]
    async fn si_23_oversize_header_refused_before_body() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        // The writer stays open and sends no body: an implementation that
        // allocated and read before checking would wait for the deadline.
        let started = std::time::Instant::now();
        let got = read_frame(&mut server, 4096).await;
        assert_eq!(got, Err(IpcError::TooLarge { max: 4096 }));
        assert!(started.elapsed() < FRAME_DEADLINE / 2);
        drop(client);
    }

    #[tokio::test]
    async fn stalled_body_times_out() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_all(&[0, 0, 0, 10, 1, 2]).await.unwrap();
        let got = tokio::time::timeout(FRAME_DEADLINE * 3, read_frame(&mut server, 4096))
            .await
            .expect("frame deadline must fire");
        assert_eq!(got, Err(IpcError::Timeout));
    }
}

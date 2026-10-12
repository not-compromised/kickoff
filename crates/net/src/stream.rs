//! One-shot join messages on QUIC streams (§4.3, §4.5): `u32` length, then the
//! body. The length is checked against `M::MAX_LEN` before anything is
//! allocated. Callers bound the whole exchange with a deadline.

use iroh::endpoint::{RecvStream, SendStream};
use kickoff_secret::SecretBuffer;
use kickoff_wire::{
    LEN_PREFIX_LEN, PublicWireMessage, WireError, WireMessage, decode, encode_framed, frame_len,
};

use crate::NetError;

pub(crate) async fn read_message<M: WireMessage>(recv: &mut RecvStream) -> Result<M, NetError> {
    let mut prefix = [0u8; LEN_PREFIX_LEN];
    recv.read_exact(&mut prefix)
        .await
        .map_err(|_| NetError::Closed)?;
    let len = frame_len::<M>(prefix).map_err(wire)?;
    let mut body = SecretBuffer::zeroed(len);
    recv.read_exact(&mut body)
        .await
        .map_err(|_| NetError::Closed)?;
    decode(&body).map_err(wire)
}

pub(crate) async fn write_message<M: PublicWireMessage>(
    send: &mut SendStream,
    msg: &M,
) -> Result<(), NetError> {
    let frame = encode_framed(msg).map_err(wire)?;
    send.write_all(&frame).await.map_err(|_| NetError::Closed)
}

pub(crate) fn wire(err: WireError) -> NetError {
    match err {
        WireError::NotImplemented => NetError::NotImplemented,
        WireError::Version => NetError::Version,
        _ => NetError::Protocol,
    }
}

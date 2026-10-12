//! The in-memory adapter: two bounded frame queues standing in for a tap, so
//! tests drive the same codec and filter as the real adapters.

use bytes::Bytes;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{self, error::TrySendError};

use crate::{Adapter, LanError};

/// Frames queued in each direction. A tap's kernel queue is bounded too.
const QUEUE: usize = 256;

/// Kickoff's end of an in-memory tap.
pub struct MemTap {
    from_game: mpsc::Receiver<Bytes>,
    to_game: mpsc::Sender<Bytes>,
}

/// The local game's end of an in-memory tap: a test plays the game by sending
/// and receiving raw Ethernet frames.
pub struct MemGame {
    to_lan: mpsc::Sender<Bytes>,
    from_lan: Mutex<mpsc::Receiver<Bytes>>,
}

pub fn mem_tap() -> (Adapter, MemGame) {
    let (to_lan, from_game) = mpsc::channel(QUEUE);
    let (to_game, from_lan) = mpsc::channel(QUEUE);
    (
        Adapter::Mem(MemTap { from_game, to_game }),
        MemGame {
            to_lan,
            from_lan: Mutex::new(from_lan),
        },
    )
}

impl MemGame {
    /// Never blocks: `Full` when Kickoff has not drained the queue.
    pub fn send_frame(&self, frame: Bytes) -> Result<(), LanError> {
        self.to_lan.try_send(frame).map_err(|e| match e {
            TrySendError::Full(_) => LanError::Full,
            TrySendError::Closed(_) => LanError::Closed,
        })
    }

    /// `Closed` once the `Lan` is dropped and every queued frame is read.
    pub async fn recv_frame(&self) -> Result<Bytes, LanError> {
        self.from_lan
            .lock()
            .await
            .recv()
            .await
            .ok_or(LanError::Closed)
    }
}

pub(crate) struct Io {
    pub from_game: Mutex<mpsc::Receiver<Bytes>>,
    pub to_game: mpsc::Sender<Bytes>,
}

impl MemTap {
    pub(crate) fn into_io(self) -> Io {
        Io {
            from_game: Mutex::new(self.from_game),
            to_game: self.to_game,
        }
    }
}

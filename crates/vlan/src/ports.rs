//! Which UDP ports peers may reach (§3.1). Compiled-in data with no
//! configuration path, so nothing at runtime can widen it (NET-1).

/// `GamePorts`, replaced by measured values in M1. Unicast to any of these
/// passes; broadcast passes only to `discovery`.
pub(crate) struct GamePorts {
    pub game: &'static [u16],
    pub discovery: &'static [u16],
}

pub(crate) const GAME_PORTS: GamePorts = GamePorts {
    // Listen server, `PORT=` default (L, RocketPlugin.h:22).
    game: &[7777],
    // UE3 LAN beacon default (U, game-lan).
    discovery: &[14001],
};

use kickoff_wire::{DENIED_PORTS as DENYLIST, denied_port as denied};

pub(crate) fn game(port: u16) -> bool {
    GAME_PORTS.game.contains(&port) || discovery(port)
}

pub(crate) fn discovery(port: u16) -> bool {
    GAME_PORTS.discovery.contains(&port)
}

// A measured port that lands on the denylist must fail the build, not be
// silently dropped at runtime.
#[expect(
    clippy::indexing_slicing,
    reason = "const evaluation: an out-of-bounds index fails the build"
)]
const _: () = {
    let lists = [GAME_PORTS.game, GAME_PORTS.discovery];
    let mut l = 0;
    while l < lists.len() {
        let list = lists[l];
        let mut i = 0;
        while i < list.len() {
            let port = list[i];
            assert!(port != 0, "port 0 is not a game port");
            let mut d = 0;
            while d < DENYLIST.len() {
                let (lo, hi) = DENYLIST[d];
                assert!(port < lo || port > hi, "a GamePorts entry is denylisted");
                d += 1;
            }
            i += 1;
        }
        l += 1;
    }
};

# kickoff-vlan

The game-facing LAN (design §2.3, §3.1). The local game's tap carries Ethernet
frames; the rest of Kickoff sees only `LanDatagram`s (slot, broadcast flag, UDP
ports, payload). Between the two sit the frame codec and the filter, shared by
every adapter.

```
game ─frame→ adapter → codec.decode → filter.outbound → Lan::recv → pump
pump → Lan::deliver → filter.inbound (charged first) → codec.udp_frame → adapter → game
```

| Module | Owns |
|---|---|
| `addr` | every MAC and IPv4 address synthesized or checked, built from a slot; the star rule (a guest talks only to the host) |
| `codec` | frame parsing and building, ARP replies, IPv4 and UDP checksums |
| `ports` | `GamePorts` and the denylist, compiled in, with a build-time check that no game port is denylisted |
| `filter` | per-peer packet and byte buckets, broadcast buckets, the fixed flow tables |
| `verdict` | the one reason for each drop, and which `LanHealth` counter it feeds |
| `mem` | the in-memory adapter (`mem_tap`) |

Interface:

```rust
pub fn open(adapter: Adapter, cfg: LanConfig) -> Result<Lan, LanError>;
impl Lan {
    pub async fn recv(&self) -> Result<LanDatagram, LanError>; // from the game, filtered; cancel-safe
    pub fn deliver(&self, datagram: LanDatagram);               // to the game; never blocks
    pub fn reset_peer(&self, slot: PeerSlot);                   // a slot's generation changed
    pub fn health(&self) -> LanHealth;
}
pub fn mem_tap() -> (Adapter, MemGame);
```

Tests: `src/tests.rs` (every forbidden case with its reason), `tests/lan.rs`
(two games through the LAN), `tests/si.rs` (SI-18, SI-21, SI-23),
`tests/prop.rs` (no input reaches a denied port or wears a foreign slot).

## NOTES (spec questions and deviations from draft 2)

1. **Generation ownership stays in session.** §3.1 keys flows by identity,
   generation and tuple. The LAN uses slot and ports; session authenticates
   the current link generation and calls `reset_peer(slot)` on route removal
   and activation before the replacement route can deliver. This call clears
   every return permission for that slot. Public VLAN reset tests and real
   session reconnect tests cover unicast and broadcast flows independently.
2. **Per-peer buckets survive `reset_peer`** on purpose. Otherwise a
   reconnect would refill a flooding peer's budget.
3. **Broadcast return permissions belong to each guest.** A host beacon
   records its tuple in every guest's existing flow table. A reset clears
   only that guest's permission, leaving other generations' replies intact.
   Broadcast and unicast share the same 64-entry limit and 30 s idle expiry.
   Admission resets a new or reused slot before installing its route, so a
   later guest cannot inherit a beacon emitted before its admission.
4. **Broadcast `peer`.** `recv` returns every broadcast with
   `peer = PeerSlot::HOST`. On the host that is the host's own slot, and the
   pump fans it out to every guest. On a guest it goes to the host only.
   Inbound, `deliver` takes the sender's slot as usual.
5. **Byte-bucket burst.** §6.3 gives 4 MB/s per link but no burst. I chose
   1 MB (0.25 s). The packet bucket is 3000/s with a burst of 1000, as in
   §6.3. These are charged again here, per peer, so one peer cannot fill the
   game's queue for the others. The §6.3 rule "above 10x for 5 s is
   disconnected" belongs to `net`/`session`; vlan only reports aggregate
   `LanHealth` counters.
6. **Payload ceiling.** Frames are at most 1514 bytes (MTU 1500), so a
   datagram payload is at most 1472. Larger inbound datagrams are dropped as
   `PayloadTooLarge`. §3.3 sets the Windows adapter MTU to 1280, which allows
   only 1252. Open question: should the LAN cap every node at 1252 so a Linux
   host never sends a Windows guest a datagram it cannot frame?
7. **`LanError`.** Removed `NotImplemented`; added `Full` (`MemGame::send_frame`
   when Kickoff has not drained the queue). The game queue holds 256 frames in
   each direction.
8. **Unicast to the discovery port** passes inbound, the same as a game port.
   The subnet broadcast `10.75.0.255` is accepted from the game; peers'
   broadcasts reach the game as `255.255.255.255`.
9. **ARP** is answered for any star slot, admitted or not. A probe (sender
   `0.0.0.0`), a request for the node's own address, gratuitous ARP and ARP
   replies from the game are dropped and counted.
10. **Not done in M2:** the `NsTap` adapter (M3; `open` returns
    `Unsupported`) and a nightly cargo-fuzz target for the codec (the
    property test feeds it raw and mutated frames in the meantime). The §7
    ≤ 2 µs hot path is a release-mode timing test, `tests/hot_path.rs`, not a
    criterion bench (docs/development.md, harness note 6).

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

1. **`Lan::reset_peer(slot)` is new.** §3.1 keys flows by (identity,
   generation, 5-tuple), but `LanDatagram` carries no generation, so the
   filter cannot see one. Flows are keyed by slot and ports, and the admission
   owner must call `reset_peer(slot)` whenever that slot's generation changes
   (reconnect, kick, eviction, slot reuse), before delivering the new
   generation's datagrams. `si_18_flows_do_not_survive_a_generation_change`
   covers the vlan side. The weakness: a forgotten call fails open. A
   fail-closed alternative for draft 3 is `Lan::admit(PeerRef)`, with
   `deliver` dropping datagrams from slots holding no current admission. I
   did not adopt it because session is being written against the stub
   `deliver` signature in parallel.
2. **Per-peer buckets survive `reset_peer`** on purpose. Otherwise a
   reconnect would refill a flooding peer's budget.
3. **Flows opened by the host's broadcasts** can be answered by any guest
   (that is how beacon replies work). `reset_peer` leaves them in place. They
   expire after 30 s idle like other flows.
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
    `Unsupported`), the §7 criterion bench for the ≤ 2 µs hot path, and a
    nightly cargo-fuzz target for the codec (the property test feeds it raw
    and mutated frames in the meantime).

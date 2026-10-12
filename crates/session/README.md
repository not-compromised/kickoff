# kickoff-session

A Kickoff session (design §2.3, §4): admission, capabilities, generations,
reconnect, budgets and the pump between the local game's LAN and the links.

| Module | Owns |
|---|---|
| `admission` | the admission owner (§4.4): seats keyed by identity and generation, the session-wide generation counter, revocation, trusted ids, the invite ledger, and the admitted set and roster it publishes. Pure state, no I/O |
| `host` | applies each decision in one critical section (route removal, LAN flow reset, published set and roster), the join loop, the accept loop, one task per link, the pump, the window sweep |
| `guest` | join, the first-roster check, the guest pump, redial with backoff |
| `routes` | the pump's only shared state: slot → (generation, link). Deliveries run under its read lock, changes take the write lock |
| `budget`, `clock` | the host fan-out bucket; the host's forward-only monotonic clock |

## Interface

```rust
pub async fn host(door: Arc<Door>, door_key: &Secret<SecretKey>, net: SessionNet, adapter: Adapter, opts: HostOpts) -> Result<Session, SessionError>;
pub async fn join(door: &Door, net: SessionNet, adapter: Adapter, ticket: Secret<Ticket>, opts: JoinOpts) -> Result<Session, SessionError>;
impl Session {
    pub fn invite(&self, kind: InviteKind) -> Result<Secret<Ticket>, SessionError>;  // host only
    pub fn events(&self) -> broadcast::Receiver<SessionEvent>;
    pub fn slot(&self) -> PeerSlot;
    pub fn members(&self) -> Vec<Member>;
    pub async fn command(&self, command: Command) -> Result<(), SessionError>;  // Kick, Readmit, Approve, Decline, PickMap, Leave
}
```

How the structure carries the rules:

- **Source slot from the link only.** The host's per-link task stamps every
  datagram with its link's slot before delivery; the guest stamps the host's.
  The wire header has no slot to read (§4.5).
- **No link-to-link path (SI-21).** A guest link's datagrams go only to
  `Lan::deliver`; the host's own game is the only source of anything sent to a
  link. A guest's LAN refuses every slot but the host's, and its session
  endpoint refuses every connection.
- **Generation on every touch (SI-18).** A link's datagrams are delivered only
  while the routing table holds that link's generation, under the table's read
  lock; kicks, drops and evictions remove the route under the write lock first,
  then reset the LAN's flows for the slot, then publish the admitted set (which
  closes the connection in `net`). Generations come from one counter, so a slot
  reused by another identity never sees an old generation again.
- **Revocation first (SI-19).** `Admission::join` refuses a revoked identity
  before it looks at trust or the capability, so a kick overrides both, and a
  refusal never spends a ticket. `Readmit` is the explicit host action.
- **Spend once (SI-20).** Every refusal that does not depend on the capability
  (revoked, version, already seated, session key taken, roster full) comes
  before `Invites::redeem`, which spends the capability whatever follows.
- **Budgets before allocation (SI-23).** Seats, prompts, revocations, replies in
  flight and events have fixed capacities; the host's fan-out pays 16 MB/s per
  emitted copy before the copy is sent; the link and LAN budgets are charged in
  `net` and `vlan` before decode and delivery. A link `net` disconnects as
  over budget loses its seat.

## Tests

In-process nodes on loopback with relays disabled and `vlan::Mem` games. Each
test plays every game with raw Ethernet frames; hostile or precise guests (and,
once, a host) are played with `kickoff-net` directly.

| Test | Proves |
|---|---|
| `bound_ticket_admits_its_invitee` | a bound invite admits its invitee at slot 2; both rosters agree |
| `si_20_bearer_ticket_admits_once` | the prompt names the authenticated identity; the same bearer ticket then fails for anyone |
| `si_20_one_capability_on_many_connections_admits_once` | eight identities racing one bearer ticket: one prompt, one admission |
| `si_20_bound_capability_raced_by_its_invitee_admits_once` | ten concurrent requests with one bound ticket: one admission |
| `si_20_expired_bearer_ticket_refused` | 15 minutes on the host clock expires a bearer ticket, not a bound one |
| `si_20_replayed_ticket_refused` | a used ticket is refused after its holder left and was evicted |
| `si_20_wrong_invitee_refused_and_the_ticket_survives` | another identity is refused and the invitee still gets in |
| `si_20_declined_prompt_spends_the_ticket` | a declined bearer join cannot retry with that ticket |
| `si_20_ticket_from_a_previous_host_session_refused` | same door key, new session: `WrongSession` |
| `another_major_version_refused_before_the_ticket_is_spent` | a newer major version gets `Version`, and the bound ticket still admits afterwards |
| `si_18_one_seat_per_identity_under_concurrent_joins` | twelve concurrent joins by one trusted identity: one seat |
| `si_18_claimed_session_key_refused_and_its_owner_unharmed` | a request naming another guest's session key is refused and that guest's link keeps working |
| `si_18_unknown_session_key_rejected` | a stranger with the session address and someone's pass gets no roster and reaches no game |
| `si_18_admission_table_invariants_hold_for_any_sequence` | property test: one seat per identity and session key, no seat for a revoked id, no generation names two admissions, epoch moves with the roster |
| `si_18_removal_waits_for_in_flight_delivery_then_drops_the_rest` | barrier race: a route removal waits out a delivery in flight, and nothing of the old generation is delivered after it |
| `si_19_kicked_peer_datagrams_dropped` | a guest still sending after its kick reaches the game no more; its redial and a fresh ticket are refused |
| `si_19_kick_overrides_trust_and_every_ticket` | after a kick, a trusted rejoin and every earlier ticket get `Revoked`; after `Readmit`, trust applies again |
| `si_18_reconnect_forgets_the_old_generations_flows` | a flow the host's game opened before a drop does not answer the redialed link |
| `reconnect_inside_the_window_keeps_the_slot` | a dropped guest's slot stays reserved and its redial carries on |
| `reconnect_after_the_window_is_refused_and_frees_the_slot` | past 30 s the seat is gone, the redial refused, the slot reused |
| `guest_redials_after_a_drop_and_carries_on` | the guest side of §4.6 against a test-played host |
| `broadcast_and_unicast_round_trip` | host beacon to both guests, guest beacon to the host, unicast to the addressed guest only |
| `host_leaving_ends_every_guest` | `Leave` on the host ends each guest with `HostEnded`; later commands get `Ended` |
| `si_21_guest_cannot_reach_another_guest` | A's beacon and unicast to B never reach B's link; another guest's dial to B's endpoint is refused |
| `si_23_peer_over_budget_is_limited_and_another_keeps_its_latency` | a guest at ~7x its datagram budget gets at most the budget through while another guest's round trips stay fast |
| `si_23_peer_far_over_budget_is_disconnected` | a guest far over budget loses its seat; the other keeps playing |
| `latency_p50_p99_over_10k_datagrams` | §7, game socket to game socket, one way |

The mutants in `/mutants.toml` now automate this (`scripts/check.sh` runs them),
including `si_18_link_up_needs_the_seat_generation_and_pass`, the session's
layer under net's admission layers, and
`si_23_link_without_hello_closed_at_the_deadline`. Before that, each `si_*`
test was run by hand with its mitigation removed and failed: the
session-key, revocation and one-seat checks in `Admission::join`; delivery
outside the routing lock; the kick's unroute and publish; the LAN flow reset on
a generation change; a host pump that forwards guest broadcasts; an over-budget
disconnect treated as a drop; the link and LAN datagram charges (both removed
together, since either alone holds the budget); and, in `wire`, a reusable
capability, a bearer ticket that never expires, and an unchecked session id.
`si_18_unknown_session_key_rejected` rests on `net`'s admission hook, whose own
test was run that way on its branch; it was not repeated here. The integration test
`si_19_kicked_peer_datagrams_dropped` cannot tell the routing gate from `net`
closing the connection; the barrier test is what pins the gate.

Measured (release build, loopback, this repository's reference Linux machine):
game-to-game one way over 10,000 datagrams p50 14 µs, p99 57 µs (§7 budget
100 µs / 500 µs); the other guest's round trip under the ~7x flood p50 75 µs,
p99 150 µs. Debug builds assert only loose ceilings; run
`cargo test --release -p kickoff-session --test budget -- --nocapture` for the
numbers.

## NOTES

Deviations from design draft 2 and open questions.

1. **`host` and `join` take an `Adapter`, not a `Lan`.** A guest learns its slot
   only from `Admitted`, and the LAN's address is its slot, so the session opens
   the LAN itself with the admitted slot; they cannot disagree.
2. **`host` takes `Arc<Door>` and `&Secret<SecretKey>`.** The join loop outlives
   the call, and invites are signed with the door key, which `Door` does not
   expose. `host` refuses a key that is not the door's.
3. **`join` takes `JoinOpts`** (name, platform, game build). `game_build` is
   sent but not compared; build mismatch handling is M6.
4. **Interface additions:** `Command::{Readmit, Decline}`, `Session::{slot,
   members}`, `HostOpts::{name, clock}`, `Clock`, `KICKOFF_VERSION`,
   `JoinOpts`, `EndReason`, `SessionEvent::{Reconnecting, Ended(EndReason)}`,
   `SessionEvent::Roster { epoch, members }`, `SessionEvent::JoinPrompt { id,
   name }`, and `SessionError` variants for each failure.
5. **`net` hands out the control stream beside the link**
   (`dial`/`accept -> (Link, CtlStream)`), so datagrams and control run on
   separate tasks (§2.5). See `crates/net/README.md` NOTES.
6. **Bound invites are single use.** `Invites::redeem` spends any capability
   once (SI-20), so "admitted without a prompt while the session lives" (§4.2)
   is read as its validity, not reuse. A guest whose app restarts needs a new
   invite or the trusted list.
7. **Trusted friends still present a ticket.** `JoinRequest.cap` is mandatory,
   and the guest needs the door address from somewhere, so a trusted identity
   joins with any ticket for the door; its capability is neither checked nor
   spent. A ticketless join (an `Option<Cap>`, a door address from the friend
   record) is a wire change for draft 3.
8. **Reconnect bumps the generation when the host notices the drop**, not when
   the redial arrives (§4.4's wording). `net` refuses a second connection from
   a session key while the first is open, so a redial before the host notices
   is refused as a duplicate and the guest retries within its 30 s window. If
   the host only learns of a silent path loss from QUIC's idle timeout, that
   timeout must stay well under the 30 s window; draft 3 should state it.
9. **`Hello` must carry the generation in the guest's pass**, also on a redial;
   the host's current generation for the seat stays internal.
10. **One seat per identity**: a second join from a seated identity (including
    one in its reconnect window) is refused `Busy`.
11. **A claimed session key is refused** (`InvalidCap`): a request naming the
    host's session key, its door id or another seat's session key would
    otherwise overwrite that admission in the published set. Not in the design.
12. **Goodbyes.** A kick and the end of the session send `Kick` or `End` and
    wait up to 500 ms for the guest to close, because QUIC discards unread
    stream data when a connection closes. Evictions for budget or protocol go
    at once, with no message.
13. **Numbers the design leaves open:** bearer prompt timeout 60 s (then
    declined), admission window 30 s for an admitted guest to connect, 1024
    revocations (`RevokedFull` beyond), 16 join replies in flight, fan-out burst
    2 MB.
14. **`Status` is read and ignored**, as §3.4 allows; `MapPick` and
    `Command::PickMap` are M6 (`NotImplemented`).
15. **The host sends no `Ping`.** iroh's 5 s keep-alive covers liveness; a guest
    still answers `Ping` with `Pong`.
16. **Kicking a guest waiting on a bearer prompt** answers it `Declined`, not
    `Revoked`; the identity is revoked either way.

### Not done

- The guest's `HostLost` after 30 s of failed redials is untested (the guest
  window runs on the runtime clock, so the test would take 30 s).
- SI-23's full flood suite: pre-handshake floods, control saturation and
  stream churn are tested in `net`; map-request churn and disk are M6; no test
  asserts RSS, fd or task ceilings yet.
- The §7 hot path (≤ 2 µs) is timed in `kickoff-vlan`'s `tests/hot_path.rs`,
  release build, not a criterion bench.
- Recreating the session endpoint on a default-route change (kickoffd's job).

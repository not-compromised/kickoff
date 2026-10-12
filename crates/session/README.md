# kickoff-session

A Kickoff session (design §2.3, §4): admission, capabilities, generations,
reconnect, budgets and the pump between the local game's LAN and the links.

| Module | Owns |
|---|---|
| `admission` | the admission owner (§4.4): seats keyed by identity and generation, the session-wide generation counter, revocation, trusted ids, the invite ledger, the approvals, and the admitted set and roster it publishes. Pure state, no I/O |
| `approval` | approval objects (§4.4, SI-41): random ids, one pending per kind, consumed once, retired by a kick, a generation change, a newer map pick, the session's end or 60 s. Pure state, owned by `admission` |
| `host` | applies each decision in one critical section (route removal, LAN flow reset, published set, roster and pending approvals), the join loop, the accept loop, one task per link (Hello deadline, Ping and idle close), the pump, the window and approval sweep |
| `guest` | join, the first-roster check, the guest pump, redial with backoff |
| `routes` | the pump's only shared state: slot → (generation, link). Deliveries run under its read lock, changes take the write lock |
| `budget`, `clock` | the host fan-out bucket; the session's forward-only monotonic clock |

## Interface

```rust
pub async fn host(door: Arc<Door>, door_key: &Secret<SecretKey>, net: SessionNet, adapter: Adapter, opts: HostOpts) -> Result<Session, SessionError>;
pub async fn join(door: &Door, net: SessionNet, adapter: Adapter, ticket: Secret<Ticket>, opts: JoinOpts) -> Result<Session, SessionError>;
impl Session {
    pub fn invite(&self, kind: InviteKind) -> Result<Secret<Ticket>, SessionError>;  // host only
    pub fn events(&self) -> broadcast::Receiver<SessionEvent>;      // includes ApprovalRequested(Approval)
    pub fn approvals(&self) -> watch::Receiver<Vec<Approval>>;      // the pending set; cannot lose one
    pub fn slot(&self) -> PeerSlot;
    pub fn members(&self) -> Vec<Member>;
    pub async fn command(&self, command: Command) -> Result<(), SessionError>;  // Kick, Readmit, Decide{approval, allow}, PickMap, Leave
}
pub struct Approval { pub id: ApprovalId, pub action: ApprovalAction, pub peer: EndpointId, pub generation: Generation }
pub enum ApprovalAction { AdmitBearer, InstallMap { map: MapId } }
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
- **One object per decision (SI-41).** A bearer join creates an `Approval`
  in the admission owner and holds its seat in `Prompting`. `Decide` consumes
  the object its id names, and admits only if that seat still waits on that
  id at that generation. A kick, eviction or generation change retires the
  peer's approvals, the sweep retires them at 60 s on the host clock, and the
  end of the session retires all of them. The waiting join reads its answer
  from the table (admitted, revoked or declined), so every path that retires
  an approval answers the guest the same way. One bearer approval is pending
  at a time: another bearer join is refused `Busy` before its capability is
  redeemed, so the refusal does not spend it.
- **Liveness (SI-23, PRIV-29).** A link must say `Hello` within 2 s of
  arriving. The host then pings it every 5 s and closes it once 15 s pass on
  the host clock without a `Pong`; the seat enters the reconnect window like
  any lost link.
- **Budgets before allocation (SI-23).** Seats, approvals, revocations, replies in
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
| `si_20_bearer_ticket_admits_once` | the approval names the authenticated identity; the same bearer ticket then fails for anyone |
| `si_20_one_capability_on_many_connections_admits_once` | eight identities racing one bearer ticket: one approval, one admission |
| `si_20_bound_capability_raced_by_its_invitee_admits_once` | ten concurrent requests with one bound ticket: one admission |
| `si_20_expired_bearer_ticket_refused` | 15 minutes on the host clock expires a bearer ticket, not a bound one |
| `si_20_replayed_ticket_refused` | a used ticket is refused after its holder left and was evicted |
| `si_20_wrong_invitee_refused_and_the_ticket_survives` | another identity is refused and the invitee still gets in |
| `si_20_declined_prompt_spends_the_ticket` | a declined bearer join cannot retry with that ticket |
| `si_41_kick_retires_the_approval_and_its_id` | a kick answers the waiting join `Revoked`; readmitted, the same identity asks again, and the old id decides nothing; the new one admits once |
| `si_41_timed_out_approval_authorizes_nothing` | 60 s on the host clock declines the join; the old id cannot decide the identity's next request |
| `si_41_session_end_retires_every_approval` | `Leave` empties the pending set; a later `Decide` gets `Ended` and the join is refused |
| `si_41_second_bearer_join_refused_while_one_is_pending` | a second bearer join gets `Busy` and its ticket survives for after the first is decided |
| `si_41_an_approval_dies_with_its_moment` | unit: single use, a newer map pick, a peer's generation change, the timeout and the end each retire an id, against the same peer asking again |
| `si_41_one_pending_approval_per_kind` | unit: one bearer approval at a time; a map approval is independent |
| `pending_approvals_are_held_not_streamed` | `Session::approvals` shows a pending approval to a reader that never drained its events, and drops it once decided |
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
| `guest_reports_host_lost_after_the_reconnect_window` | a guest whose redials are all refused keeps trying, then ends with `HostLost` once 30 s pass on its clock |
| `broadcast_and_unicast_round_trip` | host beacon to both guests, guest beacon to the host, unicast to the addressed guest only |
| `host_leaving_ends_every_guest` | `Leave` on the host ends each guest with `HostEnded`; later commands get `Ended` |
| `si_21_guest_cannot_reach_another_guest` | A's beacon and unicast to B never reach B's link; another guest's dial to B's endpoint is refused |
| `si_23_peer_over_budget_is_limited_and_another_keeps_its_latency` | a guest at ~7x its datagram budget gets at most the budget through while another guest's round trips stay fast |
| `si_23_peer_far_over_budget_is_disconnected` | a guest far over budget loses its seat; the other keeps playing |
| `si_23_link_without_hello_closed_at_the_deadline` | a link that never completes its `Hello` is closed within 4 s (deadline 2 s) |
| `si_23_link_silent_for_15_s_closed` | a guest that never answers `Ping` is closed once 15 s pass on the host clock; a real guest, which answers, keeps its link |
| `latency_p50_p99_over_10k_datagrams` | §7, game socket to game socket, one way |

The mutants in `/mutants.toml` now automate this (`scripts/check.sh` runs them),
including `si_18_link_up_needs_the_seat_generation_and_pass`, the session's
layer under net's admission layers, `si_23_link_without_hello_closed_at_the_deadline`,
the idle close, and five SI-41 mutants: ids derived from the peer (draft 2's
`Approve(id)`), two bearer approvals at once, approvals that survive a kick
or generation change, approvals that never time out, and an end that leaves
them pending. Before that, each `si_*`
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

Bearer invites require a relay-only host and guest. The host refuses bearer
creation in Direct mode and re-checks untrusted bearer requests at admission;
the guest checks its own mode before requesting admission and refuses any
host IP address in the admission reply. Each boundary has its own SI-31
mutant. A local HTTPS relay with an explicitly trusted generated CA proves
real bearer joins and game delivery without IP candidates. Bound-invite
Direct sessions still exercise the direct transport.

## NOTES

Deviations from the design (written against draft 2, updated for draft 3)
and open questions.

1. **`host` and `join` take an `Adapter`, not a `Lan`.** A guest learns its slot
   only from `Admitted`, and the LAN's address is its slot, so the session opens
   the LAN itself with the admitted slot; they cannot disagree.
2. **`host` takes `Arc<Door>` and `&Secret<SecretKey>`.** The join loop outlives
   the call, and invites are signed with the door key, which `Door` does not
   expose. `host` refuses a key that is not the door's.
3. **`join` takes `JoinOpts`** (name, platform, game build). `game_build` is
   sent but not compared; build mismatch handling is M6.
4. **Interface additions:** `Command::Readmit`, `Session::{slot, members,
   approvals}`, `HostOpts::{name, clock}`, `JoinOpts::clock`, `Clock`,
   `KICKOFF_VERSION`, `JoinOpts`, `EndReason`, `SessionEvent::{Reconnecting,
   Ended(EndReason)}`, `SessionEvent::Roster { epoch, members }`,
   `ApprovalId::{from_bytes, to_bytes}`, and `SessionError` variants for each
   failure (`NoApproval` for a `Decide` naming no current approval). Draft
   3's `Decide`, `ApprovalRequested`, `Approval`, `ApprovalId` and
   `ApprovalAction` replace draft 2's `Approve`, `Decline` and `JoinPrompt`.
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
   is refused as a duplicate and the guest retries within its 30 s window.
   Draft 3's Ping/Pong settles how a silent path is noticed: the host closes
   it after 15 s without a `Pong`, inside the window.
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
13. **Numbers the design leaves open:** admission window 30 s for an admitted
    guest to connect, 1024 revocations (`RevokedFull` beyond), 16 join replies
    in flight, fan-out burst 2 MB. (The 60 s approval timeout, 2 s `Hello`,
    5 s `Ping` and 15 s idle close are draft 3's.)
14. **`Status` is read and ignored**, as §3.4 allows; `MapPick` and
    `Command::PickMap` are M6 (`NotImplemented`).
15. **An idle link is treated as lost**, not evicted: the seat waits out the
    30 s reconnect window under a new generation, as for any dropped path.
    Draft 3 says only that the link is closed. Idle time is measured on the
    host `Clock`, like the other session windows, so tests can advance it;
    only a `Pong` resets it.
16. **Kicking a guest waiting on approval** answers it `Revoked`.
17. **`Approval.peer` is an `EndpointId`**, not a `Fingerprint`: no fingerprint
    type exists yet; the dialog (M10) renders one from the key.
18. **Lagging event receivers (development.md open question 5) are settled
    for approvals:** `Session::approvals()` is a watch of the pending set,
    which a slow reader cannot lose, and the join waits on that set rather
    than on any event. `ApprovalRequested` is still sent on the lossy event
    stream, as §2.3 lists it. Other events (`Roster`, `Reconnecting`) carry
    state that `members()` and the end event already hold.
19. **Refusals for approvals reuse existing codes** (wire has no change in
    draft 3): a second bearer join while one is pending gets `Busy`; a
    timed-out or session-ended approval answers `Declined`.
20. `ApprovalId` comes from `kickoff-wire`, shared with IPC and re-exported
    by session. The local channel carries its bytes; the admission owner
    alone mints ids and checks that their objects remain current.
21. **`InstallMap` approvals** are never created on the host and a guest
    creates none until M6; the type and its replacement rule (a newer pick
    retires the pending one) are unit-tested now. A guest's `Decide` gets
    `NoApproval`.

### Not done

- SI-41's dialog half (at most 6 native dialogs per minute, the
  compromised-webview harness) is M10.
- SI-23's full flood suite: pre-handshake floods, control saturation and
  stream churn are tested in `net`; map-request churn and disk are M6; no test
  asserts RSS, fd or task ceilings yet.
- The §7 hot path (≤ 2 µs) is timed in `kickoff-vlan`'s `tests/hot_path.rs`,
  release build, not a criterion bench.
- Recreating the session endpoint on a default-route change (kickoffd's job).

## Lifecycle and deadline boundaries

The admission owner marks ending, clears approvals and drains routes while
holding the admission mutex. Invite creation, commands, sweep and link-loss
callbacks check that same state under that mutex; `join` and `link_up` reject
before changing a seat. The drained links keep their published admission long
enough to receive `End`. Farewell waits run after releasing the mutex.

The lock order is admission, routes, LAN, then publication. Routing readers
only send or deliver; they never acquire admission. Draining takes the routing
write lock and waits for existing deliveries and sends to finish. No route can
be activated afterward. The actor paths release LAN locks before ending, and
control writes and farewell waits hold none of these locks.

Door replies use sixteen permits, with eight reserved for bound and trusted
identities. A full reply pool closes that request without waiting outside the
door's event selection. Door answer writes and close acknowledgement share a
five-second total deadline; queue overflow closes immediately.

The session endpoint captures the absolute two-second Hello deadline in its
TLS admission hook. The stream wait and host decoder use that same deadline,
including time spent waiting in the accept queue. TLS itself has its separate
five-second bound. Every host control write runs against the remaining
fifteen-second Pong window, so blocked roster and Ping writes cannot suspend
idle expiry. Status messages and roster changes never renew that window.

The lifecycle tests observe `End`, retain the public `Leave` future at that
boundary, and submit a late bearer join or an already-admitted delayed Hello.
This prevents endpoint closure from masking post-clear approvals or post-drain
frames. The door and liveness fixtures advertise zero QUIC receive credit and
keep the transport alive, rather than approximating backpressure by merely
avoiding application reads. Dedicated mutants remove each boundary.

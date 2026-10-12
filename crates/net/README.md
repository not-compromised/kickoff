# kickoff-net

Peer transport over iroh 1.3.0 (design §2.3, §3.4). It hides iroh, the relay map,
fragmentation, path status, candidate scoping and the egress policy.

| Module | Owns |
|---|---|
| `door` | the persistent-identity, relay-only endpoint on `kickoff/join/1`; pre-handshake cap (16 pending, `retry` for unvalidated addresses), invalid-request limits (10/min per id, 60/min overall, priority ids exempt from the global limit), two join queues |
| `session` | the fresh-key endpoint bound to one IPv4 interface address; the `after_handshake` admission hook reading the `ArcSwap` admitted set; one live connection per session key; guests refuse every `Incoming` |
| `link` | LAN datagrams (budget charged before decode and reassembly), the cancel-safe control stream, blob streams, path status, health counters |
| `reassembly` | fixed tables: 8 assemblies per link, 32 per endpoint, 4 fragments, 50 ms, expired on a timer |
| `egress` | `scope` (the only place peer data becomes a destination, SI-29) and `publishable` (the only filter on our own addresses, SI-31); an `EndpointHooks::before_connect` guard re-checks every dial |
| `budget` | token buckets and fixed windows |

Datagram and message codecs come from `kickoff-wire`.

## Tests

In-process, two endpoints on loopback with relays disabled (the design's test
seam); hostile peers are bare iroh endpoints. Nothing leaves the host.

| Test | Proves |
|---|---|
| `si_18_unknown_session_key_rejected_on_session_alpn` | unadmitted keys and the wrong ALPN never get a session connection |
| `si_18_one_live_connection_per_session_key` | twenty redials leave one live link |
| `si_18_republished_generation_closes_the_old_link` | a bumped generation closes the link and nothing more is delivered |
| `si_19_removed_key_cannot_reconnect` | a key removed from the admitted set cannot dial back in |
| `si_21_guest_session_endpoint_accepts_nothing` | guest endpoints refuse every connection, including another guest's |
| `si_23_reassembly_memory_cap_holds_under_a_hostile_fragment_flood` | 300k random fragments across 12 links never exceed 8 per link, 32 overall, or the byte ceiling |
| `si_23_fragment_flood_does_not_starve_a_legitimate_peer` | a guest flooding incomplete fragments over a real link leaves another guest's fragmented datagrams delivered |
| `si_23_datagram_budget_drops_then_disconnects_a_flooding_peer` | 3000/s burst 1000 is enforced; above 10x for 5 s disconnects |
| `si_23_control_length_refused_before_allocation` | a `u32::MAX` length prefix is refused without allocating |
| `si_23_control_messages_are_rate_limited` | 32 messages/s after the burst |
| `si_23_invalid_join_requests_exhaust_only_their_own_identity` | the 11th invalid request is turned away unread; another identity is still served |
| `si_29_egress_keeps_only_compiled_relays_and_scoped_ips`, `si_29_ticket_destinations_outside_the_policy_are_never_dialed` | foreign relays, loopback, CGNAT, the virtual subnet, IPv6 and port 0 are never dialed |
| `si_31_published_addresses_never_contain_stripped_ranges` | 200k addresses through `publishable` |
| `si_31_peers_learn_only_the_bound_address` | what an unadmitted and an admitted peer learn through iroh's own candidate exchange; bound to 0.0.0.0 the same test sees a Tailscale address on the reference machine |
| `unknown_control_variant_closes_the_link_with_version` | a message from a newer protocol closes the link with `VERSION` (§4.5) |
| `fragmentation_round_trip_at_the_size_boundary` | payloads at, below and above the one-datagram and four-fragment limits |
| `datagram_latency_p50_p99_over_10k` | §7 measurement, printed with `--nocapture` |

Each `si_*` test, and the `VERSION` test, was run against a build with its
mitigation removed and failed.

Latency, one-way `send_lan` to `recv_lan`, release build on the reference Linux machine, loopback:
128-byte datagrams p50 15 µs, p99 60-63 µs over 10,000; 4212-byte datagrams
(3 fragments) p50 23 µs, p99 79-89 µs over 2,000.

## NOTES

Deviations from design draft 2 and open questions.

1. **Interface additions.** `SessionNet::set_admitted(AdmittedSet)` is the
   atomically swapped set the admission owner publishes (key → identity, slot,
   generation); replacing it closes connections whose entry left or changed.
   Also `SessionNet::id` (the guest's `JoinRequest::session_key`),
   `Door::{id, addr, set_priority, close}`, `Link::{accept_blob, health,
   max_datagram_size, closed, close}`, `door_loopback` and
   `IfaceAddr::loopback` (the in-process adapter), and `NetError::{Protocol,
   NoRoute, WrongRole, Bind, Version}`.
2. **`IfaceAddr::default_route` is async** (netwatch's lookup is async) and
   IPv4 only: an IPv6 socket would enumerate every v6 interface address.
3. **The host's `accept` returns once the guest sends its first control
   message** (within the 5 s handshake deadline). QUIC announces a stream only
   with its first bytes, so the guest's session must send `Hello` right after
   `dial`.
4. **Reconnect.** A second connection from a session key is refused while the
   first is open. The admission owner replaces a link by publishing a bumped
   generation, which closes the old connection; otherwise the redial succeeds
   once the old connection times out. §4.4's "accepted only through the
   reconnect path" needs the session crate to decide when to bump.
5. **Control over budget is throttled, not disconnected.** Reads wait for
   tokens and QUIC flow control pushes back on the sender. Stream windows are
   512 KiB per stream and 2 MiB per connection.
6. **Global reassembly cap.** 32 overall is below 7 guests x 8, so four
   colluding guests can hold every global slot and drop other guests'
   fragmented datagrams. Discovery broadcasts (payload ≤ 1252) exceed the
   1156-byte single-datagram payload on a fresh relay path, so they fragment.
   Suggest 56 overall, or a per-link reservation.
7. **Datagram attempts** are counted when iroh hands them over; iroh's
   256 KiB receive buffer drops the oldest before that. The abuse rule uses
   fixed 5 s windows.
8. **Guest-side `Link::peer().id`** is the host's session key; the guest's
   session layer knows the host's door identity from the ticket.
9. **Not here:** recreating the session endpoint on a default-route change
   (the caller's job; SI-31's "after an interface change" case is untested);
   "Hide my IP" relay-only sessions; the host fan-out budget (the pump's); relay
   vouchers (M12); a pre-handshake flood test for the 16-pending cap, which is
   implemented but only exercised indirectly.
10. **Branch base.** `m2/net` merges `m2/wire` (last at `0d43905`) so it can use
    wire's datagram and message codecs instead of duplicating them.
11. **`dial` and `accept` return `(Link, CtlStream)`** instead of a `Link`
    with `ctl(&mut self)`. Datagrams (`&Link`, shared by the pump) and control
    (`&mut CtlStream`, one owner) run on separate tasks (§2.5); with the
    stream inside the link, one task could not wait on both without a borrow
    conflict.

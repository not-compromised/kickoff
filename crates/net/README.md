# kickoff-net

Peer transport over iroh 1.3.0 (design §2.3, §3.4). It hides iroh, the relay map,
fragmentation, path status, candidate scoping, the egress policy and the send
guard. iroh comes from `vendor/iroh-1.3.0` (upstream plus one patch, the
send-guard hook; `scripts/check-vendor.sh` holds it to exactly that).

| Module | Owns |
|---|---|
| `door` | the persistent-identity, relay-only endpoint on `kickoff/join/1`; at most 16 connections awaiting a `JoinRequest` and 2 per identity, 5 s to send it; invalid-request limits (10/min per id, 60/min overall, priority ids exempt from the global limit), two join queues |
| `session` | the fresh-key endpoint, `SessionBind::Direct` (one IPv4 interface address) or `SessionBind::RelayOnly` (no IP transport, no QAD, no UDP socket); the `after_handshake` admission hook reading the `ArcSwap` admitted set; one live connection per session key; guests refuse every `Incoming` |
| `incoming` | the pre-handshake gate both endpoints share: 16 pending `Incoming`s, `retry` for unvalidated addresses, 8 handshakes/s per source and 64/s overall, `refuse` beyond |
| `guarded` | the only way an endpoint gets an IP transport: registers the send guard for the exact bind address before iroh binds, then keeps the guard's view and validated paths current |
| `link` | LAN datagrams (budget charged before decode and reassembly), the cancel-safe control stream, blob streams, path status, health counters |
| `reassembly` | fixed tables: 8 assemblies per link, 32 per endpoint, 4 fragments, 50 ms, expired on a timer |
| `egress` | `scope` (the only place peer data becomes a destination, SI-29) and `publishable` (the only filter on our own addresses, SI-31); an `EndpointHooks::before_connect` guard re-checks every dial; `SendGuard`, the policy behind the vendored hook: global or bound-subnet IPv4 only, never our own addresses, gateway, resolvers or the §3.4 ranges, port ≥ 1024 and off the §3.1 denylist, at most 8 unvalidated destinations and 4 new per second, recomputed on route changes |
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
| `si_29_send_guard_refuses_own_gateway_and_resolver_addresses`, `..._low_and_denylisted_ports`, `..._forbidden_ranges`, `..._caps_unvalidated_destinations`, `..._recomputes_on_interface_change` | the guard's rules one at a time, on a synthetic view of the host (NAT-traversal candidates on our own address, the gateway, the resolver, low ports, more than 8 destinations, an interface change) |
| `si_29_send_guard_drops_what_iroh_sends_to_a_refused_destination` | through the vendored hook: a guest whose view names the host's address as its resolver never reaches it, and the guard counts the drops |
| `si_31_published_addresses_never_contain_stripped_ranges` | 200k addresses through `publishable` |
| `si_31_leaked_endpoint_shows_only_the_bound_address` | an admitted peer and an outsider it leaked the endpoint to (rejected after TLS) record only the bound address, before and after the endpoint moves to a new address; a relay-only endpoint shows none |
| `si_31_relay_only_endpoint_owns_no_socket_and_publishes_no_address` | `RelayOnly` binds no UDP socket, publishes no IP and dials no IP |
| `si_23_handshakes_are_rate_limited_per_source_and_overall`, `si_23_leaked_endpoint_flood_with_fresh_identities` | 8/s per source and 64/s overall before TLS; 40 fresh identities from one source get at most 10 handshakes and the established link keeps delivering |
| `si_23_door_holds_two_silent_connections_per_identity`, `si_23_door_caps_connections_awaiting_a_join_request`, `si_23_door_closes_silent_connections_at_the_join_deadline` | handshakes that never send `JoinRequest`: 2 per identity, 16 overall, closed at 5 s |
| `unknown_control_variant_closes_the_link_with_version` | a message from a newer protocol closes the link with `VERSION` (§4.5) |
| `fragmentation_round_trip_at_the_size_boundary` | payloads at, below and above the one-datagram and four-fragment limits |
| `datagram_latency_p50_p99_over_10k` | §7 measurement, printed with `--nocapture` |

Each `si_*` test, and the `VERSION` test, was run against a build with its
mitigation removed and failed; `/mutants.toml` now automates that for the
`si_*` tests. SI-18's admission is layered (handshake hook, re-check after the
handshake, `Link::accept`, every datagram, `set_admitted`'s close), so each
layer has a mutant and a test that drives it alone: the four in
`session::tests` and `si_18_republished_generation_closes_an_idle_link`.
Likewise `si_29_connect_guard_refuses_what_scope_would_drop` for the
`before_connect` guard under `scope`, `si_21_guest_refuses_even_a_key_it_was_told_to_admit`
for the guest's own refusal, and `si_23_silent_connection_closed_at_the_handshake_deadline`.
The latency test asserts §7 in release builds, and so does
`send_guard_on_an_approved_destination_within_budget` (≤ 50 ns per send
through the hook's entry point; 24 ns measured).

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
   (the caller's job; the SI-31 test recreates it on a second loopback
   address to stand in for one); the host fan-out budget (the pump's); relay
   vouchers (M12); a pre-handshake flood test for the 16-pending cap, which is
   implemented but only exercised indirectly; the packet-capture half of SI-29
   (M3).
10. **Branch base.** `m2/net` merges `m2/wire` (last at `0d43905`) so it can use
    wire's datagram and message codecs instead of duplicating them.
11. **`dial` and `accept` return `(Link, CtlStream)`** instead of a `Link`
    with `ctl(&mut self)`. Datagrams (`&Link`, shared by the pump) and control
    (`&mut CtlStream`, one owner) run on separate tasks (§2.5); with the
    stream inside the link, one task could not wait on both without a borrow
    conflict.
12. **`session(relays, bind: impl Into<SessionBind>, role)`.** Draft 3 says
    `bind: SessionBind`. `IfaceAddr` converts into `SessionBind::Direct`, so
    callers that pass an `IfaceAddr` (the session crate's tests) compile
    unchanged; tighten to `SessionBind` once they move. `RelayOnly` with an
    empty relay map is refused with `Bind` (iroh cannot bind an endpoint with
    no transport). `SessionNet::egress_denied` exposes the send guard's drop
    count for health reporting.
13. **The hook's shape.** iroh cannot depend on `kickoff-net`, so the patch
    calls `kickoff_send_guard::admit(bind, dst)`, a dependency-free registry
    (`crates/send-guard`) keyed by the socket address the IP transport is
    configured with. `guarded::bind` therefore chooses the port itself
    (binding port 0 would give every endpoint the same key) and registers
    before iroh binds; the registration lives in the endpoint's hooks, so it
    lasts exactly as long as iroh keeps the endpoint. An address nobody
    registered (a test's bare iroh endpoint) is not guarded. The patch is two
    hunks: the call in `poll_send` and the dependency line in iroh's
    `Cargo.toml`.
14. **Per endpoint, not per remote.** Draft 3 caps unvalidated destinations
    per remote and caches approvals per connection. The IP send path sees only
    a socket address (iroh has already mapped the path), so the 8 and 4/s caps
    and the approval cache are per endpoint. On a guest that is the same thing;
    on a host, peers share the budget, and one peer's NAT-traversal candidates
    can delay another's path upgrade (both stay on the relay meanwhile).
    Validated destinations (open IP paths of live connections, re-read every
    second) and sources the endpoint is answering (`retry`, refusal,
    handshake, 64 at most for 10 s) do not spend the budget; unvalidated ones
    expire after 10 s. Anything QUIC sends to a source it never handed Kickoff
    as an `Incoming` (stateless resets, if noq sends them to spoofed sources)
    and the QAD connection to a relay's IP address do spend it.
15. **The guard's view of the host** comes from netwatch (every interface
    address, the default gateway), `/etc/resolv.conf` and
    `/run/systemd/resolve/resolv.conf` (resolvers), and the public address QAD
    reports. A netwatch route monitor triggers the recompute; without one it
    polls every 5 s. Windows resolvers are not read yet (W milestones). A
    loopback bind (the in-process adapter) reaches loopback only and does not
    enumerate its own addresses.
16. **The §3.1 port denylist is duplicated** in `egress` from
    `kickoff-vlan`'s private `ports::DENYLIST`. One owner (exported from
    `vlan` or `wire`) would keep them equal.
17. **cargo deny and the vendored iroh.** A patched crate is a path
    dependency, so the advisory database no longer matches iroh 1.3.0 by
    source; advisories for iroh itself have to be watched by hand until the
    vendor check also checks them.
18. **Rate limits on loopback tests.** All in-process tests share 127.0.0.1,
    so the 8 handshakes/s per source applies to them. Door clients map a
    pre-handshake refusal and a `BUSY` close to `Refused(Busy)`, which the
    session crate's concurrent-join tests already expect.
19. **`mutant-si31-unbound` no longer needs a CGNAT interface.** The
    leaked-endpoint test binds loopback, so an unbound endpoint differs on any
    machine with a non-loopback IPv4 interface (development.md harness note 4
    predates this).

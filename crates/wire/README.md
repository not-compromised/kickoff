# kickoff-wire

Kickoff's peer-facing formats (design §4.2, §4.5): the LAN datagram header and
fragments, join and control messages, tickets, and the host's ledger of the
capabilities it issued. Pure: no files, no network. The only call out of the
process is `getrandom`, for fresh session ids and nonces.

Every decoder reads hostile bytes. Sizes are bounded by type and checked before
allocation; decoding is strict, so a decoded value re-encodes to exactly the
bytes it came from. No error carries input bytes (SI-30).

## Interface

| Area | Items |
|---|---|
| LAN datagrams | `LanHeader`, `FragmentHeader`, `decode_datagram(link_slot, bytes) -> Inbound`, `encode_datagram(d, frag_id, max) -> Vec<Bytes>` |
| Messages | `JoinRequest`, `JoinReply`, `GuestMsg`, `HostMsg`; nonsecret `encode`/`encode_framed`, `decode`, `frame_len`, opaque `prepare_message` |
| Tickets | `Ticket`, `Cap`, `parse_ticket -> Secret<Ticket>`, `encode_ticket -> Secret<TicketTextValue>` |
| Invites | `Invites::new`, `issue(key, invitee, now) -> Cap`, `redeem(cap, requester, now) -> Redeemed` |

## Codec and port ownership

Peer datagram and message framing lives in [`lan`](src/lan.rs) and
[`msg`](src/msg.rs). Net consumes these exported codecs. Ethernet L2 framing
lives in [`kickoff-vlan::codec`](../vlan/src/codec.rs).

[`ports`](src/ports.rs) owns the compiled denied-port policy exported as
`DENIED_PORTS` and `denied_port`. Both the VLAN filter and net egress use it.

## Invariants held here

| SI | Test |
|---|---|
| SI-3 | `schema_tests::si_3_peer_messages_cannot_express_eac_paths_or_launch_options` |
| SI-20 | `tests/tickets.rs`: `si_20_capability_admits_at_most_once`, `si_20_replayed_capability_refused`, `si_20_ticket_from_another_session_or_host_process_refused`, `si_20_bearer_validity_uses_host_monotonic_clock` |
| SI-23 (wire part) | `bounded::tests::si_23_bounded_vec_refuses_a_declared_length_before_reserving_for_it`, `tests/messages.rs`: `si_23_*` |
| SI-29 (tickets) | `tests/tickets.rs`: `si_29_ticket_cannot_carry_direct_address` |
| SI-30 | `tests/tickets.rs`: `si_30_caps_tickets_and_join_requests_cannot_be_printed_cloned_or_serialized`, `si_30_ticket_errors_carry_no_input` |

## Fuzzing

`fuzz/` holds cargo-fuzz targets `lan`, `control` and `ticket`
(`cargo +nightly fuzz run lan` from this directory). Each calls the harness in
`tests/harness/`, which the stable proptest suites also run, so CI checks the
same properties the fuzzer does.

## NOTES

- **L2 frame codec.** The draft-2 layout descriptions differed. Current
  ownership is recorded in [codec and port ownership](#codec-and-port-ownership).
- **Nonce states.** §4.4 describes `Unused → Pending(conn) → Consumed | Revoked`.
  `Invites::redeem` goes straight from unused to spent, so a declined or
  cancelled prompt cannot leave a capability usable. The caller must check
  version and roster space before redeeming, or a bound invite is spent on a
  refusal.
- **SI-19 and outstanding tickets.** The ledger does not know about kicks.
  `session` must check its revoked set before calling `redeem`.
- **SI-3 and relay URLs.** SI-3's schema test names URLs as forbidden, but
  `Admitted.session_addr` and the ticket's door need relay URLs. The test
  allowlists those two fields (plain `https://` only); `net::egress` decides
  whether one is used (SI-29).
- **The door's relays are not signed.** The capability signature covers the
  session id, invitee, nonce and door identity. §4.2 relies on TLS pinning the
  door, so an edited relay can only break the dial.
- **Capability ownership.** `Invites::issue` and decoded `JoinRequest` values
  carry an opaque `Cap` whose private fields live in `Secret<CapValue>`.
  It implements no `Debug`, `Clone` or `Serialize`. The enclosing ticket is
  a `Secret<Ticket>`; wire alone can expose its stored fields.
- **`Version`.** An unknown top-level variant, or a ticket version above 1,
  returns `WireError::Version` so the caller can close with `VERSION` (§4.5).
  An unknown nested variant, such as a new `GameState`, is `Malformed`.
- **`WireError::NotImplemented`** is unused by wire decoders;
  [net stream error mapping](../net/src/stream.rs) still translates it to
  `NetError::NotImplemented`.
- **Net codec integration.** See [codec and port ownership](#codec-and-port-ownership).
  The earlier separate net frame codec has been retired.
- **Fuzz crate outside the workspace.** libFuzzer needs nightly and sanitizer
  flags, so `fuzz/` has its own `[workspace]` and a pinned lockfile seeded from
  the workspace's. `scripts/check.sh` does not build it. Adding
  `cargo check --manifest-path crates/wire/fuzz/Cargo.toml --locked` there would
  keep it from rotting.

## Secret transmission

Wire's private consumer owns ticket fields and serialization. `encode_ticket`
returns opaque protected text. `TicketTextValue::postcard_frame` and
`prepare_message` return `Transmission`, whose body is `Secret<FrameBody>`.
It has no readable body, serializer, formatting, cloning or arbitrary writer
interface. Wire's owner closure supplies each write's borrowed bytes.
`encode` and `encode_framed` accept only the sealed `PublicWireMessage` set,
which excludes `JoinRequest`.

Local ticket transmission requires an authenticated
[`InstalledPeer`](../local/README.md), not caller-configured trust or a raw
socket. Join transmission checks the connection's identity against the
capability's immutable issuing door before opening its own stream. Signing
and signature-verified ticket parsing assign that authority; protected copies
preserve it. Ticket encoding requires that existing issuing authority too. A
decoded incoming Join cannot regain export authority by being wrapped in a
Ticket and reparsed. Raw fixture construction can provide an explicit issuer
only alongside the raw
capability inputs already known to its caller.

Owned ticket, base32, canonical and frame allocations wipe on success, error
and cancellation. The frame regression observes live bytes after their wipe
and before release. Compiler stack copies and dependency transport buffers
remain outside this owned-allocation proof.

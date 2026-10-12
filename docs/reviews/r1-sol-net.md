Redacted for publication: machine names, paths and addresses replaced with generic terms.

1. **NET-1 — high — Port numbers do not isolate Rocket League from other services**

   **Attack:** A compromised peer sends UDP to an allowed game/discovery port occupied by another application. Alternatively, Rocket League opens a flow from an ephemeral port, closes that socket, and another service reuses the port within the 30-second flow lifetime. The peer sends the permitted reverse tuple and reaches the replacement service. On Linux, this includes services bound specifically to `127.0.0.1`, if that is the proxy’s delivery address.

   **Design gap:** §3.1 admits traffic when “`dst_port` is in `GamePorts`, or if it matches a flow the local game opened.” Neither rule authenticates the receiving process or tracks socket lifetime. §6 T1 claims the “Linux proxy touches loopback game ports only.” That establishes a port restriction, not a process restriction. `/proc/net/udp` alone does not identify Rocket League ownership. A configurable allowlist also permits non-denylisted service ports. The denylist omits 9014–9088, despite §3.1 identifying those as online server ports.

   A local probe confirmed UDP delivery from `127.0.0.5` to a socket bound specifically to `127.0.0.1`. This does **not** establish unrestricted access to every loopback port; the bypass depends on an allowed port, stale flow, or unsafe configuration.

   **Mitigation:** Bind authorization to the exact game process, socket, local address, peer identity and session generation. Remove flows immediately when their socket closes or ownership changes. Reject conflicting listeners and arbitrary port overrides. If the shared host namespace cannot enforce the promised boundary, use game network isolation or narrow the security claim.

   **Test:** Use fake game and service processes. Open a permitted flow, close the game socket, rebind its port as a service, and assert that subsequent peer packets are dropped. Repeat with listeners on `127.0.0.1`, other `127.0.0.x` addresses, wildcard addresses, and permitted-port collisions.

2. **NET-2 — high — LoopProxy authenticates local socket traffic as peer traffic without proving its origin**

   **Attack:** Another local user binds an unused peer alias and port, sends forged replies to the game, or sends discovery broadcasts that Kickoff forwards under the local endpoint’s authenticated identity. If proxy sockets use reuse options, a later local binder may capture replies. Even without reuse, an attacker can prebind eagerly or lazily allocated proxy tuples and deny service.

   **Design gap:** §3.2 says the broadcast socket “receives only the game’s looped-back limited broadcast” and holds “one socket per `(peer, port)`.” UDP sockets do not establish sender process identity. Binding after observing the game does not authenticate subsequent packets. The design specifies no source-address, ingress-interface, process-ownership or socket-collision policy.

   Local experiments confirmed that two `SO_REUSEADDR` limited-broadcast listeners both receive a broadcast. A second same-tuple reusable unicast listener received traffic instead of the first. The unicast result applies if the implementation enables reuse on those sockets.

   **Mitigation:** Specify socket options, exclusive binding, collision refusal, fixed delivery destinations, ingress-interface checks and game-socket ownership requirements. Fail closed on ownership uncertainty. Treat local processes as able to forge shared-namespace UDP unless an isolation mechanism prevents it.

   **Test:** Run a second UID that prebinds peer aliases, broadcasts fake discovery, and attempts duplicate binds. Assert no forged traffic is forwarded, no replies are exposed, and collisions produce a safe session refusal.

3. **NET-3 — high — Every interactive Windows user can operate the privileged LAN adapter**

   **Attack:** A different logged-in Windows user connects to the service first, issues `LanOpen`, receives captured game traffic, injects allowed `LanDatagram`s, or holds the single-client pipe to deny service to the owner.

   **Design gap:** §3.3 says the pipe ACL admits “SYSTEM and INTERACTIVE” and “serves one client at a time.” `INTERACTIVE` does not identify the intended user or daemon. The independent game gate protects slot writes, but no corresponding authorization protects LAN commands.

   **Mitigation:** Bind each LAN lease to an authenticated user SID, logon session and pipe connection. Verify client identity using pipe impersonation. Reject competing users and ensure disconnect revokes the lease. Define how the service distinguishes the authorized daemon from another process running under that user.

   **Test:** From two non-admin interactive accounts, attempt concurrent `LanOpen`, capture and injection. Only the lease owner should succeed; disconnect and session changes must invalidate the lease.

4. **NET-4 — high — Host fan-out loses the original sender’s identity**

   **Attack:** A guest sends a discovery broadcast with a chosen source port and payload. If the host fans it out, another guest receives it over its authenticated **host** link and assigns the host’s source slot. The guest-originated packet now appears to come from the host. A malicious roster member may also attempt direct guest-to-guest connections if the same roster-wide hook runs on guests.

   **Design gap:** §2.4 says the host “fans out to every link when `bcast` is set.” §4.3 says “Source and destination slots come from the link” and are absent from the wire. Those rules cannot preserve guest provenance through the host. The session ALPN admits “EndpointIds in the current roster,” without a role-specific restriction enforcing the star topology.

   **Mitigation:** Define directional discovery rules. Prefer guest queries delivered only to the host and host advertisements delivered to guests. If guest-originated forwarding is necessary, carry host-validated origin metadata and prohibit guests from asserting it. Guest endpoints must accept session traffic only from their designated host.

   **Test:** In a three-node test, have guest A send a beacon resembling a host response and dial guest B directly. B must neither receive A’s packet as host-originated nor accept the direct connection.

5. **NET-5 — high — A kick does not revoke all routes back into the session**

   **Attack:** A kicked trusted friend immediately rejoins using the persistent allowlist. A kicked peer reuses an outstanding bound invitation or races a reconnect handshake with the kick. Multiple existing connections or queued packets may survive if only “the link” is closed.

   **Design gap:** §4.4 says a kick “removes the id, bumps the epoch, closes the link and refreshes the hook’s admitted set.” §4.2 permits trusted friends to join “without a new ticket.” No session-scoped revoked-ID set overrides trust and invitations. There is no atomic ordering between revocation, handshake completion, reconnect callbacks and delivery. LAN headers carry no generation or epoch.

   **Mitigation:** Maintain a session-scoped revocation set checked by every admission path. Atomically revoke all connections, reconnect eligibility, pending admissions, flows, proxy sockets and reassemblies. Require a current connection generation at delivery. Re-admission after a kick must require an explicit host action.

   **Test:** Use deterministic barriers to race kick against handshake, reconnect and queued delivery. Try trusted rejoin and every previously issued ticket. Assert zero post-kick delivery and no automatic re-admission.

6. **NET-6 — high — The roster cap does not cap connections per identity**

   **Attack:** One admitted peer opens many simultaneous session connections. Each can obtain tasks, datagram buffers, control streams and map streams. It can also churn connections during the reconnect window. Eight roster entries do not bound these resources.

   **Design gap:** §2.5 creates tasks “Per link”; §3.4 configures 1 MiB datagram buffers; §6 T3 relies on an “8-member roster” and per-connection stream limits. No maximum of one active connection per peer or aggregate per-identity budget is specified.

   **Mitigation:** Allow one active connection generation per peer and session. Define atomic replacement during reconnect. Bound pending connections globally and charge every connection’s traffic and resources to its authenticated identity.

   **Test:** Have one admitted endpoint open hundreds of connections and reconnect repeatedly. Assert bounded tasks, memory, streams and connections, with the other peers remaining within latency budget.

7. **NET-7 — high — Application admission limits do not bound handshake work**

   **Attack:** An outsider repeatedly initiates QUIC/TLS handshakes, including on the session ALPN with fresh identities. The host consumes transport state and cryptographic CPU before the roster hook rejects them. Connections that never send `JoinRequest` may avoid the advertised join-attempt counter.

   **Design gap:** §4.3 rejects unauthorized session peers in `after_handshake`. The 10-attempt limit and five-second request deadline do not specify limits on incomplete handshakes or pending transport connections.

   Iroh 1.3 registers a completed connection before invoking this hook. The hook is an application authorization gate, not a pre-handshake resource gate.

   **Mitigation:** Specify global pending-handshake and accepted-connection limits, transport timeouts, address-validation/retry policy, bounded accept concurrency and fair admission queues. Count attempts before waiting for application data. Preserve capacity for existing admitted peers.

   **Test:** Flood incomplete handshakes and completed handshakes without requests while a legitimate session runs. Assert bounded CPU and memory and continued legitimate admission and traffic.

8. **NET-8 — high — Resource limits are placed after fragmentation and socket allocation**

   **Attack:** A peer sends fragments with changing IDs, duplicate indices, inconsistent headers or counts, and then valid packets using many source ports. Reassembly consumes work before `vlan.deliver` applies its limits. Lazy `(peer, port)` sockets can accumulate independently of the 256-flow cap.

   **Design gap:** §3.4 specifies “at most 4 fragments” and a 50 ms deadline, but no receiver allocation cap, total-message cap or duplicate policy. §3.2 says sockets “open on first use,” without a socket budget or reclamation rule. §3.1’s limits live in `vlan`, after `net.recv_lan` reassembly.

   **Mitigation:** Apply byte and packet budgets to raw received datagrams before allocation. Bound reassemblies globally and per identity, validate count/index/reserved fields before allocation, reject conflicting fragments, and key state by connection generation. Specify a hard socket cap and reclamation policy.

   **Test:** Fuzz malformed fragments and send incomplete assemblies across every fragment ID. Sweep all source ports. Assert fixed memory/FD ceilings, bounded cleanup time, and no delivery from mixed or conflicting assemblies.

9. **NET-9 — high — A token embedded in open clients cannot restrict the relay to Kickoff builds**

   **Attack:** An attacker extracts the shared token from source or a distributed binary, uses an ordinary relay client, generates many identities and connections, and exhausts the shared server's bandwidth or connection resources.

   **Design gap:** §3.4 proposes “`access.shared_token` so only Kickoff builds use it.” A bearer token proves possession, not software provenance. `[limits.client.rx]` limits one connection’s read bandwidth, so multiple connections multiply the allowance.

   The pinned relay source explicitly states that connection-accept limit settings are unimplemented. [The same limitation is documented publicly](https://docs.rs/iroh-relay/1.3.0/iroh_relay/server/struct.Limits.html), although that documentation URL was unavailable through the browsing tool; the local crate source was inspected directly.

   **Mitigation:** Replace the build-authentication claim with enrolled EndpointIds or separately issued, revocable credentials. Enforce aggregate identity, connection and server budgets outside the ineffective accept-limit settings. Isolate the public relay from the shared server’s other services.

   **Test:** Using an extracted credential, open many connections and identities. Assert aggregate bandwidth and connection ceilings and confirm credential revocation blocks new access.

10. **NET-10 — medium — Tailscale and private addresses can leak before application authorization**

    **Attack:** An outsider reaches the endpoint through a known relay and completes TLS on the public join ALPN, or a session ALPN that will be rejected. It observes QNT address announcements containing local and overlay addresses. Filtering the invitation does not prevent this disclosure.

    **Design gap:** §3.4 strips addresses only in `Net::addr()` and leaves QNT filtering unverified. Its fallback says “peers learn your LAN and public addresses,” but disclosure can occur before admission.

    Iroh 1.3’s `connection.rs` registers the connection before calling `after_handshake`; `remote_state.rs` adds local candidates during registration. Its candidate set comes directly from `local_direct_addrs`. The builder’s address-publication filter is for address-lookup services, not this QNT path.

    **Mitigation:** Treat candidate filtering as a release blocker. Filter at the actual transport candidate source, including interface changes and IPv6 overlays. Use relay-only admission if candidate disclosure must wait for authorization. State precisely which addresses outsiders, admitted peers and relays learn.

    **Test:** Use an unauthorized endpoint to inspect QNT candidates on join and rejected session connections. Include Tailscale, configurable Kickoff subnets, private IPv4 and IPv6 candidates. Repeat after interface changes.

11. **NET-11 — medium — Windows firewall changes broaden physical-network exposure**

    **Attack:** A local-network attacker reaches an existing Rocket League listener after Kickoff removes its broad block rule. Traffic arrives through a physical adapter and never passes the virtual-LAN filter. Existing broad UDP allow rules can also admit unrelated services on the tap.

    **Design gap:** §3.3 offers to remove existing Rocket League block rules and adds an allow rule without port restrictions. It blocks TCP on the tap but does not specify an enforceable UDP default-deny policy independent of existing rules.

    Consent to removing a rule does not establish the resulting policy as safe. Microsoft confirms that explicit allows override default blocking and explicit blocks override allows. [Windows firewall precedence](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules).

    **Mitigation:** Preserve existing physical-adapter protection. Show the exact policy expansion before changing any rule, and prefer a scoped replacement. Define enforcement for UDP on the tap and forwarding/ICS independent of existing application exceptions. Bind rules to the recorded adapter identity.

    **Test:** Install broad UDP allows, broad Rocket League blocks and ICS before setup. Verify only intended game traffic enters through the tap and physical-adapter exposure does not increase.

12. **NET-12 — medium — Tap setup has no fail-closed activation or crash recovery contract**

    **Failure:** Setup brings the adapter or media up before every filter and routing rule is installed. A setup failure leaves partial policy, or a service crash leaves addresses, routes or rules active. Linux permits an existing application to use the persistent tap; Windows broadcasts may be redirected by metric 1 until media is reset.

    **Design gap:** §3.2 describes individual NM, policy-routing, ufw and nft operations without an activation transaction. §3.3 says `store=active` means “a crash leaves nothing”; active configuration alone does not establish process-crash cleanup. “On exit” cleanup does not cover forced termination.

    **Mitigation:** Install and verify restrictive policy before enabling traffic. Refuse sessions when ownership, routing or firewall invariants fail. Define recovery for every partially completed setup step and forced termination. Use only manual addressing, no DHCP, gateways or DNS. Ensure privileged-service failure forces media down.

    **Test:** Fault-inject after every setup operation and terminate the daemon/service forcibly. Assert no forwarding or unintended reachability, media-down behavior, and idempotent recovery.

13. **NET-13 — medium — Invitation consumption and lifetime rules are incomplete**

    **Attack:** Two connections submit the same bearer capability concurrently while the host prompt is pending. Separate tasks both observe an unused nonce and admit. A bound ticket remains reusable after reconnect eligibility expires, or a clock rollback extends its validity.

    **Design gap:** §4.2 specifies “single-use nonce and at most 15 minutes” only for bearer invitations. It does not define atomic nonce reservation, cancellation, replay-cache lifetime, bound-ticket lifetime or clock behavior. §6 T4’s replay test does not establish concurrent consumption safety.

    **Mitigation:** Give every capability a bounded lifetime and explicit use policy. Atomically transition nonces through pending, consumed and revoked states. Bind approval to the exact authenticated EndpointId and request. Use monotonic deadlines after issuance and reject capabilities from inactive sessions.

    **Test:** Submit one capability concurrently over many connections, cancel prompts, restart the host and move its wall clock backwards. At most one endpoint may be admitted.

14. **NET-14 — medium — Invite credentials are absent from the redaction contract**

    **Attack:** A bearer ticket leaks through deep-link argv, process inspection, launcher diagnostics, clipboard history, a QR screenshot or an exported error log. An attacker races the recipient and requests admission using their display name.

    **Design gap:** §4.2 delivers deep links as argv. §1 claims diagnostics “never leak credentials,” but the listed redaction covers game credentials, JWTs and display names, not Kickoff tickets, capability encodings or relay tokens. A host prompt based on a caller-chosen name does not establish recipient identity.

    **Mitigation:** Redact complete tickets, deep-link URLs and relay credentials across all exports. Avoid retaining raw argv or invite strings. Default to bound invitations where practical. Make bearer approval show a verified identity/fingerprint and explain that the link is transferable.

    **Test:** Feed tickets and relay tokens through argv errors, URL-parser errors, IPC errors and diagnostic exports. Assert no recoverable secret remains. Race a leaked bearer invite using the intended recipient’s name.

15. **NET-15 — medium — Untrusted invitation addresses trigger network access before host authentication**

    **Attack:** An attacker supplies a syntactically valid ticket containing a localhost/private relay URL or arbitrary direct addresses. After confirmation, iroh contacts those addresses before capability verification by the intended host. A valid capability’s address fields can also be altered because the signature covers `Cap`, not the enclosing `EndpointAddr`.

    **Design gap:** §4.2 says parsing is strict and the UI confirms dialing. Neither limits destinations. §3.4 uses the full ticket address. Iroh’s relay actor can start a connection to a supplied relay URL outside the configured relay map.

    **Mitigation:** Define permitted relay origins and URL schemes. Reject credentials, unexpected ports and unapproved private/loopback destinations; revalidate resolved addresses. Explain direct-address exposure before dialing. Do not attach custom-relay credentials to arbitrary destinations. Iroh’s current token lookup is URL-scoped, which should remain an invariant.

    **Test:** Supply malicious tickets with localhost, private hosts, redirects and DNS changes. Assert no forbidden outbound connection occurs before rejection and no token reaches an unapproved relay.

16. **NET-16 — medium — Reliable control and map requests bypass LAN flood limits**

    **Attack:** An admitted peer streams repeated maximum-size `Status` messages, churns map requests and offsets, or repeatedly opens allowed streams after closing them. It consumes decoding, hashing, compression and blocking-worker capacity without exceeding LAN packet limits.

    **Design gap:** §3.1 limits datagrams. §4.3 caps individual control messages at 64 KiB. §6 limits concurrent streams, but not stream-open rate, total control throughput, map-request rate or compression jobs. §3.4 pauses maps based on an untrusted peer’s reported `Match` state, allowing a peer to stall transfers indefinitely.

    **Mitigation:** Add per-identity control-byte, message, stream-open and map-request budgets. Bound decompression/compression work globally. Coalesce status updates and cap collections. Define how false or stale match reports affect transfer scheduling.

    **Test:** Saturate control streams and churn map requests below concurrent-stream limits. Assert bounded worker queues and CPU, preserved game latency, and recovery from stale or dishonest status reports.

17. **NET-17 — medium — Broadcast and aggregate host budgets are unspecified**

    **Attack:** Several compromised peers each send within their individual limits. The host fans discovery packets out, and the local game may produce larger responses. All attackers remain below the disconnect threshold while the host’s total egress and game-socket workload become excessive.

    **Design gap:** §3.1 allows 3000 pps and 4 MB/s **per peer**, plus 10 discovery broadcasts/s. §2.4 fans broadcasts to every link. No host-wide budget, fan-out charge, maximum discovery payload or response budget is specified. The “above 10x” disconnect condition also does not say whether it measures attempted traffic or traffic surviving the limiter.

    **Mitigation:** Charge fan-out by total emitted bytes and packets. Add global budgets, per-peer fairness and role-specific discovery limits. Count attempted traffic before dropping it. Bound discovery payloads and prevent discovery from opening arbitrary flows.

    **Test:** Run seven peers at their permitted limits against a synthetic responder that expands replies. Assert bounded total egress, bounded game delivery and fair latency.

18. **NET-18 — medium — The global join quota lets one outsider block every legitimate invite**

    **Attack:** An outsider sends ten invalid join attempts every minute. All legitimate friends are denied admission for as long as the attacker continues.

    **Design gap:** §4.3 allows “at most 10 attempts per minute across all peers.” There is no reserved capacity for bound invitations or trusted identities, nor a distinction between failed attempts and authenticated valid requests.

    **Mitigation:** Separate global safety limits from identity/address abuse limits. Reserve bounded admission capacity for valid capabilities and explicitly approved identities. Ensure attackers cannot cause unbounded work by exploiting that reserved lane.

    **Test:** Exhaust the public join quota with invalid identities while submitting a valid bound invitation and a trusted-friend request. Both must retain bounded admission latency.

19. **NET-19 — medium — Relay authentication does not cover all exposed listeners or metadata**

    **Attack/failure:** Deploying the relay with the proposed abbreviated configuration leaves its metrics listener exposed. Anyone able to reach it observes operational metadata. A compromised relay operator also observes client source addresses, endpoint identities, connection timing and traffic relationships despite pkarr being disabled.

    **Design gap:** §3.4 specifies 443, UDP 7842 and a shared token but no complete listener inventory or metrics binding. In the inspected relay 1.3 source, metrics default to enabled and inherit the HTTP bind IP, normally wildcard, on port 9090. Its access configuration explicitly controls relaying, not every endpoint. §3.4’s claim that knowing an EndpointId reveals “neither online status nor relay region” is too strong: a known relay and endpoint permit connection probes, and successful or rejected TLS handshakes establish online presence.

    **Mitigation:** Publish a complete deployment configuration: explicitly bind or disable metrics, constrain backend HTTP, expose only intended ports, and define relay logging/retention. Describe no-pkarr as preventing directory publication, not preventing presence detection or relay metadata collection.

    **Test:** Enumerate relay listeners in a deployment fixture. Unauthorized clients must not access metrics or backend HTTP. Verify diagnostics omit sensitive metadata and document the observable results of presence probes.

**Claims verified as sound**

- The tuple format contains no raw Ethernet/IP header, so it cannot directly transport ARP, TCP, IPv6, VLAN tags or IPv4 fragments. This depends on strict decoding and canonical adapter synthesis.
- Iroh 1.3 authenticates the remote Ed25519 identity and pins the server identity expected by the dialer. Evidence: local crate `src/tls/verifier.rs` and `src/endpoint/connection.rs`.
- Awaiting ordinary connection establishment runs the roster hook before returning the usable application connection. Rejection closes it. Evidence: `src/endpoint/connection.rs:359`. This does not prevent pre-hook candidate disclosure.
- `presets::Minimal` adds the crypto provider without adding pkarr/DNS lookup. The builder’s lookup list starts empty. Evidence: `src/endpoint/presets.rs` and `src/endpoint.rs`.
- `clear_ip_transports()` supports relay-only transport when IP transports are not subsequently re-added. Evidence: iroh builder source and relay-only tests.
- The denylist and UDP-only decoder can block direct RCON 9002 and TCP access. I did not establish an arbitrary-port or TCP bypass through the tuple protocol.
- A loopback broadcast did not reach the probe bound specifically to `127.0.0.1`; it did reach a wildcard listener. Unicast from the peer alias did reach the specifically bound listener. Evidence: local probe (not published).
- The nft research confirms a drop in the Kickoff table can override another table’s accept, while a Kickoff accept cannot override another table’s drop. Evidence: recorded firewall results (not published).
- Relay credentials are currently selected from the configured relay entry matching the URL, rather than automatically attached to every supplied relay URL. Evidence: iroh `src/socket/transports/relay/actor.rs:1344`.

**Open questions**

- What exact local destination address does LoopProxy use for each unicast, and how does it identify the game socket and its lifetime?
- Does discovery need guest-to-guest fan-out? If so, how will forwarded origin identity be represented?
- Can one daemon host multiple sessions? If yes, how are connections bound to a session when `Hello` carries only an epoch?
- Are 0-RTT application operations prohibited? Admission, nonce consumption and revocation must not rely on replayable early data.
- What are the receiver’s fragment-size, total-size, state-count and socket-count limits?
- Can iroh 1.3 filter QNT candidates before registration, including IPv6 and interface changes?
- What mechanism forces Windows media down after an abrupt service crash?
- Will the fallback enforce firewall and forwarding policy independently of ufw configuration, Windows application exceptions and ICS?
- Do measured Rocket League payloads contain addresses, advertised ports or URLs that can redirect clients beyond the tuple boundary?
- What complete shared-server relay configuration, process isolation and credential-enrollment policy will be reviewed before deployment?

# kickoff-local

The Linux kernel owner shared by IPC and wire. It holds the canonical installed
executable identities, uid and live pidfd checks, and `DataOnly` reads that
refuse ancillary data and truncated control messages. The transport owns its
socket and returns no raw socket accessor.

`DataOnly::installed_peer(PeerKind)` performs the fixed recipient check and
refuses a peer in the same process. It returns a borrowed `InstalledPeer`
retaining the pidfd. That capability has
private fields and no constructor accepting custom trust, paths or callbacks.
`Trust::same_user` and `Trust::for_uid` can configure ordinary channel fixtures;
they cannot grant this transmission authority. A socket pair in an unrelated
executable fails before a secret write.

IPC owns roles, framing limits, deadlines and commands. Wire owns
[secret serialization and transmission](../wire/README.md#secret-transmission).
The shared kernel mutations live here and have the workspace release guard.
Moved ancillary unit regressions remain with `DataOnly`; installed-recipient
refusal is exercised in `tests/installed.rs`.

# Kickoff

Kickoff is a free, open-source app for playing Rocket League custom maps on PC, alone or with friends, on Linux and Windows. The aim is one link: open it, install Kickoff, pick a map, play. No manual file swapping, command line, port forwarding or networking knowledge.

Kickoff is designed to be secure first:
- It never modifies the game install that online play uses. Custom maps run in a separate copy of the game, launched in the game's own offline mode without anti-cheat, so online play never sees a modified file. That removes the usual way custom-map tools risk a ban, but no third-party tool can guarantee how Psyonix or Epic enforce their rules; use Kickoff at your own risk.
- On Linux the game runs in a sandbox, so a malicious map or player cannot reach your files, your desktop or other devices on your network. The Windows equivalent is being designed and tested.
- Playing with friends works like a LAN party over the internet, through an encrypted peer-to-peer connection that carries only game traffic.

## Status

Design phase; **not usable yet**. The design has been through two rounds of independent security review. Milestone M2, the core networking (wire format, session admission, the in-process LAN), is in progress. There are no releases yet.

## Documents

- [Design](docs/design.md): goals, architecture, networking, security model and milestones.
- [Security invariants](docs/SECURITY-INVARIANTS.md): the standing security rules and the tests that enforce them. Each one is a release requirement.
- [Security reviews](docs/reviews/): each review round and how every finding was resolved.
- [Development](docs/development.md): workspace layout, the check script and coding conventions.

## Licence

GPL-3.0. See [LICENSE](LICENSE).

Kickoff is not affiliated with or endorsed by Psyonix or Epic Games.

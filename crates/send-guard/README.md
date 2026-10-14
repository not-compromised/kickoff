# kickoff-send-guard

The registry the vendored iroh calls before every IP send (design §3.4,
R2-10). `vendor/iroh-1.3.0.patch` adds one call, in `IpSender::poll_send`:

```rust
if !kickoff_send_guard::admit(self.config.into(), Self::canonical_addr(dst)) {
    return Poll::Ready(Ok(()));
}
```

`kickoff-net` registers each endpoint's `SendGuard` under the exact address the
endpoint's IP transport is configured with, before the endpoint binds, and the
registration lives in the endpoint's hooks. The policy itself is in
`kickoff-net`'s `egress` module; this crate has no dependencies, because iroh
depends on it.

An unregistered address passes, as upstream iroh would: that is a bare iroh
endpoint in a test, never one Kickoff built. Port 0 cannot be registered.

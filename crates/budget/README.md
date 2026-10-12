# kickoff-budget

Dependency-free token arithmetic shared by session fan-out, network ingress and
the LAN filter. Each caller owns its rates, state lifetime and charging order.

`Bucket` starts full, carries fractional tokens below capacity, and discards
credit earned while full. Refused charges consume nothing. Availability and full
checks refill without charging. Timestamps never move backwards.

The saturation regression spends a one-token burst at 0.9 seconds, refuses a
second token at 1.0 seconds, and allows it at 1.9 seconds. The same regression
runs at each caller. The registered saturation mutant retains idle credit;
existing layer mutants still remove only that layer's protection.

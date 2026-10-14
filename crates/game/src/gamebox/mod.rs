//! The gamebox spawn path of design §3.2.6: a systemd user scope per box,
//! trusted links that sweep descriptors and arm parent-death checks, and a
//! supervisor that owns teardown through the scope's cgroup.
//!
//! Three binaries share this module: `kickoff-gamebox` (the supervisor, a
//! user service), `kickoff-box-link` (the trusted links of the chain) and
//! `kickoff-box-probe` (the synthetic payload that stands in for the game).
//! They find each other only as installed siblings, never by a path taken
//! from input.

mod barrier;
mod events;
mod gate;
mod install;
mod link;
mod net;
mod netlink;
mod probe;
mod refused;
mod scope;
mod startup;
mod supervisor;
mod view;

pub use barrier::Check;
pub use link::link_main;
pub use probe::probe_main;
pub use refused::Refused;
pub use supervisor::supervisor_main;

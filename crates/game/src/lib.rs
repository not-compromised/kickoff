//! Install discovery, copy generations and gamebox launch (design §2.3).
//!
//! Implemented so far: the Linux gamebox spawn path of design §3.2.6, which
//! runs only Kickoff's own synthetic containment probes (M0). Discovery,
//! copy generations and the game itself land in M5a and M3.

#[cfg(target_os = "linux")]
pub mod gamebox;

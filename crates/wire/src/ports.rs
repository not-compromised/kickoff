//! The compiled port denylist shared by the LAN filter and IP send guard.

/// Inclusive ranges that never pass in either direction, whatever
/// `GAME_PORTS` or a flow says.
pub const DENIED_PORTS: &[(u16, u16)] = &[
    (22, 22),
    (53, 53),
    (67, 68),
    (137, 138),
    (1900, 1900),
    (5353, 5353),
    (5355, 5355),
    (9002, 9002), // BakkesMod RCON
    (47984, 48010),
    (49123, 49124),
    (53317, 53317),
];

pub fn denied_port(port: u16) -> bool {
    DENIED_PORTS
        .iter()
        .any(|&(lo, hi)| (lo..=hi).contains(&port))
}

/// IP transport peers must use unprivileged ports outside the shared denylist.
pub fn transport_port_allowed(port: u16) -> bool {
    port >= 1024 && !denied_port(port)
}

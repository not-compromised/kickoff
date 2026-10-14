//! Local approval identifiers shared by the session owner and IPC.

/// Names one approval object (§4.4, SI-41): 128 random bits minted by the
/// admission owner in kickoffd. Opaque here; only the owner can tell whether
/// it is still current, and a decision on a stale id authorizes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApprovalId([u8; 16]);

impl ApprovalId {
    pub const fn from_bytes(bytes: [u8; 16]) -> ApprovalId {
        ApprovalId(bytes)
    }

    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

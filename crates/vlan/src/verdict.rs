/// Why a frame or datagram was dropped. Every drop has exactly one reason,
/// and each reason feeds exactly one `LanHealth` counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reject {
    // The bytes do not parse.
    Truncated,
    Oversize,
    BadIpHeader,
    BadLength,
    BadChecksum,

    // Parses, but the policy forbids it.
    NotIpv4,
    VlanTag,
    Ipv6,
    IpOptions,
    IpFragment,
    NotUdp,
    /// A frame from the game that does not carry the game's own MAC or IP.
    ForeignSource,
    /// A datagram claiming this node's own slot.
    OwnSlot,
    /// Guest to guest: the star has no such edge.
    NotInStar,
    UnknownDestination,
    MacMismatch,
    ArpNotAnswered,
    ZeroPort,
    DeniedPort,
    NotGamePort,
    BroadcastNotDiscovery,
    BroadcastTooLarge,
    PayloadTooLarge,

    // A budget or a queue is full.
    PeerBudget,
    BroadcastBudget,
    QueueFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Malformed,
    Filter,
    Overload,
}

impl Reject {
    pub fn class(self) -> Class {
        use Reject::*;
        match self {
            Truncated | Oversize | BadIpHeader | BadLength | BadChecksum => Class::Malformed,
            NotIpv4
            | VlanTag
            | Ipv6
            | IpOptions
            | IpFragment
            | NotUdp
            | ForeignSource
            | OwnSlot
            | NotInStar
            | UnknownDestination
            | MacMismatch
            | ArpNotAnswered
            | ZeroPort
            | DeniedPort
            | NotGamePort
            | BroadcastNotDiscovery
            | BroadcastTooLarge
            | PayloadTooLarge => Class::Filter,
            PeerBudget | BroadcastBudget | QueueFull => Class::Overload,
        }
    }
}

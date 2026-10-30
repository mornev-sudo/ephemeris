/// Why a packet was not forwarded. Counting drops per reason is the single
/// most useful debugging tool a router has ("show interface counters").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum DropReason {
    /// Frame too short or header fields inconsistent.
    Malformed,
    /// Unicast frame for some other MAC address.
    NotForUs,
    /// A VLAN no interface is configured for on that card (or an untagged
    /// frame on a card that only has VLAN interfaces).
    Vlan,
    /// Not IPv4 or ARP (e.g. IPv6, LLDP).
    UnsupportedEthertype,
    /// Bad IPv4 version, length or header checksum.
    BadIpHeader,
    /// Addresses that must never be routed: multicast, broadcast, loopback,
    /// unspecified (0.0.0.0/8) or reserved (240.0.0.0/4). See `filter`.
    Martian,
    /// TTL ran out (an ICMP Time Exceeded may have been sent instead).
    TtlExceeded,
    /// No matching route (an ICMP Net Unreachable may have been sent instead).
    NoRoute,
    /// Next hop's MAC is unknown; an ARP request was sent.
    NeighborMiss,
    /// Addressed to the router but not something the data plane answers.
    LocalUnhandled,
    /// ICMP generation suppressed by the rate limiter.
    IcmpRateLimited,
    /// ARP packet consumed (answered or learned from), not really a drop.
    ArpConsumed,
    /// Egress TX ring was full (counted by the I/O layer).
    TxRingFull,
    /// TCP/UDP header truncated.
    BadL4Header,
    /// No session, and the ingress port may not start new ones.
    NoSession,
    /// TCP packet that doesn't fit the session's state (e.g. a stray ACK).
    InvalidTcpState,
    /// The session table is full; new flows are refused.
    SessionTableFull,
    /// The host starting this flow has `sessions.max_per_host` already.
    HostSessionLimit,
    /// Overlay route, but no tether to that site is up.
    NoPath,
    /// Too big for the overlay MTU with Don't Fragment set (an ICMP
    /// Fragmentation Needed was sent instead), or too big to encapsulate.
    TooBig,
    /// Overlay packet from an address that isn't a configured tether peer.
    UnknownTether,
    /// Overlay packet with a bad header, version or site id.
    BadOverlay,
    /// Overlay probe or probe reply, consumed by the router.
    OverlayControl,
    /// Source NAT couldn't find a free port for a new session.
    NatExhausted,
    /// Source is one of the router's own addresses, or the destination itself.
    SpoofedSource,
    /// Source route, record route, timestamp or stream ID option, or a
    /// malformed option list.
    IpOption,
    /// A fragment that can never be part of a valid packet.
    BadFragment,
    /// A fragment addressed to the router, which never reassembles.
    FragmentToRouter,
    /// Matches a session, but arrived on the wrong interface, or (NAT) was
    /// sent to the inside host's own address instead of the translated one.
    SessionMismatch,
    /// ICMP error addressed to someone other than the sender of the packet
    /// it quotes.
    IcmpMismatch,
    /// A non-first fragment that would need source NAT: it has no ports to
    /// translate.
    NatUntranslatable,
    /// Overlay packet that failed authentication (wrong key, or modified).
    OverlayAuth,
    /// Overlay packet seen before (replayed), or too old.
    OverlayReplay,
    /// DHCP packet handed to the control plane (server or client).
    DhcpToControl,
    /// PPPoE discovery or PPP control packet handed to the control plane.
    PppoeToControl,
    /// For the control plane, but its queue was full (e.g. a DHCP flood).
    ControlQueueFull,
    /// SSH or portal traffic handed to the router's own host (see `host`).
    ToHost,
    /// A reply to a NAT address and port with no session: it expired, or
    /// was never made (a stray, or a scan).
    NatNoSession,
    /// A reply to a NAT port another worker owns: the network card sent it
    /// to the wrong queue. Replies need steering (see chapter 13), or one
    /// worker.
    NatWrongWorker,
    /// Overlay packet sealed with a session key we don't have (unknown,
    /// expired, or from before a restart).
    OverlayNoKey,
    /// SD-WAN handshake message handed to the control plane.
    OverlayHandshake,
    /// From a site without a fixed address, over more of its WAN links than
    /// it has slots here (`links` in its `[[site]]`).
    OverlayLinksFull,
    /// Handed to the worker that owns its session (not a real drop; see
    /// `steer`).
    HandedOff,
    /// For another worker, but its queue was full.
    HandoffFull,
}

impl DropReason {
    pub const ALL: [DropReason; 44] = [
        DropReason::Malformed,
        DropReason::NotForUs,
        DropReason::Vlan,
        DropReason::UnsupportedEthertype,
        DropReason::BadIpHeader,
        DropReason::Martian,
        DropReason::TtlExceeded,
        DropReason::NoRoute,
        DropReason::NeighborMiss,
        DropReason::LocalUnhandled,
        DropReason::IcmpRateLimited,
        DropReason::ArpConsumed,
        DropReason::TxRingFull,
        DropReason::BadL4Header,
        DropReason::NoSession,
        DropReason::InvalidTcpState,
        DropReason::SessionTableFull,
        DropReason::HostSessionLimit,
        DropReason::NoPath,
        DropReason::TooBig,
        DropReason::UnknownTether,
        DropReason::BadOverlay,
        DropReason::OverlayControl,
        DropReason::NatExhausted,
        DropReason::SpoofedSource,
        DropReason::IpOption,
        DropReason::BadFragment,
        DropReason::FragmentToRouter,
        DropReason::SessionMismatch,
        DropReason::IcmpMismatch,
        DropReason::NatUntranslatable,
        DropReason::OverlayAuth,
        DropReason::OverlayReplay,
        DropReason::DhcpToControl,
        DropReason::PppoeToControl,
        DropReason::ControlQueueFull,
        DropReason::ToHost,
        DropReason::NatNoSession,
        DropReason::NatWrongWorker,
        DropReason::OverlayNoKey,
        DropReason::OverlayHandshake,
        DropReason::OverlayLinksFull,
        DropReason::HandedOff,
        DropReason::HandoffFull,
    ];
    pub const COUNT: usize = Self::ALL.len();

    pub fn name(self) -> &'static str {
        match self {
            DropReason::Malformed => "malformed",
            DropReason::NotForUs => "not-for-us",
            DropReason::Vlan => "vlan",
            DropReason::UnsupportedEthertype => "unsupported-ethertype",
            DropReason::BadIpHeader => "bad-ip-header",
            DropReason::Martian => "martian",
            DropReason::TtlExceeded => "ttl-exceeded",
            DropReason::NoRoute => "no-route",
            DropReason::NeighborMiss => "neighbor-miss",
            DropReason::LocalUnhandled => "local-unhandled",
            DropReason::IcmpRateLimited => "icmp-rate-limited",
            DropReason::ArpConsumed => "arp-consumed",
            DropReason::TxRingFull => "tx-ring-full",
            DropReason::BadL4Header => "bad-l4-header",
            DropReason::NoSession => "no-session",
            DropReason::InvalidTcpState => "invalid-tcp-state",
            DropReason::SessionTableFull => "session-table-full",
            DropReason::HostSessionLimit => "host-session-limit",
            DropReason::NoPath => "no-path",
            DropReason::TooBig => "too-big",
            DropReason::UnknownTether => "unknown-tether",
            DropReason::BadOverlay => "bad-overlay",
            DropReason::OverlayControl => "overlay-control",
            DropReason::NatExhausted => "nat-exhausted",
            DropReason::SpoofedSource => "spoofed-source",
            DropReason::IpOption => "ip-option",
            DropReason::BadFragment => "bad-fragment",
            DropReason::FragmentToRouter => "fragment-to-router",
            DropReason::SessionMismatch => "session-mismatch",
            DropReason::IcmpMismatch => "icmp-mismatch",
            DropReason::NatUntranslatable => "nat-untranslatable",
            DropReason::OverlayAuth => "overlay-auth",
            DropReason::OverlayReplay => "overlay-replay",
            DropReason::DhcpToControl => "dhcp-to-control",
            DropReason::PppoeToControl => "pppoe-to-control",
            DropReason::ControlQueueFull => "control-queue-full",
            DropReason::ToHost => "to-host",
            DropReason::NatNoSession => "nat-no-session",
            DropReason::NatWrongWorker => "nat-wrong-worker",
            DropReason::OverlayNoKey => "overlay-no-key",
            DropReason::OverlayHandshake => "overlay-handshake",
            DropReason::OverlayLinksFull => "overlay-links-full",
            DropReason::HandedOff => "handed-off",
            DropReason::HandoffFull => "handoff-full",
        }
    }
}

/// Per-worker counters. Plain integers: only the owning worker writes them.
#[derive(Debug, Clone)]
pub struct Stats {
    pub rx: u64,
    pub forwarded: u64,
    /// Packets the router itself sent (ARP, ICMP).
    pub originated: u64,
    pub sessions_active: u64,
    pub sessions_created: u64,
    pub sessions_expired: u64,
    /// Of those, the ones that never got a single packet back.
    pub sessions_unanswered: u64,
    /// Dropped early to make room in a full table.
    pub sessions_early_dropped: u64,
    /// Packets other workers handed to this one (their session is here).
    pub handed_in: u64,
    /// TCP segments whose sequence number didn't fit their connection (any
    /// RST or FIN in them was ignored).
    pub tcp_blind: u64,
    /// ARP packets that disagreed with a known neighbour (re-checked, not
    /// believed).
    pub arp_conflicts: u64,
    pub drops: [u64; DropReason::COUNT],
    /// Per interface (index = port id): what came in and what went out.
    pub ports: Vec<PortCounters>,
}

/// Traffic through one interface. Bytes are whole Ethernet frames.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PortCounters {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
}

// By hand: `Default` isn't derived for arrays longer than 32.
impl Default for Stats {
    fn default() -> Self {
        Stats {
            rx: 0,
            forwarded: 0,
            originated: 0,
            sessions_active: 0,
            sessions_created: 0,
            sessions_expired: 0,
            sessions_unanswered: 0,
            sessions_early_dropped: 0,
            handed_in: 0,
            tcp_blind: 0,
            arp_conflicts: 0,
            drops: [0; DropReason::COUNT],
            ports: Vec::new(),
        }
    }
}

impl Stats {
    /// A frame left through `port` (the I/O layer calls this once it's on
    /// the TX ring).
    #[inline(always)]
    pub fn sent(&mut self, port: crate::PortId, len: usize) {
        if let Some(p) = self.ports.get_mut(port as usize) {
            p.tx_packets += 1;
            p.tx_bytes += len as u64;
        }
    }

    #[inline(always)]
    pub fn drop(&mut self, r: DropReason) {
        self.drops[r as usize] += 1;
    }
}

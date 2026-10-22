use eph_fib::{BuildError, Fib, Prefix};
use eph_packet::Mac;
use std::net::Ipv4Addr;

/// Index of an interface in the router's port table.
pub type PortId = u16;

/// A data-plane interface as the pipeline sees it.
#[derive(Debug, Clone)]
pub struct Port {
    pub id: PortId,
    pub name: String,
    pub mac: Mac,
    /// The router's own address on this link, e.g. 10.10.1.1
    pub addr: Ipv4Addr,
    /// The subnet attached to this link, e.g. 10.10.1.0/24
    pub subnet: Prefix,
    /// May traffic arriving on this port start new sessions? Usually `true`
    /// for inside and `false` for outside interfaces: then only replies to
    /// sessions started from the inside get in.
    pub allow_new_sessions: bool,
    pub role: Role,
    /// TCP MSS adjust: SYNs leaving or entering through this port announce
    /// at most this MSS, e.g. 1452 behind PPPoE. `None`: leave MSS alone.
    pub mss_adjust: Option<u16>,
    /// DHCP on this link: the router serves leases here, or gets its own
    /// address here. DHCP packets on such a port go to the control plane.
    pub dhcp: Dhcp,
    /// The next hop towards everything beyond this link (an ISP's router),
    /// if known: used for SD-WAN tethers leaving through this port.
    pub gateway: Option<Ipv4Addr>,
    /// PPPoE on this link (the ISP side of a DSL/fibre line).
    pub pppoe: Pppoe,
    /// Addresses outside `subnet` that are still neighbours on this link:
    /// a gateway outside a /32 DHCP lease, routes the DHCP server said are
    /// on-link, a PPPoE link's far end. Connected routes, like `subnet`.
    pub onlink: Vec<Prefix>,
    /// Largest IP packet this link carries (1500 on Ethernet, 1492 over
    /// PPPoE). Bigger ones get "fragmentation needed" (or are dropped).
    pub mtu: u16,
    /// The network card this port sends and receives on: an index into the
    /// router's list of cards (one AF_XDP socket per card and worker). VLAN
    /// ports share their card with each other and with an untagged port.
    pub card: u16,
    /// 802.1Q VLAN ID: frames on this port carry this tag on the wire.
    /// `None`: untagged.
    pub vlan: Option<u16>,
}

/// A port's PPPoE state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Pppoe {
    #[default]
    Off,
    /// Dialling: discovery and PPP control go to the control plane.
    Dialing,
    /// A session: IPv4 is carried in it, to the access concentrator.
    Up {
        session: u16,
        peer: eph_packet::Mac,
        mtu: u16,
    },
}

impl Port {
    /// The PPPoE session, if one is up.
    pub fn pppoe_up(&self) -> Option<(u16, eph_packet::Mac, u16)> {
        match self.pppoe {
            Pppoe::Up { session, peer, mtu } => Some((session, peer, mtu)),
            _ => None,
        }
    }

    /// Largest IP packet out of this port right now.
    pub fn ip_mtu(&self) -> u16 {
        self.pppoe_up()
            .map_or(self.mtu, |(_, _, m)| m.min(self.mtu))
    }

    /// Can `ip` be reached directly on this link: in its subnet, or one of
    /// its on-link prefixes? Never while the port has no address.
    pub fn reaches(&self, ip: Ipv4Addr) -> bool {
        self.connected_len(ip).is_some()
    }

    /// The length of the longest connected prefix on this port holding `ip`.
    pub fn connected_len(&self, ip: Ipv4Addr) -> Option<u8> {
        if self.addr.is_unspecified() {
            return None;
        }
        std::iter::once(&self.subnet)
            .chain(&self.onlink)
            .filter(|p| p.contains(ip))
            .map(|p| p.len())
            .max()
    }
}

/// The router's DHCP role on a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Dhcp {
    #[default]
    Off,
    /// Lease addresses to hosts on this link.
    Server,
    /// Get this port's own address (and gateway) from a server on the link.
    Client,
}

/// Which side of the network an interface faces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Role {
    /// Your networks: LANs, servers.
    #[default]
    Inside,
    /// The internet / ISP side: source NAT applies on the way out.
    Outside,
}

impl Port {
    /// The subnet's broadcast address (all host bits set).
    pub fn broadcast(&self) -> Ipv4Addr {
        let host_bits = if self.subnet.len() == 32 {
            0
        } else {
            u32::MAX >> self.subnet.len()
        };
        (u32::from(self.subnet.addr()) | host_bits).into()
    }
}

/// Where the FIB sends a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHop {
    /// Out of a local port. `gateway: None` for a directly connected subnet
    /// (the destination itself is the neighbour to ARP for), `Some(gw)` for a
    /// route via another router.
    Ip {
        port: PortId,
        gateway: Option<Ipv4Addr>,
    },
    /// Into the SD-WAN overlay, towards site `Overlay::sites[idx]`. Which
    /// tether (WAN path) is decided per session by the path table.
    Site(usize),
}

#[derive(Debug, Clone, Copy)]
pub struct StaticRoute {
    pub prefix: Prefix,
    pub via: Ipv4Addr,
}

/// A prefix reachable at another site, through the overlay.
#[derive(Debug, Clone, Copy)]
pub struct OverlayRoute {
    pub prefix: Prefix,
    /// Index into `Overlay::sites`.
    pub site_idx: usize,
}

/// Compile interfaces + static routes into a forwarding table.
///
/// This is a tiny version of what a real control plane does: the RIB (all the
/// routes we know) gets *resolved* into the FIB (exactly one usable next hop
/// per prefix). A static route's gateway must sit on a connected subnet; we
/// look up which port that is now, so the data plane never has to.
pub fn build_fib(
    ports: &[Port],
    statics: &[StaticRoute],
    overlay: &[OverlayRoute],
) -> Result<Fib<NextHop>, String> {
    let mut routes = Vec::new();
    for p in ports {
        // A port still waiting for its address (DHCP, PPPoE) has no
        // connected network yet: nothing to route to it.
        if p.addr.is_unspecified() {
            continue;
        }
        for &prefix in std::iter::once(&p.subnet).chain(&p.onlink) {
            routes.push((
                prefix,
                NextHop::Ip {
                    port: p.id,
                    gateway: None,
                },
            ));
        }
    }
    for r in overlay {
        routes.push((r.prefix, NextHop::Site(r.site_idx)));
    }
    for r in statics {
        let port = ports
            .iter()
            .filter_map(|p| Some((p, p.connected_len(r.via)?)))
            .max_by_key(|(_, len)| *len)
            .map(|(p, _)| p)
            .ok_or_else(|| {
                format!(
                    "route {} via {}: gateway is not on any connected subnet",
                    r.prefix, r.via
                )
            })?;
        routes.push((
            r.prefix,
            NextHop::Ip {
                port: port.id,
                gateway: Some(r.via),
            },
        ));
    }
    Fib::build(routes).map_err(|e| match e {
        BuildError::TooManyNextHops => "too many distinct next hops".to_string(),
        BuildError::TooManyTbl8Groups => "too many routes longer than /24".to_string(),
    })
}

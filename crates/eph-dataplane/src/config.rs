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

    /// Can `ip` be reached directly on this link? On a PPPoE link the far
    /// end (`gateway`) is the only neighbour, outside the router's /32.
    pub fn reaches(&self, ip: Ipv4Addr) -> bool {
        !self.addr.is_unspecified()
            && (self.subnet.contains(ip) || (self.pppoe_up().is_some() && self.gateway == Some(ip)))
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
        routes.push((
            p.subnet,
            NextHop::Ip {
                port: p.id,
                gateway: None,
            },
        ));
        // A PPPoE link's far end is connected too, though not in our /32.
        if let (Some(_), Some(peer)) = (p.pppoe_up(), p.gateway) {
            routes.push((
                Prefix::new(peer, 32).expect("a /32"),
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
            .filter(|p| {
                p.subnet.contains(r.via) || (p.pppoe_up().is_some() && p.gateway == Some(r.via))
            })
            .max_by_key(|p| p.subnet.len())
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

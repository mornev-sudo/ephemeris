//! The host path: the router's own SSH server and web portal, reached on an
//! inside interface's address.
//!
//! sshd and nginx run in Linux, which never sees the data-plane NICs (AF_XDP
//! takes every frame). So the pipeline hands their traffic to the kernel
//! through a tun device, `eph-host`, and sends the replies back out:
//!
//! ```text
//!  client ── lan ──▶ pipeline ── dst 10.10.1.1 → 169.254.240.1 ──▶ eph-host ──▶ sshd/nginx
//!  client ◀─ lan ─── pipeline ◀─ src 169.254.240.1 → 10.10.1.1 ── eph-host ◀── replies
//! ```
//!
//! Each interface has an address of its own in [`HOST_NET`] (port id + 1),
//! so the way back needs no state: a reply's source says which interface,
//! and so which address, it belongs to. Linux treats the whole range as its
//! own and routes anything from it back into `eph-host` (set up by
//! `nic-setup`). sshd and nginx see the client's real address.
//!
//! Only inside interfaces, never outside ones or SD-WAN tethers: checked
//! here on every packet, whatever the config says.
//!
//! ## The router's own connections
//!
//! With `[management] outbound = "dataplane"`, the router's own traffic
//! (software updates, DNS, time) leaves through the data plane too, so a
//! router needs no management network to update itself. Linux sends it
//! into `eph-host` from [`SELF_ADDR`]; the pipeline routes it like a LAN
//! host's, always source-NATed to the way out's address, with a session,
//! and hands the replies back into `eph-host`:
//!
//! ```text
//!  sysupdate ── 169.254.255.254 ──▶ eph-host ──▶ pipeline ── NAT to wan's address ── wan ──▶ update server
//!  sysupdate ◀───────────────────── eph-host ◀── pipeline ◀── reply to wan's address ─ wan ◀──
//! ```
//!
//! Nothing can start a connection to the router this way: only replies to
//! its sessions come back, and link-local addresses never arrive from the
//! network (`filter`, RFC 3927).

use crate::config::{PortId, Role};
use crate::Port;
use eph_fib::Prefix;
use std::net::Ipv4Addr;

/// The portal (nginx, HTTPS).
pub const HTTPS_PORT: u16 = 8443;
/// SSH.
pub const SSH_PORT: u16 = 22;

/// Link-local addresses for the host side, one per interface. (Clear of
/// 169.254.169.254, the cloud metadata address.)
pub const HOST_NET: Ipv4Addr = Ipv4Addr::new(169, 254, 240, 0);
pub const HOST_NET_LEN: u8 = 20;
/// Interfaces the range has room for (its last address is [`SELF_ADDR`]).
pub const HOST_PORTS_MAX: usize = (1 << (32 - HOST_NET_LEN)) - 3;
/// The source of the router's own outbound connections through the data
/// plane: the range's last usable address.
pub const SELF_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 255, 254);

pub fn host_net() -> Prefix {
    Prefix::new(HOST_NET, HOST_NET_LEN).expect("a valid prefix")
}

/// The host-side address standing in for `port`'s own address.
pub fn host_addr(port: PortId) -> Option<Ipv4Addr> {
    ((port as usize) < HOST_PORTS_MAX).then(|| (u32::from(HOST_NET) + port as u32 + 1).into())
}

/// The interface a host-side address stands for.
pub fn port_of(addr: Ipv4Addr) -> Option<PortId> {
    let n = u32::from(addr).checked_sub(u32::from(HOST_NET) + 1)?;
    ((n as usize) < HOST_PORTS_MAX).then_some(n as PortId)
}

/// Which of the router's own services an interface offers, and to whom.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostAccess {
    pub https: bool,
    pub ssh: bool,
    /// Only clients in these prefixes; empty: anyone who reaches the address.
    pub from: Vec<Prefix>,
}

impl HostAccess {
    pub fn any(&self) -> bool {
        self.https || self.ssh
    }

    /// Is TCP port `port` one of the services offered?
    pub fn offers(&self, port: u16) -> bool {
        (port == HTTPS_PORT && self.https) || (port == SSH_PORT && self.ssh)
    }

    pub fn admits(&self, src: Ipv4Addr) -> bool {
        self.from.is_empty() || self.from.iter().any(|p| p.contains(src))
    }
}

/// May a TCP segment from `src` to port `dport` on `port`'s address go to
/// the host? Inside interfaces only.
pub fn allowed_in(port: &Port, src: Ipv4Addr, dport: u16) -> bool {
    port.role == Role::Inside && port.host.offers(dport) && port.host.admits(src)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_addresses_map_to_interfaces_and_back() {
        assert_eq!(host_addr(0), Some(Ipv4Addr::new(169, 254, 240, 1)));
        assert_eq!(host_addr(300), Some(Ipv4Addr::new(169, 254, 241, 45)));
        for p in [0, 1, 300, HOST_PORTS_MAX as u16 - 1] {
            assert_eq!(port_of(host_addr(p).unwrap()), Some(p));
            assert!(host_net().contains(host_addr(p).unwrap()));
        }
        assert_eq!(host_addr(HOST_PORTS_MAX as u16), None);
        assert_eq!(port_of(HOST_NET), None, "the network address itself");
        assert_eq!(port_of("169.254.169.254".parse().unwrap()), None);
        assert!(host_net().contains(SELF_ADDR));
        assert_eq!(port_of(SELF_ADDR), None, "not an interface's");
        assert_ne!(host_addr(HOST_PORTS_MAX as u16 - 1), Some(SELF_ADDR));
        assert_eq!(port_of("10.0.0.1".parse().unwrap()), None);
    }
}

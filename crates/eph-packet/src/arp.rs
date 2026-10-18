//! ARP (RFC 826): how a host turns "next hop 10.0.1.10" into a MAC address.
//!
//! ```text
//!  0      2      4    5    6      8           14       18          24       28
//! +------+------+----+----+------+-----------+--------+-----------+--------+
//! |htype |ptype |hlen|plen|  op  | sender MAC|sender IP| target MAC|target IP|
//! +------+------+----+----+------+-----------+--------+-----------+--------+
//! ```

use crate::eth::{self, Mac};
use crate::{rd16, rd_ip, wr16, wr_ip};
use std::net::Ipv4Addr;

pub const LEN: usize = 28;
pub const OP_REQUEST: u16 = 1;
pub const OP_REPLY: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    pub op: u16,
    pub sha: Mac,
    pub spa: Ipv4Addr,
    pub tha: Mac,
    pub tpa: Ipv4Addr,
}

/// Parse an Ethernet/IPv4 ARP packet; anything else is `None`.
pub fn parse(b: &[u8]) -> Option<Arp> {
    if b.len() < LEN || rd16(b, 0) != 1 || rd16(b, 2) != eth::TYPE_IPV4 || b[4] != 6 || b[5] != 4 {
        return None;
    }
    Some(Arp {
        op: rd16(b, 6),
        sha: b[8..14].try_into().unwrap(),
        spa: rd_ip(b, 14),
        tha: b[18..24].try_into().unwrap(),
        tpa: rd_ip(b, 24),
    })
}

pub fn write(b: &mut [u8], a: &Arp) {
    wr16(b, 0, 1); // Ethernet
    wr16(b, 2, eth::TYPE_IPV4);
    b[4] = 6;
    b[5] = 4;
    wr16(b, 6, a.op);
    b[8..14].copy_from_slice(&a.sha);
    wr_ip(b, 14, a.spa);
    b[18..24].copy_from_slice(&a.tha);
    wr_ip(b, 24, a.tpa);
}

/// Minimum Ethernet frame (without FCS, which the NIC adds).
pub const MIN_FRAME: usize = 60;

/// Build a broadcast "who-has `target`? tell `my_ip`" frame. Returns its length.
pub fn build_request(frame: &mut [u8], my_mac: Mac, my_ip: Ipv4Addr, target: Ipv4Addr) -> usize {
    frame[..MIN_FRAME].fill(0);
    eth::write(frame, eth::BROADCAST, my_mac, eth::TYPE_ARP);
    write(
        &mut frame[eth::HDR_LEN..],
        &Arp {
            op: OP_REQUEST,
            sha: my_mac,
            spa: my_ip,
            tha: eth::ZERO,
            tpa: target,
        },
    );
    MIN_FRAME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let mut f = [0xaau8; 64];
        let me = [2, 0, 0, 0, 0, 1];
        let n = build_request(
            &mut f,
            me,
            Ipv4Addr::new(10, 0, 1, 1),
            Ipv4Addr::new(10, 0, 1, 10),
        );
        assert_eq!(n, 60);
        assert_eq!(eth::dst(&f), eth::BROADCAST);
        assert_eq!(eth::ethertype(&f), eth::TYPE_ARP);
        let a = parse(&f[14..]).unwrap();
        assert_eq!(a.op, OP_REQUEST);
        assert_eq!(a.sha, me);
        assert_eq!(a.tpa, Ipv4Addr::new(10, 0, 1, 10));
        assert!(f[42..60].iter().all(|&b| b == 0), "padding must be zeroed");
    }
}

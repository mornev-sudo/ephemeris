//! Ethernet II framing.
//!
//! ```text
//!  0                   6                   12      14
//! +-------------------+-------------------+-------+------------
//! | destination MAC   | source MAC        | type  | payload ...
//! +-------------------+-------------------+-------+------------
//! ```

use crate::{rd16, wr16};

pub type Mac = [u8; 6];

pub const HDR_LEN: usize = 14;
pub const BROADCAST: Mac = [0xff; 6];
pub const ZERO: Mac = [0; 6];

pub const TYPE_IPV4: u16 = 0x0800;
pub const TYPE_ARP: u16 = 0x0806;
pub const TYPE_VLAN: u16 = 0x8100;

#[inline(always)]
pub fn dst(f: &[u8]) -> Mac {
    f[0..6].try_into().unwrap()
}

#[inline(always)]
pub fn src(f: &[u8]) -> Mac {
    f[6..12].try_into().unwrap()
}

#[inline(always)]
pub fn ethertype(f: &[u8]) -> u16 {
    rd16(f, 12)
}

/// Write a complete Ethernet header.
#[inline(always)]
pub fn write(f: &mut [u8], dst: Mac, src: Mac, ethertype: u16) {
    f[0..6].copy_from_slice(&dst);
    f[6..12].copy_from_slice(&src);
    wr16(f, 12, ethertype);
}

/// Rewrite only the MAC addresses: what a router does to every forwarded frame.
#[inline(always)]
pub fn set_macs(f: &mut [u8], dst: Mac, src: Mac) {
    f[0..6].copy_from_slice(&dst);
    f[6..12].copy_from_slice(&src);
}

/// Group bit set = broadcast or multicast.
#[inline(always)]
pub fn is_multicast(mac: &Mac) -> bool {
    mac[0] & 1 == 1
}

pub fn fmt_mac(m: &Mac) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

pub fn parse_mac(s: &str) -> Option<Mac> {
    let mut out = [0u8; 6];
    let mut parts = s.trim().split(':');
    for b in out.iter_mut() {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_roundtrip() {
        let m = parse_mac("52:54:00:aB:cd:EF").unwrap();
        assert_eq!(fmt_mac(&m), "52:54:00:ab:cd:ef");
        assert!(parse_mac("52:54:00:ab:cd").is_none());
        assert!(parse_mac("52:54:00:ab:cd:ef:01").is_none());
    }

    #[test]
    fn multicast_bit() {
        assert!(is_multicast(&BROADCAST));
        assert!(is_multicast(&[0x01, 0, 0x5e, 0, 0, 1]));
        assert!(!is_multicast(&[0x52, 0x54, 0, 0, 0, 1]));
    }
}

//! Ethernet II framing.
//!
//! ```text
//!  0                   6                   12      14
//! +-------------------+-------------------+-------+------------
//! | destination MAC   | source MAC        | type  | payload ...
//! +-------------------+-------------------+-------+------------
//! ```
//!
//! An 802.1Q VLAN tag is 4 bytes slipped in before the type: 0x8100, then
//! 3 bits of priority, 1 drop-eligible bit and the 12-bit VLAN ID. The real
//! type follows it.
//!
//! ```text
//!  0                   6                   12      14      16      18
//! +-------------------+-------------------+-------+-------+-------+------
//! | destination MAC   | source MAC        | 8100  | PCP/  | type  | payload
//! |                   |                   |       | VID   |       |
//! +-------------------+-------------------+-------+-------+-------+------
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

/// Bytes an 802.1Q tag adds to a frame.
pub const VLAN_TAG_LEN: usize = 4;
/// VLAN IDs 0 (priority tag only) and 4095 are reserved.
pub const VLAN_ID_MAX: u16 = 4094;

/// The VLAN ID of a tagged frame (one whose type is [`TYPE_VLAN`]).
#[inline(always)]
pub fn vlan_id(f: &[u8]) -> u16 {
    rd16(f, 14) & 0x0fff
}

/// Take the 802.1Q tag out of the frame starting at `off`: the two MAC
/// addresses move forward over it, nothing else is copied. Returns the
/// frame's new start (4 bytes later).
#[inline(always)]
pub fn pop_vlan(buf: &mut [u8], off: usize) -> usize {
    buf.copy_within(off..off + 12, off + VLAN_TAG_LEN);
    off + VLAN_TAG_LEN
}

/// Put an 802.1Q tag for `vid` (priority 0) into the frame starting at
/// `off`, which needs 4 bytes of room in front of it: the MAC addresses move
/// back into that room. Returns the frame's new start.
#[inline(always)]
pub fn push_vlan(buf: &mut [u8], off: usize, vid: u16) -> usize {
    let new = off - VLAN_TAG_LEN;
    buf.copy_within(off..off + 12, new);
    wr16(buf, new + 12, TYPE_VLAN);
    wr16(buf, new + 14, vid & 0x0fff);
    new
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
    fn vlan_tag_roundtrip() {
        let mut buf = [0u8; 64];
        let plain: Vec<u8> = (0..30u8).collect();
        buf[8..38].copy_from_slice(&plain);
        wr16(&mut buf, 8 + 12, TYPE_IPV4);
        let tagged = push_vlan(&mut buf, 8, 0x0123);
        assert_eq!(tagged, 4);
        let f = &buf[tagged..];
        assert_eq!(dst(f), dst(&plain));
        assert_eq!(src(f), src(&plain));
        assert_eq!(ethertype(f), TYPE_VLAN);
        assert_eq!(vlan_id(f), 0x123);
        assert_eq!(rd16(f, 16), TYPE_IPV4);
        assert_eq!(&f[18..34], &plain[14..30]);
        // A priority (PCP) set by someone else doesn't change the ID.
        buf[tagged + 14] |= 0xe0;
        assert_eq!(vlan_id(&buf[tagged..]), 0x123);
        let back = pop_vlan(&mut buf, tagged);
        assert_eq!(back, 8);
        assert_eq!(ethertype(&buf[8..]), TYPE_IPV4);
        assert_eq!(&buf[8..20], &plain[..12]);
        assert_eq!(&buf[22..38], &plain[14..30]);
    }

    #[test]
    fn multicast_bit() {
        assert!(is_multicast(&BROADCAST));
        assert!(is_multicast(&[0x01, 0, 0x5e, 0, 0, 1]));
        assert!(!is_multicast(&[0x52, 0x54, 0, 0, 0, 1]));
    }
}

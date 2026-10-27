//! Zero-copy packet header access.
//!
//! Nothing in this crate allocates or copies a packet. Every function reads
//! or writes bytes at fixed offsets inside a buffer that the NIC (via AF_XDP)
//! handed us. That is the whole trick behind fast packet processing: a packet
//! is just a byte array, and "parsing" it is knowing which offsets mean what.
//!
//! All multi-byte header fields on the wire are big-endian ("network byte
//! order"), so reads go through `u16::from_be_bytes` and friends.

// No unsafe code here: packet parsing, routing and forwarding logic is
// all safe Rust, and the compiler keeps it that way.
#![forbid(unsafe_code)]

pub mod arp;
pub mod checksum;
pub mod dhcp;
pub mod eth;
pub mod icmp;
pub mod ipv4;
pub mod l4;
pub mod pppoe;

pub use eth::Mac;

#[inline(always)]
pub(crate) fn rd16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

#[inline(always)]
pub(crate) fn wr16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_be_bytes());
}

#[inline(always)]
pub(crate) fn rd_ip(b: &[u8], off: usize) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::new(b[off], b[off + 1], b[off + 2], b[off + 3])
}

#[inline(always)]
pub(crate) fn wr_ip(b: &mut [u8], off: usize, ip: std::net::Ipv4Addr) {
    b[off..off + 4].copy_from_slice(&ip.octets());
}

/// Every parser on random and truncated bytes: none may panic. (`fuzz/`
/// does this guided by coverage; this runs with every `cargo test`.)
#[cfg(test)]
mod hostile_input {
    #[test]
    fn parsers_never_panic() {
        let mut x: u64 = 0x5eed_1234;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..100_000 {
            let n = (next() % 700) as usize;
            let mut b: Vec<u8> = (0..n).map(|_| next() as u8).collect();
            // Now and then a plausible start, to get past the first checks.
            match next() % 4 {
                0 if n > 240 => b[236..240].copy_from_slice(&[99, 130, 83, 99]), // DHCP magic
                1 if n > 1 => b[0] = 0x11, // PPPoE version/type
                2 if n > 0 => b[0] = 0x45, // IPv4, 20-byte header
                _ => {}
            }
            let _ = crate::arp::parse(&b);
            let _ = crate::ipv4::parse(&b);
            let _ = crate::ipv4::find_option(&b, |_| true);
            if let Some(m) = crate::dhcp::Message::parse(&b) {
                let _ = (
                    m.msg_type(),
                    m.prefix_len(),
                    m.text(crate::dhcp::OPT_HOSTNAME),
                );
                let _ = (
                    m.ips(crate::dhcp::OPT_DNS),
                    m.u32(crate::dhcp::OPT_LEASE_TIME),
                    m.encode(),
                );
            }
            let _ = crate::dhcp::parse_frame(&b);
            if let Some(f) = crate::pppoe::Frame::parse(&b) {
                let _ = f.tag(crate::pppoe::TAG_AC_NAME);
                if let Some((_, p)) = f.ppp() {
                    if let Some(c) = crate::pppoe::Control::parse(p) {
                        let _ = crate::pppoe::options(&c.data);
                    }
                }
            }
            let _ = crate::pppoe::Control::parse(&b);
            let _ = crate::pppoe::options(&b);
        }
    }
}

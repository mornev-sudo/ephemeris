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

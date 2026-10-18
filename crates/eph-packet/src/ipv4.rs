//! IPv4 header.
//!
//! ```text
//!  0       4       8              16      19             31
//! +-------+-------+--------------+----------------------+
//! |Version|  IHL  |    DSCP/ECN  |     Total Length     |  0
//! +-------+-------+--------------+------+---------------+
//! |        Identification        |Flags | Frag Offset   |  4
//! +---------------+--------------+------+---------------+
//! |      TTL      |   Protocol   |   Header Checksum    |  8
//! +---------------+--------------+----------------------+
//! |                    Source Address                   | 12
//! +-----------------------------------------------------+
//! |                 Destination Address                 | 16
//! +-----------------------------------------------------+
//! |              Options (if IHL > 5) ...               | 20
//! ```

use crate::checksum;
use crate::{rd16, rd_ip, wr16, wr_ip};
use std::net::Ipv4Addr;

pub const MIN_HDR_LEN: usize = 20;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// Flags + fragment offset word (bytes 6-7).
pub const FLAG_RESERVED: u16 = 0x8000;
pub const FLAG_DF: u16 = 0x4000;
pub const FLAG_MF: u16 = 0x2000;
pub const FRAG_OFFSET_MASK: u16 = 0x1fff;

/// Option types (RFC 791 and the IANA registry). The top bit ("copied")
/// is part of the type number.
pub const OPT_EOL: u8 = 0;
pub const OPT_NOP: u8 = 1;
pub const OPT_RECORD_ROUTE: u8 = 7;
pub const OPT_TIMESTAMP: u8 = 68;
pub const OPT_LOOSE_SOURCE_ROUTE: u8 = 131;
pub const OPT_STREAM_ID: u8 = 136;
pub const OPT_STRICT_SOURCE_ROUTE: u8 = 137;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    TooShort,
    NotV4,
    BadHeaderLen,
    BadTotalLen,
    BadChecksum,
    /// An option's length is too short or runs past the header.
    BadOptions,
}

/// The fields the forwarding path cares about, pulled out once.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub hdr_len: usize,
    pub total_len: usize,
    pub ttl: u8,
    pub proto: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

/// Sanity-check an IPv4 header the way RFC 1812 (Requirements for IP Version 4
/// Routers, section 5.2.2) asks a router to before forwarding it.
/// `ip` starts at the IP header and ends at the end of the received frame.
#[inline]
pub fn parse(ip: &[u8]) -> Result<Header, Error> {
    if ip.len() < MIN_HDR_LEN {
        return Err(Error::TooShort);
    }
    if ip[0] >> 4 != 4 {
        return Err(Error::NotV4);
    }
    let hdr_len = ((ip[0] & 0x0f) as usize) * 4;
    if hdr_len < MIN_HDR_LEN || hdr_len > ip.len() {
        return Err(Error::BadHeaderLen);
    }
    let total_len = rd16(ip, 2) as usize;
    // Ethernet pads short frames to 60 bytes, so the frame may be longer than
    // the IP packet, never shorter.
    if total_len < hdr_len || total_len > ip.len() {
        return Err(Error::BadTotalLen);
    }
    if checksum::checksum(&ip[..hdr_len]) != 0 {
        return Err(Error::BadChecksum);
    }
    Ok(Header {
        hdr_len,
        total_len,
        ttl: ip[8],
        proto: ip[9],
        src: rd_ip(ip, 12),
        dst: rd_ip(ip, 16),
    })
}

/// Decrement TTL and patch the header checksum incrementally (RFC 1624).
/// TTL shares a 16-bit word with the protocol field, so that's the word we
/// hand to the incremental update.
#[inline(always)]
pub fn decrement_ttl(ip: &mut [u8]) {
    let old = rd16(ip, 8);
    ip[8] -= 1;
    let new = rd16(ip, 8);
    let hc = rd16(ip, 10);
    wr16(ip, 10, checksum::update16(hc, old, new));
}

/// The flags + fragment offset word. The offset is in units of 8 bytes.
#[inline(always)]
pub fn frag_word(ip: &[u8]) -> u16 {
    rd16(ip, 6)
}

/// Is this packet a fragment (more to come, or not the first piece)?
#[inline(always)]
pub fn is_fragment(ip: &[u8]) -> bool {
    frag_word(ip) & (FLAG_MF | FRAG_OFFSET_MASK) != 0
}

/// Walk the options of a header (`hdr` = exactly the `hdr_len` bytes) and
/// return the first option type `wanted` picks. `Err` if the option list
/// is malformed: a length that is too short or runs past the header.
pub fn find_option(hdr: &[u8], mut wanted: impl FnMut(u8) -> bool) -> Result<Option<u8>, Error> {
    let mut i = MIN_HDR_LEN;
    while i < hdr.len() {
        let typ = hdr[i];
        match typ {
            OPT_EOL => return Ok(None),
            OPT_NOP => {
                i += 1;
                continue;
            }
            _ => {}
        }
        // Every other option is type, length (including these two bytes), data.
        let len = *hdr.get(i + 1).ok_or(Error::BadOptions)? as usize;
        if len < 2 || i + len > hdr.len() {
            return Err(Error::BadOptions);
        }
        if wanted(typ) {
            return Ok(Some(typ));
        }
        i += len;
    }
    Ok(None)
}

/// Write a fresh 20-byte header (no options) and its checksum. Used when the
/// router itself originates a packet (ICMP replies and errors).
pub fn write_header(
    ip: &mut [u8],
    total_len: u16,
    ident: u16,
    ttl: u8,
    proto: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
) {
    ip[0] = 0x45; // version 4, IHL 5 (20 bytes)
    ip[1] = 0; // DSCP/ECN
    wr16(ip, 2, total_len);
    wr16(ip, 4, ident);
    wr16(ip, 6, 0x4000); // Don't Fragment
    ip[8] = ttl;
    ip[9] = proto;
    wr16(ip, 10, 0);
    wr_ip(ip, 12, src);
    wr_ip(ip, 16, dst);
    let c = checksum::checksum(&ip[..MIN_HDR_LEN]);
    wr16(ip, 10, c);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut p = vec![0u8; 28];
        write_header(
            &mut p,
            28,
            7,
            64,
            PROTO_ICMP,
            Ipv4Addr::new(10, 0, 1, 10),
            Ipv4Addr::new(10, 0, 2, 10),
        );
        p
    }

    #[test]
    fn parse_valid() {
        let h = parse(&sample()).unwrap();
        assert_eq!(h.hdr_len, 20);
        assert_eq!(h.total_len, 28);
        assert_eq!(h.ttl, 64);
        assert_eq!(h.dst, Ipv4Addr::new(10, 0, 2, 10));
    }

    #[test]
    fn rejects_garbage() {
        let mut p = sample();
        p[11] ^= 1;
        assert_eq!(parse(&p).unwrap_err(), Error::BadChecksum);
        let mut p = sample();
        p[0] = 0x65;
        assert_eq!(parse(&p).unwrap_err(), Error::NotV4);
        assert_eq!(parse(&sample()[..19]).unwrap_err(), Error::TooShort);
        assert_eq!(parse(&sample()[..25]).unwrap_err(), Error::BadTotalLen);
    }

    #[test]
    fn finds_options_and_rejects_bad_lengths() {
        let mut hdr = [0u8; 32];
        hdr[0] = 0x48; // IHL 8: 12 bytes of options
        hdr[20] = OPT_NOP;
        hdr[21..24].copy_from_slice(&[OPT_RECORD_ROUTE, 7, 4]);
        hdr[28] = OPT_EOL;
        assert_eq!(find_option(&hdr, |_| false), Ok(None));
        assert_eq!(
            find_option(&hdr, |t| t == OPT_RECORD_ROUTE),
            Ok(Some(OPT_RECORD_ROUTE))
        );
        // Nothing after EOL counts, even garbage.
        hdr[29] = OPT_STRICT_SOURCE_ROUTE;
        assert_eq!(
            find_option(&hdr, |t| t == OPT_STRICT_SOURCE_ROUTE),
            Ok(None)
        );
        // Length runs past the header.
        hdr[22] = 12;
        assert_eq!(find_option(&hdr, |_| false), Err(Error::BadOptions));
        // Length too short to cover type and length.
        hdr[22] = 1;
        assert_eq!(find_option(&hdr, |_| false), Err(Error::BadOptions));
        // Option type as the last byte, with no room for its length.
        let mut hdr = [0u8; 24];
        hdr[20..24].copy_from_slice(&[OPT_NOP, OPT_NOP, OPT_NOP, OPT_TIMESTAMP]);
        assert_eq!(find_option(&hdr, |_| false), Err(Error::BadOptions));
    }

    #[test]
    fn fragment_bits() {
        let mut p = sample();
        assert!(!is_fragment(&p), "DF alone is not a fragment");
        p[6..8].copy_from_slice(&FLAG_MF.to_be_bytes());
        assert!(is_fragment(&p));
        p[6..8].copy_from_slice(&3u16.to_be_bytes());
        assert!(is_fragment(&p), "last fragment: offset only");
    }

    #[test]
    fn ttl_decrement_keeps_checksum_valid() {
        let mut p = sample();
        decrement_ttl(&mut p);
        let h = parse(&p).unwrap();
        assert_eq!(h.ttl, 63);
    }
}

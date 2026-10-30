//! The always-on packet filter: IPv4 packets no router should accept or
//! forward, checked on every packet before routing, sessions or NAT.
//!
//! This is the "drop these" list the Common Criteria protection profiles for
//! network devices and firewalls require, i.e. what FIPS / ICSA certified
//! firewalls enforce, plus a few checks of the same kind that are standard
//! firewall practice (marked *extra*):
//!
//! | Dropped | Counter |
//! |---|---|
//! | Source is a broadcast address (255.255.255.255 or a connected subnet's), multicast (224.0.0.0/4) or loopback (127.0.0.0/8) | `martian` |
//! | Source or destination is unspecified (0.0.0.0/8) or reserved for future use (240.0.0.0/4) | `martian` |
//! | *Extra:* destination is multicast or loopback (no multicast routing here) | `martian` |
//! | Source or destination is link-local (169.254.0.0/16): routers never forward those (RFC 3927, section 7), and the router's own host path lives there | `martian` |
//! | Source is the router's own address (any interface, or a NAT pool); *extra:* source equals destination ("LAND") | `spoofed-source` |
//! | IP options Loose Source Route, Strict Source Route, Record Route; *extra:* Timestamp, Stream ID, or a malformed option list | `ip-option` |
//! | Invalid fragments (see [`check_fragment`]) | `bad-fragment` |
//! | Any fragment addressed to the router: it never reassembles, so none can be completed (checked in the pipeline) | `fragment-to-router` |
//! | *Extra:* the reserved ("evil") flag bit set | `bad-ip-header` |
//!
//! None of this is configurable: no legitimate traffic on a routed IPv4
//! network needs any of these packets. Drops are silent, with no ICMP error,
//! so spoofers and scanners learn nothing.

use crate::config::Port;
use crate::nat::NatConfig;
use crate::stats::DropReason;
use eph_packet::{icmp, ipv4, l4};
use std::net::Ipv4Addr;

/// `ip` is exactly the IP packet, `h` its parsed header.
#[inline]
pub(crate) fn check(
    ip: &[u8],
    h: &ipv4::Header,
    ports: &[Port],
    nat: &NatConfig,
) -> Result<(), DropReason> {
    if is_martian(h.src)
        || is_martian(h.dst)
        || h.src.is_link_local()
        || h.dst.is_link_local()
        || is_subnet_broadcast(h.src, ports)
    {
        return Err(DropReason::Martian);
    }
    if h.src == h.dst || ports.iter().any(|p| p.addr == h.src) || nat.owns(h.src) {
        return Err(DropReason::SpoofedSource);
    }
    if h.hdr_len > ipv4::MIN_HDR_LEN
        && ipv4::find_option(&ip[..h.hdr_len], forbidden_option) != Ok(None)
    {
        return Err(DropReason::IpOption);
    }
    if ipv4::frag_word(ip) & ipv4::FLAG_RESERVED != 0 {
        return Err(DropReason::BadIpHeader);
    }
    check_fragment(ip, h)
}

/// Never a valid source or destination on the wire: "this network"
/// (0.0.0.0/8), loopback (127.0.0.0/8), multicast (224.0.0.0/4) and
/// reserved (240.0.0.0/4, which includes 255.255.255.255).
#[inline]
pub(crate) fn is_martian(ip: Ipv4Addr) -> bool {
    let a = ip.octets()[0];
    a == 0 || a == 127 || a >= 224
}

/// A connected subnet's broadcast address. /31 and /32 have none: on a /31
/// both addresses are hosts (RFC 3021).
#[inline]
fn is_subnet_broadcast(ip: Ipv4Addr, ports: &[Port]) -> bool {
    ports
        .iter()
        .any(|p| p.subnet.len() < 31 && ip == p.broadcast())
}

/// Source routing lets the sender pick the path, sidestepping routing and
/// filtering; Record Route and Timestamp make routers disclose their
/// addresses; Stream ID is obsolete (RFC 6814).
fn forbidden_option(typ: u8) -> bool {
    matches!(
        typ,
        ipv4::OPT_LOOSE_SOURCE_ROUTE
            | ipv4::OPT_STRICT_SOURCE_ROUTE
            | ipv4::OPT_RECORD_ROUTE
            | ipv4::OPT_TIMESTAMP
            | ipv4::OPT_STREAM_ID
    )
}

/// What can be checked on a single fragment without reassembling (RFC 791,
/// RFC 1858). Applies to forwarded traffic too.
///
/// * A fragment carries data, and every fragment but the last a multiple of
///   8 bytes (offsets count in 8-byte units).
/// * It ends within 65535 bytes ("ping of death").
/// * The first fragment holds the whole transport header ("tiny fragment"
///   attack: TCP flags pushed into a second fragment, past the filter).
/// * No TCP fragment starts at offset 8 ("overlapping fragment" attack:
///   rewriting the first fragment's TCP flags).
fn check_fragment(ip: &[u8], h: &ipv4::Header) -> Result<(), DropReason> {
    let word = ipv4::frag_word(ip);
    let more = word & ipv4::FLAG_MF != 0;
    let offset = (word & ipv4::FRAG_OFFSET_MASK) as usize * 8;
    if !more && offset == 0 {
        return Ok(()); // not a fragment
    }
    let payload = h.total_len - h.hdr_len;
    if payload == 0 || (more && !payload.is_multiple_of(8)) || offset + payload > 65535 {
        return Err(DropReason::BadFragment);
    }
    let l4_min = match h.proto {
        ipv4::PROTO_TCP => l4::TCP_MIN_HDR_LEN,
        ipv4::PROTO_UDP => l4::UDP_HDR_LEN,
        ipv4::PROTO_ICMP => icmp::HDR_LEN,
        _ => 0,
    };
    if (offset == 0 && payload < l4_min) || (offset == 8 && h.proto == ipv4::PROTO_TCP) {
        return Err(DropReason::BadFragment);
    }
    Ok(())
}

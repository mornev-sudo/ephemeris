//! ICMP (RFC 792): the network's error and diagnostic channel. `ping` uses
//! echo request/reply; `traceroute` relies on routers sending Time Exceeded.
//!
//! ```text
//!  0       8      16              31
//! +-------+-------+----------------+
//! | type  | code  |    checksum    |
//! +-------+-------+----------------+
//! |  rest of header (id/seq, or 0) |
//! +--------------------------------+
//! |  data ...                      |
//! ```

use crate::checksum;
use crate::{rd16, wr16};

pub const HDR_LEN: usize = 8;

pub const ECHO_REPLY: u8 = 0;
pub const DEST_UNREACHABLE: u8 = 3;
pub const ECHO_REQUEST: u8 = 8;
pub const TIME_EXCEEDED: u8 = 11;

/// Destination Unreachable codes.
pub const CODE_NET_UNREACHABLE: u8 = 0;
pub const CODE_HOST_UNREACHABLE: u8 = 1;
/// "Fragmentation needed and DF set": the packet is too big for the next
/// link. The error carries that link's MTU, which is how path MTU discovery
/// (RFC 1191) learns to send smaller packets.
pub const CODE_FRAG_NEEDED: u8 = 4;

/// RFC 1812 4.3.2.3: quote the offending IP header plus at least 8 bytes of
/// its payload, enough for the sender to match the error to a TCP/UDP flow.
pub const ERROR_QUOTE_PAYLOAD: usize = 8;

/// Turn an echo request into an echo reply in place. Only the type byte
/// changes, so again the checksum is patched rather than recomputed.
#[inline]
pub fn echo_request_to_reply(icmp: &mut [u8]) {
    let old = rd16(icmp, 0);
    icmp[0] = ECHO_REPLY;
    let new = rd16(icmp, 0);
    let hc = rd16(icmp, 2);
    wr16(icmp, 2, checksum::update16(hc, old, new));
}

/// Write an error header in front of the already-placed quoted data
/// (`icmp[8..len]`) and checksum the whole message. `rest` is the 4-byte
/// "rest of header" field (zero, or the next-hop MTU for Frag Needed).
pub fn write_error(icmp: &mut [u8], len: usize, typ: u8, code: u8, rest: u32) {
    icmp[0] = typ;
    icmp[1] = code;
    icmp[2..4].fill(0);
    icmp[4..8].copy_from_slice(&rest.to_be_bytes());
    let c = checksum::checksum(&icmp[..len]);
    wr16(icmp, 2, c);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_reply_checksum() {
        let mut m = vec![ECHO_REQUEST, 0, 0, 0, 0x12, 0x34, 0, 1, b'h', b'i', b'!'];
        let c = checksum::checksum(&m);
        m[2..4].copy_from_slice(&c.to_be_bytes());
        echo_request_to_reply(&mut m);
        assert_eq!(m[0], ECHO_REPLY);
        assert_eq!(checksum::checksum(&m), 0);
    }
}

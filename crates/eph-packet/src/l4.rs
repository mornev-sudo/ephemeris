//! Just enough of TCP and UDP to track sessions: ports and TCP flags.
//!
//! ```text
//! UDP  0        2        4        6        8
//!     +--------+--------+--------+--------+
//!     |src port|dst port| length |checksum|
//!     +--------+--------+--------+--------+
//!
//! TCP  0        2        4                 8                 12   13    14
//!     +--------+--------+-----------------+-----------------+----+-----+---
//!     |src port|dst port| sequence number |  ack number     |off |flags| ...
//!     +--------+--------+-----------------+-----------------+----+-----+---
//! ```
//!
//! Both start with the two port numbers, which is why a session table can
//! treat them alike.

use crate::rd16;

pub const UDP_HDR_LEN: usize = 8;
pub const TCP_MIN_HDR_LEN: usize = 20;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

/// Source and destination port of a TCP or UDP header.
#[inline(always)]
pub fn ports(l4: &[u8]) -> (u16, u16) {
    (rd16(l4, 0), rd16(l4, 2))
}

/// The TCP flag byte (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR).
#[inline(always)]
pub fn tcp_flags(tcp: &[u8]) -> u8 {
    tcp[13]
}

/// Sequence number, acknowledgement number and window of a TCP header.
#[inline(always)]
pub fn tcp_seq_ack_win(tcp: &[u8]) -> (u32, u32, u16) {
    let rd32 = |o: usize| u32::from_be_bytes([tcp[o], tcp[o + 1], tcp[o + 2], tcp[o + 3]]);
    (rd32(4), rd32(8), rd16(tcp, 14))
}

/// TCP header length in bytes (data offset), at least 20 and at most the
/// buffer.
#[inline(always)]
pub fn tcp_header_len(tcp: &[u8]) -> usize {
    ((tcp[12] >> 4) as usize * 4).clamp(TCP_MIN_HDR_LEN, tcp.len())
}

/// The window scale option (RFC 7323) of a SYN, if it has one.
pub fn tcp_window_scale(tcp: &[u8]) -> Option<u8> {
    let end = tcp_header_len(tcp);
    let mut i = TCP_MIN_HDR_LEN;
    while i < end {
        match tcp[i] {
            0 => return None,
            1 => i += 1,
            kind => {
                let len = *tcp.get(i + 1)? as usize;
                if len < 2 || i + len > end {
                    return None;
                }
                if kind == 3 && len == 3 {
                    return Some(tcp[i + 2].min(14)); // RFC 7323: at most 14
                }
                i += len;
            }
        }
    }
    None
}

pub fn fmt_tcp_flags(f: u8) -> String {
    let names = [
        (TCP_SYN, 'S'),
        (TCP_ACK, 'A'),
        (TCP_FIN, 'F'),
        (TCP_RST, 'R'),
        (TCP_PSH, 'P'),
    ];
    names
        .iter()
        .filter(|(b, _)| f & b != 0)
        .map(|(_, c)| *c)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_ports_and_flags() {
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&443u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&50000u16.to_be_bytes());
        tcp[13] = TCP_SYN | TCP_ACK;
        assert_eq!(ports(&tcp), (443, 50000));
        assert_eq!(fmt_tcp_flags(tcp_flags(&tcp)), "SA");
    }

    #[test]
    fn reads_sequence_numbers_and_window_scale() {
        let mut tcp = [0u8; 28];
        tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&2000u32.to_be_bytes());
        tcp[12] = 7 << 4; // 28 bytes
        tcp[14..16].copy_from_slice(&512u16.to_be_bytes());
        tcp[20..28].copy_from_slice(&[2, 4, 5, 180, 1, 3, 3, 7]); // MSS, NOP, WS 7
        assert_eq!(tcp_seq_ack_win(&tcp), (1000, 2000, 512));
        assert_eq!(tcp_header_len(&tcp), 28);
        assert_eq!(tcp_window_scale(&tcp), Some(7));
        tcp[27] = 20;
        assert_eq!(tcp_window_scale(&tcp), Some(14), "capped");
        tcp[25] = 9; // option length running past the header
        assert_eq!(tcp_window_scale(&tcp), None);
        tcp[12] = 5 << 4;
        assert_eq!(tcp_window_scale(&tcp), None, "no options");
    }
}

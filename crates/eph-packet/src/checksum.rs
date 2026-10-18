//! The Internet checksum (RFC 1071) and its incremental update (RFC 1624).
//!
//! The checksum is the ones'-complement of the ones'-complement sum of all
//! 16-bit words. "Ones'-complement addition" just means: add normally, then
//! fold any carry out of bit 15 back into bit 0.
//!
//! A router changes the TTL of every packet it forwards, which changes the IP
//! header checksum. Recomputing it over the whole 20+ byte header is wasteful;
//! RFC 1624 shows you can patch it using only the old and new value of the
//! 16-bit word that changed. That's a handful of instructions per packet.

/// Ones'-complement sum of `data`, not yet folded or inverted.
#[inline]
pub fn sum(data: &[u8], mut acc: u32) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        acc += u16::from_be_bytes(*w) as u32;
    }
    if let [last] = rest {
        acc += (*last as u32) << 8;
    }
    acc
}

#[inline]
pub fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// Full RFC 1071 checksum. A buffer that already contains a correct checksum
/// field sums to 0xffff, so `checksum(..) == 0` means "valid".
#[inline]
pub fn checksum(data: &[u8]) -> u16 {
    !fold(sum(data, 0))
}

/// RFC 1624 eqn. 3: HC' = ~(~HC + ~m + m')
#[inline(always)]
pub fn update16(hc: u16, old: u16, new: u16) -> u16 {
    !fold((!hc as u32) + (!old as u32 & 0xffff) + new as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example() {
        // Worked example from RFC 1071 section 3.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(fold(sum(&data, 0)), 0xddf2);
    }

    #[test]
    fn incremental_matches_full() {
        let mut hdr = [
            0x45, 0x00, 0x00, 0x54, 0x12, 0x34, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 10, 0, 1, 10,
            10, 0, 2, 10,
        ];
        let c = checksum(&hdr);
        hdr[10..12].copy_from_slice(&c.to_be_bytes());
        assert_eq!(checksum(&hdr), 0);

        for _ in 0..64 {
            let old = u16::from_be_bytes([hdr[8], hdr[9]]);
            hdr[8] -= 1;
            let new = u16::from_be_bytes([hdr[8], hdr[9]]);
            let hc = u16::from_be_bytes([hdr[10], hdr[11]]);
            hdr[10..12].copy_from_slice(&update16(hc, old, new).to_be_bytes());
            assert_eq!(checksum(&hdr), 0, "ttl {}", hdr[8]);
        }
    }
}

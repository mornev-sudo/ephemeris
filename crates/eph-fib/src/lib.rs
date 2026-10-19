//! The Forwarding Information Base: "for destination X, which next hop?"
//!
//! Routing tables match on the *longest* prefix: with routes for 10.0.0.0/8
//! and 10.1.2.0/24, address 10.1.2.3 must use the /24. A naive implementation
//! walks a binary trie one bit at a time (up to 32 memory reads per packet).
//! At 10 Gb/s you have ~67 ns per packet and a single cache miss costs ~80 ns,
//! so that's far too slow.
//!
//! DIR-24-8 (Gupta, Lin & McKeown, "Routing Lookups in Hardware at Memory
//! Access Speeds", 1998) trades memory for speed:
//!
//! * `tbl24` has one entry for every possible /24 (2^24 entries × 2 bytes =
//!   32 MiB). Index it with the top 24 bits of the address and you're done
//!   for any route of length ≤ 24. That's **one** memory read.
//! * When some /25../32 exists inside a /24, that /24's entry instead points
//!   to a 256-entry `tbl8` group indexed by the last octet. **Two** reads.
//!
//! The same structure is used by DPDK's `rte_lpm`.
//!
//! The table is built once from a route list and then only read. When routes
//! change, the control plane builds a new table and swaps a pointer, so the
//! data plane never sees a half-updated table and never takes a lock.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// An IPv4 prefix such as `10.1.0.0/16`. Host bits are always zero.
// `len` is the prefix length, not a container size.
#[allow(clippy::len_without_is_empty)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Prefix {
    addr: u32,
    len: u8,
}

impl Prefix {
    pub fn new(addr: Ipv4Addr, len: u8) -> Option<Self> {
        (len <= 32).then(|| Prefix {
            addr: u32::from(addr) & mask(len),
            len,
        })
    }
    pub fn addr(&self) -> Ipv4Addr {
        self.addr.into()
    }
    pub fn len(&self) -> u8 {
        self.len
    }
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask(self.len) == self.addr
    }
}

#[inline]
fn mask(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - len)
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr(), self.len)
    }
}

impl FromStr for Prefix {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let (a, l) = s
            .split_once('/')
            .ok_or_else(|| format!("{s:?}: expected a.b.c.d/len"))?;
        let addr: Ipv4Addr = a.parse().map_err(|e| format!("{s:?}: {e}"))?;
        let len: u8 = l.parse().map_err(|e| format!("{s:?}: {e}"))?;
        Prefix::new(addr, len).ok_or_else(|| format!("{s:?}: prefix length > 32"))
    }
}

const TBL8_FLAG: u16 = 0x8000;
const MAX_ID: usize = 0x7fff;
/// Entry value 0 means "no route".
const EMPTY: u16 = 0;

#[derive(Debug, PartialEq, Eq)]
pub enum BuildError {
    TooManyNextHops,
    TooManyTbl8Groups,
}

/// Immutable longest-prefix-match table mapping prefixes to values of `T`
/// (in the router: a next hop).
pub struct Fib<T> {
    tbl24: Box<[u16]>,
    tbl8: Vec<u16>,
    /// Index 0 is unused so that entry value 0 can mean "no route".
    values: Vec<T>,
    routes: Vec<(Prefix, T)>,
}

impl<T: Clone + PartialEq> Fib<T> {
    /// Build a table. If a prefix appears more than once, the last one wins.
    pub fn build(routes: impl IntoIterator<Item = (Prefix, T)>) -> Result<Self, BuildError> {
        let mut routes: Vec<(Prefix, T)> = routes.into_iter().collect();
        // Deduplicate (last wins), then insert shortest prefixes first so that
        // longer, more specific prefixes simply overwrite them.
        let mut dedup: Vec<(Prefix, T)> = Vec::with_capacity(routes.len());
        for (p, v) in routes.drain(..) {
            match dedup.iter_mut().find(|(q, _)| *q == p) {
                Some(slot) => slot.1 = v,
                None => dedup.push((p, v)),
            }
        }
        dedup.sort_by_key(|(p, _)| (p.len, p.addr));

        let mut fib = Fib {
            tbl24: vec![EMPTY; 1 << 24].into_boxed_slice(),
            tbl8: Vec::new(),
            values: Vec::new(),
            routes: Vec::new(),
        };
        // Values are stored once and shared: many routes usually point to the
        // same few next hops. A placeholder fills slot 0.
        let mut ids: Vec<T> = Vec::new();
        for (prefix, value) in &dedup {
            let id = match ids.iter().position(|v| v == value) {
                Some(i) => i + 1,
                None => {
                    ids.push(value.clone());
                    ids.len()
                }
            };
            if id > MAX_ID {
                return Err(BuildError::TooManyNextHops);
            }
            fib.insert(*prefix, id as u16)?;
        }
        if let Some(first) = ids.first().cloned() {
            fib.values.push(first);
        }
        fib.values.extend(ids);
        fib.routes = dedup;
        Ok(fib)
    }

    fn insert(&mut self, p: Prefix, id: u16) -> Result<(), BuildError> {
        if p.len <= 24 {
            let start = (p.addr >> 8) as usize;
            let count = 1usize << (24 - p.len);
            for e in &mut self.tbl24[start..start + count] {
                debug_assert!(
                    *e & TBL8_FLAG == 0,
                    "prefixes must be inserted shortest first"
                );
                *e = id;
            }
        } else {
            let i24 = (p.addr >> 8) as usize;
            let cur = self.tbl24[i24];
            let group = if cur & TBL8_FLAG != 0 {
                (cur & !TBL8_FLAG) as usize
            } else {
                // Expand this /24 into a group, inheriting the covering route.
                let g = self.tbl8.len() / 256;
                if g > MAX_ID {
                    return Err(BuildError::TooManyTbl8Groups);
                }
                self.tbl8.extend(std::iter::repeat_n(cur, 256));
                self.tbl24[i24] = TBL8_FLAG | g as u16;
                g
            };
            let start = group * 256 + (p.addr & 0xff) as usize;
            let count = 1usize << (32 - p.len);
            self.tbl8[start..start + count].fill(id);
        }
        Ok(())
    }
}

impl<T> Fib<T> {
    /// The hot-path lookup: one or two array reads, no branches on prefix length.
    #[inline(always)]
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<&T> {
        let ip = u32::from(ip);
        let mut e = self.tbl24[(ip >> 8) as usize];
        if e & TBL8_FLAG != 0 {
            e = self.tbl8[(((e & !TBL8_FLAG) as usize) << 8) | (ip & 0xff) as usize];
        }
        if e == EMPTY {
            None
        } else {
            Some(&self.values[e as usize])
        }
    }

    /// The routes this table was built from, sorted by prefix length.
    pub fn routes(&self) -> &[(Prefix, T)] {
        &self.routes
    }

    pub fn tbl8_groups(&self) -> usize {
        self.tbl8.len() / 256
    }

    /// Distinct next hops in use (at most [`MAX_NEXT_HOPS`]).
    pub fn next_hops(&self) -> usize {
        self.values.len().saturating_sub(1)
    }

    /// Memory the lookup tables take: 32 MiB for tbl24, plus 512 bytes per
    /// tbl8 group.
    pub fn memory_bytes(&self) -> usize {
        (self.tbl24.len() + self.tbl8.len()) * 2
    }
}

/// Capacity limits (entries are 15-bit ids): distinct next hops, and /24s
/// holding routes longer than /24 (each takes a 256-entry tbl8 group).
pub const MAX_NEXT_HOPS: usize = MAX_ID;
pub const MAX_TBL8_GROUPS: usize = MAX_ID + 1;

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Prefix {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn prefix_parsing_masks_host_bits() {
        assert_eq!(p("10.1.2.3/16").to_string(), "10.1.0.0/16");
        assert_eq!(p("0.0.0.0/0").to_string(), "0.0.0.0/0");
        assert!("10.0.0.0/33".parse::<Prefix>().is_err());
        assert!(p("10.1.0.0/16").contains(ip("10.1.255.1")));
        assert!(!p("10.1.0.0/16").contains(ip("10.2.0.1")));
    }

    #[test]
    fn longest_prefix_wins() {
        let fib = Fib::build([
            (p("0.0.0.0/0"), "default"),
            (p("10.0.0.0/8"), "ten"),
            (p("10.1.2.0/24"), "slash24"),
            (p("10.1.2.128/25"), "slash25"),
            (p("10.1.2.200/32"), "host"),
        ])
        .unwrap();
        assert_eq!(fib.lookup(ip("8.8.8.8")), Some(&"default"));
        assert_eq!(fib.lookup(ip("10.9.9.9")), Some(&"ten"));
        assert_eq!(fib.lookup(ip("10.1.2.5")), Some(&"slash24"));
        assert_eq!(fib.lookup(ip("10.1.2.130")), Some(&"slash25"));
        assert_eq!(fib.lookup(ip("10.1.2.200")), Some(&"host"));
        assert_eq!(fib.lookup(ip("10.1.2.201")), Some(&"slash25"));
        assert_eq!(fib.tbl8_groups(), 1);
        assert_eq!(fib.memory_bytes(), ((1 << 24) + 256) * 2);
    }

    #[test]
    fn no_default_route_means_none() {
        let fib = Fib::build([(p("192.168.0.0/16"), 1)]).unwrap();
        assert_eq!(fib.next_hops(), 1);
        let two = Fib::build([
            (p("10.0.0.0/8"), 1),
            (p("10.1.0.0/16"), 2),
            (p("10.2.0.0/16"), 1),
        ])
        .unwrap();
        assert_eq!(two.next_hops(), 2, "next hops are shared between routes");
        assert_eq!(fib.lookup(ip("192.168.4.4")), Some(&1));
        assert_eq!(fib.lookup(ip("192.169.0.0")), None);
        let empty: Fib<u8> = Fib::build([]).unwrap();
        assert_eq!(empty.lookup(ip("1.2.3.4")), None);
    }

    #[test]
    fn insertion_order_does_not_matter_and_duplicates_last_win() {
        let fib = Fib::build([
            (p("10.1.2.128/25"), 2),
            (p("10.0.0.0/8"), 1),
            (p("10.0.0.0/8"), 3),
        ])
        .unwrap();
        assert_eq!(fib.lookup(ip("10.1.2.129")), Some(&2));
        assert_eq!(fib.lookup(ip("10.1.2.1")), Some(&3));
    }

    /// Compare against a brute-force longest-match over random routes.
    #[test]
    fn matches_reference_on_random_tables() {
        let mut seed: u64 = 0x9e3779b97f4a7c15;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        // Cluster addresses in 10.0.0.0/14 so prefixes actually overlap.
        let mut routes = Vec::new();
        for i in 0..400u32 {
            let addr = 0x0a00_0000 | (rnd() as u32 & 0x0003_ffff);
            let len = 8 + (rnd() % 25) as u8;
            routes.push((Prefix::new(addr.into(), len).unwrap(), i));
        }
        let fib = Fib::build(routes.clone()).unwrap();
        for _ in 0..20_000 {
            let a: Ipv4Addr = (0x0a00_0000 | (rnd() as u32 & 0x0003_ffff)).into();
            // Reference: longest matching prefix, last duplicate wins.
            let mut best: Option<(u8, u32)> = None;
            for (pfx, v) in &routes {
                if pfx.contains(a) && best.is_none_or(|(l, _)| pfx.len() >= l) {
                    best = Some((pfx.len(), *v));
                }
            }
            assert_eq!(fib.lookup(a).copied(), best.map(|b| b.1), "lookup {a}");
        }
    }
}

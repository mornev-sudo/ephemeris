# 3. The routing table and longest-prefix match

## Prefixes

`10.10.2.0/24` means "every address whose first 24 bits match 10.10.2", that
is, 10.10.2.0 to 10.10.2.255. The number after the slash is how many leading
bits are fixed. `/0` matches everything (the default route), and `/32`
matches exactly one host.

## Longest match wins

Routes overlap all the time:

```
0.0.0.0/0        via ISP           (everything else)
10.0.0.0/8       via HQ tether     (all company networks)
10.10.2.0/24     direct, lan-b     (this branch's LAN)
```

For 10.10.2.7, all three match. The rule is: **the most specific one (the
longest prefix) wins.** So it goes to lan-b, not to HQ or the ISP. This is
called *longest-prefix match* (LPM), and it's the core lookup every IP
router does for every packet.

## Why the obvious implementations are too slow

- **A list, checked in order:** with 1,000 routes, that's 1,000 comparisons
  per packet. Hopeless.
- **A binary trie** (a tree that branches on each bit of the address): at
  most 32 steps. Sounds fine, but each step is a pointer to somewhere else
  in memory, and following a pointer that isn't in the CPU cache costs
  roughly 80–100 ns. At 10 Gbit/s we get **67 ns per packet in total**
  (chapter 4 explains where that number comes from). One cache miss already
  blows the budget.

So the real goal isn't "few comparisons". It's **few memory accesses**.

## DIR-24-8: spend memory, save time

Published in 1998 for hardware routers, and still what DPDK uses today. The
insight: almost all real routes are /24 or shorter. So:

- **Table 1 (`tbl24`)** has one slot for *every possible* /24. There are
  2²⁴ ≈ 16.7 million of them, at 2 bytes each, which is **32 MiB**. To look
  up an address, take its first 24 bits and use them directly as the array
  index. **One memory read, no searching.**
- If some longer route (/25 to /32) exists inside a /24, that /24's slot
  instead points to a little **256-entry side table (`tbl8`)** indexed by
  the last 8 bits. **Two memory reads.**

```
10.10.2.7  →  tbl24[0x0A0A02] = next hop #2        (done, 1 read)
10.10.9.77 →  tbl24[0x0A0A09] = "see tbl8 group 0"
              tbl8[0*256 + 77] = next hop #5       (done, 2 reads)
```

Building the table is simple: sort routes from shortest to longest, and
"paint" each one over the slots it covers. Longer routes paint later, so they
win. A /16 paints 256 slots and a /8 paints 65,536, which is fine because
building happens rarely and off the fast path.

The code is in [`eph-fib/src/lib.rs`](../../crates/eph-fib/src/lib.rs). Its
tests compare the result against a brute-force "check every route" lookup on
20,000 random addresses.

**Why 32 MiB is fine:** the OS only gives us physical memory for the parts we
actually write. And the hot parts of the table (the /24s you're actually
talking to) end up in the CPU cache.

## RIB vs FIB

Two words you'll hear constantly:

- **RIB (Routing Information Base):** *everything* the router knows. That
  includes static routes, routes learned from BGP and OSPF, several candidate
  paths for the same prefix, and gateways that themselves need a lookup to
  reach. Rich, slow, owned by the control plane.
- **FIB (Forwarding Information Base):** the distilled answer: exactly one
  *resolved* next hop (port plus neighbour) per prefix. Lean, fast, read by
  the data plane.

Even our tiny Phase 0 does this resolution step. A static route says "via
10.10.2.254", and [`build_fib`](../../crates/eph-dataplane/src/config.rs)
works out *in advance* that 10.10.2.254 lives on lan-b. The data plane never
has to do a second lookup.

## How the table will change while running (Phase 2)

The FIB is immutable once built. To change routes, the control plane builds a
complete new FIB and atomically swaps the pointer the workers read. Workers
finish the batch they're on with the old table and pick up the new one on the
next. Nobody locks, nobody sees a half-updated table. The old table is freed
once no worker can still be holding it.

This "build new, swap pointer" pattern (sometimes called RCU, read-copy-update)
shows up everywhere in high-performance systems, including inside the Linux
kernel itself.

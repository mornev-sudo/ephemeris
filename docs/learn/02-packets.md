# 2. Packets are just bytes

## The key mental shift

A packet isn't an object. It's a run of bytes in memory, usually 60 to 1514
of them. "Parsing" a header means knowing that, for example, *bytes 22 and
23 hold the TTL and protocol*. That's all [`eph-packet`](../../crates/eph-packet)
is: named offsets.

This matters for speed. A typical high-level library would allocate a
`Packet` object, copy fields into it, maybe build a list of headers. Each of
those steps costs time we don't have (see chapter 4). We read and write the
bytes **in place**, in the very buffer the network card wrote them into.

## Layers, like envelopes inside envelopes

```
┌─────────────────── Ethernet frame (what the cable carries) ───────────────┐
│ dst MAC │ src MAC │ type=0x0800 │┌──────────── IPv4 packet ──────────────┐│
│ 6 bytes │ 6 bytes │   2 bytes   ││ header (20 B)  │┌── ICMP / TCP / UDP ┐││
│                                 ││ TTL, src, dst  ││ header │ payload   │││
│                                 │└────────────────┴┴────────┴───────────┘││
└───────────────────────────────────────────────────────────────────────────┘
```

Each layer only cares about its own header:

| Layer | Header | Answers the question | Changes per hop? |
|---|---|---|---|
| Ethernet (L2) | 14 bytes | Which device *on this cable* gets it? | **Yes**, rewritten by every router |
| IPv4 (L3) | 20+ bytes | Which host *on the internet* is it for? | Only TTL and checksum |
| TCP/UDP/ICMP (L4) | 8–20+ bytes | Which program on that host? | No (until we do NAT, which we're not) |

A router is an **L3** device: it reads the IP header to decide, and rewrites
the L2 header to deliver.

## Byte order ("endianness")

Network protocols send multi-byte numbers *big-endian*: most significant byte
first. x86 and ARM CPUs store numbers *little-endian*. So the 16-bit value
`0x0800` (IPv4) arrives as bytes `08 00`, and you must convert it, not just
reinterpret the memory. In Rust that's `u16::from_be_bytes([b[12], b[13]])`.
Forgetting this is the classic first bug in every packet-processing project.

## ARP: the phone book between layers 2 and 3

The routing table tells us "send to 10.10.2.10 via lan-b". But the Ethernet
header needs a MAC address. ARP fills that gap:

- *Request*, broadcast to everyone: "Who has 10.10.2.10? Tell 10.10.2.1."
- *Reply*, unicast: "10.10.2.10 is at 52:54:00:12:34:56."

Every router and host keeps an **ARP (neighbour) cache** of these answers.
Ours lives in each worker's [`Pipeline`](../../crates/eph-dataplane/src/pipeline.rs).
When one worker learns a neighbour, it sends a message to the others. That's
the only thing workers ever share.

Security note: ARP has no authentication. Anyone on the segment can claim any
IP ("ARP spoofing"). We only learn from ARP packets aimed at us or that refresh
entries we already have, which is what RFC 826 recommends, but it's still
trust-on-the-wire. That's one reason segments are kept small.

## The checksum, and why routers patch it instead of recomputing

The IPv4 header carries a 16-bit checksum so routers can detect corrupted
headers. Because we decrement TTL, the checksum changes on every hop.

Recomputing means summing ten 16-bit words. Cheap, but RFC 1624 shows a
neater trick: since only one word changed, you can patch the checksum using
just the old and new value of that word:

```
new_checksum = ~(~old_checksum + ~old_word + new_word)
```

That's 3 additions and some bit flips. See
[`checksum.rs`](../../crates/eph-packet/src/checksum.rs). The unit test
decrements TTL 64 times and verifies the checksum stays correct every time.

Only the IP *header* checksum changes. TCP/UDP checksums cover the
addresses but not the TTL, so a router that doesn't do NAT never touches them.

## ICMP: the network talking back

ICMP is how routers report problems to senders. We generate three kinds:

| Message | When | What you see |
|---|---|---|
| Echo Reply | Someone pings one of our IPs | `64 bytes from 10.10.1.1` |
| Time Exceeded | TTL hit zero | `traceroute` hops, `Time to live exceeded` |
| Destination Unreachable (net) | No route matches | `Destination Net Unreachable` |

An ICMP error carries the *start of the packet that caused it* (its IP
header plus 8 bytes). Those 8 bytes contain the TCP/UDP ports, so the
sender's OS can work out which connection the error belongs to.

Two rules from RFC 1812 that we follow, and why:

1. **Never send an ICMP error about an ICMP error.** Otherwise two
   confused routers could ping-pong errors forever.
2. **Rate-limit ICMP errors** (we allow 100/s per core, bursts of 50).
   Otherwise an attacker could send a flood of TTL=1 packets and make the
   router spend all its time writing error messages. This is a small taste of
   "the data plane must protect itself".

## Things we deliberately don't handle yet

- **VLAN tags** (802.1Q): an extra 4 bytes after the MACs. Handled now:
  see chapter 17. A tag no interface is configured for is dropped and
  counted.
- **IPv6**: dropped and counted as "unsupported-ethertype".
- **Fragmentation**: if a packet is bigger than the outgoing link's MTU, a
  real router fragments it or sends "Fragmentation Needed". All our lab links
  are 1500 bytes, so it can't happen yet.
- **IP options**: forwarded untouched, which is fine.

The drop counters printed by `ephemerisd` show each of these by name. When
something doesn't work, the counters usually tell you why.

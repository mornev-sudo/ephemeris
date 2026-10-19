# 14. The packet filter and MSS adjust: what a certified firewall always drops

## A baseline every packet must pass

Some IPv4 packets have no legitimate use on a routed network. They exist
to spoof, probe or slip past filters. Firewalls certified under Common
Criteria (the protection profiles that FIPS and ICSA certified devices
are evaluated against) must drop them all, on every interface, whatever
else is configured. Ephemeris does the same in
[`filter.rs`](../../crates/eph-dataplane/src/filter.rs), as the first thing
after the IPv4 header checks and before routing, sessions or NAT. It's
not configurable, and drops are silent (no ICMP error), so a scanner learns
nothing.

| Dropped | Why | Counter |
|---|---|---|
| Source is a broadcast address (255.255.255.255, or the broadcast address of a connected subnet), multicast (224.0.0.0/4) or loopback (127.0.0.0/8) | No real host sends from these. Replies to them would go to everyone, which is the "smurf" amplification trick | `martian` |
| Source or destination is unspecified (0.0.0.0/8) or reserved for future use (240.0.0.0/4) | Never valid on the wire | `martian` |
| Destination is multicast or loopback | No multicast routing here | `martian` |
| Source is one of the router's own addresses, or equals the destination ("LAND") | Spoofed: the router never receives its own packets | `spoofed-source` |
| IP options Loose Source Route, Strict Source Route, Record Route, Timestamp, Stream ID, or a malformed option list | Source routing lets the sender choose the path around your filters. Record Route and Timestamp make routers disclose their addresses. Stream ID is obsolete | `ip-option` |
| Invalid fragments (below) | Can never be part of a real packet | `bad-fragment` |
| Any fragment addressed to the router | The router doesn't reassemble, so it could never complete one | `fragment-to-router` |
| The reserved flag bit set | Must be zero (RFC 791) | `bad-ip-header` |

The /31 exception: a /31 link (RFC 3021) has no broadcast address, since
both of its addresses are hosts, so neither counts as broadcast.

### Fragments

A router forwards fragments without reassembling them, so it can only judge
each fragment on its own. These are the checks that work on one fragment
(RFC 791 and RFC 1858):

- Every fragment carries data, and every fragment except the last carries a
  multiple of 8 bytes, because offsets count in 8-byte units.
- Offset plus length stays within 65,535 bytes. Going past that limit is
  the old "ping of death".
- The first fragment holds the whole TCP, UDP or ICMP header. The "tiny
  fragment" attack pushes the TCP flags into the second fragment, where a
  filter looking only at first fragments never sees them.
- No TCP fragment starts at offset 8. The "overlapping fragment" attack uses
  such a fragment to overwrite the first fragment's flags after the filter
  has looked at them.

Fragmented replies to NATed sessions were never usable (later fragments
have no ports to find their session by), and are now dropped as
`fragment-to-router`. Later fragments going *out* through source NAT can't
be translated either, so they're dropped (`nat-untranslatable`) rather than
leaving with an inside address.

### Spoofing and the session table

The checks above look at one packet at a time. These use what the router
knows about its interfaces and sessions:

| Dropped | Why | Counter |
|---|---|---|
| A source on one of the router's connected subnets, arriving on a different port | Anti-spoofing (RFC 3704): a LAN host's packets can only come from the LAN | `spoofed-source` |
| A packet out of an SD-WAN tether whose source isn't one of that site's prefixes | Same, for the overlay | `spoofed-source` |
| A packet that matches a session but arrives on a different port than that direction does | The session's 5-tuple guessed or copied from elsewhere. Replies are expected where the first packet left | `session-mismatch` |
| A reply to a NATed session sent to the inside host's own (private) address | Going around the NAT: replies come to the translated address | `session-mismatch` |
| An ICMP error addressed to someone other than the sender of the packet it quotes | Using a visible session to reach other inside hosts | `icmp-mismatch` |

TCP sessions also track sequence numbers and windows (with window scaling)
in both directions. A RST or FIN whose sequence number doesn't fit the
connection is still forwarded (the endpoint decides), but it doesn't close
the session in the router: a blind attacker who knows the addresses and
ports but not the sequence numbers can't tear connections down. Those
segments are counted as `tcp_blind`.

ARP entries are re-checked after 5 minutes and forgotten after 20 without
an answer, at most 16 384 per worker. An ARP packet that disagrees with a
known neighbour doesn't overwrite it: the router asks again and believes
the first answer to its own question (`arp_conflicts`).

### Exercises

1. From a LAN client, run `ping -R 10.10.2.10` (Record Route). Watch the
   `ip-option` counter go up in `ephctl status` or on the portal's dashboard.
2. Run `ping -s 3000 10.10.1.1` (a fragmented ping to the router itself) and
   find the counter that goes up.

## MSS adjust

TCP's **MSS** (maximum segment size) is how much data a host is willing to
receive in one segment. Each side announces its MSS in the SYN or SYN-ACK
that opens the connection, usually its MTU minus 40 bytes (1460 on
Ethernet). Neither side knows about a smaller link in between, such as
PPPoE (MTU 1492) or a tether. Full-size segments then don't fit, and if
ICMP "fragmentation needed" messages are filtered somewhere on the way, the
connection simply hangs.

**MSS adjust** fixes this at the router. Set it per interface:

```toml
[[interface]]
name = "wan"
device = "ens20"
address = "203.0.113.2/30"
role = "outside"
mss_adjust = 1452       # PPPoE: 1492 - 40
```

An interface with a smaller **MTU** gets this automatically: set
`mtu = 1400` (576-1500; PPPoE's default is 1492), and unless you set
`mss_adjust` yourself it becomes the MTU minus 40. Packets too big for the
interface's MTU get ICMP "fragmentation needed" (with DF) or are dropped
(the router doesn't fragment). MTUs above 1500 (jumbo frames) aren't
supported yet: they need bigger packet buffers and the NIC's own MTU raised.

Any TCP SYN going **out** of that interface, and any SYN-ACK coming back
**in** through it, has its MSS option lowered to 1452 if it was higher.
Both directions matter. The SYN tells the server how much the client can
receive. The server's SYN-ACK tells the client how much to send, and the
client sends through this interface too. Cisco's `ip tcp adjust-mss` works
the same way.

The details, in [`pipeline.rs`](../../crates/eph-dataplane/src/pipeline.rs)
(`mss_limit` and `clamp_mss`):

- **The value is a ceiling.** It never raises an MSS, and doesn't add an
  MSS option to a SYN that has none.
- **The smallest limit wins.** That is the smallest of the ingress
  interface's value, the egress interface's value and, for traffic through
  an SD-WAN tether, the overlay MTU minus 40.
- **Only the checksum word changes.** The TCP checksum is patched
  incrementally (RFC 1624), even when the MSS option starts at an odd byte
  offset. Its two bytes then straddle two 16-bit checksum words, and the
  update uses the byte-swapped values.
- **Later fragments are never touched.** Their payload isn't a TCP header,
  even if it happens to look like one.

Valid values are 536 (the smallest MSS every IPv4 host must accept) to 1460.

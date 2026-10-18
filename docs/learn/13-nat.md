# 13. NAT at the edge: inside, outside, and many hosts behind one address

## Why NAT exists

Your LAN uses private addresses (10.x, 172.16-31.x, 192.168.x) that the
internet doesn't route. Your ISP gives you one public address, maybe a few.
For a host at 10.10.1.10 to talk to 8.8.8.8, its packets must leave with a
public source address, and the replies must find their way back to
10.10.1.10. That's **source NAT**.

## Inside and outside

Every interface now has a **role**:

| Role | Faces | Default policy | NAT |
|---|---|---|---|
| `inside` | your networks | may start sessions | nothing |
| `outside` | the internet | **replies only** | traffic leaving here is translated |

With just that, the defaults give a working internet edge: inside hosts can
reach out, their traffic leaves with the outside interface's address, the
replies come back in, and nothing from the internet can start a connection
inwards. The stateful firewall (chapter 7) and NAT reinforce each other.

## PAT: one address, many hosts

PAT (port address translation, also called "masquerade" or "NAT overload")
gives every *connection* its own source **port** on the outside address:

```
inside                              outside (what 8.8.8.8 sees)
10.10.1.10:40000 → 8.8.8.8:443      203.0.113.1:40000 → 8.8.8.8:443
10.10.1.11:40000 → 8.8.8.8:443      203.0.113.1:1027  → 8.8.8.8:443   (40000 already taken)
```

The reply to `203.0.113.1:1027` belongs to 10.10.1.11:40000. The router
keeps the original port when it can, because a few protocols notice when it
changes. An outside port only has to be unique *per destination*, so one
address can carry far more than 65,535 connections.

## How Ephemeris does it: NAT is part of the session

A translation is stored *in the session* ([`NatBinding`](../../crates/eph-dataplane/src/session.rs)),
and the translated 5-tuple is added to the session table as a **second
key** for the same session:

```
key 1:  10.10.1.10:40000 ↔ 8.8.8.8:443      (as the inside host sees it)
key 2:  203.0.113.1:40000 ↔ 8.8.8.8:443     (as the internet sees it)
        └──────── both point at the same session ────────┘
```

- **Outbound packet:** matches key 1. Forward direction, so rewrite the
  source to `203.0.113.1:40000`.
- **Reply:** matches key 2. Rewrite the destination back to
  `10.10.1.10:40000` *before* routing, because the router has to route it
  to the inside host.
- **Session expires:** both keys go, so the port is free again.

So NAT costs no extra lookups: the one hash lookup that finds the session
finds the translation too. Linux conntrack works the same way (it calls the
two keys the "original" and "reply" tuples).

### Rewriting without recalculating

Changing an address or port changes the IP header checksum and the TCP/UDP
checksum. The TCP/UDP checksum covers a "pseudo-header" that includes the
IP addresses. As with the TTL (chapter 2), each changed 16-bit word is
patched with RFC 1624's incremental formula ([`nat.rs`](../../crates/eph-dataplane/src/nat.rs)):
a few additions per packet, not a pass over the payload. For ping, the ICMP
echo *identifier* plays the role of the port.

### ICMP errors

When a router on the internet sends "TTL exceeded" (traceroute) about one
of our translated packets, it sends it to the *outside* address, and it
quotes the packet *as translated*. The router finds the session from the
quote, sends the error on to the inside host, and rewrites the quote back
to what that host originally sent. Without this, traceroute through NAT
shows nothing, and path MTU discovery breaks.

### Many cores

Each worker has its own session table (chapter 7), so two workers could
pick the same outside port for different hosts. Instead, the 1024-65535
range is **split between workers**: worker *w* of *n* only uses ports where
`port % n == w`.

## Pools and rules

The defaults cover a home or branch office. For more control:

```toml
[nat]
masquerade = true                      # the default rule

[[nat.pool]]
name = "public"
addresses = ["203.0.113.10-203.0.113.20"]

# Checked in order; the first match wins; otherwise the default above.
[[nat.rule]]
name = "partner-vpn"
destination = "172.16.0.0/12"
translate = "none"                     # exempt: keep the original source

[[nat.rule]]
name = "servers"
source = "10.10.1.128/25"
outbound = "wan"
translate = "pool"
pool = "public"
```

- **Pool translation** still uses PAT, but picks the pool address from a
  hash of the inside host's address. Each host therefore always appears as
  the *same* public address, which some services (banking sites, SIP)
  require.
- **The router answers ARP for pool addresses** on outside interfaces
  ("proxy ARP"). Otherwise the ISP's router would ask "who has
  203.0.113.12?" and nobody would answer.
- NAT rules are applied **live**: new sessions use them immediately, and
  existing sessions keep their translation until they end.

All of this is also in the portal: Configuration → NAT.

## What's not here yet

- **Destination NAT / port forwarding:** for example, "203.0.113.1:443 →
  10.10.1.20:443" to publish an inside server. This is the natural next NAT
  feature.
- **DHCP on the outside interface:** most ISP links hand out their address
  by DHCP. For now the outside address and default route are static.
- **NAT hairpinning:** an inside host reaching an inside server via its
  public address.
- **Real NICs with several workers:** replies must arrive at the worker that
  made the translation. On virtio (Proxmox) this happens naturally. On
  hardware NICs it needs RSS steering by port range or a worker handoff,
  which is a future step. Use one worker for now.

## Exercises

1. On a router, run `ephctl sessions` while a client browses. Find the "NAT
   as" column in the portal's Sessions tab. Which inside hosts share an
   outside port number, and why is that allowed?
2. Add an exemption rule for one destination and watch its sessions show
   no translation.
3. Run `traceroute -n 8.8.8.8` from an inside client and work out which
   function rewrote each reply.

# 1. The big picture: what a router actually does

## The one-sentence version

A router receives a packet on one cable, looks at the destination address,
decides which cable leads closer to that destination, rewrites a few bytes,
and sends it out that cable. It does this millions of times per second.

Everything else, from routing protocols and firewalls to SD-WAN and web UIs,
exists to make that decision better or to manage it.

## An analogy: the sorting office

Think of a postal sorting office.

- **Letters** are packets. The address on the envelope is the destination IP
  address.
- **The sorting desk** is the *data plane*. A clerk glances at the postcode,
  checks a big wall chart, and drops the letter into the right outgoing bag.
  They don't open letters or phone anyone. If the clerk is slow, the queue
  backs up to the street.
- **The wall chart** is the *forwarding table* (FIB). "Postcodes starting
  with 10.10.2 go in bag B."
- **The planning office upstairs** is the *control plane*. It talks to other
  sorting offices ("we can now reach 192.168.x through you") and redraws the
  wall chart when things change. It's allowed to be slow and careful.
- **The manager's desk with the phone and the clipboard** is the
  *management plane*: the CLI and web portal where a human says "add this
  route", "show me the counters".

The single most important design rule follows from this: **never make the
sorting clerk wait for the planning office.** The clerk only reads the chart.
When the chart changes, upstairs prints a whole new chart and swaps it on the
wall in one motion. In code, that's "build a new table, swap a pointer".

## What our router does to each packet (Phase 0)

Say host A (10.10.1.10) pings host B (10.10.2.10) through the router.

1. **A works out it needs the router.** 10.10.2.10 isn't on A's own subnet,
   so A sends the packet to its *default gateway*, 10.10.1.1 (us).
2. **A needs our MAC address.** Ethernet doesn't understand IP addresses; it
   delivers frames to 6-byte hardware (MAC) addresses. A broadcasts an
   **ARP** request ("who has 10.10.1.1?") and we answer with our MAC.
3. **A sends the frame.** Ethernet destination = our MAC, IP destination =
   10.10.2.10. Note the split: the *Ethernet* address names the next hop,
   while the *IP* address names the final destination.
4. **We look up 10.10.2.10** in the routing table: "10.10.2.0/24 is directly
   connected on port lan-b".
5. **We need B's MAC.** If we don't know it, we ARP for it. Phase 0 drops
   the packet while waiting, which is why your first ping is often lost.
6. **We rewrite and send.**
   - Ethernet destination becomes B's MAC, and Ethernet source becomes our
     lan-b MAC.
   - IP TTL goes down by 1, and the IP header checksum is patched to match.
   - Everything else (IP addresses, payload) stays untouched.
7. **B replies**, and the same thing happens in reverse.

That's routing. The rest of this guide is about doing step 6 tens of millions
of times per second, and about why each detail exists.

## Why TTL exists

TTL ("time to live") is a hop counter. If two routers are misconfigured to
point at each other, a packet would loop forever and melt the network. Each
router decrements TTL, and at zero the packet is dropped. The router then
tells the sender with an ICMP "Time Exceeded" message. `traceroute` abuses
this on purpose: it sends packets with TTL 1, 2, 3… and collects the Time
Exceeded replies to discover every router on the path.

Our router implements this, so `traceroute` through it works.

## Stateless vs stateful

What we built in Phase 0 is **stateless**: each packet is judged on its own.
The router has no idea that packet #5,000 belongs to the same video call as
packet #1.

**Stateful** (Phase 1) means keeping a *session table*. The first packet of
a conversation creates an entry, and every later packet, in **both**
directions, matches it. That unlocks:

- **Firewalling:** "allow replies to connections we started, block
  everything else".
- **Speed:** do the expensive decisions once per session, not per packet.
- **SD-WAN:** "this session is a Teams call, keep it on the low-latency
  link", and keep it there even if the routing table changes.

"Forward and reverse flows" means: A→B is the forward direction, B→A is the
reverse. Both must find the *same* session entry. That's a surprisingly
interesting problem when you have many CPU cores, which Phase 1 covers.

## Where SD-WAN fits

A traditional router picks a path by destination alone. An SD-WAN router has
several WAN links (fibre, LTE, a second ISP), builds encrypted tethers over
each of them to other sites, constantly measures each tether's latency, jitter
and loss, and steers each *session* onto the best tether for that kind of
traffic. A central controller pushes policy to every router.

All of that sits on top of exactly the packet path we're building now.

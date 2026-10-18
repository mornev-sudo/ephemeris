# 12. SD-WAN: many links, one network, the best path per application

## What problem SD-WAN solves

A branch office typically has more than one way out: business fibre, a cheap
consumer broadband line, an LTE/5G modem. A classic router uses one of them
(the default route) and maybe fails over when it goes completely dead.

That wastes the other links. It also ignores the most common real problem,
which isn't a dead link but a *bad* one: 3% packet loss, latency spikes,
jitter. Users experience that as choppy calls and frozen video, even though
the link is technically "up".

SD-WAN fixes this with three ideas, all built in this phase:

1. **An overlay.** Build tethers between sites over *every* link, so each
   link is a usable path to every other site. (A *tether* is Ephemeris's
   name for a tunnel between two sites: one per pair of WAN links.)
2. **Measure continuously.** Probe every tether several times a second, and
   know its latency, jitter and loss right now.
3. **Decide per application.** Voice needs low latency and loss; a backup
   job needs bandwidth and doesn't care about latency. Steer each kind of
   traffic onto the path that suits it, and move it when that path degrades.

## The overlay on the wire

Between two Ephemeris routers, a packet from host A to host B looks like this
on the fibre link:

```
| Ethernet | IPv4 192.0.2.1 → 192.0.2.2 | UDP → 4800 | Ephemeris (16 B) | encrypted: IPv4 10.1.0.10 → 10.2.0.10 | ICMP ... | tag (16 B) |
  └──────────────── outer: "router to router, over the fibre" ────────┘ └──────── inner: the original packet ────────┘
```

[`overlay.rs`](../../crates/eph-dataplane/src/overlay.rs) defines the
16-byte header: a version, a type (data, probe, probe reply), the application
class, the sender's site id, tether id and worker, and a 64-bit counter.

### Encryption and authentication

Each tether has a 256-bit **pre-shared key**, the same on both routers. Every
overlay packet, probes included, is sealed with **ChaCha20-Poly1305**
(RFC 8439, the AEAD WireGuard uses): the inner packet is encrypted, and the
16-byte tag at the end authenticates it *and* the whole Ephemeris header. A
packet that was modified, forged, or sealed with another key fails the tag
check and is dropped (`overlay-auth`), before anything in it is believed.

An AEAD must never see the same nonce twice under one key. The nonce is
built from the sender's site id (the two sites share the key, but not a
site id), its worker number (each worker seals on its own) and the counter.
The counter's top 16 bits are the **run**: a number the router saves to
`/var/lib/ephemeris/overlay-run` and raises every time it starts, *before* it
seals anything. So even a crash and restart never reuses a nonce.

The receiver accepts each counter **once**. A sliding window per sending
worker (1024 packets wide, shared by all receiving workers) drops replayed
packets and anything from an older run (`overlay-replay`). The newest run
seen from each peer is saved too, so a restarted router still refuses
packets captured before the peer's last restart.

And a packet that comes out of a tether must have a source address that
belongs to the site the tether leads to (its overlay routes). Otherwise it's
dropped as `spoofed-source`.

### Encapsulation without copying

The obvious way to add 44 bytes of headers is to allocate a bigger buffer
and copy the packet into it. We don't. Every packet sits inside a 4 KiB UMEM
frame, and AF_XDP leaves 256 bytes of **headroom** before the packet. The
outer headers are simply written into that headroom, the packet is encrypted
where it is, the tag goes after it, and the TX descriptor points 44 bytes
earlier. That's why
[`Pipeline::process`](../../crates/eph-dataplane/src/pipeline.rs) now takes
`(frame, off, len)` and returns `Tx { port, off, len }`. Decapsulation is
the reverse: the inner packet's start becomes the new offset.

### Why UDP, and why the source port varies

UDP passes through NAT, firewalls and ISPs that would drop an unknown IP
protocol. The **source port** is derived from a hash of the inner flow. That
way, NICs with multiple queues (RSS) and routers along the path (ECMP) spread
different flows across their queues and links, instead of seeing one giant
flow. The hash is symmetric, so both directions of a flow use the same port.

## Measuring paths: probes

One worker (the *prober*) sends a probe down every tether 5 times a second:
a sequence number plus its clock. The far router echoes it back immediately,
in place, from the data plane. Whichever worker receives the echo computes
the round trip (all workers share one clock), and updates:

- **RTT:** a smoothed average, `rtt = 7/8·rtt + 1/8·sample` (like TCP's SRTT).
- **Jitter:** a smoothed difference between consecutive RTTs (RFC 3550).
- **Last reply time:** no reply for 1 second means the tether is **down**.

The control loop ([`paths.rs`](../../crates/ephemerisd/src/mgmt/paths.rs))
also computes **loss** over a 5-second window from probes sent versus
replies received.

This is the same idea as BFD (Bidirectional Forwarding Detection) in
traditional routers, extended with quality measurements.

## Deciding: path selection

Every 500 ms, [`select_paths`](../../crates/eph-dataplane/src/overlay.rs)
answers, for every remote site and every application class: *which tether?*

1. Candidates: tethers to that site that are **up**.
2. Order them by the class's `prefer` list, or by latency if it has none.
3. Take the first that meets the class's **SLA** (`max_latency_ms`,
   `max_jitter_ms`, `max_loss_pct`). If none does, take the best available
   anyway: degraded service beats none.
4. **Hysteresis:** keep the current choice while it still meets the SLA and
   isn't clearly worse (more than 20% + 2 ms slower). Otherwise sessions
   would flap between two similar links on every small change in latency.

The result is a small **path table**, swapped into the workers exactly like
a FIB (chapter 9). The data plane never makes these decisions. It
**measures** (probes) and **obeys** (the path table). Measuring in the fast
path and deciding in the slow path is the core design pattern of every
SD-WAN product.

## Sessions and paths

Each session's **class** is decided by its first packet, from protocol,
server port and DSCP ([`[[class]]`](../../config/ephemeris.example.toml)).
The session caches the tether it uses together with the path table's
*generation*. While the generation stays the same, a flow stays on one path.
When the table changes (failover, or a better path appears), each session
picks up its new tether on its next packet. That move is what "failover"
means for a running video call.

## MTU: the cost of tethering

The outer headers and the tag take 60 bytes, so a full-size 1500-byte LAN
packet no longer fits in a 1500-byte WAN packet. Two mechanisms handle it:

- **Path MTU discovery.** A packet bigger than the overlay MTU (1440) with
  "Don't Fragment" set is answered with ICMP *Fragmentation Needed* carrying
  MTU 1440. The sender's OS remembers it and sends smaller packets. This
  only works if ICMP isn't blocked, which is why the session layer passes
  related ICMP errors through (chapter 7).
- **TCP MSS clamping.** In every TCP SYN entering or leaving the overlay,
  the advertised Maximum Segment Size is lowered to 1400 (1440 minus 40
  bytes of IP and TCP headers), and the TCP checksum is patched (RFC 1624
  again). Both ends then never send segments that are too big, with no ICMP
  needed. Every SD-WAN box does this, because ICMP *is* often blocked.

## Configuration

```toml
[overlay]
site_id = 1

[[tether]]
name = "fibre"
interface = "wan1"
remote = "192.0.2.2"      # the other router's address on that link
site = 2
# The same 64 hex characters on both routers, and on every tether to site 2.
# Generate one with: openssl rand -hex 32. A tether without a key stays down.
key = "<64 hex characters>"

[[tether]]
name = "lte"
interface = "wan2"
remote = "198.51.100.2"
site = 2
key = "<the same key>"

[[overlay_route]]
prefix = "10.2.0.0/24"    # site 2's LAN
site = 2

[[class]]
name = "voice"
protocol = "udp"
ports = "10000-20000"
max_latency_ms = 150
max_loss_pct = 1.0

[[class]]
name = "bulk"
protocol = "tcp"
ports = "5201"
prefer = ["lte", "fibre"] # keep the fibre free for interactive traffic
```

Watch it:

```bash
ephctl overlay
```

The portal's **SD-WAN** tab shows the same information live.

## How it's tested

- **Unit:** [`tests_overlay.rs`](../../crates/eph-dataplane/src/tests_overlay.rs)
  wires two routers back to back in memory and checks encapsulation,
  per-class paths, failover, probe RTT, path MTU, MSS clamping, and that
  spoofed tether packets are rejected.
- **End to end:** [`sdwan-test.sh`](../../lab/netns/sdwan-test.sh) runs in
  every CI boot. It starts two real routers with a 5 ms "fibre" and a 40 ms
  "LTE" link (Linux `netem`) and checks pings, RTT, Frag Needed, a TCP
  transfer on the bulk class over LTE, and then **cuts the fibre** mid-ping.
  The test requires that the loss is detected, that traffic moves to LTE
  with most pings surviving, and that traffic moves back when the fibre
  returns.

## Limits of Phase 4a, and what comes next

- **Pre-shared keys, no handshake yet.** Tethers are encrypted and
  authenticated, but with a static key: there is no forward secrecy (a key
  stolen later decrypts recorded traffic), and changing a key means editing
  both routers. Next: a WireGuard-style handshake with ephemeral keys and
  rotation. Also, right after a router restarts, a packet captured during
  the peer's *current* run can be replayed once if it's within the window
  of the first fresh packet. Older runs are always refused.
- **Static configuration.** Tethers and remote prefixes are written by hand
  on both routers. Next (4c): a central controller that hands out the site
  topology and policies (the "SD" in SD-WAN), and FRR/BGP to learn routes
  from the LAN side.
- **No fragmentation.** Oversized packets without DF are dropped.
- **One prober thread.** Probes always come from worker 0, which is fine
  until thousands of tethers.

## Exercises

1. In the lab, add `tc qdisc change ... netem delay 5ms loss 5%` on the
   fibre and a `voice` class with `max_loss_pct = 1`. Watch voice move to
   LTE while default traffic stays on fibre.
2. Make the hysteresis too small (change the 20% in `select_paths`) and add
   jitter with `netem delay 10ms 8ms`. Watch the path flap in the log. Then
   put the hysteresis back.
3. Add a `ephctl overlay probe-now` command that triggers an immediate
   probe round. Think about which worker should handle the request.

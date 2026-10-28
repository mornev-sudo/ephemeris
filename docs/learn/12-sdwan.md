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

### Session keys from a handshake

A static key has two weaknesses. Whoever steals it later can decrypt
everything recorded with it (no **forward secrecy**), and replacing it means
editing both routers. So a site can instead be given the other router's
**public key**. The two routers then agree fresh session keys in a
handshake, and replace them every two minutes.

Each router has one X25519 key pair, its **identity**, made on first start
and kept in `/var/lib/ephemeris/overlay-identity`. Only the public half
ever leaves the router. The handshake is
[Noise](https://noiseprotocol.org/) `IKpsk2`, the pattern WireGuard uses,
from the [`snow`](https://docs.rs/snow) library:

```
 initiator                                      responder
    │ ── initiation: ephemeral key, its identity (encrypted), its key id ──▶
    │ ◀─ response: ephemeral key, its key id ─────────────────────────────
 both: one key per direction, from four Diffie-Hellman results and the
       pre-shared key (if set); the ephemeral private keys are forgotten
```

- **Forward secrecy.** The session keys come from *ephemeral* keys that
  are thrown away. Stealing a router's identity or the pre-shared key later
  doesn't recover them, so recorded traffic stays secret.
- **Authentication.** The initiation proves the sender holds the private
  key of the public key configured for it; the response proves the same
  for the responder. With a pre-shared key, both must also know it.
- **On the wire** the header gets version 3, and its spare byte becomes
  the **key id**: which session key sealed the packet (each side numbers
  its own). The handshake messages are types 4 and 5. The data plane hands
  them to the control plane ([`sdwan.rs`](../../crates/ephemerisd/src/sdwan.rs)),
  at most 20 a second per worker, and that thread does the key exchange.
- **Rekeying without loss.** A router keeps up to three sessions per site:
  the current one, the previous one (for packets still on their way), and
  a new one. The responder only switches to new keys once a packet sealed
  with them arrives from the initiator: proof the initiator has them. A
  replayed initiation therefore never makes it switch to keys nobody else
  holds.
- **Who starts.** Whichever side needs keys and knows where the other is.
  A hub can't reach a branch without a fixed address, so the branch starts.
  If both start at once, the higher site id answers the other's initiation
  and drops its own. The side that answered the last handshake waits 15
  seconds longer before rekeying, so both rarely start together. And if
  nothing at all arrives from a site for 3 seconds (it restarted and lost
  its keys), a new handshake starts straight away.
- **Junk costs nothing.** Every handshake message ends in `mac1`, a keyed
  BLAKE2s keyed with the *receiver's* public key. It's not a secret, but
  random packets fail it before any expensive key exchange.
- **Each packet number used once.** New keys come with every session and
  count from 0, so the run numbers above aren't needed. Packets captured
  before a restart can't be replayed either: their keys are gone.

With no session (yet), a site's tethers are down: no probes, no data.
`overlay-no-key` counts packets sealed with a key the router doesn't have
(expired, or from before a restart); `overlay-handshake` counts handshake
messages handed to the control plane.

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
The exception: towards a peer whose address is *learned* (see
Configuration), the source port is always the overlay port, because that
peer may be behind a NAT that only lets replies in from the port it sent to.

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

## Configuration: sites and roles

Each router describes its own place in the network (`[overlay]`) and lists
every *other* router as a `[[site]]`. The admin gives each router a
**role**, and the roles decide who builds tethers to whom:

| | Hub | Spoke | Mesh |
|---|---|---|---|
| **Hub** | ✔ | ✔ | ✔ |
| **Spoke** | ✔ | ✘ | ✘ |
| **Mesh** | ✔ | ✘ | ✔ |

- A **hub** connects to every site. Typically a head office or data centre
  with a fixed address.
- A **spoke** only connects to hubs. Typically a branch.
- A **mesh** site connects to hubs and to other mesh sites, for sites that
  talk to each other a lot and shouldn't detour through a hub.

Two sites that don't connect directly still reach each other: their
networks are routed **through the first hub**. Spoke A to spoke B goes
A → hub → B, and the hub simply routes between its tethers.

For every site this router connects to, a tether is created per outside
interface and per address of that site, named `<site>-<interface>`:

```toml
# On "cpt", a branch.
[overlay]
site_id = 1
name = "cpt"
role = "spoke"

[[site]]
name = "jhb"
id = 2
role = "hub"
addresses = ["203.0.113.2", "192.0.2.2"]   # its WAN addresses: two tethers
prefixes = ["10.2.0.0/16"]                 # the networks behind it
key = "<64 hex characters>"                # shared by cpt and jhb only

[[site]]
name = "dbn"                               # another branch: through jhb
id = 3
role = "spoke"
prefixes = ["10.3.0.0/16"]
```

### Keys

**Public keys (recommended).** `ephctl sdwan identity` (or the SD-WAN tab)
shows this router's public key. Put it in the other router's `[[site]]`
entry for this one, and the other router's in this one's:

```toml
[[site]]
name = "jhb"
id = 2
public_key = "<jhb's: ephctl sdwan identity on jhb>"
```

or `ephctl sdwan public-key jhb --set <key>`. Both routers must agree: a
site with a public key on one side and without on the other gets no
tethers. Routers on 0.11 and earlier don't have public keys, so a pair
moves over once both run 0.12. Until then, it keeps its pre-shared key.

**Pre-shared keys.** Each pair of routers that builds tethers shares **its
own** key (32 random bytes, 64 hex characters). A leaked key exposes one
pair, not the network. With a public key, the pre-shared key is optional
and only mixed into the handshake, as a second secret. Without one, it
seals the packets directly (no forward secrecy). Sites reached through a
hub need no keys at all: the hub's tethers carry them.

- **Portal:** Configuration → SD-WAN. The key field has *Generate* (made in
  your browser from the system's secure random source), *Show* and *Copy*.
- **CLI:** `ephctl sdwan key jhb` shows it. `--generate` or `--set <hex>`
  replaces it and commits.

The other router needs the same keys in its entry for *this* router. The
SD-WAN tab's **Copy entry for its router** button, or
`ephctl sdwan entry jhb`, prints a ready-made `[[site]]` block describing
this router, with the shared key and (if this router uses a public key for
jhb) this router's public key filled in. Paste it on the other side.
Like any change to sites, it applies after a data-plane restart.

### Peers without a fixed address

A branch on a home or LTE connection usually gets its WAN address by DHCP
(chapter 15), and it may change. Leave such a site's `addresses` empty.
The hub then creates a tether that **learns** where the site is: when an
authenticated packet arrives from that site, the hub remembers the source
address *and port*, and sends there.

- **Behind NAT:** because the port is learned, this works even when the
  branch is behind NAT (a home router, carrier-grade NAT). The hub always
  replies *from* its overlay port, and the branch accepts traffic from its
  hub's overlay port, so the NAT lets the replies in.
- **Keepalives:** the branch's probes, five a second, keep the NAT's
  mapping alive.
- **Several links:** a branch with fibre *and* LTE, each behind its own
  NAT, reaches the hub from two addresses. Tell the hub how many links it
  has (`links = 2` in its `[[site]]`; "Copy entry" fills it in), and the
  hub keeps a tether per link, `<site>-<wan>` and `<site>-<wan>-2`, each
  following its own link's address and NAT port. They're told apart by the
  sender's tether id in the header, which differs per link. A link that
  falls silent for 30 seconds frees its tether for another (say the branch's
  tethers were renumbered). More links than tethers are counted as
  `overlay-links-full`.
- **Security:** only a packet that authenticates *and* isn't a replay ever
  moves a tether, so without the key nobody can redirect one, and a
  captured packet sent again from elsewhere doesn't either. (That's also
  why handshake messages never move one: a captured initiation would still
  verify. The answer to it goes back where it came from; the tether moves
  with the first sealed packet.)
- **The limit:** one side of each pair needs a reachable address. Two
  sites that both learn would wait for each other forever.

### Addresses that change

A hub on PPPoE keeps its public address only until the line redials. Its
`[[site]]` entries elsewhere still name the old one. Two things follow it
there:

- **Following.** Every tether, configured address or not, follows its
  peer to wherever its authenticated packets come from. The hub keeps
  probing from its new address five times a second, so a branch that can
  receive them (a public address, or a NAT that lets them in) switches at
  once.
- **Announcing.** Many NATs drop packets from an address they haven't sent
  to. So for an hour after one of its outside addresses changes, a router
  tells every peer, once a second over every tether that still works,
  "192.0.2.2 is now 203.0.113.9" (message type 6, sealed like a probe).
  Tethers still sending to the old address move to the new one, the branch
  sends there first, and its NAT opens.

A branch remembers where a peer moved (`/var/lib/ephemeris/overlay-moved`),
so a restart doesn't go back to the stale address; editing the address in
the config wins over that. The SD-WAN tab shows such a tether as
`203.0.113.9 (moved from 192.0.2.2)`.

**When it can't recover by itself:** a hub with a single WAN whose address
changes, and branches behind NATs that drop packets from unknown
addresses. No path is left to carry the news, so those branches need the
new address in their config. Give such a hub a second WAN (any path
carries the announcement), or a fixed address.

### Hand-written tethers and application classes

`[[tether]]` and `[[overlay_route]]` still exist, for a tether that
doesn't follow the roles or that needs an explicit underlay `gateway`.
Application classes refer to tethers by name, generated or hand-written:

```toml
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
prefer = ["jhb-wan2", "jhb-wan1"]   # keep the first link free
```

Watch it:

```bash
ephctl sdwan sites
ephctl overlay
```

The portal's **SD-WAN** tab shows the same information live: sites and how
they're reached, tethers with their measured health (and, for learned
peers, where they were last heard from), and the path each class uses.

## How it's tested

- **Unit:** [`tests_overlay.rs`](../../crates/eph-dataplane/src/tests_overlay.rs)
  wires two routers back to back in memory and checks encapsulation,
  per-class paths, failover, probe RTT, path MTU, MSS clamping, and that
  spoofed tether packets are rejected.
  [`tests_session_keys.rs`](../../crates/eph-dataplane/src/tests_session_keys.rs)
  does the same with session keys (confirmation, rekeys without loss,
  expiry, unknown keys), and the tests in
  [`sdwan.rs`](../../crates/ephemerisd/src/sdwan.rs) run handshakes between
  two routers: wrong keys, tampering, replays, both starting at once,
  retries on the other WAN, and a peer learned from its initiation.
- **End to end:** [`sdwan-test.sh`](../../lab/netns/sdwan-test.sh) runs in
  CI on every change (the `sdwan` job). It starts two real routers, each with the other's public
  key, checks that they agree keys in a handshake, with a 5 ms "fibre" and a 40 ms
  "LTE" link (Linux `netem`) and checks pings, RTT, Frag Needed, a TCP
  transfer on the bulk class over LTE, and then **cuts the fibre** mid-ping.
  The test requires that the loss is detected, that traffic moves to LTE
  with most pings surviving, and that traffic moves back when the fibre
  returns.

## Limits of Phase 4a, and what comes next

- **Sites on a pre-shared key** have no forward secrecy, and right after a
  router restarts, a packet captured during the peer's *current* run can
  be replayed once if it's within the window of the first fresh packet.
  Give them a public key.
- **No cookie reply yet.** WireGuard answers a flood of initiations with a
  cookie the sender must echo, which proves its address. Here a flood that
  passes mac1 (from someone who knows the public key) is only rate-limited,
  which can delay a site's next rekey.
- **Each router holds its own site list.** Roles and keys keep it short,
  but every router is still configured on its own (with "Copy entry" to
  help). Next (4c): a central controller that hands out the site topology
  and policies (the "SD" in SD-WAN), and FRR/BGP to learn routes from the
  LAN side.
- **Site changes need a data-plane restart.** Adding a site or changing a
  key rebuilds the tethers, which a restart does (a few seconds).
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

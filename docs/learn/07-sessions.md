# 7. Stateful routing: sessions, both directions, and many cores

## What "stateful" means

In Phase 0 the router judged every packet on its own. It had no memory: the
4,000th packet of a video call was a stranger, just like the first.

A **stateful** router remembers *conversations*. The first packet of a
conversation creates a **session**, and every later packet in either
direction is matched to it. Three things become possible:

1. **Direction-aware policy.** "The office may start connections to the
   internet; the internet may only *reply*." This is the core of every
   firewall and SD-WAN edge, and we now enforce it with one config line,
   `allow_new_sessions = false`.
2. **Do the expensive work once.** Route lookup, policy evaluation, and later
   "which WAN link should this app use?" happen on the first packet. The
   answer is cached in the session for the rest.
3. **Visibility.** Who's talking to whom, how much, for how long. That is
   exactly what an SD-WAN dashboard shows.

Code: [`eph-dataplane/src/session.rs`](../../crates/eph-dataplane/src/session.rs)
and `Pipeline::track` in
[`pipeline.rs`](../../crates/eph-dataplane/src/pipeline.rs).

## Naming a conversation: the 5-tuple

A conversation is identified by five values:

| | Example |
|---|---|
| protocol | TCP (6) |
| source IP : port | 10.10.1.10 : 40000 (your browser picked a random port) |
| destination IP : port | 10.10.2.10 : 443 (the web server) |

Ping has no ports, but each ping run picks an *identifier* that the replies
echo back, so we use that in place of the ports.

## Forward and reverse: one key for both directions

The request travels `10.10.1.10:40000 → 10.10.2.10:443`. The reply travels
`10.10.2.10:443 → 10.10.1.10:40000`. Same conversation, mirror-image tuple.
If we used the tuple as-is for the lookup, the reply would look like a brand
new conversation.

The trick is a **canonical key**: always put the endpoint that sorts lower
first.

```
request:  (10.10.1.10:40000, 10.10.2.10:443)   → already in order  → lo→hi = true
reply:    (10.10.2.10:443, 10.10.1.10:40000)   → swap              → lo→hi = false
key for both: lo = 10.10.1.10:40000, hi = 10.10.2.10:443, proto = TCP
```

Both directions now produce *the same key*, plus a flag saying which way the
packet is going. The session remembers which side spoke first (the
**initiator**), so each packet is labelled:

- **Forward**: same direction as the first packet (client → server).
- **Reverse**: the reply direction (server → client).

That's what "forward and reverse flows" means. A session holds counters for
each direction, so the router can report "40 KB up, 3 MB down".

An alternative design, used by Linux conntrack and VPP, stores two hash
entries per session (one per direction) pointing at the same record. That
costs more memory but no swap logic. Both approaches are common.

## TCP has a life story; we follow it

TCP connections open with a 3-way handshake and close with FINs:

```
   client                         server        session state
     │ ── SYN ─────────────────▶    │           syn-sent
     │ ◀──────────────── SYN+ACK ── │           syn-received
     │ ── ACK ─────────────────▶    │           established
     │ ◀═══════ data both ways ═══▶ │           established
     │ ── FIN ─────────────────▶    │           fin-wait
     │ ◀──────────────────── FIN ── │           time-wait   (linger 2 min)
                 …or anyone sends RST           closed      (linger 10 s)
```

Following the state machine lets the router:

- **Use sensible timeouts.** A half-open handshake (SYN, no answer) is
  forgotten after 30 s. An established connection is kept for an hour of
  silence. A closed one goes after seconds. That frees memory quickly and
  limits damage from SYN floods.
- **Reject nonsense.** The server answering a SYN with a plain ACK is
  invalid and dropped (`invalid-tcp-state`). An RST never *opens* a session.
- **Strict vs loose** (`tcp_strict`). Strict: only a SYN may create a
  session, so it's the most secure. Loose (the default): a mid-stream packet
  is "picked up" as established. Loose matters because after a router restart
  every existing connection would otherwise be cut.

UDP and ICMP have no handshake, so they're simpler: `new` until the other
side answers, then `established`. One-way UDP times out after 30 s, and UDP
that has seen replies (a "stream", like a VoIP call) after 180 s.

### ICMP errors are "related"

If client A sends UDP to a closed port on B, B answers with an ICMP "port
unreachable". That ICMP packet doesn't match any session by its own 5-tuple,
but it *quotes* the header of A's packet. We read the quoted header, rebuild
*that* packet's key, and if the session exists, let the error through. Linux
calls this state `RELATED`. Without it, the closed side could never tell you
"nothing's listening here", and things like path MTU discovery would break.

## Forgetting: the timer wheel

Sessions must expire when idle. The naive approach is to scan all 262,144
sessions every second. That's slow, and it competes with packets for the
CPU cache.

A **timer wheel** is like a clock face with 1,024 one-second slots. A session
due to expire at second *t* is filed in slot *t mod 1024*. Each second, the
worker looks at **only one slot**.

And the key trick, **lazy rescheduling**: when a packet arrives, we just
update the session's `last_seen` time. We *don't* move it in the wheel. That
would be extra work on every packet. When the old slot comes round, we check
the real expiry time:

- still idle past its timeout → delete it
- had traffic since → refile it under the new expiry second

Busy sessions get "touched" by the wheel about once per timeout period, no
matter how many packets they carry. That's how Linux kernel timers work too.

One exception to "lazy": when a session's timeout gets *shorter* (an
established connection sees its FIN or RST), it is refiled straight away.
Otherwise a closed connection would sit in the table until its old,
hour-long slot came round.

**Nothing is kept forever.** Every timeout is capped at a day: a
`*_timeout_secs` above 86,400 is applied as 86,400 (with a warning in the
log), and a closing or closed TCP session goes within 10 minutes at most
(`MAX_IDLE_SECS`, `MAX_CLOSING_SECS` in
[`session.rs`](../../crates/eph-dataplane/src/session.rs)). A session that
keeps carrying traffic stays as long as it's in use, as it should: cutting
a live SSH session or video call would be a bug, not a safeguard.

## How long an idle session lives

Too short, and a quiet but live connection breaks: an SSH session left
open over lunch, a VoIP call on hold. Too long, and dead flows fill the
table. The defaults (`[sessions]`) follow the IETF's NAT behaviour
requirements where applications depend on them, and Linux conntrack's
practice for the rest:

| Session | Default | Why |
|---|---|---|
| TCP handshake (SYN sent, not answered) | 30 s | A real handshake takes milliseconds; scans and SYN floods leave these behind |
| TCP established | 2 h 4 min | RFC 5382 REQ-5: longer than TCP's own 2-hour keepalive, so an idle connection with keepalives survives |
| TCP closing (one FIN) / closed (both FINs, or a reset) | 120 s / 10 s | Long enough for the last retransmits |
| UDP, not answered yet | 30 s | What fills a table during a scan or flood; real requests get their answer in seconds. (RFC 4787 asks for 2 minutes here; conntrack, like us, chooses 30 s) |
| UDP, answered | 3 min | RFC 4787 REQ-5: at least 2 minutes |
| ICMP (echo) | 60 s | RFC 5508: at least 60 s |
| Other protocols (GRE, ESP, ...) | 60 s | |

Two more tools:

- **Per-application timeouts.** Some applications want something else:
  DNS is done after one answer, while a VoIP or Teams media flow may
  pause for minutes. `[[sessions.timeout]]` sets them by protocol and
  server port, decided when the session starts; the first match wins:

  ```toml
  [[sessions.timeout]]
  name = "dns"
  protocol = "udp"
  ports = "53"
  idle_secs = 10           # once answered
  unanswered_secs = 5      # before an answer (else the protocol's)
  ```

- **Early drop.** When the table is full, a new flow isn't simply
  refused: the session due to expire soonest among those that never got an
  answer (or are closing) makes room for it, as Linux conntrack does
  (`sessions.early_drop`, on by default). Only if every session is a live,
  answered conversation is the new one refused. `ephctl status` shows how
  many were dropped early.

`ephctl status` also counts the sessions that expired **without a single
packet back**. A handful is normal (a DNS server that didn't answer). A
lot of them, while users complain, means replies aren't arriving: see
chapter 13's "Replies that don't come back".

There's one more subtlety: a freed slab slot can be reused by a new session
while the wheel still holds a stale entry for the old one. Every slot carries
a **generation number** that is bumped on free, and stale wheel entries carry
the old number, so they are ignored. This is a common pattern for "handles"
in systems code.

## Memory: reserve everything up front

Each worker reserves room for `max_per_worker` sessions at startup (about
300 bytes each: the 200-byte session itself, and room in the hash map for
both of its keys, its own and its NAT translation's). With `"auto"`, the
default, the size comes from the memory the machine has free at start; a
fixed size that won't fit is refused (see `ephemerisd/src/memory.rs`). A full table refuses *new* flows (`session-table-full`), after first
trying to make room by dropping one that never got an answer (early drop,
above); existing conversations keep working. Two reasons:

- **No allocation on the fast path** (chapter 4).
- **Predictable behaviour under attack.** A flood of fake flows fills the
  table; it can't consume all RAM and crash the router.

The hash table uses a random per-process seed, so an attacker can't
precompute thousands of flows that land in the same bucket and turn every
lookup into a long search ("hash flooding"). The hash function (FxHash) is
fast but not cryptographically strong. A hardened build would use a keyed
hash like SipHash, at some cost per packet. That's a classic speed vs
security trade-off.

## Many cores: why symmetric RSS matters

Each worker has its **own** session table, with no locks and no sharing.
That's only correct if *both directions of a conversation land on the same
worker*. Otherwise worker 0 creates the session on the request, worker 1
receives the reply, finds nothing, and drops it as `no-session`.

Remember that the NIC picks the RX queue (and therefore the worker) by
hashing the packet's addresses and ports (RSS). The standard Toeplitz hash
gives `hash(A→B) ≠ hash(B→A)`, so the directions scatter. There are two
fixes:

- **Symmetric RSS.** Configure the NIC so the hash ignores direction:
  `ethtool -X dev hfunc toeplitz symmetric-xor` on Linux 6.10+, or the
  classic trick of a Toeplitz key made of the repeating bytes `6d 5a`.
  `bootstrap.sh` tries this on every data NIC.
- **Hand-off.** If a packet lands on the wrong worker, pass it to the owner,
  through a ring between workers, like VPP's "worker handoff". This is more
  general, but costs a cross-core hop.

**In our Proxmox lab (virtio) it works out anyway.** The host-side tap device
picks the guest's RX queue using a hash that is already symmetric, and it
also remembers which queue the guest *sent* each flow on and delivers replies
there. Since worker *N* sends on queue *N*, replies come back to worker *N*.
With a single worker the question never arises.

If you see `no-session` drops with multiple workers on real NICs, asymmetric
RSS is the first suspect.

## What about routing changes?

The session caches its next hop per direction (`next_hop[Forward]`,
`next_hop[Reverse]`) together with the FIB *generation* it came from. When
Phase 2 swaps in a new FIB, the generation number goes up and every cached
next hop is quietly recomputed on its next packet. Nothing walks the session
table, and nothing locks.

## Try it in the lab

The example config makes lan-b "replies only":

```bash
pct exec 9101 -- ping -c2 10.10.2.10       # A → B: works (A started it)
pct exec 9102 -- ping -c2 10.10.1.10       # B → A: dropped (no-session)
pct exec 9101 -- iperf3 -c 10.10.2.10 -R   # B sends the data, on A's session: works
```

In the `ephemerisd` log every few seconds:

```
sessions: active=2 created=7 expired=5
  tcp   10.10.1.10:51234 -> 10.10.2.10:5201  established  pkts 9120/48210 bytes 474K/71M age 4s idle 0s
  icmp  10.10.1.10:3 -> 10.10.2.10:3         established  pkts 2/2 bytes 168/168 age 9s idle 8s
```

## Exercises

1. **Watch the timeouts.** Set `udp_timeout_secs = 5`, run
   `iperf3 -u -t 2`, and watch the session appear and then expire.
2. **Strict mode.** Start a long `iperf3`, restart `ephemerisd` with
   `tcp_strict = true`, and see the existing connection die
   (`invalid-tcp-state`). Then try with `false`.
3. **Fill the table.** Set `max_per_worker = 50`, then in client-a run:
   ```bash
   for p in $(seq 1 100); do echo | nc -u -w0 10.10.2.10 $p; done
   ```
   Watch `session-table-full`.
4. **Harder: sequence-number tracking.** Real firewalls also check that TCP
   sequence numbers fall inside the window, which blocks blind RST injection
   attacks. Add `seq`/`ack` tracking per direction to `Session`.

# Design: spreading SD-WAN tether traffic across workers

Status: proposed, for review. Nothing here is built yet.

## Summary

A router decrypts every packet that arrives over a tether on the worker
the network card puts it on. When the card puts all of a tether's packets
on one queue, one core decrypts the whole tether, and the tether's
throughput is that core's, however many workers the router has.

Today that happens in three cases:

- the receiving card hashes UDP on addresses only;
- the hub is sending to a branch behind NAT;
- the branch behind NAT is sending to the hub.

This design fixes all three, in two parts:

1. **Cards hash UDP ports.** `nic-setup` asks each data-plane card to
   include UDP ports in its hash. That's one `ethtool` line, and it fixes
   the first case.
2. **Several source ports for routers behind NAT** (`[overlay]
   source_ports`). A branch sends from a few UDP ports instead of one, so
   its NAT keeps a mapping per port. The hub learns every mapping as an
   address and port per tether, and sends each flow to one of them. This
   fixes the other two cases.

The header, the crypto, nonces and replay protection don't change, and
routers on older versions keep working with newer ones.

## Where it stands today

### What already spreads

- **Sending to a peer with a configured address**
  ([`encap`](../../crates/eph-dataplane/src/pipeline.rs)): the outer UDP
  source port is `49152 | hash(inner flow)`. The hash is symmetric, so
  each inner flow keeps its own outer 5-tuple, and a card hashing UDP
  ports spreads them across queues.
- **Receiving on any worker:**
  - the sliding replay windows are shared by all workers
    ([`ReplayGuard`](../../crates/eph-dataplane/src/overlay.rs)), one per
    sending (site, worker, tether lane);
  - the learned peer addresses ([`Endpoints`](../../crates/eph-dataplane/src/overlay.rs))
    are shared atomics.

  So any worker may receive any tether packet, and correctness doesn't
  depend on which one.
- **After decrypting:** the inner packet is handed to the worker that holds
  its session ([`tether_owner`](../../crates/eph-dataplane/src/pipeline.rs)),
  as chapter 7 describes.

### Where it lands on one core

| Case | Why it's one 5-tuple, or hashed like one |
|---|---|
| **A.** The receiving card hashes UDP on addresses only | Many cards do by default (several Intel drivers, for example). Every packet from one peer address then hashes the same, whatever the ports. `nic-setup` doesn't change it today. |
| **B.** Hub → branch behind NAT | The branch's NAT has one mapping for the tether: branch `4800` ↔ hub `4800`. The hub must send to that mapping's public port, from `4800`, so every packet arrives at the branch as the same 5-tuple. |
| **C.** Branch behind NAT → hub | Towards a hub that learns its address, the branch always sends from the overlay port, so its NAT keeps one mapping. Every packet arrives at the hub from the same NAT address and port. |
| D. A PPPoE WAN | Cards can't hash inside PPPoE. Out of scope here, as for all PPPoE traffic (chapter 13). |

Cases B and C are a hub and its home or LTE branches, the common setup.

### What one core costs

`ephemerisd --bench-crypto` measures one core opening 1440-byte packets.
On an Apple M-series core: AES-256-GCM 379 ns (30 Gbit/s), and
ChaCha20-Poly1305 2.9 µs (3.9 Gbit/s). Without AES in hardware (small
x86 boxes, older ARM), ChaCha20 is the cipher, and a few Gbit/s per core
is the tether's ceiling in cases A–C. The handoff to the session's
worker adds a copy per packet on top of that.

## Goals and non-goals

Goals:

- Spread the work of receiving a tether across workers in cases A, B and C.
- Keep each inner flow on one path, with no reordering within a flow while
  nothing changes.
- Keep crypto, nonces, replay protection and the header exactly as they
  are.
- Interoperate with routers on older versions in either role, during a
  rolling upgrade.
- Need no configuration for peers with a configured address.

Non-goals:

- PPPoE WANs (case D).
- Choosing ports so packets land directly on the worker that holds the
  inner session. The sender can't know how the receiver's card hashes,
  so the handoff stays.
- IPv6 underlays.

## Part 1: cards hash UDP ports

In `nic-setup`, for each data-plane device, after the RSS setup that's
there today:

```sh
ethtool -N "$dev" rx-flow-hash udp4 sdfn 2>/dev/null || true
```

- `sdfn` adds the source and destination ports to the hash. Cards that
  can't do it refuse, and keep hashing on addresses: no worse than today.
- ephemerisd already reads which fields a card hashes
  ([`CardRss::udp_ports`](../../crates/eph-dataplane/src/steer.rs)) and
  logs it at start. With ports in the hash, source NAT can steer UDP
  replies to their worker too, as it does TCP, so this helps beyond
  tethers.
- Risk: none that I know of. A card's hash is symmetric only if both
  directions hash alike, and with `symmetric-xor` ports are XORed like
  addresses, so that still holds.

This is small enough to ship on its own, before part 2.

## Part 2: several source ports for routers behind NAT

### The idea

A router configured with `[overlay] source_ports = N` (N from 1 to 8,
default 1, so off) sends its tether packets **from N UDP ports**:

- the overlay port and the N − 1 ports after it (`4800`–`4803` for N = 4);
- each inner flow always from the same one, `port + hash(flow) % N`.

It also accepts tether traffic **to** any of those N ports.

Behind NAT, each source port gets its own NAT mapping. The far end
learns each mapping as one more address and port for the tether, and
sends each inner flow to one of them. So both directions carry N
different 5-tuples instead of one, and the cards spread them.

N consecutive ports, rather than random ones, keep the router's own
firewall rules and its upstream NAT's rules simple: one range.

### Sending side (the branch)

- **`encap`:** towards a peer with a learned address (today: always the
  overlay port), use `udp_port + flow_hash % N`. Towards a peer with a
  configured address, nothing changes: `49152 | hash` already spreads.
- **Probes** (5 a second per tether): sent from each of the N ports in
  turn, rather than from the overlay port only. Each NAT mapping then
  sees a packet every N × 200 ms (800 ms for N = 4), far inside any UDP
  NAT timeout (typically 30 s or more), and the probe rate doesn't change.
  RTT, jitter and loss stay per tether, as today.
- **Handshakes:** keep sending from the overlay port. Their rate is too
  low to matter.
- **`is_overlay`:** accept UDP to any of the N ports, as well as from a
  peer's overlay port, as now.

### Receiving side (the hub)

`Endpoints` keeps a few addresses and ports per slot instead of one: up to
`MAX_SOURCE_PORTS` = 8, each with its own "last heard" time.

- **Learning:** as today, only after a packet authenticates and passes the
  replay check. An address and port already known is refreshed; a new one
  takes a free entry, or the stalest. All entries in a slot belong to the
  same sending tether, which the slot is already bound to by the
  sender's tether id.
- **Expiry:** an entry not heard from for 3 seconds is dropped. With
  probes in turn, a live entry is heard at least every 800 ms (N = 4),
  so 3 s means about four probes missed in a row. A NAT that forgot the
  mapping costs the flows hashed to it at most 3 s of loss. Today's
  30-second rebinding of a whole slot (`STALE_SECS`) stays as it is.
- **Sending** (`tether_dest`): to a learned peer, pick the entry by
  `hash(inner flow) % live entries`, in a stable order (sorted by port),
  so a flow stays on one entry while the set doesn't change. The source
  port stays the overlay port, since that's what each branch mapping
  expects to hear from.
- **Address announcements** (`TYPE_ADDRESSES`): replace the whole set, as
  they replace the one address today.

Configured peers are unaffected: their slot is the configured address and
the overlay port, as now.

### The cost of state

8 entries × (address, port, heard) per slot, as atomics like today's one,
is about 200 bytes per tether, shared by all workers. Choosing an entry
on send reads them all: about 8 relaxed loads, small next to sealing a
packet.

### Why not a header field

A lane number in the authenticated header would let the hub know which
mapping is which. But byte 7 is already the receiver's key id in version 3
(the handshake, which is the recommended mode), and every other byte is
taken. A new header version would break mixed-version networks. Learning
mappings as a set needs no header change, and the hub doesn't need to
know which mapping is which, only that each one reaches the branch.

## Compatibility

| Branch → hub | Behaviour |
|---|---|
| new (N = 4) → old hub | The old hub learns one port at a time, the newest. It may switch between the branch's four mappings, but each still reaches the branch, which listens on all four. It works, without spreading at the branch. |
| old → new hub | One mapping: one entry. Same as today. |
| new (N = 4) → new hub, configured address for the branch | The hub ignores the source port for configured peers, as today. The branch's spreading still helps the hub's receive side, if the hub's card hashes ports. |
| new (N = 1) → anything | Today's behaviour exactly. |

`source_ports` needs no agreement between the two ends, so it can be
turned on one router at a time.

## Security

- **Learning:** new addresses and ports are learned only from packets that
  authenticate and aren't replays, exactly as today. An attacker can't add
  an entry without the key.
- **Captured packets:** a packet replayed from another source port fails
  the shared replay window before it's learned.
- **Bounded state:** at most 8 entries per tether, so a misbehaving peer
  with the key can't make the hub track more.
- **Firewalling:** opening N ports instead of one on the branch's WAN
  changes nothing beyond the port count. All N reach only the overlay's
  receive path, which drops anything that doesn't authenticate.

## Testing

- **Unit tests:**
  - `Endpoints` with several entries: learning, refreshing, expiry,
    choosing an entry by flow, and announcements replacing the set;
  - `encap`'s source port per flow;
  - `is_overlay` across the N ports;
  - probes taking the ports in turn.
- **`lab/netns/sdwan-test.sh`:** add a NAT namespace in front of one router
  (`iptables -t nat MASQUERADE`), and run two workers on each side.
  - Check that the four mappings exist (`conntrack -L`).
  - Check that the hub's tether traffic arrives on both workers (per-worker
    rx counters).
  - Check that a flow's packets stay in order.
  - Flush conntrack mid-test: one mapping disappears, its flows recover
    within 3 s, and the others don't notice.
- **The benchmark** (`--bench-pipeline`): add a case for tether receive
  (decrypt + handoff), so the per-core cost is visible before and after.

## Rollout

1. Part 1 on its own, in the next release. It's one line in `nic-setup`,
   checked in CI's VM, if its virtio-net cards (with RSS) accept `rx-flow-hash`; if they don't, the step still does no harm.
2. Part 2, with `source_ports` defaulting to 1, in the release after.
3. Default to 4 once the lab confirms it through real NATs (including
   carrier-grade NAT on LTE, which is where mappings get scarce).

## Open questions

1. **Default N once it's on:** 4 matches typical worker counts on small
   boxes. More ports mean more NAT mappings, and carrier-grade NAT may
   limit a subscriber's mappings.
2. **Expiry:** 3 s trades fast recovery against flapping on a lossy link.
   Tie it to the probe loss already measured per tether instead?
3. **Hubs behind NAT** (both ends learned): out of scope, as today, where
   at least one end needs a reachable address.
4. **Spreading by worker instead of by flow:** the sender could use its
   own worker id as the port choice (`port + worker % N`). That gives each
   sending worker a stream, which is simpler, but flows sent from one
   worker would land on one receiving core. By flow spreads better.

# 6. Code tour: following one packet through the source

Read this with the code open. We follow a ping from client-a (10.10.1.10) to
client-b (10.10.2.10) through `ephemerisd`, in the order things happen.

For the same path as a picture, with every check and drop reason and more
scenarios (NAT, PPPoE, VLANs, SD-WAN, the host path), open
[packet-walk.html](../packet-walk.html) in a browser.

## Startup: [`ephemerisd/src/run.rs`](../../crates/ephemerisd/src/run.rs)

1. **Config → ports → FIB.** [`config.rs`](../../crates/ephemerisd/src/config.rs)
   parses the TOML. Each `[[interface]]` becomes a `Port` (MAC read from
   `/sys/class/net/<dev>/address`). `build_fib` turns connected subnets and
   static routes into a DIR-24-8 table, wrapped in an `Arc` (a shared,
   read-only pointer) that every worker gets a copy of.
2. **Per worker:** allocate a `Umem` (frames, on huge pages if available),
   then create one `Xsk` socket per network card (VLAN interfaces share
   their card's, chapter 17), all on the same queue number
   and **sharing that UMEM**. The first socket registers the UMEM; the others
   pass `XDP_SHARED_UMEM`. See `Xsk::new` in
   [`eph-xdp/src/socket.rs`](../../crates/eph-xdp/src/socket.rs) for the exact
   kernel dance: `socket` → `setsockopt` × 5 → `getsockopt` (ring offsets) →
   `mmap` × 4 → `bind`.
3. **XSKMAP entries.** "Queue w of ens19 → this socket's fd."
4. **Attach XDP** last, once every queue has a socket. `XdpRedirect::attach`
   in [`bpf.rs`](../../crates/eph-xdp/src/bpf.rs) loads the 6-instruction
   program and creates a *BPF link*. Because the link is tied to our file
   descriptor, if `ephemerisd` crashes the kernel detaches the program
   automatically, and traffic doesn't vanish into a dead socket.
5. **Spawn the worker threads**, then the main thread just prints stats until
   Ctrl-C.

## The packet arrives

**In the NIC driver (kernel).** The frame lands in a UMEM frame we
previously put on ens19's FILL ring. The driver runs our XDP program, which
returns "redirect to the socket in XSKMAP slot = this RX queue". The kernel
writes a descriptor `{addr, len}` onto that socket's RX ring and advances the
ring's `producer` counter.

**In the worker loop:** [`worker.rs` → `Worker::run`](../../crates/ephemerisd/src/worker.rs).
Each iteration does seven things in order:

1. **Reap completions.** Frames the NICs finished sending go back on the
   `free` list.
2. **Top up FILL rings** from the free list, so the NICs always have
   somewhere to write.
3. **Receive.** Pop up to 64 descriptors from each RX ring, then `release()`
   the ring in one go (one shared-memory write, not 64). For each descriptor:
   - `umem.frame_mut(addr)` turns the address into a `&mut [u8]`: the
     packet's bytes, right where the NIC put them.
   - `pipeline.process(card, buf, off, len)` decides. More on that next.
   - `Verdict::Tx { port, off, len }`: push `{addr + off, len}` onto the
     TX ring of the **egress port's card** (`pipeline.card_of(port)`).
     Same frame, no copy.
   - `Verdict::Drop(reason)`: return the frame to the free list.
4. **Emit** router-generated frames (ARP requests) into fresh frames.
5. **Broadcast** newly learned neighbours to sibling workers.
6. **Commit TX rings and kick** the kernel (`sendto` with no data) where
   needed.
7. **Idle handling:** spin, and after 1000 empty rounds sleep in `poll()`.

## The decision: [`eph-dataplane/src/pipeline.rs`](../../crates/eph-dataplane/src/pipeline.rs)

`Pipeline::process` → `classify`:

- **Ethernet checks.** Is the frame long enough? Is it for our MAC (or
  broadcast)? What's the EtherType? ARP goes to `arp()`, IPv4 to `ipv4()`,
  anything else is dropped and counted.

`ipv4()` is the heart of the router, top to bottom:

1. `ipv4::parse` validates version, lengths and header checksum (RFC 1812's
   list of checks).
2. **Martian check:** sources or destinations that can never be legitimate
   (127.x, 0.0.0.0, multicast, broadcast).
3. **Is it for us?** Is the destination one of our interface IPs? Then
   `local()` answers pings.
4. **TTL ≤ 1?** Then `icmp_error(TIME_EXCEEDED)`.
5. **`track()`: sessions, then the route** (Phase 1, see chapter 7). Build
   the 5-tuple key and look it up in the session table. A known session
   advances its state and reuses its cached next hop. A new session is
   checked against the ingress port's policy, then `fib.lookup(dst)` (one or
   two array reads) picks the route, and the session is created. No route
   means `icmp_error(NET_UNREACHABLE)`.
6. **Pick the neighbour:** the route's gateway, or the destination itself if
   directly connected.
7. **Neighbour lookup** in the ARP cache (a hash map). On a miss: `resolve()`
   queues an ARP request (at most one per second per address) and the packet
   is dropped.
8. **Forward:** `ipv4::decrement_ttl` (with the RFC 1624 checksum patch) and
   `eth::set_macs`. Return `Tx` on the egress port.

That last step touches **14 bytes** of the packet. That's all forwarding is.

### Building replies in place

`icmp_error` is worth reading closely. Rather than allocating a new packet,
it:

1. moves the original IP header plus 8 bytes forward by 28 bytes (with
   `copy_within`) to make room,
2. writes a new ICMP header and a new IP header in front,
3. calls `output()` to route the reply back like any router-originated
   packet.

This only works because `process` receives the *whole frame buffer* (up to
4 KiB), not just the received bytes. That's a small API decision with a big
consequence: no allocation, even on the error path.

## Why the logic is separate from the I/O

`eph-dataplane` doesn't know AF_XDP exists. It takes bytes and returns a
verdict. Because of that:

- **All forwarding behaviour is unit-tested on a Mac:**
  [`tests.rs`](../../crates/eph-dataplane/src/tests.rs) builds real frames
  and checks ARP replies, forwarding, TTL, ICMP errors and rate limiting.
  Run `cargo test` to see them.
- **The same logic can sit behind DPDK later,** or behind a pcap file for
  replaying captured traffic, without changing a line.

## Where to experiment

Some exercises that teach a lot:

1. **Count per-port traffic.** Add `rx_per_port` to `Stats` and print it.
   This is a gentle first change.
2. **Queue instead of drop on ARP miss.** Hold up to 3 frames per unresolved
   neighbour, like Linux does, and send them when the reply arrives. Think
   about who owns those frames meanwhile (hint: they're UMEM frames, so don't
   return them to the free list).
3. **Answer pings faster.** For echo replies, measure with `perf` whether
   recomputing the IP checksum fully vs incrementally makes any measurable
   difference. Usually it won't, which is a lesson in itself: optimise
   what the profiler shows, not what you guess.
4. **Break it on purpose.** Remove the RFC 1624 checksum patch and watch the
   receiver's `netstat -s` "bad checksum" counter climb.

## Glossary

| Term | Meaning |
|---|---|
| **Data plane** | The code that touches every packet. Must be fast. |
| **Control plane** | Decides *what* the data plane should do (routes, ARP, protocols). Can be slow. |
| **Management plane** | How humans and systems configure it (CLI, API, web). |
| **FIB / RIB** | Forwarding table (resolved, fast) / routing table (everything known). |
| **LPM** | Longest-prefix match: the most specific route wins. |
| **MAC address** | 6-byte hardware address used on one Ethernet segment. |
| **ARP** | Maps IPv4 address → MAC address on the local segment. |
| **TTL** | Hop counter that stops routing loops. |
| **ICMP** | Control and error messages (ping, Time Exceeded, Unreachable). |
| **eBPF** | Safe, verified, JIT-compiled programs running inside the Linux kernel. |
| **XDP** | Hook running eBPF in the NIC driver, before the kernel stack. |
| **AF_XDP / XSK** | Socket type that delivers XDP-redirected packets to user space with no copies. |
| **UMEM** | Shared packet-buffer memory between our program, the kernel and the NIC. |
| **RSS** | NIC hashing flows across multiple RX queues, which lets you use multiple cores. |
| **Zero-copy** | Packet bytes are written once by the NIC and never copied again. |
| **Mpps** | Million packets per second: the real measure of router speed (more than Gbit/s). |
| **Run-to-completion** | One thread handles a packet from RX to TX, with no hand-offs. |
| **Huge pages** | 2 MiB memory pages that reduce address-translation overhead. |

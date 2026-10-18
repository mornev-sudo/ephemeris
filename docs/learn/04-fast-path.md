# 4. Going fast on Linux: XDP, eBPF, and AF_XDP

## The budget

A 10 Gbit/s link carrying the smallest possible packets (64 bytes, plus 20
bytes of preamble and gap on the wire) delivers **14.88 million packets per
second**. Divide one second by that:

> **67 nanoseconds per packet.** A 3 GHz core gets about 200 clock cycles.

For scale, here's what things cost (rough numbers):

| Operation | Cost |
|---|---|
| Add two numbers | < 1 ns |
| Read from L1 cache | ~1 ns |
| Read from main memory (cache miss) | 80–100 ns |
| System call (entering the kernel and back) | 100–1000 ns |
| Allocate + free memory | 20–100 ns |
| Take an uncontended lock | ~20 ns; contended: much more |

So per packet you can't afford a syscall, an allocation, a contended lock,
or more than about one cache miss. Every design choice in the data plane
follows from this table.

(Real traffic averages larger packets, so you rarely need the worst case. But
"line rate at 64 bytes" is the industry yardstick, and attackers send small
packets.)

## Why the normal Linux network stack can't do it

Linux is a general-purpose OS, and it does a lot for each packet:

1. The NIC raises an interrupt.
2. The kernel allocates an `sk_buff` (a ~200-byte bookkeeping structure).
3. The packet passes through netfilter hooks, conntrack, routing, more
   netfilter, and the queueing discipline.
4. If an application wants it, the bytes are *copied* to user space via a
   syscall.

That's flexible, and roughly 1–2 million packets per second per core.
Excellent for a server, but about 10× short of line rate.

## Option 1: bypass the kernel entirely (DPDK)

DPDK unbinds the NIC from Linux and gives it to your program, which talks to
the hardware's queues directly from user space, polling them in a tight loop.
It's the fastest option and the industry standard (VPP, most commercial
SD-WAN). The costs: the NIC vanishes from Linux (no `ip link`, no `tcpdump`),
it needs supported NICs and special setup, and it's a large C dependency.

## Option 2: XDP + eBPF (run your code inside the kernel)

**eBPF** is a tiny virtual machine built into the Linux kernel. You give the
kernel a small program, and it does two things:

1. **Verifies** it: proves the program terminates, only reads memory it's
   allowed to, and can't crash the kernel.
2. **JIT-compiles** it to native machine code.

**XDP** ("eXpress Data Path") is a hook *inside the NIC driver*, at the
earliest possible moment, before the kernel has allocated anything. An XDP
eBPF program sees the raw packet bytes and returns a verdict:

| Verdict | Meaning |
|---|---|
| `XDP_DROP` | Discard. Used by Cloudflare and Facebook for DDoS defence at 10s of Mpps per core |
| `XDP_PASS` | Continue into the normal Linux stack |
| `XDP_TX` | Bounce back out the same port |
| `XDP_REDIRECT` | Send to another port, another CPU, **or a user-space socket** |

The catch: eBPF programs are deliberately limited (bounded loops, small
stack, no arbitrary function calls), so writing a whole router in eBPF is
possible but awkward.

## Option 3: AF_XDP, and what we use

AF_XDP combines the two: a 6-instruction XDP program redirects every packet
into a special socket, and **our normal Rust program** does the real work in
user space, with no copying and no syscall per packet. The NIC stays visible
to Linux for setup and debugging.

### The pieces

**UMEM.** Our program allocates one big block of memory and carves it into
4 KiB *frames*. We register it with the kernel. From then on, **the NIC
writes packets straight into our frames** (in zero-copy mode, via DMA). We
never copy packets around. We pass around *frame addresses* (plain numbers),
and whoever holds an address owns that frame.

**Four rings.** Each is a circular queue in memory shared by us and the
kernel:

```
          we give empty frames                kernel gives full frames
  ┌──────────┐   FILL ring  ┌──────────┐  RX ring  ┌──────────┐
  │   free   │ ───────────▶ │   NIC    │ ────────▶ │ pipeline │
  │   list   │              │ receives │           │ (our code)│
  │          │ ◀─────────── │ transmits│ ◀──────── │          │
  └──────────┘ COMPLETION   └──────────┘  TX ring  └──────────┘
          kernel returns sent frames         we give frames to send
```

A packet's life: frame on FILL → the NIC fills it → appears on RX → our
pipeline rewrites the headers **in place** → we put the *same frame address*
on the egress port's TX ring → the NIC sends it → it appears on COMPLETION →
back to our free list.

Our router shares one UMEM across all ports a worker serves. So forwarding
from lan-a to lan-b is **literally just moving an 8-byte address** from one
ring to another. The packet bytes never move.

**How the rings avoid locks.** Each ring has exactly one producer and one
consumer, and two counters that only go up: `producer` and `consumer`. The
producer writes entries, *then* bumps `producer`. The consumer reads entries,
*then* bumps `consumer`. The CPU's memory-ordering rules (release on write,
acquire on read) guarantee that whoever sees the counter move also sees the
data. No lock, no syscall: the kernel and our program coordinate purely
through shared memory. See [`ring.rs`](../../crates/eph-xdp/src/ring.rs);
it's about 100 lines.

**The XDP program and XSKMAP.** A NIC with 4 queues gets 4 sockets (one per
worker). The XSKMAP is a kernel table "queue N → socket N". Our eBPF program
is:

```c
return bpf_redirect_map(&xsks, ctx->rx_queue_index, XDP_DROP);
```

The last argument is what happens when no socket is bound to that queue.
`XDP_DROP` fails closed: data-plane traffic never ends up in the kernel's
own network stack by accident.

We assemble those 6 instructions by hand in
[`bpf.rs`](../../crates/eph-xdp/src/bpf.rs) and load them with the raw `bpf()`
syscall. Normally a compiler does this. Doing it manually shows there's no
magic, and means no C toolchain is needed.

### Native vs generic XDP, zero-copy vs copy

| | Native (driver) | Generic (SKB) |
|---|---|---|
| Where it runs | Inside the NIC driver | After the kernel built an `sk_buff` |
| Speed | Fast | Not much better than normal Linux |
| Works on | Drivers with XDP support (virtio_net, ixgbe, i40e, ice, mlx5…) | Any interface |

| | Zero-copy | Copy |
|---|---|---|
| Who moves the bytes | The NIC, via DMA straight into UMEM | The kernel copies into UMEM |
| Needs | Driver support for AF_XDP ZC | Nothing |

`ephemerisd` logs which modes it got at startup. In a Proxmox VM with virtio
you should get native XDP; zero-copy depends on kernel and QEMU versions.

## The tricks inside our worker loop

Look at [`worker.rs`](../../crates/ephemerisd/src/worker.rs) with these in mind:

- **Polling instead of interrupts.** The worker spins checking its rings.
  An interrupt costs microseconds; a check of a ring counter costs
  nanoseconds. When idle for a while, we fall back to sleeping in `poll()`
  so an idle lab router doesn't burn a CPU. Set `busy_poll = true` for the
  DPDK-style "always spin".
- **Batching.** We take up to 64 packets per ring per round. Fixed costs
  (reading the shared counters, the TX "kick" syscall in copy mode) are paid
  once per batch, not once per packet.
- **Run-to-completion.** One thread takes a packet all the way from RX to TX.
  No hand-offs between threads, no queues between stages.
- **Share nothing between cores.** Each worker has its own UMEM, sockets,
  ARP cache and counters. The only cross-core traffic is the rare "I learned
  a neighbour" message. Two cores writing the same cache line is one of the
  biggest silent performance killers ("false sharing").
- **No allocation on the fast path.** Frames are pre-allocated. Even
  generated ARP requests use a fixed 64-byte buffer.
- **Read the clock once per batch.** Even `Instant::now()` costs ~20 ns,
  so the pipeline gets the time handed to it.
- **Huge pages.** The CPU caches address translations in the TLB, which only
  has a few thousand entries. With 4 KiB pages, 32 MiB of frames needs 8,192
  entries; with 2 MiB huge pages it needs 16. Fewer TLB misses means fewer
  stalls.
- **Multiple queues and RSS.** The NIC hashes each packet's addresses and
  ports and picks an RX queue, so different flows land on different cores.
  That's how you scale beyond one core. (Phase 1 will make the hash
  *symmetric*, so A→B and B→A land on the same core, because both directions
  need the same session entry.)

## Why Rust for this

- **No garbage collector**, so there are no surprise pauses mid-burst.
- **The same machine code C would produce** for the hot loop, including
  inlining and SIMD.
- **Memory safety where it matters.** Packets come from untrusted sources.
  In C, a packet with a lying length field is a classic remote exploit. In
  our code, an out-of-range access panics instead of reading someone else's
  memory, and the `unsafe` code is confined to the small `eph-xdp` crate where
  it's unavoidable (raw shared memory with the kernel).
- **One language** for data plane, control plane, CLI and API server.
